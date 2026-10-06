"""Playwright flows against the live review site: login, approve/redact/release, withhold, settings
(standing mode and temporary YOLO override), catalog, investigation, history, and the exact
before/after view of a mutation followed by its receipt.

Every flow that submits a form from the browser is currently blocked by one product bug (see
ORIGIN_NULL_BUG). Those flows are kept as strict xfails so they flip the moment it is fixed; the page
rendering at each stage is verified separately with the reviewer session injected as a cookie and the
state changes driven through httpx."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator

import pytest
from playwright.async_api import Browser, BrowserContext, Page, async_playwright, expect

from tests.conftest import DIGESTS, REPO, Env

pytestmark = [pytest.mark.asyncio, pytest.mark.browser]

ORIGIN_NULL_BUG = (
    "Browser form submissions are rejected by the server's own headers: HostOriginMiddleware "
    "(src/local_ops/app.py:208-210) returns 403 'invalid Origin' for any Origin outside the allow list, while "
    "the same middleware sets 'Referrer-Policy: no-referrer' (src/local_ops/app.py:214). Per the Fetch spec, a "
    "non-GET request under referrer policy 'no-referrer' carries 'Origin: null', so Chromium sends "
    "'Origin: null' on POST /login (and every other form) and the review site cannot be used from a browser."
)
origin_bug = pytest.mark.browser  # the Origin: null bug (ORIGIN_NULL_BUG) is fixed; flows run for real now


@pytest.fixture
async def browser() -> AsyncIterator[Browser]:
    async with async_playwright() as pw:
        b = await pw.chromium.launch(headless=True)
        try:
            yield b
        finally:
            await b.close()


@pytest.fixture
async def context(browser: Browser) -> AsyncIterator[BrowserContext]:
    ctx = await browser.new_context()
    try:
        yield ctx
    finally:
        await ctx.close()


@pytest.fixture
async def page(context: BrowserContext) -> Page:
    p = await context.new_page()
    p.set_default_timeout(15000)
    return p


async def login(page: Page, env: Env, password: str | None = None, next_path: str = "/review") -> None:
    """Log in through the real form. Fails fast when the POST is rejected instead of waiting for navigation."""
    await page.goto(f"{env.base_url}/login?next={next_path}")
    await page.fill("input[name=username]", "reviewer")
    await page.fill("input[name=password]", password or env.reviewer_password)
    await page.click("button[type=submit]")
    await page.wait_for_load_state()
    body = await page.content()
    assert "invalid Origin" not in body, f"POST /login rejected: {body[:200]}"


async def login_by_cookie(page: Page, env: Env, path: str) -> None:
    """Inject a reviewer session obtained over httpx so page rendering can be verified in a browser."""
    c = await env.reviewer()
    sid = c.cookies.get("lop_session")
    await c.aclose()
    assert sid
    await page.context.add_cookies([{"name": "lop_session", "value": sid, "url": env.base_url}])
    await page.goto(f"{env.base_url}{path}")
    assert page.url == f"{env.base_url}{path}"
    assert "Log out (reviewer)" in await page.content()


async def reload_until(page: Page, text: str, wait_seconds: float = 20.0) -> None:
    deadline = time.perf_counter() + wait_seconds
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise AssertionError(f"{text!r} not visible on {page.url} within {wait_seconds}s")
        try:
            await expect(page.locator("body")).to_contain_text(text, timeout=min(500, remaining * 1000))
            return
        except AssertionError:
            await page.reload(wait_until="domcontentloaded")


async def _pending_scan(env: Env, reason: str) -> str:
    sub = await env.call("read", "discovery_scan", {"providers": ["demo-fake"], "reason": reason})
    assert sub["execution_status"] == "pending_request_review"
    return str(sub["request_id"])


# --------------------------------------------------------------------------- (a) login


@origin_bug
async def test_login_wrong_then_right_password(page: Page, env: Env) -> None:
    await login(page, env, password="nope")
    await page.wait_for_selector("p.error")
    assert "invalid username or password" in await page.inner_text("p.error")
    assert page.url.endswith("/login")
    await login(page, env)
    await page.wait_for_url(f"{env.base_url}/review")
    assert "Review queue" in await page.inner_text("h1")
    assert "Log out (reviewer)" in await page.content()


async def test_login_page_renders_and_protects_review(page: Page, env: Env) -> None:
    await page.goto(f"{env.base_url}/review")
    await page.wait_for_url(f"{env.base_url}/login?next=/review")
    assert "Reviewer login" in await page.inner_text("h1")
    assert await page.locator("input[name=username]").count() == 1
    assert await page.locator("input[name=password][type=password]").count() == 1
    assert "Agent API keys cannot log in here" in await page.content()


# --------------------------------------------------------------------------- (b) approve, redact, release


@origin_bug
async def test_approve_then_redact_and_release(page: Page, env: Env) -> None:
    rid = await _pending_scan(env, "browser flow")
    await login(page, env)
    await page.wait_for_url(f"{env.base_url}/review")
    section = page.locator("section", has_text="Pending execution approval")
    await section.locator(f"a[href='/review/{rid}']").click()
    await page.wait_for_url(f"{env.base_url}/review/{rid}")
    assert "Request review" in await page.content()
    await page.click("#request-review button.primary")
    await page.wait_for_url(f"{env.base_url}/review/{rid}")
    await reload_until(page, "pending disclosure")
    content = await page.content()
    assert "Coverage" in content and "Evidence fragments" in content
    await page.fill("textarea[name=redact_paths]", "items.0.resource_key")
    await page.click("form[action$='/release'] button.primary")
    await page.wait_for_url(f"{env.base_url}/review/{rid}")
    await reload_until(page, "released")
    res = await env.call("read", "request_result", {"request_id": rid})
    assert res["items"][0]["resource_key"] == "[REDACTED by reviewer]"


async def test_request_page_renders_each_review_stage(page: Page, env: Env) -> None:
    rid = await _pending_scan(env, "render stages")
    await login_by_cookie(page, env, "/review")
    assert "Review queue" in await page.inner_text("h1")
    section = page.locator("section", has_text="Pending execution approval")
    assert "1" in await section.locator("span.pill").first.inner_text()
    row = section.locator("tr", has_text=rid)
    assert "discovery_scan" in await row.inner_text() and "render stages" in await row.inner_text()
    await section.locator(f"a[href='/review/{rid}']").click()
    await page.wait_for_url(f"{env.base_url}/review/{rid}")
    assert "discovery_scan" in await page.inner_text("h1")
    assert await page.locator("#request-review button.primary", has_text="Approve").count() == 1
    assert await page.locator("textarea[name=edited_args]").count() == 1
    assert "pending_request_review" in await page.inner_text("main")

    assert (await env.approve(rid)).status_code == 303
    await reload_until(page, "pending disclosure")
    main = await page.inner_text("main")
    assert "Coverage" in main and "demo-fake/local-1" in main
    assert "Evidence fragments" in main and "demo fixture discovery" in main
    assert "Candidate response" in main
    assert await page.locator("textarea[name=redact_paths]").count() == 1
    assert await page.locator("form[action$='/release'] button.primary").count() == 1
    assert await page.locator("form[action$='/withhold'] button.danger").count() == 1
    # the evidence link opens the sanitized fragment view
    ev_id = (await env.core.db.evidence_for_request(rid))[0]["id"]
    await page.click(f"a[href='/review/{rid}/evidence/{ev_id}']")
    await page.wait_for_url(f"{env.base_url}/review/{rid}/evidence/{ev_id}")
    assert "fixture" in await page.inner_text("main")

    assert (await env.release(rid, redact_paths="items.0.resource_key")).status_code == 303
    await page.goto(f"{env.base_url}/review/{rid}")
    await reload_until(page, "released")
    main = await page.inner_text("main")
    assert "redacted: items.0.resource_key" in main
    assert await page.locator("form[action$='/release']").count() == 0  # nothing left to release
    res = await env.call("read", "request_result", {"request_id": rid})
    assert res["items"][0]["resource_key"] == "[REDACTED by reviewer]"
    assert res["items"][1]["resource_key"] != "[REDACTED by reviewer]"
    assert res["redaction_record"]["paths"] == ["items.0.resource_key"]


# --------------------------------------------------------------------------- (c) withhold


@origin_bug
async def test_withhold_denies_the_agent(page: Page, env: Env) -> None:
    rid = await _pending_scan(env, "withhold flow")
    await login(page, env, next_path=f"/review/{rid}")
    await page.wait_for_url(f"{env.base_url}/review/{rid}")
    await page.click("#request-review button.primary")
    await reload_until(page, "pending disclosure")
    await page.click("form[action$='/withhold'] button.danger")
    await page.wait_for_url(f"{env.base_url}/review/{rid}")
    await reload_until(page, "withheld")
    res = await env.call("read", "request_result", {"request_id": rid})
    assert res["__error__"]["error"] == "authorization_denied"


async def test_withheld_request_page_renders(page: Page, env: Env) -> None:
    rid = await _pending_scan(env, "withhold render")
    await env.approve(rid)
    await env.wait("read", rid)
    await env.withhold(rid)
    await login_by_cookie(page, env, f"/review/{rid}")
    main = await page.inner_text("main")
    assert "withheld" in main
    assert await page.locator("form[action$='/withhold']").count() == 0
    assert await page.locator("form[action$='/release']").count() == 1  # a withheld result can still be released later
    res = await env.call("read", "request_result", {"request_id": rid})
    assert res["__error__"]["error"] == "authorization_denied"


# --------------------------------------------------------------------------- (d) settings


@origin_bug
async def test_settings_mode_and_yolo_override(page: Page, env: Env) -> None:
    pid = (await env.core.db.principal_by_name("read-default"))["id"]
    await login(page, env, next_path="/settings")
    await page.wait_for_url(f"{env.base_url}/settings")
    row = page.locator("tr").filter(has=page.locator(f"input[name=principal_id][value='{pid}']")).filter(has=page.locator("input[name=data_class][value='inventory']"))
    assert await row.count() == 1
    await row.locator("select[name=mode]").select_option("yolo")
    async with page.expect_navigation():
        await row.locator("button", has_text="Set").click()
    await page.goto(f"{env.base_url}/review")
    assert "YOLO active" in await page.locator("div.banner.yolo").inner_text()
    sub = await env.call("read", "discovery_scan", {"providers": ["demo-fake"], "reason": "auto-run under yolo"})
    assert sub["execution_status"] in ("queued", "running")
    assert (await env.wait("read", sub["request_id"]))["response_status"] == "released"
    await page.goto(f"{env.base_url}/settings")
    form = page.locator("form[action='/settings/yolo']")
    await form.locator("select[name=principal_id]").select_option(label="read-default")
    await form.locator("select[name=data_class]").select_option("content")
    await form.locator("input[name=minutes]").fill("5")
    async with page.expect_navigation():  # posts via fetch, then replaces the page
        await form.locator("button", has_text="Enable YOLO override").click()
    overrides = await env.core.db.active_overrides()
    assert len(overrides) == 1 and overrides[0]["capability"] == "content"
    async with page.expect_navigation():
        await page.click(f"form[action='/settings/yolo/{overrides[0]['id']}/revoke'] button")
    assert await env.core.db.active_overrides() == []


async def test_settings_page_renders_modes_banner_and_override(page: Page, env: Env) -> None:
    pid = (await env.core.db.principal_by_name("read-default"))["id"]
    await login_by_cookie(page, env, "/settings")
    row = page.locator("tr").filter(has=page.locator(f"input[name=principal_id][value='{pid}']")).filter(has=page.locator("input[name=data_class][value='inventory']"))
    assert await row.count() == 1
    assert "review_both" in await row.inner_text()
    assert await row.locator("select[name=mode] option").count() == 4
    assert await row.locator("button", has_text="Set").count() == 1
    exec_row = page.locator("tr").filter(has=page.locator("input[name=data_class][value='mutation']")).first
    assert await exec_row.locator("select[name=mode] option[value=review_responses]").count() == 0  # response-only review is never offered for mutations
    assert await page.locator("div.banner.yolo").count() == 0

    assert (await env.set_mode("read-default", "inventory", "yolo")).status_code == 303
    await page.reload()
    assert "yolo" in await row.inner_text()
    await page.goto(f"{env.base_url}/review")
    banner = page.locator("div.banner.yolo")
    assert "YOLO active" in await banner.inner_text()
    assert "read-default / inventory (standing setting)" in await banner.inner_text()
    sub = await env.call("read", "discovery_scan", {"providers": ["demo-fake"], "reason": "auto-run under yolo"})
    assert sub["execution_status"] in ("queued", "running")
    assert (await env.wait("read", sub["request_id"]))["response_status"] == "released"

    c = await env.reviewer()
    diag = await env.core.db.principal_by_name("read-default")
    r = await c.post("/settings/yolo", data={"csrf": await env.csrf(c), "principal_id": diag["id"], "data_class": "content", "minutes": "5"})
    assert r.status_code == 303
    await c.aclose()
    overrides = await env.core.db.active_overrides()
    assert len(overrides) == 1
    await page.goto(f"{env.base_url}/settings")
    assert f"override {overrides[0]['id']}" in await page.inner_text("main")
    assert await page.locator(f"form[action='/settings/yolo/{overrides[0]['id']}/revoke'] button").count() == 1
    await page.goto(f"{env.base_url}/review")
    assert "read-default / content until" in await page.locator("div.banner.yolo").inner_text()
    c = await env.reviewer()
    assert (await c.post(f"/settings/yolo/{overrides[0]['id']}/revoke", data={"csrf": await env.csrf(c)})).status_code == 303
    await c.aclose()
    await page.goto(f"{env.base_url}/settings")
    assert f"override {overrides[0]['id']}" not in await page.inner_text("main")
    assert await env.core.db.active_overrides() == []


# --------------------------------------------------------------------------- (e) catalog


async def test_catalog_pages(page: Page, env: Env) -> None:
    await login_by_cookie(page, env, "/catalog")
    assert "Service map: test-demo" in await page.inner_text("h1")
    rows = await page.locator("table.list tr").all_inner_texts()
    assert any("demo-app" in r and "Demo application" in r for r in rows)
    assert any("demo-db" in r for r in rows)
    await page.click("a[href='/catalog/demo-db']")
    await page.wait_for_url(f"{env.base_url}/catalog/demo-db")
    text = await page.inner_text("main")
    assert "Contradictions requiring verification" in text
    assert "runs in local-1" in text and "runs in local-2" in text
    assert "documentary" in text
    assert "backup recoverability unverified" in text
    await page.goto(f"{env.base_url}/catalog/demo-app")
    text = await page.inner_text("main")
    assert "execution enabled" in text and "No released observations for this service yet" in text
    assert "Contradictions requiring verification" in text and "None recorded." in text


# --------------------------------------------------------------------------- (f) investigation


async def test_investigation_page_shows_timeline(page: Page, env: Env) -> None:
    await env.set_mode("read-default", "content", "yolo")
    sub = await env.call("read", "investigation_run", {"recipe": "identity_and_deployment_audit", "sources": ["demo-fake"], "filters": {"scenario": "suspicious"}})
    rid = sub["request_id"]
    st = await env.wait("read", rid, timeout=60)
    assert st["response_status"] == "released"
    await login_by_cookie(page, env, f"/investigation?request_id={rid}")
    text = await page.inner_text("main")
    assert f"Coverage for {rid}" in text
    assert "Event timeline" in text
    assert "carol-departed" in text and "StopLogging" in text and "192.0.2.44" in text
    assert "R1.departed_identity_activity" in text and "R8.cross_source_correlation" in text
    rows = page.locator("section", has_text="Event timeline").locator("table.list tr")
    assert await rows.count() > 20
    assert "<script>" not in await page.content()
    # filters narrow the timeline without changing the findings
    await page.goto(f"{env.base_url}/investigation?request_id={rid}&actor=alice")
    text = await page.inner_text("main")
    assert "DescribeInstances" in text and "StopLogging" not in text.split("Event timeline", 1)[1]


# --------------------------------------------------------------------------- (g) history


async def test_history_page_lists_requests(page: Page, env: Env) -> None:
    rid = await _pending_scan(env, "history flow")
    await env.reject(rid)
    await login_by_cookie(page, env, "/history")
    section = page.locator("section", has_text="Requests")
    assert await section.locator(f"a[href='/review/{rid}']").count() == 1
    row = section.locator("tr", has_text=rid)
    assert "rejected" in await row.inner_text() and "read-default" in await row.inner_text()
    audit = page.locator("section", has_text="Application audit trail")
    assert "request.reject" in await audit.inner_text()


# --------------------------------------------------------------------------- (h) mutation before/after + receipt


async def _prepare_update_and_submit(env: Env) -> tuple[str, dict]:  # type: ignore[type-arg]
    await env.set_mode("write-default", "mutation", "yolo")
    prep = await env.call("write", "action_prepare", {"service_id": "demo-app", "binding_id": "demo-deployment", "action": "update", "desired_artifact": f"{REPO}:v2"})
    st = await env.wait("write", prep["request_id"], timeout=60)
    assert st["execution_status"] == "succeeded" and st["response_status"] == "released"
    plan = await env.call("write", "request_result", {"request_id": prep["request_id"]})
    assert plan["plan"]["requested_artifact"]["digest"] == DIGESTS["v2"]
    await env.set_mode("write-default", "mutation", "review_both")
    sub = await env.call("write", "action_submit", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"], "idempotency_key": f"browser-{uuid.uuid4()}"})
    assert sub["execution_status"] == "pending_request_review"
    env.app_state.version = "2.0.0"  # the fake app reports the new version once rolled out
    return str(sub["request_id"]), plan


async def _assert_plan_view(page: Page, plan: dict) -> None:  # type: ignore[type-arg]
    text = await page.inner_text("main")
    assert "action_submit" in text and "mutation" in text.lower()
    assert "Exact plan" in text and plan["plan_id"] in text
    assert "a1a1" in text and "b2b2" in text  # before/after digests
    assert "strategic_merge_patch" in text
    assert "version 2.0.0" in text
    assert DIGESTS["v1"] in await page.locator("table.kv tr", has_text="Before").first.inner_text()
    assert DIGESTS["v2"] in await page.locator("table.kv tr", has_text="After").first.inner_text()
    assert await page.locator("textarea[name=edited_args]").count() == 0  # mutations cannot be edited, only approved or rejected


async def _assert_receipt_view(page: Page, env: Env) -> None:
    text = await page.inner_text("main")
    assert "rollout converged" in text
    assert "Before → after artifact" in text
    rt = await page.locator("#receipt").inner_text()
    assert DIGESTS["v1"] in rt and DIGESTS["v2"] in rt
    assert "ran" in rt and "pass ready_replicas" in rt
    assert env.kube.workloads[("Deployment", "demo", "demo-app")]["spec"]["template"]["spec"]["containers"][0]["image"] == f"{REPO}@{DIGESTS['v2']}"


@origin_bug
async def test_mutation_page_shows_exact_before_after_and_receipt(page: Page, env: Env) -> None:
    rid, plan = await _prepare_update_and_submit(env)
    await login(page, env, next_path=f"/review/{rid}")
    await page.wait_for_url(f"{env.base_url}/review/{rid}")
    await _assert_plan_view(page, plan)
    await page.click("#request-review button.primary")
    await page.wait_for_url(f"{env.base_url}/review/{rid}")
    await reload_until(page, "Operation receipt", wait_seconds=40)
    await _assert_receipt_view(page, env)


async def test_mutation_page_renders_plan_then_receipt(page: Page, env: Env) -> None:
    rid, plan = await _prepare_update_and_submit(env)
    await login_by_cookie(page, env, f"/review/{rid}")
    await _assert_plan_view(page, plan)
    assert await page.locator("#request-review button.primary", has_text="Approve").count() == 1
    assert (await env.approve(rid)).status_code == 303
    await reload_until(page, "Operation receipt", wait_seconds=40)
    await _assert_receipt_view(page, env)
    assert "Provider intents" in await page.inner_text("main")


async def test_accepting_from_a_proposal_page_keeps_back_on_the_list(page: Page, env: Env) -> None:
    rev = (await env.call("read", "catalog_read", {"service_id": "demo-app", "include_observed": False}))["catalog"]["revision"]
    res = await env.call("read", "catalog_propose", {"service_id": "demo-app", "base_revision": rev, "changes": [{"op": "add", "path": "/unknowns/-", "value": "back button"}], "reason": "browser test"})
    await login(page, env, next_path="/proposals")
    await page.wait_for_url(f"{env.base_url}/proposals")
    assert "catalog proposals 1" in await page.inner_text("#pending-banner")
    await page.click(f"a[href='/proposals/{res['proposal_id']}']")
    await page.wait_for_url(f"{env.base_url}/proposals/{res['proposal_id']}")
    async with page.expect_navigation():
        await page.click("button:has-text('Accept')")
    assert page.url == f"{env.base_url}/proposals"
    assert (await env.core.db.proposal(res["proposal_id"]))["status"] == "accepted"
    await page.go_back()
    assert page.url.rstrip("/").endswith("/proposals")  # one Back: the detail page was replaced, not stacked
