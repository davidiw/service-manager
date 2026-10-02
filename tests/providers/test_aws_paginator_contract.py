"""Check each adapter paginator against the installed service-specific SDK model."""
from __future__ import annotations

import ast
from pathlib import Path

from botocore import xform_name
from botocore.session import get_session

_PROVIDER_DIR = Path(__file__).parents[2] / "src" / "local_ops" / "providers"


def _operations(source: str) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()

    def visit(node: ast.AST, clients: dict[str, str], function: str = "") -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = node.name
        if isinstance(node, ast.AsyncWith):
            clients = dict(clients)
            for item in node.items:
                call = item.context_expr
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "_client":
                    assert isinstance(item.optional_vars, ast.Name)
                    assert isinstance(call.args[0], ast.Constant)
                    clients[item.optional_vars.id] = str(call.args[0].value)
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ""
            if name in {"_paginate", "_paginated", "child"}:
                if name == "child":
                    service, operation = clients["ec2"], node.args[0]
                else:
                    offset = 1 if name == "_paginated" else 0
                    client, operation = node.args[offset:offset + 2]
                    if not isinstance(operation, ast.Constant):
                        # The two forwarding helpers are checked at their literal call sites.
                        assert (function, name, ast.unparse(operation)) in {
                            ("_paginated", "_paginate", "operation"),
                            ("child", "_paginate", "operation"),
                        }
                        return
                    assert isinstance(client, ast.Name)
                    service = clients[client.id]
                assert isinstance(operation, ast.Constant) and isinstance(operation.value, str)
                found.add((service, operation.value))
        for child in ast.iter_child_nodes(node):
            visit(child, clients, function)

    visit(ast.parse(source), {})
    return found


def test_every_adapter_pagination_call_has_a_service_specific_botocore_paginator() -> None:
    session = get_session()
    operations = set().union(*(_operations((_PROVIDER_DIR / name).read_text()) for name in ("aws.py", "aws_data.py", "aws_edge.py")))
    assert len(operations) >= 40
    for service, operation in sorted(operations):
        supported = {xform_name(name) for name in session.get_paginator_model(service)._paginator_config}
        assert operation in supported, f"{service}.{operation} has no installed botocore paginator"


def test_contract_resolves_eventbridge_service_not_similarly_named_other_api() -> None:
    source = 'async def scan():\n async with adapter._client("events", region) as c:\n  await adapter._paginate(c, "list_event_buses", "EventBuses", ctx, budget)'
    assert _operations(source) == {("events", "list_event_buses")}
    model = get_session().get_paginator_model("events")
    assert "list_event_buses" not in {xform_name(name) for name in model._paginator_config}
