-- D28: capabilities become read/write; review policy is keyed by data class (inventory, content, mutation).
-- Existing credentials keep working: discovery/diagnosis grants become read, execution becomes write.
-- A review setting or override moves to the data class its old capability governed, so no data class
-- gains a less strict mode than the one that applied to the same operations before.

-- Before regranting, drop review state that never had effect: a setting or principal-specific override for a
-- capability the principal did not hold (the pre-D28 settings page allowed storing these). Regranting would
-- otherwise turn, e.g., a dormant diagnosis=yolo on a discovery-only key into an active content=yolo.
-- Temporary YOLO overrides (at most yolo_override_max_minutes long) are all cleared: any of them, global or
-- per principal, could cover a data class a credential gains by the merge (e.g. a former discovery-only key
-- now able to request content). The reviewer re-creates any still wanted.
DELETE FROM review_settings WHERE NOT EXISTS (
  SELECT 1 FROM principals p, json_each(p.grants) g WHERE p.id = review_settings.principal_id AND g.value = review_settings.capability
);
DELETE FROM review_overrides;

UPDATE principals SET grants = (
  SELECT json_group_array(DISTINCT CASE value WHEN 'discovery' THEN 'read' WHEN 'diagnosis' THEN 'read' WHEN 'execution' THEN 'write' ELSE value END)
  FROM json_each(principals.grants)
);

UPDATE review_settings SET capability = CASE capability WHEN 'discovery' THEN 'inventory' WHEN 'diagnosis' THEN 'content' WHEN 'execution' THEN 'mutation' ELSE capability END;

UPDATE requests SET capability = CASE capability WHEN 'discovery' THEN 'read' WHEN 'diagnosis' THEN 'read' WHEN 'execution' THEN 'write' ELSE capability END;
UPDATE approvals SET capability = CASE capability WHEN 'discovery' THEN 'read' WHEN 'diagnosis' THEN 'read' WHEN 'execution' THEN 'write' ELSE capability END;
UPDATE schedules SET capability = CASE capability WHEN 'discovery' THEN 'read' WHEN 'diagnosis' THEN 'read' WHEN 'execution' THEN 'write' ELSE capability END;
UPDATE proposals SET capability = CASE capability WHEN 'discovery' THEN 'read' WHEN 'diagnosis' THEN 'read' WHEN 'execution' THEN 'write' ELSE capability END;
