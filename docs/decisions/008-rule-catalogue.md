# 008 Rule catalogue derived from implemented rules

Status: accepted    Source status: verified (CWE, MITRE ATT&CK, MITRE ATLAS)

Decision: `GET /v1/rules` is generated from the analyzer's own reason table plus per-rule severity and CWE/ATT&CK references, so the catalogue cannot advertise checks that do not exist.

Why: Transparency is only credible if the published catalogue equals the code. Generating it from `REASONS` makes drift a test failure (`test_rule_catalogue_matches_implemented_rules`).

Alternatives rejected: a hand-maintained YAML catalogue (drifts); a static marketing list (unverifiable).

Evidence: 48 rules, each with rationale and references; test asserts the catalogue set equals `REASONS`.

Sources: more_info.md §3, §6; CWE Top 25; MITRE ATT&CK; MITRE ATLAS.
