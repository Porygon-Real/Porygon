# Guided rule authoring

The workbench accepts a typed expression and fixture JSON, but authoring still requires knowing event fields, missingness, safe controls and syntax. Add a local rule assistant that starts with a detection objective, asks for the constraints that determine its meaning, and produces an editable expression with evidence requirements, counterexamples and a test result. It must work without an external provider. Existing AI audit endpoints remain independent.

## Backend

Add a bounded playbook catalog and a stateless authoring API under the existing rule workbench router. Cover successful writes below a configurable path, successful outbound connects to selected ports, memory-backed execution, writable executables under a path, and an exec under verified shell ancestry if practical. Describe exact requirements and relevant blind spots. Generate positive and negative fixture pairs and an optional missing-field probe separately. Compile with the existing DSL and evaluate using the existing typed matcher and fixture normalization. Candidate drafts default to informational. This API must perform no database writes and must not create, activate or disable rules. Use analyst authorization and update the route permission inventory. Test bounded parameters, fixture pairing, and target/unknown semantics.

## Dashboard

Add an assistant entry beside Create Custom Rule and a visible guided mode inside the existing dialog. Render catalog choices, objective and controls, editable typed parameters, generated expression and positive/negative/unknown results. Applying a proposal imports editable fields and labelled fixtures into the existing draft workflow. Make the distinction between applying to the editor and saving explicit. Keep manual authoring available and preserve reviewed revisions when opening existing rules. Provide loading/error and empty states, distinct IDs, accessible keyboard controls, and the existing square-corner design. Verify 320px and desktop.

## Contracts and verification

`GET /api/v1/rule-workbench/assistant` returns the bounded catalog and parameter definitions. `POST /operator/v1/rule-workbench/assistant/triage` accepts an objective and returns recommendations, rationale, clarification and optional suggested parameters for operator confirmation. `POST /operator/v1/rule-workbench/assistant/propose` accepts a recipe and parameters, with an optional edited expression to recheck. The returned rule uses `RuleDocumentIn` fields. The review fixtures use `PreviewIn` labels and carry positive and negative controls. Missing evidence is evaluated separately and reported in the checks. Requirements and limitations describe what must be observed for the rule to work. The dashboard only offers to apply a proposal after all checks pass.

Run relevant API and detector tests after implementation. Rebuild isolated backend with response disabled. Exercise a generated proposal through the real preview and shadow workflow and verify that a rule remains a draft until the existing activation gate is used. Verify all five service suites, research integrity and shell gates. Capture the working assistant on desktop and mobile. No migrations, external provider calls, publication or git commit.

## Objective triage and implementation boundaries

The objective endpoint accepts bounded plain language and recommends supported playbooks or asks for clarification. It derives no executable instructions from telemetry or text. An operator supplies or confirms typed parameters. Compare generated conditions with the normal workbench validator at `backend/src/porygon_api/rule_workbench.py:128–150` and evaluate fixtures using `_fixture_events` and `evaluate_custom_condition_detailed`. The pre-existing entry points are `dashboard/app.js:925` (editor setup), `dashboard/app.js:1034` (save), and the Incidents controls in `dashboard/index.html`. Never display successful simulated checks as observed telemetry.

Backend scope includes the authoring module, the existing router registration and permissions, plus focused tests. Dashboard scope includes its HTML, JS and CSS. The isolated service-trust worktree is the integration target. Preserve all existing modifications, migration IDs, historical artifacts and production response settings. If an unsupported objective cannot be mapped faithfully, keep manual authoring accessible and explain which signals the catalog supports.

Acceptance includes verifying the suggestion API is free of writes, all recipes compile, positives match, legitimate controls do not match, and missing required evidence remains unknown. Exercise an invalid path or port, an unsupported objective and a weakened expression. Check the applied draft at narrow and desktop widths and verify review remains explicit. Treat a renderer or network failure as a verification failure until it is reproduced or resolved.
