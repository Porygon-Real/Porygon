# Custom rule workbench

Custom rules are backend matchers over normalized process, Docker lifecycle, or kernel evidence. They do not add Falco collection rules. Falco rules decide which syscalls and fields reach Porygon; backend rules compare fields already ingested. Adding a backend rule cannot detect a field the sensor does not emit.

## Author and activate a rule

A new rule is stored as a draft. Draft creation does not affect live detection. The API validates the bounded expression language and writes an immutable content-hash revision. Use `scripts/rule_workbench.py` from the repository root. It reads the operator token only from `PORYGON_OPERATOR_API_TOKEN`; it does not read `.env` or print request headers.

The dashboard's **Guided authoring** entry routes a plain-language objective to the local bounded playbooks. Objective routing, recipe generation, and fixture evaluation require analyst authorization and do not call an external provider. When the objective is ambiguous, choose one of the suggested recipes explicitly or refine the objective. Review the recipe requirements and limitations, then inspect or edit the proposed expression. The positive, negative, and unknown checks are synthetic fixture outcomes: they show how the matcher evaluates those supplied examples, not whether the live sensor observes the needed fields. Missing fields and unverified evidence should remain visible as `unknown`. Editing the objective, recipe parameters, or expression invalidates the prior checks; rerun them before applying. **Apply to editable draft** only copies the fields and labeled fixtures into the manual editor. It does not save, activate, or change a rule. Review the imported content and use **Save draft** explicitly, then preview and shadow the saved revision before any separately authorized activation.

```sh
export PORYGON_API_BASE_URL=http://127.0.0.1:8000
export PORYGON_OPERATOR_API_TOKEN='<operator credential from your secure credential store>'
python3 scripts/rule_workbench.py validate examples/rules/sensitive-file-write.json
python3 scripts/rule_workbench.py draft examples/rules/sensitive-file-write.json
```

Copy the returned `custom_rule_id`. Before activation, run a local labeled fixture selection and an operator-selected event preview. Preview selections are capped at 250 records. Database selections must share one Docker host and container, span no more than one hour, and share a sensor epoch. Kernel selections must also share one resolved process PID/start/namespace lifetime. Missing ancestry and missing fields return `unknown`; `not` does not turn missing data into a match.

```sh
python3 scripts/rule_workbench.py preview RULE_ID examples/rule-preview/sensitive-file-write.json --expected-revision-hash CURRENT_HASH
python3 scripts/rule_workbench.py shadow RULE_ID examples/rule-preview/sensitive-file-write.json --expected-revision-hash CURRENT_HASH
python3 scripts/rule_workbench.py activate RULE_ID --expected-revision-hash CURRENT_HASH --reference CHANGE_OR_REVIEW_RECORD
```

The local fixture should contain both positive and negative labels. Process fixtures can link `parent_fixture_id` values to model ancestry; the workbench synthesizes deterministic fixture-only host, sensor, PID namespace, PID and start-time metadata and rejects cycles, missing parents, and inconsistent identity links. Set `lineage_complete: true` only on a fixture root when the fixture explicitly represents a complete ancestry chain. This metadata is synthetic software-test input and is never reported as observed telemetry. Activation rejects fixture receipts with a missed positive, a matched negative, any unknown result, a stale receipt, changed revision, or changed interpreter contract. Both the preview and shadow receipts used for activation must come from labelled fixtures with passing positive and negative controls. Run both after creating or restaging the candidate. Event-ID previews are available for investigation. A passing fixture demonstrates software behavior. The authenticated operator must provide a meaningful reference when promoting a rule. Promotion is a human operations decision, not an independent research review.

An operator can inspect immutable revision hashes in the dashboard or API. Activation, rollback, preview/shadow review, and revision edits include the current hash the operator reviewed; the server rejects a stale hash if another change landed first. To revise an active rule, open it in the workbench, edit the expression and metadata, provide a reference, and save the new revision as a draft candidate. The existing active revision continues to match and remains in new run snapshots while the candidate is previewed and shadowed. Activation atomically swaps the active revision pointer after the checks pass. To roll back, select an earlier immutable revision, stage it while supplying the currently displayed candidate hash, preview and shadow it again, then activate it with the staged current hash and an operator reference. Disable is the explicit action that stops the active revision; it does not delete revisions or run history.

## Expression language

The expression is compiled to the same bounded condition tree used by the API. It supports `and`, `or`, `not`, parentheses, `==`, `!=`, `>`, `>=`, `<`, `<=`, `in`, `not in`, `contains`, and case-sensitive `startswith` for path fields. Python, arbitrary code evaluation, and regular expressions are not accepted. Expressions are limited to 2,000 characters, condition trees to 40 leaves and depth 6, list values to 100 items, and string values to 512 characters. At most 128 rules and 256 KiB of canonical active rule content are accepted; the complete run snapshot is capped at 512 KiB. Preview spends at most 50,000 shared leaf/ancestry operations across the selected events, while one detection run spends at most 100,000 across its entire active ruleset and emits at most 250 custom-rule match documents. An exhausted work or output budget appears explicitly in the response, leaves unprocessed preview events `unknown`, and cannot satisfy activation proof. Activation serializes capacity checks and rejects over-cap active content instead of silently dropping rules. These are resource bounds, not performance or accuracy measurements.

Process target fields include `exe_from_memfd` and `exe_writable` when the exec event supplies them. A process rule can therefore match an executed image whose backing memory or executable file was observed as writable. `memfd_create` alone remains allocation evidence and does not prove a later execution. Kernel target fields are `runtime_action`, `event_type`, `return_value`, `exe_from_memfd`, `exe_writable`, `file_path`, `remote_address`, `remote_port`, `process_name`, `executable`, `executable_path`, `user_uid`, `process_pid`, `process_start_ns`, `pid_namespace_start_ns`, `sensor_epoch`, `docker_host_id`, and `container_id`. Numeric comparisons require integer fields; booleans remain booleans. A missing or incompatible field produces `unknown`, not a negative comparison success. Kernel rules match one kernel record at a time; this workbench does not join stateful behavior across multiple events or infer asynchronous network completion.

Example expressions:

```text
runtime_action == "file_write" and return_value > 0 and file_path startswith "/etc/"
runtime_action == "net_outbound" and return_value == 0 and remote_port in [80, 443]
exe_from_memfd == true
executable == "wget" and ancestor.parent_executable in ["sh", "bash"]
```

The first matches positive bytes written below `/etc/`, not an open-for-write record. The second is successful connect evidence; an in-progress connect is not treated as completion. The third uses the observed exec flag; a `memfd_create` allocation alone does not match. The fourth uses an in-window, host/container/sensor/PID-lifetime verified ancestry chain. An unavailable or truncated chain yields `unknown`.

## Add a telemetry-backed field safely

1. Confirm the source event actually carries the proposed value and document missingness, units, normalization, and whether it represents an observed result or only an attempted operation. Treat command lines and raw telemetry as untrusted data.
2. Update the producing Falco output and the telemetry normalizer/storage schema only when necessary. Keep Docker lifecycle fields separate from kernel syscall fields. Do not store credentials or arbitrary command arguments to make a rule convenient.
3. Add the field to the target-specific allowlist and type contract in `backend/src/porygon_api/detection.py`, its field accessor and comparison compatibility checks, the expression validator/renderer when new operators are involved, and the workbench preview fixture schema. Include the changed semantics in `CUSTOM_RULE_INTERPRETER_CONTRACT` so new run keys and receipts bind the interpreter behavior.
4. Add positive, negative, missing-field, malformed-type, scope, host/epoch/lifetime, and performance-bound tests. Then update the example pack and this field list. Do not backfill new field values or rewrite prior detection-run snapshots.
5. Keep collection and matching changes separately reviewable. A rule needs observed source evidence before it can provide operational proof; a fixture pass alone does not establish sensor coverage.

Every new detection run stores its exact active custom-rule snapshot and interpreter hash. Historical runs whose original rule content was never retained remain explicitly unavailable by hash; current rules are never substituted for old content. Preview/shadow receipts retain bounded event identifiers, scope and sanitized counts/reasons, not raw argv or field values. A maximum of 50 recent receipts are retained per rule; lifecycle audit entries keep actor, reference and receipt hash history.
