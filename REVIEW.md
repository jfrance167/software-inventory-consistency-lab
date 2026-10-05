# ECC self-review — October 5, 2026

Used installed ecc-code-review with its pinned reviewer checklist and ecc-verification-loop for completion. Implementing Codex performed this review; it is not independent. No native ECC plugin installed or provider/model override used. No GitHub review posted/merge authorized.

## Scope and baseline

This new directory is untracked in the existing shared parent repository; focused staged/unstaged Git diffs are empty. Read the actual untracked admission/model/graph/CLI/bootstrap, callers, all tests/frozen oracle, mutation/consolidated harnesses and contract. Preserve unrelated `.gitignore`, install_weekly_cron.sh and nmap_scan_report.py parent modifications. No Git writes/commits/new repo. Research references and prior workbench remain separate and unexecuted.

Reviewed exact types/coercion and predecode/resource guards, all-record validation/status precedence, duplicate grouping and reference resolution, assertion comparisons/null absence, immutable evidence, SCC/roots gates, deterministic sorting/permutation semantics, serializer/delivery/diagnostics and trusted-harness commands. Inspected ordinary-file-only CLI scope and explicit no hostile-filesystem/OS containment promises. Reviewed scope/licensing/AI disclosure and actual scanner outputs rather than claiming standards/SBOM/security certification.

## Actionable finding and fix

P2 — CLI empty output option: `main([owned_fixture, "--output", ""])` formerly tested `if args.output`, selected stdout and returned 0 although a file output was explicitly requested. This violated the contract's no-successful-fallback rule. Fixed at inventory_lab/cli.py:87 with `args.output is not None`; opening the empty path fails with fixed output_io diagnostic/exit 5 and zero stdout. Added regression in tests/test_cli.py's exclusive-output test. Re-read caller/transport handling and reran all affected tests plus final normal/optimized/actual-CLI/mutation/SAST/compile receipt checks.

No additional actionable model defects established after review/checks. Long analysis function is a finite set of cohesive indexed rules, not a severity finding by length alone. Admission error diagnostics purposely return the first structural error and no partial semantic results, while all admitted records are processed before consistency verdict. Boundary tests and independent graph oracle support these exact rules; no broad parser/container/runtime proof.

## Retained harness advisories

Production `inventory_lab/` + lab.py scan: zero findings/errors, no suppressions. Separate harness scan retains five LOW advisories, all source/callers read:

| Site | Advisory | Reviewed disposition |
|---|---|---|
| scripts/verify_mutations.py:7 and :46 | B404, B603 | Existing explicit sys.executable argv runs only reviewed owned mutated source copies/tests; shell=False, 30s bound; recipes are fixed strings, source anchor unique, syntax compiles, original unchanged. No sample/input data enters command syntax. |
| scripts/verify_project.py:13 and :32 | B404, B603 | Explicit lists for existing trusted interpreter/installed scanner and own scripts; shell=False, timeout. `--bandit-python` is an operator-selected trusted installed interpreter, not untrusted inventory data. |
| scripts/verify_project.py:58 | B603 | Explicit interpreter/lab.py/fresh owned frozen-case path, shell=False/10s deadline. Frozen cases are trusted synthetic fixture/oracle data, not arbitrary executable inputs. |

No advisories were dismissed/suppressed; raw scan retained. Capture/time bounds here constrain trusted verification calls, not a malware containment boundary or general hostile test-runner service. Existing scanner dependencies not audited/upgraded in this task. Test-wheel limitations from prior workbench remain irrelevant to this stdlib/unittest lab; do not rewrite those earlier facts.

Remaining limits: supplied synthetic flag cannot detect private/real data, omitted inventory/indirect truth remain unknown, no hostile-file races/hard runtime isolation, no cross-runtime/OS/broad fuzzing/full standards/hosted/audit claims. Manual review remains required before any separately authorized consequential expansion/publication/merge/deployment.
