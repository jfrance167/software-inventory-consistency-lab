# Verification — October 5, 2026

Actual local Windows x64/CPython 3.13.7 checks for the approved custom synthetic scope. No real inventory, artifact inspection/execution, network/host collection, installation, publication, separate Git repository or hosted checks occurred. [evidence/receipt.json](evidence/receipt.json) records exact source/test/contract hashes and exit outcomes. Raw acceptance logs/mutant copies remain in ignored `.verification-work/`; `.verification-work/final-evidence.json` selects the final receipt. Earlier runs/failures are preserved.

| Check / command | Actual result |
|---|---|
| `python -I scripts/run_tests.py` | PASS, exit 0: 24 tests, 32 frozen cases, CLI transport seams, exact-type/boundary/cycle/no-mutation/permutation checks |
| `python -I -O scripts/run_tests.py` | PASS, exit 0: same 24 tests; production guards do not depend on assert |
| Independent boolean transitive closure in test_model | PASS: all 512 directed graphs on three named nodes, SCCs/cycles/reachability; no exhaustive larger-graph claim |
| `python -I scripts/verify_mutations.py` | PASS, exit 0: three isolated source-copy defects each caught by the intended behavioral AssertionError, original bytes unchanged |
| Actual `python -I lab.py INPUT` through consolidated verifier | PASS: all 32 frozen JSON cases match expected exit/status/consistency/code multisets, stderr empty for evaluated reports |
| `python -I -m compileall -q inventory_lab lab.py scripts tests` | PASS, exit 0 |
| Installed `python -I -m bandit -r inventory_lab lab.py -f json ...` | PASS, exit 0: Bandit 1.9.4, zero findings/errors, no rule exclusions/suppressions |
| Separate installed `bandit -r scripts -f json ...` | Five LOW advisories: B404×2/B603×3, reviewed harness subprocess sites, retained without suppression; this is NOT a whole-project zero-finding result |
| Pure-model AST import/call inspection plus actual source review | PASS for inspected source; not a complete dynamic call graph or OS containment guarantee |
| Source/fixture hash and byte-length comparison | PASS: final public receipt matches current 14 named source/test/contract/oracle files |
| Focused prospective credential/private-path pattern inspection | PASS for original product/source/examples/receipts; no exhaustive secret scanner or history claim; upstream source snapshots retain public contributor metadata |
| Dedicated lint/type checker, broad fuzzing, other runtime/OS | NOT RUN: no project-configured installed checker; no tool downloaded for a completion label |
| Hosted CodeQL/Bandit/protections/alerts | NOT RUN: no new repository/publication authorized |

Tests cover raw cap+1 and exact 64 KiB input, predecode depth, escaped brackets, UTF-8/BOM, duplicate keys, numeric/nonfinite tokens, key/type/subclass rejection, node/text/count bounds, shared acyclic and native cyclic API values. Whole common validation prevents unknown-profile or earlier semantic findings from hiding malformed later data. Supported profile identity/hash comparisons are literal declaration comparisons only.

Grouped duplicate ID/root/edge/assertion evidence retains raw indices and counts. Unknown/ambiguous references have separate endpoint paths. Unresolved assertions do not disable a structurally well-defined graph; duplicate component IDs and unresolved edges/roots do. Empty inventory is vacuously consistent, roots-empty reachability not requested. Self/multi-node cycles remain observations. Different label/hash declarations never authenticate or merge artifacts. Permutation comparisons remove/relocate index evidence while preserving semantic observations; same-input report encoding is deterministic.

Delivery tests include fresh-only output, existing-file/input alias refusal, empty output filename, short writes, flush/close and both-channel-closed errors, private exception/terminal-control omission. Findings/output maxima are defensive guards tested by reduced-constant seams; no natural 1,024-finding/1 MiB overflow under current admission is claimed. The maximum-count example verifies 64 nodes, 128 raw/64 unique edges, 16 raw/one unique root and grouped findings. Size caps do not prove hard CPU/RSS/durability/race containment.

Initial failures: default OS temporary directory was sandbox-denied, corrected to fresh owned workspace test directories. Initial unknown-reference mutant also caused graph lookup errors, so was not accepted as an assertion-only catch; revised to omit unknown-reference evidence while retaining graph gates. Existing workbench venv lacked Bandit; used existing base CPython/Bandit 1.9.4, no installation. ECC fixed empty `--output` fallback and reran affected/final checks. Earlier receipts are historical, not substitutes for current source-bound evidence.

No model input bytes, inventory truth or publisher identity was established. Synthetic flag is supplied metadata, and negative/cycle tests are finite learning evidence. No independent audit or universal accuracy/safety claim.
