# Software inventory consistency research

October 5, 2026 preimplementation research snapshot. Research/plan were completed before any code; coordinator subsequently approved stages 1–4 at 02:31. Current implementation/checks are in STATE.md and VERIFICATION.md. Findings below describe research-time evidence, not current authorization status.

## Authorization and reuse

Read the original human turns in coordinator chat `01a10a45-1a24-78b3-9cef-7c461a966d26`: Jake delegates approval/start of further work, then explicitly asks to create more labs after completion, with an October 6 08:00 Eastern cutoff. The coordinator's October 5 02:10 selection assigns this sole writer research/planning only in a separate directory. Implementation waits for its recorded plan review. No new chats, agents, publication or external targets.

Read selected vault Home/Codex Integration and relevant Linux permission plan found by a focused CycloneDX/SPDX/SBOM search. That note's SPDX references concern source licensing, not an inventory model. Targeted README and Python searches in cloud-iac-security-scanning, vulnerability-management-lab and container-security-hardening-lab found no equivalent component/reference checker. These are bounded searches, not an exhaustive inventory. Binary-workbench evidence reporting/escaped JSON patterns are useful concepts; its PE/ELF parser, Windows supervisor and native engines do not fit this small pure model. Reuse shared workers and installed verification tools rather than reconstructing them.

## Sources and candidate assessment

Used the connected GitHub integration for repository discovery and actual source, tests, licenses, dependency manifests, CI and release inspection. Primary CycloneDX 1.6 JSON schema and SPDX 2.3 document/package/relationship clauses were inspected. Versioned sources are deliberately design references, not claims about the newest supported standard.

| Candidate | Observed fit and evidence | Decision |
|---|---|---|
| [CycloneDX Python library](https://github.com/CycloneDX/cyclonedx-python-lib/tree/ef790884051bac5f18f54c259f9fe53fb7cf4204) | Apache-2.0; inspected Bom.validate, JSON validator, model tests and Python CI. JSON validation uses packaged schemas/registry; model validation separately checks unknown dependencies and normalizes dependency entries, and is marked deprecated. Tests exercise dependency registration, missing root edges and historical component identity regressions. Manifest lists packageurl-python, py-serializable, sortedcontainers, license-expression, optional JSON/XML validators. CI has test matrices, Bandit, static checks, immutable action pins. Release v11.12.0 published August 13, 2026. | Strong choice for broad CycloneDX integration, excessive scope for this synthetic lab. Do not copy normalization or silently generate IDs/edges. |
| [SPDX Python tools](https://github.com/spdx/tools-python/tree/cef432adee09dbff2eedf7e33e4aa8be7c11ccfd) | Apache-2.0; inspected document and relationship validators and relationship tests. Explicit checks cover duplicate IDs and unknown references; document validator handles 2.2/2.3. Manifest includes beartype, click, license_expression, ply, pyyaml, rdflib, semantic_version, uritools, xmltodict. Inspected multi-OS/Python test CI uses moving action tags. Release v0.8.5/current inspected commit dated March 13, 2026. | Stronger fit for full SPDX document handling, which is outside this lab. No install or fork. |

Retrieved source records with URLs/blob identities are in `research/upstream-source-records.json`; full official CycloneDX schema in `research/cyclonedx-1.6-schema.json`. They are unexecuted reference evidence, not application dependencies. Both candidates have substantive source/tests and recent release evidence; upstream tests/CI were not run, no Scorecard audit or full dependency/advisory scan was performed. Missing indicators are not insecurity evidence. SPDX open-issue listing and one commit request failed connector transport; release/actual source evidence succeeded. CycloneDX [issue 540](https://github.com/CycloneDX/cyclonedx-python-lib/issues/540) is a closed historical duplicate-component/dependency regression, not proof of a current defect. Do not infer safety from maintenance or stars.

Apache-2.0 redistribution entails license/notice preservation and modified-file notices where applicable. Recommend original MIT lab code, source links and AI-assistance disclosure, with no copied upstream implementation. Retained upstream reference snapshots carry their original license text; keep them separate from original product code and preserve attribution.

## Semantic consequences

[CycloneDX 1.6 schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json) distinguishes document-local references from component identity. Its dependency definition warns that omitted entries may mean unknown dependencies. Do not invent a dependency-free or completeness inference from omission. Hash fields alone neither authenticate publisher nor compare artifact bytes.

[SPDX 2.3 document IDs/namespaces](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/), [package checksum](https://spdx.github.io/spdx-spec/v2.3/package-information/#710-package-checksum-field) and [typed relationships](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/) have distinct purposes. External references and NONE/NOASSERTION have semantics that this lab will explicitly exclude. A local opaque ID is not a universal package identity; equal name/version may legitimately describe different artifacts. Directed cycles are observations, not automatically invalid inventory.

Recommend BUILD a precisely named custom learning format inspired by these concepts. Avoid labelling it CycloneDX/SPDX validation. Alternate: graph reachability alone has a smaller surface but cannot establish completeness and misses identity/assertion contradictions. Include bounded reachability as a secondary observation over supplied edges, not as an assurance verdict.

## Worker evidence

Local Ollama was attempted first using the existing helper, 800-token/90-second bound and explicit test-idea acceptance criteria. Initial sandbox loopback failure reserved an empty output; an approved same-name retry stopped before inference on EEXIST. One approved fresh-path inference returned in 6.178 seconds, truncated at 800 tokens. Raw output/metadata preserved separately. Duplicate/dangling ideas overlap obvious cases; cycle-invalid and changed-hash-proves-conflict claims are incorrect and rejected. No unreviewed draft is adopted.

Explicitly considered configured free OpenRouter/OmniRoute after local inadequacy. Read startup rules/current status and ran the read-only readiness helper: degraded/unverified loopback/free guardrails; no inference sent. Remote calls cannot meet verified-free requirements, so none used. Codex performs reviewed plan drafting/security judgment; no spending. Laya's tested classification/refund schemas do not fit inventory semantics and add no value here.

Research gate completed: coordinator reviewed/approved PLAN stages 1–4 with bounded amendments incorporated in CONTRACT.md. Current stage/status: STATE.md.
