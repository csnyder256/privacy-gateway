# Research verification

Verified on 2026-09-21 against the exact revisions below. Repository README
statements are recorded as upstream claims unless the implementation path was
also inspected. Privacy Gateway does not copy code from these repositories.

## CLM implementation inspection

Source revision: `sam61252/clm-platform@c52d594ddc2e16c0cbbf06a58a888b8c9e747868`
(the local `main`, Forgejo `origin/main`, and GitHub `main` resolved to the same
commit when the inspection began; this proves source alignment, not deployment health).

| Finding | Direct evidence | Verdict |
| --- | --- | --- |
| Tenant gating requires platform availability and tenant activation. | `shared/anonymizer.py:31-51` reads `synthetic_data_enabled` and `synthetic_data_active` and requires both. | Confirmed. |
| Detection uses regex, spaCy, and Presidio. | `shared/anonymizer.py:79-101`, `104-191`, and `194-221`. | Confirmed. Missing spaCy/Presidio and Presidio runtime failure return no detections; spaCy inference failure is not caught here and reaches fail-open integration wrappers. |
| Replacements include realistic names, companies, locations, dates, and money. | `shared/anonymizer.py:251-270`, `shared/anonymizer_data.py:94-118`, and `shared/anonymizer_fpe.py:10-80`. | Confirmed. |
| Mapping persistence exists. | `shared/anonymizer.py:323-358`; migration `0038_anonymization_mappings.py:12-31`. | Confirmed. |
| Mapping storage is encrypted. | `shared/anonymizer.py:292-307` encrypts only when a key is present and returns plaintext after a missing key or any exception. | **Original wording narrowed:** storage supports encryption but does not guarantee it. |
| Restoration wraps AI calls on the server. | Restorer: `shared/anonymizer.py:433-457`. Response call sites: `services/ingestion/main.py:727,1125,1321,1835,2135,4281`; `services/clause-extraction/worker.py:2167,2392`; `services/contract-normalization/main.py:1124,20249-20256`. | Confirmed; restoration is string replacement on the server. |
| Users get only an on/off control rather than entity/action policy construction. | `frontend/app/(app)/settings/synthetic-data/page.tsx:79-108`; the other controls at `110-175` govern page visibility and AI analysis, not entity policies. | Confirmed. |
| Detection failure can fail open. | `services/ingestion/main.py:173-183` catches any exception and returns the original text; equivalent wrappers exist in clause extraction and normalization. | Confirmed. |
| Encryption can silently fall back to plaintext. | `shared/anonymizer.py:299-307`. | Confirmed. |
| Expiry is recorded but not enforced by the inspected load path or a cleanup path. | Migration `migrations/alembic/versions/0038_anonymization_mappings.py:20-30` creates/indexes `expires_at`; loader `shared/anonymizer.py:339-345` does not filter it. The reproducible scoped searches below found the table only in that migration and the insert/load functions, and found no runtime delete/expiry predicate. | Confirmed within the inspected repository. Absence is scoped to this revision, not external database jobs. |
| Synthetic lookup uses process-randomized `hash()`. | `shared/anonymizer_data.py:94-118`. | Confirmed. |
| Reverse mappings can collide. | `shared/anonymizer.py:411-416` assigns `replacement_to_original[replacement]` without detecting an existing replacement. | Confirmed. |
| Existing document mappings suppress detection of newly introduced PII. | `shared/anonymizer.py:379-389` applies the old map and returns before lines `391-399` run detection. | Confirmed. |
| Restoration is neither tolerant nor streaming. | `shared/anonymizer.py:433-457` performs exact whole-string `.replace`; no incremental restorer is in this subsystem. | Confirmed. |
| Audit persistence is not classification-granular. | Migration stores `mapping_data` and `entity_count`; store path `323-335` writes those values. | Confirmed for this subsystem. |
| UI makes stronger claims than implementation proves. | UI `page.tsx:270-276` says entities are never sent, mapping is encrypted, and it is automatically deleted; the fail-open, plaintext fallback, and missing cleanup paths above contradict an unconditional reading. | Confirmed discrepancy. |
| Detector priority follows spaCy → Presidio → regex. | `shared/anonymizer.py:232-233` declares that priority, but `_merge_entities` sorts only by start and descending length at `229-244`; `source_priority` is never read. | **Original implementation implication rejected:** the declared priority is dead code. Actual overlap resolution is positional/longest-first. |

### Reproducible CLM inspection commands

Run from `/repos/clm-platform-main` at the revision above:

```bash
git rev-parse HEAD
git show-ref --verify refs/remotes/origin/main
/repos/2nd-Brain/system/tools/hostctl exec /opt/brain/repos/2nd-Brain/system/tools/repoctl gh sam61252 api repos/sam61252/clm-platform/commits/main --jq .sha
grep -RIn --exclude-dir=.git -E 'deanonymize_json|deanonymize\(' services/ingestion services/clause-extraction services/contract-normalization shared/anonymizer.py
grep -RIn --exclude-dir=.git -E 'anonymization_mappings' .
grep -RIn --exclude-dir=.git -E 'DELETE[[:space:]]+FROM[[:space:]]+anonymization_mappings|anonymization_mappings[^\n]*expires_at|expires_at[^\n]*anonymization_mappings' .
```

Observed result: the local, Forgejo, and account-authenticated GitHub commands each
returned `c52d594ddc2e16c0cbbf06a58a888b8c9e747868`; the restoration search returned
the definition and call sites enumerated above; the full-tree table search returned
migration `0038`, its `0039` revision references, and
`shared/anonymizer.py:327,342`; the
delete/expiry-predicate search returned only the migration's expiry index at line 30.

## Upstream projects

The revisions below were checked from clean clone worktrees with `git status
--short` empty. `git rev-parse HEAD` produced the listed SHA for each project;
`git show HEAD:LICENSE` (or the repository's named license file) was read directly.
For line-count/citation validation, `git show HEAD:README.md | nl -ba` was used;
at the recorded Anonproxy revision its README has 646 lines, including the cited
test/restoration table at 587-600.

### `daslabhq/pii-proxy`

- Revision: `922bcd1d72cfefaf25eb055d4b46e02256513b10`
- License: MIT (`LICENSE`).
- Evidence: README lines 6-21 describe local detection and plausible fake values;
  lines 125-127 describe layered detection and a bijective map; lines 166-169
  list format-preserving identifiers; lines 178-197 demonstrate recursive object
  masking/unmasking; lines 266-272 explicitly scope local processing, map
  sensitivity, and incomplete-detection limits.
- Verified synthesis: local/layered detection and plausible format-aware
  surrogates are valid inspirations. Reversible bijection is an upstream design
  goal, not a proven invariant: `src/map.ts:12-14` overwrites an existing reverse
  entry, while `src/index.ts:128-145` accepts a still-colliding fake after ten
  retries. Privacy Gateway will not inherit that behavior or claim it as safe.
  The map is not itself an encrypted vault; upstream tells deployers to protect it.

### `jfreemansh/Anonproxy`

- Revision: `d32a770de9ba1571562b916f3188a01fbc6b1bfd`
- License: MIT (`LICENSE`).
- Evidence: README lines 42-82 demonstrate the tolerant streaming problem and
  consistency rescan; lines 109-121 show per-engagement SQLite vault and Burp
  integration; lines 174-187 cover the wizard; lines 384-404 and 516-533 cover
  AES-GCM encrypted vaults; lines 546-565 describe verification and tool-call
  probes; lines 587-600 state the test/benchmark surfaces and restoration scope;
  `THREAT-MODEL.md:1-46` explicitly records assets, trust boundaries, controls,
  residual risks, and verification.
- Verified synthesis: isolated vaults, encryption, consistency rescans, tolerant
  streaming restoration, guided setup, verification probes, and an explicit
  threat model are valid inspirations.

### `akazah/prompt-anonymizer`

- Revision: `d7d5771ffd684d1f5dde4d0ba38d3c4f8cf3d3d7`
- License: MIT (`LICENSE`).
- Evidence: README lines 34-47 cover CI gating and on-device WebGPU/WASM/spaCy
  operation; lines 75-104 enumerate browser, extension, React/Vue, proxy, MCP,
  and scan surfaces; lines 196-240 cover local proxy/MCP/CI behavior; lines
  328-369 cover allow/deny lists and multilingual engines.
- Verified synthesis: client-side operation, multilingual and granular policies,
  broad adapters, local mappings, MCP, and CI scans are valid inspirations.

### `data-privacy-stack/presidio`

- Revision: `645dfa1cc6ed2178af7c3473f02a40d0968070b1`
- License: MIT (`LICENSE`).
- Evidence: `docs/supported_entities.md:3-7` documents predefined and custom
  recognizers; `docs/analyzer/index.md:3-11` defines the recognizer extension
  surface; `docs/anonymizer/index.md:232-235` defines built-in and custom operators;
  `docs/getting_started.md:3-7` enumerates text, image, and structured tools;
  `docs/getting_started/getting_started_structured.md:3-8` scopes table/JSON support
  and marks it alpha; `docs/image-redactor/index.md:3-16` scopes image/DICOM pixel
  redaction, marks it beta, and explicitly excludes DICOM metadata scrubbing.
- Verified synthesis: pluggable recognizers/operators and extensibility across
  text, structured data, and images are valid inspirations.

### `sdv-dev/SDV`

- Revision: `cb6229d83921a1cf35e7cc5b4f947bc0e03699bd`
- License: Business Source License 1.1 (`LICENSE`). The Additional Use Grant says
  the work or derivatives may not be used for a “Synthetic Data Service,” then
  defines that term as a commercial offering exposing its data specification,
  transformation, ML, or synthetic-creation functionality to third parties.
- Evidence: README lines 83-89 define dataset metadata, types, and primary key;
  lines 109-115 describe distribution preservation plus primary/foreign-key
  relationships; lines 158-160 cover single-table, multi-table, sequential data,
  workflow customization, and constraints; lines 207-211 cover transformation,
  modalities, and quality/privacy measurement.
- Verified synthesis: metadata, relationship, constraint, and evaluation
  workflows are useful problem-shaping ideas.
- Hard boundary: no SDV code, APIs, schemas, tests, fixtures, generated artifacts,
  or implementation structure will be copied, adapted, imported, or bundled.
  Privacy Gateway's implementation and vocabulary will be independently designed.

#### Clean-room procedure for Stage 4

1. The only inputs to requirements are the high-level capabilities already frozen
   in `PLAN.md`, SDV's public README/docs descriptions, and Privacy Gateway's own
   user stories. No SDV source package is an implementation reference.
2. Before Stage 4 code, author an independent Privacy Gateway metadata/schema spec,
   fixtures, and acceptance tests without importing or executing SDV.
3. Maintain `docs/provenance.md`: every Stage 4 source file records its author,
   requirements source, dependencies, and confirmation that no restricted source
   was consulted or copied.
4. The primary implementer has inspected SDV's LICENSE, README, and documentation
   search results, but not SDV implementation files. The round-1 skeptic did not
   contribute implementation. The temporary upstream clone is not used during
   Stage 4 and will be removed before implementation begins.
5. Stage 4 uses only MIT/Apache/BSD-compatible dependencies verified in the lockfile;
   CI rejects any `sdv`/`rdt`/`sdmetrics` dependency or import.
6. A fresh reviewer audits provenance, dependencies, identifiers, schema vocabulary,
   fixture lineage, and git diff before the Stage 4 refutational verdict.

An untested single-table prototype was written before this process was frozen and
then removed. The reset verified a current tree with no synthetic source, a local
repository with zero commits/remotes, and no GitHub repository at the intended
name. It is explicitly excluded as a Stage 4 input. Stage 4 currently has no
implementation source. `docs/provenance.md` records this reset; implementation
cannot resume until the independent spec, fixtures, and acceptance tests exist.


## Target portfolio conventions

- Profile repository revision: `csnyder256/csnyder256@4cd0b860adf0bcd1e9318edfb57fe4bb011e7080`.
  Its README uses a concise Projects table and explicitly says unfinished or
  unproven work is labeled as such (`README.md:12-25`, `75-79`).
- Portfolio site revision: `csnyder256/csnyder256.github.io@e123a4c696265c503c08258e2bee49a570658f27`.
  It uses a long-form editorial project record with direct GitHub links.
- Reproducible local inventory:

  | Repository | Revision | `docs/index.html` | `docs/.nojekyll` | Agent guide |
  | --- | --- | --- | --- | --- |
  | `gba-rom-hack-ide` | `655515a68d7ec6cd9b436713e5994691b620f49b` | yes | yes | no |
  | `grain-bids-to-excel` | `1eaf14ce908158ed1d19b308522c05400c722a2d` | yes | yes | no |
  | `harness-tuner` | `717d01babb0647b66d308a50f6798c48f9286a1b` | yes | yes | `AGENT-GUIDE.md` |
  | `kafka-wire` | `5bb1d753d926f59fc5fe6bd2facf06f444f7c9e8` | yes | yes | no |
  | `option-contract-grader` | `bfeaa55cb3131c0661df8f81db7a9b40370eb016` | yes | yes | no |
  | `shadow-options-trading-lab` | `dfda6a918cba65446587da26d2391f6e0d61dd2a` | yes | yes | no |
  | `ux-struggle-detector` | `b73084896208f7d2794b84bf23de3157eca5fc09` | yes | yes | no |
  | `RAG-OS` | `8edb82cb269a0b44d3d894a64282b19a888f5890` | no | no | no |
  | `org-memory-os` | `b97fbdfcf94afc3a4371ed64cd090ab868641242` | no | no | no |
  | `openrouter-model-picker` | `a09f2e71e0577c87243acb5d5f03a40f64772363` | root `index.html` | root `.nojekyll` | no |

- This inventories all ten projects listed in the target profile at the recorded
  profile revision. Seven application repos use `docs/`; one browser application
  uses root Pages files; the two architecture blueprints have no landing page in
  their local repositories. Privacy Gateway will use `docs/`, matching the
  majority application convention, without copying prose or visuals.

## Corrections to the original summary

Three statements needed correction after direct reverification and adversarial review:

1. CLM does **not** guarantee encrypted mapping storage. It conditionally encrypts
   and otherwise silently stores plaintext.
2. CLM declares a detector source-priority table, but does not use it. Actual
   overlap behavior is start-position then longest-span ordering.
3. `pii-proxy` aims for a bijective round trip but does not reject every generated
   replacement collision; its current implementation is not evidence of a safe bijection.

The remaining listed CLM deficiencies and research inspirations were supported by
the current inspected sources at the revisions above.
