# Executive Board RC2 P2 Production Enablement Implementation Plan

> **For Hermes:** Use subagent-driven-development and strict TDD task-by-task.

**Goal:** Izgraditi zaseban P2 driver koji može proći production transition samo uz P2-bound approval i verificirane offline/canonical/runtime adaptere, dok se ovaj lane izvršava isključivo u sandboxu.

**Architecture:** P1 driver ostaje neizmijenjen i daje state/checkpoint/HMAC jezgru. Novi `deploy_driver_p2.py` dodaje P2 plan i approval envelope te P2 backend. `dependency_lock.py` posjeduje offline lock/wheelhouse provjeru i install. `canonical_adapter.py` posjeduje path/hash/write-gate i maintenance restore, `installed_adapter.py` installed-wheel operacije, `p2_installed_launcher.py` cijelu SQLite transakciju, a `managed_runtime.py` zasebni PID/listener/health/shutdown lifecycle bez SQLite capabilityja. Production behavior aktivira se samo kad plan eksplicitno nosi `simulation=false`; testni plan nosi `simulation=true`, izolirani DB i port različit od 18791.

**Tech stack:** Python 3.12, stdlib sqlite3/subprocess/http.server/hashlib/hmac, pytest, deterministic ZIP wheel tooling.

---

### Task 1: P2 plan and artifact binding

**Files:**
- Create: `scripts/executive_board/deploy_driver_p2.py`
- Create: `tests/hermes_cli/test_executive_board_deploy_driver_p2.py`

**Steps:**
1. Napisati RED test da P1 plan/approval i missing P2 hashes budu odbijeni.
2. Pokrenuti ciljane testove i potvrditi očekivani import/behavior FAIL.
3. Implementirati `P2DeployPlan`, canonical hash i P2 approval create/verify s bindingom drivera, plana, wheela, manifesta, locka, adaptera, deployment ID-a, targeta, porta i rollback referencea.
4. Potvrditi GREEN i rejection testove za replay/tamper/expiry.

### Task 2: Hash-pinned offline dependency adapter

**Files:**
- Create: `scripts/executive_board/dependency_lock.py`
- Test: `tests/hermes_cli/test_executive_board_deploy_driver_p2.py`

**Steps:**
1. RED: floating requirement, missing hash, wheelhouse mismatch, network-capable install command, editable/source shadowing moraju pasti.
2. Implementirati parser/manifest verifier i install command koji dopušta samo `pip install --no-index --require-hashes` za dependency lock te overlay wheel `--no-deps`.
3. Testirati stvarni offline install u prazni sandbox venv.

### Task 3: Canonical, installed SQLite i managed-runtime adapteri

**Files:**
- Create: `scripts/executive_board/canonical_adapter.py`
- Create: `scripts/executive_board/installed_adapter.py`
- Create: `scripts/executive_board/managed_runtime.py`
- Create: `scripts/executive_board/p2_installed_launcher.py`
- Test: `tests/hermes_cli/test_executive_board_deploy_driver_p2.py`

**Steps:**
1. RED: krivi HERMES_HOME/DB/venv/adapter hash, unknown writer, non-loopback, occupied port i missing rollback ref moraju pasti.
2. Implementirati read-only contract validation i physical-restore gate bez pokretanja procesa.
3. Implementirati installed SQLite entrypoint koji jedini posjeduje `BEGIN`/migration/schema+integrity+FK/`COMMIT` ili `ROLLBACK`; unutarnji migration primitive ostaje transaction-neutral.
4. Implementirati zasebni controlled start/health/shutdown controller s PID/start-time/executable/listener-inode/loopback atribucijom i bez SQLite pristupa.
5. Fizički restore ostaviti iza zasebnog maintenance approvala i no-writer/no-listener gatea.

### Task 4: P2 production state transitions

**Files:**
- Modify: `scripts/executive_board/deploy_driver_p2.py`
- Test: `tests/hermes_cli/test_executive_board_deploy_driver_p2.py`

**Steps:**
1. RED testovi za svaku production granicu i failure→rollback klasifikaciju.
2. Implementirati P2 backend koji reusea P1 stanja, ali production stateove delegira verificiranim adapterima.
3. Revalidirati approval neposredno prije canonical migration i controlled starta.
4. Dokazati commit samo nakon health/security/Board lifecycle E2E.

### Task 5: Isolated production simulation and failure matrix

**Files:**
- Test: `tests/hermes_cli/test_executive_board_deploy_driver_p2.py`
- Create evidence under P2 release root only.

**Steps:**
1. Pokrenuti simulated execute nad DB kopijom, izoliranim venvom i testnim loopback portom.
2. Dokazati transitione do `COMMIT_DEPLOY` i port shutdown nakon testa.
3. Injectati failure u svaki state; pre-boundary BLOCKED, post-boundary verified rollback.
4. Potvrditi canonical hash/mtime nepromijenjen i 18791 zatvoren.

### Task 6: Reproducible release and installed gates

**Files/artifacts:**
- P2 release root with wheel A/B, manifest, dependency lock, wheelhouse manifest, deploy plan, report.

**Steps:**
1. Izgraditi byte-identične wheel A/B iz potpuno stageanog i verificiranog P2 sourcea; commit je dopušten tek nakon svih gateova.
2. Auditirati RECORD i dopuštene delte.
3. Exportirati hash-pinned lock, stvoriti wheelhouse manifest i napraviti offline install.
4. Pokrenuti installed-wheel suite i clean-CWD parity.

### Task 7: Final review and commit

**Steps:**
1. Pokrenuti fokusni P2, P1 regression i relevantni source suite.
2. `py_compile`, `git diff --check`, secret/shell/eval/pickle/SQL scan.
3. Neovisni spec review, zatim code/security review.
4. Popraviti svaki blocking nalaz i ponoviti gateove.
5. Commitati samo verified file list; generirati post-commit plan/hashove i read-backati clean worktree.

## Final exit criteria

`READY_FOR_SEPARATELY_APPROVED_PRODUCTION_DEPLOY` samo ako svi transition, security, offline, build, installed, parity i rollback gateovi prođu. Inače `BLOCKED`; canonical deploy se u ovom laneu nikad ne izvršava.
