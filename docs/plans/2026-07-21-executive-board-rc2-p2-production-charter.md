# Executive Board RC2 P2 Production-Enablement Charter

## Lane
`executive-board-rc2-p2-production-enablement`

## Goal
Iz P1 state-machinea izgraditi zaseban P2 driver koji je production-capable, ali se u ovom laneu izvršava isključivo nad izoliranom SQLite kopijom, odvojenim virtualenvom i testnim loopback portom.

## Baseline
- P1 HEAD: `7492087ad19beaa35b155f1338cddccb52d9f236`
- P1 V3 plan hash: `32d32dc17be2560d2914827ab7d5c97d035c8f529aad217e3b1e5fce18a6713e`
- P1 driver SHA-256: `d5335725363d8b3502eac53451dfb91b623c45cc109d33f98fe82f44e76bb76f`

## Scope
- Novi P2 driver, canonical adapter, dependency-lock verifier, testovi i P2 release/evidence artefakti.
- Reuse P1 checkpoint/HMAC/state reconciliation bez izmjene P1 drivera.
- Production transitions moraju biti dokazani samo u sandboxu.

## Allowed paths
- Ovaj P2 worktree.
- Novi release root `/home/goran/releases/executive-board-v0.19.0-rc2-p2-*`.
- Privremeni sandboxi pod `/tmp`.

## Blocked paths/actions
- `/home/goran/.hermes-doni-clean/agents_os/state.sqlite` — bez writea.
- Aktivni `/home/goran/.venvs/hermes-agent-0.14.0` — bez izmjena.
- P1 release root — read-only.
- Port `18791` — ne otvarati.
- Aktivni launcheri, watcher, gateway, dashboard, profili, cronovi i servisi — bez izmjena/restarta.
- Nema stvarnog deploya, javne radnje, vanjskih modela ni credentials rada.

## Architecture contract
1. `deploy_driver.py` ostaje byte-identičan P1 baselineu.
2. `deploy_driver_p2.py` proširuje P1 state-machine s P2 planom, P2 approval bindingom i production backendom.
3. `canonical_adapter.py` posjeduje isključivo canonical path/hash/write-gate i physical-restore maintenance gate; ne pokreće procese.
4. `installed_adapter.py` poziva hash-verificirani installed launcher, a `p2_installed_launcher.py` posjeduje cijelu SQLite transakciju (`BEGIN` → neutralna migracija → schema/integrity/FK provjere → `COMMIT` ili `ROLLBACK`).
5. `managed_runtime.py` zasebno posjeduje PID/listener/executable atribuciju, health i shutdown; nema SQLite capability.
6. `dependency_lock.py` verificira hash-pinned requirements + wheelhouse manifest i instalira samo `--no-index --require-hashes`/`--no-deps` putem.
7. P2 execute odbija P1 plan/approval i svaki artefakt mismatch prije canonical boundaryja.

## Success criteria
- Svi P1 testovi ostaju zeleni.
- Novi P2 production transition i failure-injection testovi zeleni.
- Simulated execute nad izoliranom DB kopijom i testnim loopback portom prolazi do `COMMIT_DEPLOY`.
- Svaki post-boundary failure vodi u verificirani logical rollback; pre-boundary failure završava BLOCKED bez lažnog rollback claima.
- Offline dependency install, clean-CWD parity i reproducibilni A/B build prolaze.
- Neovisni final review PASS; committed clean worktree; P2 report i hash manifest odgovaraju commitu.

## Kill criteria
- Stop/`BLOCKED` ako se dotakne canonical DB, port 18791 ili aktivni runtime.
- Stop/`BLOCKED` ako bilo koji production transition/security test ne prođe.
- Stop/`BLOCKED` ako offline wheelhouse nije kompletan ili hashovi nisu reproducibilni.
- Stop/`FAIL` ako rollback ne vrati izolirani logical baseline.

## Output artifacts
- P2 implementation plan.
- Novi driver, adapter i dependency verifier.
- P2 tests.
- P2 wheel, manifest, dependency lock/wheelhouse manifest, deploy plan.
- Simulated execute/rollback evidence i finalni report.
