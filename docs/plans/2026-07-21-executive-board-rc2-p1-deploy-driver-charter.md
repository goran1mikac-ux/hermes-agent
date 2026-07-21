# Executive Board RC2 P1 Deploy Driver — Task Charter

- **Lane:** executive-board-rc2-p1-deploy-driver
- **Goal:** Pretvoriti verificirani RC2 runbook u committed, reproducibilan i fail-closed deploy/rollback state-machine driver bez stvarnog deploya.
- **Baseline:** commit `f2ec8fa0c9abd07140bed028ffc23dc8a8611942`; release `/home/goran/releases/executive-board-v0.19.0-rc2-p0-20260721T152152Z`; wheel `5b7c06de1dee5cbfb10a8140f1fd14bc2295f84c98358b5457fa04f65f1020f3`; manifest `6924b4069294ad0caa28144642067e8ab79bcc8b53ccae1726e5625bddc7a7ff`; runbook `acaaf139e2e33e63f701ef6eaefb06d43701cd9e187f31c2067df1536a6861e7`.

## Scope

- Implementirati jedan Python CLI driver s 18 eksplicitnih stanja, bez preskakanja.
- Atomic external checkpoint storage, verified resume i fail-closed rollback.
- Hash/plan/approval binding, TTL, single-use approval ledger i target binding.
- Realne preflight/artifact/backup/restore/venv/parity/migration/verify-only operacije; controlled start i canonical mutacije ostaju nedodirnute u ovoj fazi.
- TDD testovi za transitione, failure injection i sve korisnikove negativne scenarije.
- Izolirani `--plan`, `--dry-run`, `--verify-only`, simulated resume i isolated rollback proof.

## Allowed paths

- `/home/goran/worktrees/hermes-executive-board-v0.19.0-rc1/scripts/executive_board/`
- `/home/goran/worktrees/hermes-executive-board-v0.19.0-rc1/tests/hermes_cli/`
- `/home/goran/worktrees/hermes-executive-board-v0.19.0-rc1/docs/plans/`
- novi P1 evidence direktorij pod `/home/goran/releases/`
- privremeni direktoriji pod `/tmp/`

## Blocked paths / radnje

- `/home/goran/.hermes-doni-clean/agents_os/state.sqlite` — read-only baseline; bez migracije ili write transakcije
- `/home/goran/.venvs/hermes-agent-0.14.0`
- aktivni config, launcher, watcher, cronovi, servisi i 11 legacy datoteka
- port `18791`, stvarni `--execute`, canonical migracija, service restart/stop, quarantine i physical restore uz aktivne writere
- vanjski modeli, poslovne automatizacije i javni side effecti

## Success criteria

- Svih 18 stanja imaju ulazne uvjete, acceptance i rollback mapu.
- Zabranjeni skip/replay/tamper/expiry/double-execute scenariji failaju bez nastavka.
- Checkpoint je atomic JSON izvan canonical baze s hash-chainom i verified resumeom.
- Approval veže wheel, manifest, target environment i canonical deploy-plan hash; TTL i single-use ledger rade.
- Izolirani plan/dry-run/verify-only/resume/rollback prolaze; port 18791 ostaje zatvoren.
- Puni source i installed suite prolaze; wheel build A/B je reproducibilan.
- Driver i testovi su commitani; finalni report ima realne hashove i readiness presudu.

## Kill criteria

- Stop i `BLOCKED` ako je za test potreban stvarni canonical write, start porta 18791 ili promjena aktivnog servisa.
- Stop ako driver može preskočiti stanje, nastaviti nakon neuspjeha ili prihvatiti stale/replayed/tampered approval.
- Stop ako checkpoint tamper nije detektiran ili rollback failure bude prikazan kao uspjeh.
- Stop ako dry-run dodirne aktivni venv, launcher, canonical DB ili legacy datoteke.

## Output artefakti

- `scripts/executive_board/deploy_driver.py`
- `tests/hermes_cli/test_executive_board_deploy_driver.py`
- P1 state-machine dokument/plan
- release evidence: plan, checkpoint primjeri, test logovi, failure matrix i final report
