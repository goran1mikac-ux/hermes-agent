# Executive Board RC Remediation Implementation Plan

> **For Hermes:** Execute this plan task-by-task with strict TDD and fail-closed verification.

**Goal:** Ispraviti izolirani SQLite migration verifier i release launcher, reproducibilno izgraditi novi RC te dokazati migration/rollback i verify-only bez dodira aktivnog runtimea.

**Architecture:** Release tooling živi pod `scripts/executive_board/` i radi samo nad eksplicitno zadanim putanjama. Verifier normalizira prvi stupac `PRAGMA integrity_check` neovisno o tuple/sqlite3.Row obliku, ali i dalje odbija sve osim točne vrijednosti `ok`. Launcher uklanja source-copy/PYTHONPATH lane i prosljeđuje `--verify-only` izoliranom Python runneru prije ikakvog DB/listener rada.

**Tech Stack:** Python 3.12, sqlite3, Bash, pytest, deterministic ZIP overlay wheel.

---

1. Dodati RED testove za tuple, sqlite3.Row, loš integrity rezultat i launcher verify-only.
2. Implementirati minimalni migration verifier i release launcher/runner.
3. Pokrenuti focused GREEN testove, zatim puni Executive Board source suite.
4. Na dvije kopije verificiranog Faze 0B online backupa dokazati migration i rollback/logičku paritetu.
5. Commitati promjene, reproducibilno izgraditi dva byte-identična wheela te auditirati RECORD/delta.
6. Instalirati wheel samo u novi izolirani venv; pokrenuti installed suite, clean-CWD parity i stvarni launcher `--verify-only` uz DB/port invariants.
7. Generirati novi manifest i closeout. Ne instalirati u aktivni runtime, ne dirati canonical DB, launchere, servise ni port 18791.
