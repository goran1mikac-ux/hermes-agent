# /goal — Executive Board RC remediation

Izolirano popravi i verificiraj Executive Board RC release tooling nakon rollbacka.

## Granice
- Radi samo u `/home/goran/worktrees/hermes-executive-board-v0.19.0-rc1` i novom remediation outputu pod release direktorijem.
- Ne mijenjaj `/home/goran/.venvs/hermes-agent-0.14.0`, `/home/goran/.hermes-doni-clean/agents_os/state.sqlite`, postojeće launchere/config, procese ili servise.
- Ne pokreći listener na `18791`.
- Ne koristi `/mnt/d/HermesAgent/app` kao source ili runtime.

## Acceptance
- tuple i sqlite3.Row integrity rezultati čitaju prvi stupac i prihvaćaju samo `ok`.
- namjerno loš integrity rezultat ostaje fail-closed.
- release launcher nema dirty copy/PYTHONPATH i stvarno prosljeđuje `--verify-only`.
- verify-only ne mijenja DB i ne otvara port.
- source i installed Executive Board suiteovi prolaze.
- dva reproducibilna wheela su byte-identična.
- migration i rollback prolaze na dvije svježe kopije verificiranog online backupa.
- novi manifest sadrži hashove, test countove i klasifikaciju `EXPECTED_PHYSICAL_DIFFERENCE_AFTER_SQLITE_BACKUP_RESTORE`.
- lokalni commit postoji; nema instalacije/deploya u aktivni runtime.
