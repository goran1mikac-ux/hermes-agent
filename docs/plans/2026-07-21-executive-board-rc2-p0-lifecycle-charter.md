# Task Charter — Executive Board RC2 P0 lifecycle remediation

- **lane:** executive-board-rc2-p0-lifecycle
- **goal:** Implementirati i dokazati puni fail-closed Executive Board lifecycle isključivo u RC2 worktreeju i izoliranim testnim bazama/venvovima.
- **scope:** meeting, blind proposals, bidirectional challenge, consensus/dissent, recommendation, owner-bound decision, gated action request, closure, security negatives, migration/rollback, wheel/manifest/runbook refresh.
- **allowed paths:** ovaj worktree; novi RC2 P0 release evidence direktorij pod `/home/goran/releases/`; postojeći RC2 runbook samo radi novih hashova.
- **blocked paths:** aktivni venv, canonical DB, `.hermes-doni-clean` config/launchers, drugi profili, ERO, port 18791 i aktivni procesi.
- **success criteria:** puni lifecycle E2E prolazi; svaki nevaljani prijelaz je fail-closed; source/installed/parity/migration/rollback prolaze; reproducibilni wheel i manifest verificirani.
- **kill criteria:** stop ako test dodirne canonical DB, launcher pokrene listener, import origin nije izolirani site-packages, migration/rollback ne vrati logički baseline ili se aktivni servis/config/launcher promijeni.
- **output artifacts:** commit, reproducibilni wheel, manifest, test logovi, P0 remediation report i hash-refresh runbooka.
