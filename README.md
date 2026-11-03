# quality-gate

A reusable pipeline that judges an AI executor's pull requests. GitHub holds the rules, not a model:

- the executor works only in pull requests;
- each pull request is judged by checks the executor cannot change;
- another vendor's model reviews it independently;
- a generator, not a model, writes the report;
- the protected branch accepts nothing without green mandatory checks, stored evidence and a human approval.

The pipeline names no application, so it can be pointed at another one.

| Where | What |
|---|---|
| `.github/workflows/` | the reusable workflows: `judge`, `executor`, `spec-tests`, `feedback` |
| `gate/` | the scripts: `env_check`, `run_checks`, `guard`, `acceptance`, `security_check`, `concurrency_harness`, `report`, `publish`, `archive`, `feedback`, `reproduce`, `review_local` |
| `docs/CONTRACTS.md` | the numbered rules each script must meet |
| `ACTIONS-LOCK.md` | every pin, with the date it was checked |
| `REPRODUCE.md` | the accounts, the manual setup and the commands |
| `tests/` | the spec-derived tests and the gate's own tests |

The application's other repository calls these workflows at a full commit SHA only.

Known limits: PR code runs inside the `run` job, so the gate does not prove resistance to a deliberately adversarial executor. It proves only what its checks see.
