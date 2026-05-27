# `.github/state/`

Workflow-tracked state files. Each row in here is the *latest version
the CI has committed back into the repo* for some upstream-tracked
resource — used by recurring workflows to decide "anything new since
last run?" without making them stateful.

## Files

| File | Owner workflow | What it tracks |
|------|----------------|----------------|
| `nsrl-current-version.txt` | `.github/workflows/whitelist-refresh.yml` (TASK-175) | Latest NSRL RDSv3 modern-minimal release the project has shipped. The job compares against `https://s3.amazonaws.com/rds.nsrl.nist.gov/` and opens a draft PR bumping this file when newer. |

## Conventions

- One file per tracked resource. Kebab-case, lowercase, no extension
  bloat.
- Sentinel content is a single trimmed line (no newline drama).
- Bumps land via the same workflow's draft PR; humans review the
  change before merging.
