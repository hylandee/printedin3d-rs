# printedin3d-rs

Rust backend for hylandee.com.

## Feature Status

Use this section as the single source of truth for shipped and upcoming backend work.

| Feature | Status | Notes |
| --- | --- | --- |
| Auth: signup/login/logout/session cookies | Done | Live and verified in integration tests |
| Role support on users (`Customer`, `Operator`, `Admin`) | Done | Startup migration adds `role` column when missing |
| Profile endpoint and profile editing | Done | Profile data is live on auth pages |
| Role visibility in profile UI (non-customer only) | Done | Hidden for `Customer`, visible otherwise |
| SQLite hardening (WAL + busy timeout) | Done | Reduces lock contention |
| Integration test suite | Done | 7 tests passing in prior run |
| Deploy script: first-time setup | Done | Installs binary and systemd service |
| Deploy script: update mode | In Progress | Local change currently uncommitted |
| Product catalog CRUD | Planned | Basic schema exists, endpoints can be expanded |
| Orders lifecycle and fulfillment states | Planned | Add explicit status machine |
| Admin management endpoints | Planned | Promote/demote roles via API |
| Observability (metrics/health/version endpoint) | Planned | Add production diagnostics |

## Runtime Notes

- Database is SQLite at `auth.db` relative to process working directory.
- For systemd deploys, this usually resolves to `/opt/printedin3d/printedin3d-rs/auth.db`.

## Updating This File

When a feature changes state:

1. Update the `Status` cell.
2. Add one short note if there is migration or deploy impact.
3. Keep completed items at the top and planned items near the bottom.
