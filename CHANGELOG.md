# Changelog

All notable changes to OpenSCM are documented here.

---

## [Unreleased]

---

## [0.2.3] - TBD

### Added
- **CMD enabled warning** — scmclient logs a warning at startup when `cmd_enabled = true` to alert operators that the client will execute commands received from the server.

### Fixed
- **CMD element captures stderr** — commands that write to stderr instead of stdout (e.g. macOS `softwareupdate`) now evaluate correctly against OUTPUT conditions. Previously they always returned False.

### Build
- Windows installer filename no longer includes the redundant `windows` label — e.g. `scmclient-0.2.3-1-x86_64.exe`.

---

## [0.2.2] - 2026-05-03

### Added
- **System compliance report** — new live report page (`/systems/report/:id`) showing every policy the system belongs to, with each test result (PASS / FAIL / NA) grouped per policy. Includes overall pass/fail/NA counters and a per-policy verdict.
- **Dashboard drill-down for systems** — Top Failed Systems table now links directly to the system compliance report on click, matching the existing behaviour of the Top Failed Policies table.
- **Compliance report button** — green clipboard button added to each active system row in the Systems table for one-click access to the system report.
- **Policy report link from dashboard** — Top Failed Policies table now links directly to the live policy report.

### CI / Build
- Replaced manual build script with GitHub Actions workflows triggered on version tag (`v*`).
- **Stable workflow** builds all targets, packages deb / rpm / archlinux / Windows exe / macOS pkg / FreeBSD pkg, pushes a Docker multi-arch image (amd64 + arm64) to Docker Hub, and creates a draft GitHub Release with all artifacts attached.
- **Testing workflow** (manual trigger) builds and packages all targets for validation without publishing.

### Fixed
- Error 500 on system groups add and edit pages.

---

## [0.2.0] - 2026-04-30

### Added
- **First-run setup screen** — a guided account-creation page is shown on the first visit to a fresh installation, replacing the previous default `admin/admin` credentials and the associated warning message in package scripts.
- `init_tera_with_overrides()` — public function that loads all CE templates then lets callers substitute individual templates by name. Used by EE and SaaS to inject custom pages without forking CE.
- Optional `organization` field in `LoginForm` — if provided, scopes the user lookup to that tenant and returns a clear "Organization not found" error if unknown. CE and EE are unaffected (field is absent from their login form). Powers SaaS multi-tenant login.
- `success_message` support added to the login page context (used by SaaS to confirm account creation after registration).

### Changed
- Schema migrated to **v4** — test applicability conditions moved from inline JSON columns to a dedicated `test_conditions` table, enabling indexed lookups and cleaner per-condition management.
- `create_core_router` refactored into `build_core_routes` + `apply_core_layers` helpers; later simplified once the optional `organization` login approach was adopted.
- Server public key is now included in the heartbeat response **only** when the agent explicitly requests it (i.e. when `public_key` is present in the payload). Previously the key was sent on every heartbeat regardless. The REGISTER response also now correctly includes the server public key for initial key exchange.

### Fixed

**Server**
- Policy schedule edit page always showing scan and report schedules as disabled after saving — `schedule_type` column was missing from the SELECT query, causing a silent sqlx decode failure.

**Agent**
- macOS client service not restarted after package upgrade — `preinstall` script added to stop the running service before Payload extraction; `postinstall` now uses `launchctl enable` + `bootstrap` (with fallback to `load -w`) so the service is reliably re-enabled on Sonoma and later.
- Arch Linux client service not restarted after upgrade — installer scripts now correctly detect the pacman version-string argument (e.g. `0.2.0`) passed by nfpm/pacman hooks, where Debian/RPM pass `configure`/`1`/`2`. Dedicated Arch `.install` files added for PKGBUILD/AUR packaging.
- macOS package detection — Homebrew (`brew list`) and `pkgutil` are now checked for package existence and version, covering packages installed outside the App Store.
- False `ERROR` log when a file-content check is run against a path that does not exist — the check now returns `false` silently (logged at `DEBUG`) instead of attempting to open the file and logging an OS error.

### Security
- Resolved all high, medium, and low-severity findings from a full code review of the server and agent codebases (`receive_result`, input validation, error handling, and two additional high-severity gaps in result ingestion).

---

## [0.1.9] - 2026-04-28

### Added
- **Bulk actions** — Systems: approve, add to group, delete. Tests: delete, add to policy. Reports: delete. All actions operate on user-selected rows across any page of the table.
- **Version update notifications** — server checks the GitHub releases API hourly and sends a dismissible in-app notification to all administrators when a newer version is available. Deduplicates notifications so admins are only alerted once per version.

### Changed
- Pinned Rust toolchain to 1.95.0 via `rust-toolchain.toml` for reproducible builds.

### Fixed
- Missing tooltips on action buttons in the Tests table.

---

## [0.1.8] - 2026-04-14

### Added
- **CMD element** — new test element type that runs a shell command and evaluates its output against a string condition. Disabled by default; opt in with `cmd_enabled = true` in client config so admins explicitly permit command execution on agents.
- **Username duplicate check** — creating a user now fails with a clear error if the username is already taken.

### Changed
- `scmserver` refactored into a library crate (`lib.rs`) with a thin `main.rs` entry point, enabling the Enterprise Edition binary to depend on it directly.
- CMD element output field renamed from `stdout` to `output`.

### Fixed
- Package existence check on Debian/Ubuntu now inspects dpkg output text instead of exit code (exit code is always 0, masking uninstalled packages).

---

## [0.1.7]

### Added
- **Arch Linux agent support** — `pacman` package manager added to package existence and version checks.
- **Arch Linux packages** — `.pkg.tar.zst` packages for x86_64, aarch64, and armv7h architectures.
- **Report scheduling** — each policy can now have an independent auto-report schedule that automatically saves compliance snapshots on a defined interval.
- `schedule_type` column in `policy_schedules` — supports `scan` and `report` schedule types per policy.
- Schema migration v3 — recreates `policy_schedules` with `UNIQUE(policy_id, schedule_type)` constraint.
- Scheduler now notifies administrators when a scheduled report is saved successfully or fails.

### Fixed
- Policy compliance score — systems with only NA results were incorrectly counted as compliant (100%), now excluded from both numerator and denominator.
- `systems_passed` calculation — now requires at least one PASS result, not just the absence of FAIL results.
- Compliance score returning 100% when all test results are NA — now correctly returns -1 (Not Scanned).
- Compliance score returning 0% for all-NA policies — correctly shows as Not Scanned in dashboard.

### Improved
- Extracted `save_policy_report_logic` as a shared function — used by both the manual save handler and the report scheduler, with `submitter_name` set to the user or `Scheduler` accordingly.
- Schema migration now runs inside a transaction with cleanup of leftover tables from previously failed migrations.

---

## [0.1.6]

### Added

**Server**
- Applicability conditions — tests can now be configured to run only when specific conditions are met (e.g. only run Apache checks if Apache is installed).
- `test_conditions` table to store applicability conditions per test.
- Applicability section in test create and edit forms, and display in test view modal.
- Schema migration system — automatic database upgrades on server startup via `schema_info` table.
- NA count to Highest Risk Assets dashboard table.
- NA badge to policy live report and archived report views.
- NA handling to test detail modal in both live and archived report views.

**Agent**
- Applicability evaluation — agent checks applicability conditions before running a test, sends NA if not applicable.
- Directory content search — File/Content checks against a directory path now search all files in the directory.

### Fixed

**Server**
- Compliance score calculation — NA results were incorrectly included in the denominator, causing scores to appear lower than actual.
- `total_tests` count — now includes NA results so dashboard correctly derives NA count.
- Policy report showing duplicate results for systems in multiple groups — replaced DISTINCT with subquery approach.
- `is_passed` logic — systems with all PASS+NA results now correctly marked as compliant.
- `fail_count` — systems with only NA results no longer counted as failures.

**Agent**
- 100% CPU spike when a File/Content check is run against a directory path — now correctly searches all files in the directory.
- `Unknown string condition: 'None'` errors — empty or None conditions are now skipped gracefully.
- Unsupported platform checks now return NA instead of FAIL.

### Improved
- Multi-condition test logic correctly handles NA — ALL mode: any FAIL→FAIL, all NA→NA, otherwise PASS. ANY mode: any PASS→PASS, all NA→NA, otherwise FAIL.
- Unsupported platform checks return NA instead of FAIL — file/directory owner, group, and permissions on Windows; registry checks on Unix.

---

## [0.1.5]

### Added

**Server**
- Export options to Tests table — PDF, Excel, CSV, print and column visibility.

**Agent**
- macOS preremove script — stops and unloads the service cleanly before uninstall.

### New Platforms
- Linux ARMv7 (armhf) client support.
- macOS universal binary (ARM64 + x86_64) — runs natively on both Apple Silicon and Intel Macs.

### Fixed

**Server**
- Compliance recalculation function — added `tenant_id` filters across all queries, fixed ghost result purge, rewrote policy stats update to be SQLite compatible.
- Missing button titles in server UI.
- Compliance score calculation — NA results were incorrectly included in the denominator.
- `total_tests` count — now excludes NA results to correctly reflect the number of evaluated checks.

### Improved
- Compliance engine refactored to use native Rust functions — replaced external command calls for user/group/port checks.
- Added `group` sub-element for file/directory elements and system group checks — supports `equals`, `contains`, and `regex` conditions.
- Updated Rust toolchain to 1.95.0.

---

## [0.1.4]

### Added

**Server**
- Dynamic settings engine — database-backed `settings` table replacing hardcoded configurations.
- Settings UI — admin interface to configure compliance thresholds and offline detection parameters in real-time.
- Configurable compliance thresholds — SAT, MARGINAL, and UNSAT thresholds fully customizable.
- Offline detection — systems exceeding the configurable inactivity threshold flagged with an Offline badge and greyscale highlighting.
- Context-aware UI — dashboard progress bars and policy status colors update dynamically based on user-defined thresholds.

### New Platforms
- FreeBSD (amd64) — full agent support including native `.pkg` package format, standard `/usr/local` paths, and RC service script.
- Linux PowerPC64LE (ppc64le) agent support.

### Fixed

**Server**
- Self-healing directory structure — prevents crashes if critical application folders (logs, keys, db) are missing or removed.
- Top Failed dashboard table — now excludes systems with a -1 score (unscanned).

**Agent**
- Directory validation logic to ensure agent stability if environment paths are modified or missing.

### Changed
- Deprecated RISC-V support — support may be revisited as the ecosystem matures.

---

## [0.1.3]

### Added

**Server**
- Docker image support — multi-arch images for amd64, arm64, and RISC-V published to Docker Hub (`openscm/scmserver`).
- Test detail modal in live compliance report — click any test name to view description, check procedure, and remediation.
- Test detail modal in archived report view.

### Fixed

**Server**
- -1% display for unscanned policies in dashboard — now shows Not Scanned badge.
- Hourly compliance snapshot firing immediately on startup.
- Redundant compliance recalculation every 60 seconds — removed from loop, only triggered by events and on startup.
- Unused import warnings on Windows.
- `save_to` dead code warning on Windows.
- PDF report rule name overlapping status column — rule names now truncated and wrapped.
- PDF report description column removed from rules table.

**Agent**
- Doc comment `///` → `//` in `config.rs`.
- Maximum tests per system capped at 20 — increased to 500.

---

## [0.1.2]

### Fixed

**Server**
- Default database path on Linux — moved from `/etc/openscm/scm.db` to `/var/lib/openscm/scm.db` following FHS conventions.
- Windows installer using user-specific `%APPDATA%` instead of system-wide `%PROGRAMDATA%`.
- Windows registry key `Tenant_id` → `TenantId` to match server config expectations.
- Windows upgrade file lock error — added graceful `sc stop` before force kill.
- Compliance trend graph tooltip showing unrounded percentages — scores now rounded to 2 decimal places at source.

**Agent**
- Windows installer using user-specific `%APPDATA%` instead of system-wide `%PROGRAMDATA%`.
- Windows registry key `Tenant_id` → `TenantId`.
- Windows upgrade file lock error.

### Improved

**Server**
- Server now runs as dedicated `openscm` system user instead of root.
- Binary path moved to `/usr/bin/scmserver` following FHS conventions.
- systemd service hardening — `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`.
- Restart delay (`RestartSec=5s`) for both Linux and Windows services.
- Log rotation added to Windows service XML.
- Database migration in `postinst` for upgrades from pre-0.1.2.
- Welcome and finish pages, URL/help links, and application icon added to Windows installer.

**Agent**
- Binary path moved to `/usr/bin/scmclient` following FHS conventions.
- Same Windows installer improvements as server.

---

## [0.1.1]

### Added
- Regex condition support (`REGEX`) with multiline file content matching.
- Unscanned systems and policies now display Not Scanned badge instead of 0%.

### Fixed
- Missing `tenant_id` filters across `dashboard.rs` and `systems.rs`.
- Stale compliance results — orphaned results now cleaned up when system groups, policies, or group memberships change.
- `normalize_status` missing NA case — NA results were incorrectly stored as FAIL.
- Compliance trend incorrectly including unscanned systems in average score calculation.
- Compliance history recorded across all tenants instead of per tenant.
- Unscanned systems and policies showing 0% instead of Not Scanned.
- Duplicate failures section displayed in report view.
- Duplicate notifications fetch in `dashboard.rs`.
- Windows upgrade failure — added retry delay when writing agent files to allow the OS to release file locks.

---

## [0.1.0]

First release.
