# Changelog

All notable changes to OpenSCM are documented here.

---

## [Unreleased]

---

## [0.3.10] - 2026-05-18

### Fixed
- **Scheduler notifications were silently dropped on fresh CE installs** — two places in `scheduler.rs` decided who to notify with a hard-coded `WHERE role = 'admin'` query:
  - `get_policy_owners` — emits the "Scheduled scan completed" / "Scheduled report saved" / "Scheduled X FAILED" notifications when a `policy_schedules` row fires
  - `check_for_updates` — emits the hourly "OpenSCM vX.Y.Z is available" notification when a newer release is detected on GitHub
  The bootstrap admin on a fresh CE install is stored with role `'superuser'` (see `install.rs`), so on a typical single-tenant install the queries returned an empty list and **no notification of any kind from the scheduler** ever reached the bell. Both queries now match `role IN ('admin', 'superuser')`. No data migration needed; effective on the next scheduler tick after restart.
- **Certificate icon floated awkwardly in policy list view** — the policy grid uses an inner `col-7` / `col-5` Bootstrap split inside each card for description vs. the big `fa-certificate` icon. In the 3-up Grid View each card is ~33% wide and the split looks right; switching to List View made each card span the full screen but left the inner column widths untouched, so the cert icon ended up centred in a ~40%-wide empty column halfway across the screen. Fixed by pulling the cert column out of the flex flow in list view and pinning it as a corner badge at the card's upper-right (`position: absolute; top: 8px; right: 12px`), shrinking from `fa-4x` to a 3rem font-size so it reads as a tight badge rather than a poster. The description column then stretches to 100% width with just enough right-padding to clear the badge. Click target preserved.

### Internal
- **`systems.rs` split into `systems.rs` + `groups.rs`** — `systems.rs` had grown past 1500 lines after the live-system-report and clickable-test-name features landed. The 6 group functions (`system_groups`, `system_groups_add[_save]`, `system_groups_delete`, `system_groups_edit[_save]`) are now in `scmserver/src/groups.rs`; everything that operates on the `systems` table itself stays in `systems.rs` (including `systems_bulk_add_group`, which is a bulk action that assigns systems to a group id — the action is on systems, the group is just a parameter). `fetch_system_report_data` and `fetch_tenant_tests_metadata` also stay in `systems.rs` since they're report helpers, not group-table operations. `lib.rs` registers the new `pub mod groups;` and reroutes the four `/system_groups/*` routes to `groups::*`; no URL paths change, no behaviour change.

  Result: `systems.rs` is now 983 lines, `groups.rs` is 599 lines.

---

## [0.3.9] - 2026-05-17

### Added
- **Email Me PDF — for all four report views.** Every report view page (archive policy, archive system, live policy, live system) now has an "Email Me PDF" button next to the existing "Download PDF" button. Clicking it POSTs to a new endpoint that generates the same PDF the download button would produce and sends it as an attachment to the logged-in user's account email. Available only when SMTP is configured — the button is rendered behind `{% if is_smtp_configured %}` and every handler re-checks SMTP server-side as defence in depth. PDF building was factored into `build_archive_policy_pdf` / `build_live_policy_pdf` (both returning `Result<Vec<u8>, ()>`) so the download and email paths share one source of truth per PDF flavour; the two system-PDF flows already used a shared `build_system_report_pdf`. New `Mailer::send_with_attachment(to, subject, html, filename, mime, bytes)` in `email.rs` builds a MultiPart/mixed message via lettre's `Attachment::new(filename).body(bytes, mime)` — no new crate dependency. Four new POST routes (`/reports/email/{id}`, `/reports/system/email/{id}`, `/policies/email/{id}`, `/systems/report/{id}/email`), all Viewer-gated like their download counterparts. Handlers share `reports::flash_back / user_email / report_email_body` helpers so the success/error wording is identical across endpoints.
- **Clickable test names on system compliance reports** — both the live system report (`/systems/report/{id}`) and the saved system snapshot (`/reports/system/view/{id}`) now make every test row clickable. Clicking pops the same detail modal the policy reports already use, showing the test's description, check procedure (rational), remediation, and current status. Test metadata is pulled live from the `tests` table via a new `systems::fetch_tenant_tests_metadata(tenant_id, pool)` helper — so even old saved snapshots get current descriptions. Rows whose test was renamed or deleted since the snapshot was saved fall through to plain text (no info icon, not clickable), the same graceful-degradation pattern the policy archive view already uses.
- **Hook for Policy Store update badge (CE side)** — new `set_store_update_provider(Arc<dyn Fn(&str) -> u32>)` registration function in `handlers.rs`, mirroring the existing `enable_saas_mode()` pattern. CE itself never registers a provider, so `store_update_count` is always 0 in `render_template` and the new template branch in `base.html` (`{% if store_update_count > 0 %}` red badge on the Policy Store sidebar link) stays hidden — exactly zero behaviour change for CE-only installs. SaaS registers a provider backed by an hourly background refresh so each tenant Admin sees how many of their installed policies have a newer version waiting in the store.

### Changed
- **Database reset is now an Admin action, scoped to the caller's tenant** (was Superuser-only). The reset SQL was already filtering by `auth.tenant_id` end-to-end, so dropping the role gate from Superuser to Admin only widens *who* can invoke it — an Admin can wipe their own tenant's systems / groups / tests / policies / reports / users, and nothing else. Superuser still has every Admin power (`Superuser > Admin`), so the CE single-tenant case and the SaaS platform-admin-of-`default`-tenant case keep working unchanged. Template gates split so the Email tab stays Superuser-only (SMTP is platform-global in SaaS) while the Danger Zone tab / card / confirmation modal move to `is_admin`. UI copy clarified: "all data **for this tenant**…" / "**for this tenant only**…" so a tenant Admin doesn't fear wiping the platform.
- **PDF policy report — "Tests in this Policy" now starts on its own page** (both archive and live PDF flows). The 1.0-unit `Break` before the section is replaced with a hard `PageBreak`, so page 1 is just the cover (title + submitter + logo + Report Details) and page 2 begins the test catalog. The existing PageBreak after the catalog (separating it from the per-system breakdown) is unchanged. Legacy archive reports with empty `tests_metadata` skip both the section and its new PageBreak, so their layout is unaffected.

### Fixed
- **Editing the bootstrap admin's name or email aborted with "The bootstrap admin role cannot be changed"** — the v9 trigger `protect_bootstrap_admin_role` was declared `BEFORE UPDATE OF role`, which in SQLite fires whenever the `role` column appears in the UPDATE statement's SET clause regardless of whether the value actually changes. The user-edit handler always re-passes the current role to keep one canonical UPDATE shape, so editing only name/email of `users.id = 1` (default tenant) tripped the trigger. Trigger rebuilt with an additional `AND NEW.role != OLD.role` guard in its WHEN clause; new schema migration **v16 → v17** drops and recreates it on already-upgraded installs, the fresh-install path and the v8→v9 source both updated to match. The guarantee (you can never *change* the bootstrap admin's role) is preserved.
- **v16 → v17 migration crashed on startup with "trigger protect_bootstrap_admin_role already exists"** — the migration's `DROP TRIGGER IF EXISTS` and `CREATE TRIGGER` were executed through the `&SqlitePool` reference, so sqlx was free to grab a different pooled connection for the CREATE. The CREATE's prepared-statement compilation on the second connection could still see the pre-DROP schema state and refuse to create the trigger. Fixed by pinning both DDL statements to a single acquired connection (`pool.acquire()` once, then `&mut *conn` for each query), so the DROP/CREATE pair lands on the same SQLite session and the schema change is visible to the CREATE.
- **"Email Me PDF" silently succeeded on archive report views** — the new email handlers redirected to `/reports/view/{id}?success_message=…` and `/reports/system/view/{id}?success_message=…` on success, but the matching view handlers (`reports_view`, `system_reports_view`) never read the query string, so the flash was thrown away before reaching the template. The two archive templates were also missing the `{% if success_message %}` alert block (`reports_view.html`) or both flash blocks (`system_report_view.html`). Fixed by adding `Query<ErrorQuery>` to both handlers and inserting `success_message` / `error_message` into the template context, plus adding the matching alert markup to both templates. The two live-report views (`policies_report`, `system_report`) already had this wired through.

### Hardening
- **`run_migrations` documents the single-connection rule for multi-DDL migrations** — top-of-fn comment explains when to use `pool.begin()` vs `pool.acquire()` vs plain `&SqlitePool`, so the next migration author doesn't repeat the v16→v17 mistake. The rule applies to any step that issues ≥ 2 dependent DDL statements (DROP+CREATE of the same object, ALTER ADD COLUMN followed by an UPDATE that references the new column, RENAME COLUMN followed by a SELECT on the new name).
- **v13 → v14 and v14 → v15 wrapped in transactions preemptively** — both ALTER ADD COLUMN + per-row backfill. They've run fine in the field, but they're structurally the same shape that bit v16→v17 in theory. Switched from `pool` to `pool.begin()` + `&mut *tx`. Side benefit: each step is now atomic — if the backfill fails partway through, the ALTER rolls back too, so the migration can be retried cleanly.

---

## [0.3.8] - 2026-05-17

### Changed
- **`offline_threshold` setting now stored in minutes (was seconds)** — aligned with `auto_prune_inactive`, which was already minutes, so both fields use the same unit and a quick visual comparison is meaningful (e.g. "mark offline after 60 min, delete after 1440 min"). Default changed from `3600` (s) to `60` (min) — same effective duration. The Admin Settings page label now reads "Offline Threshold (minutes)" with `min="1" max="1440"` on the input. `systems.rs` multiplies by 60 at SQL bind time, matching how `prune_inactive_systems` has always handled `auto_prune_inactive`. Schema migration **v15 → v16** divides every existing tenant's stored value by 60 (integer division, clamped to a minimum of 1) so upgrade is a no-op for the user — the column unit changes but the behaviour stays the same.

### Added
- **Delete Test button on the test edit page** — editors can now delete a test directly from `/tests/edit/{id}` without going back to the list, via a red `Delete Test` button on the left of the card footer. Uses the existing `GET /tests/delete/{id}` route (ON DELETE CASCADE already removes its conditions and unlinks it from policies); confirm dialog warns about the policy-unlink consequence.
- **PDF report — Tests Summary on the first page** — both policy report PDFs now render a `Tests in this Policy (N)` section directly after the Report Details table, listing every test's name and description in a two-column bordered table:
  - **Archive PDF** (`GET /reports/download/{id}`) reads the `tests_metadata` JSON already persisted on save — no schema change, every newly-saved report gets it; legacy reports without `tests_metadata` skip the section cleanly.
  - **Live PDF** (`GET /policies/report/download/{id}`) builds the same section from a fresh DB query, so it always reflects current test definitions.

  The per-system breakdown that follows is unchanged. The system-scoped PDF (`/systems/report/download/{id}`) is unaffected — it shows multiple policies per host and already lists tests per-policy.

---

## [0.3.7] - 2026-05-16

### Added
- **`apply_policy_import(pool, tenant_id, export)` extracted from `policies_import`** — the per-test upsert + conditions-replace + unlink logic now lives in one reusable async fn returning a structured `PolicyImportSummary { policy_id, action, inserted_tests, updated_tests, unlinked_tests }`. The existing multipart `POST /policies/import` is now a thin wrapper around it; SaaS's new Policy Store install/update handler uses the same core so the import semantics stay identical no matter where the file came from.
- **`is_saas` sidebar entry: Policy Store** — new `base.html` link to `/store` gated on `is_saas and is_editor`. CE renders nothing (flag defaults to false) so behaviour is unchanged for the CE edition.

### Fixed (scmclient)
- **Tests with no server-assigned id were silently dropped** — `process_compliance_tests` defaulted to `test_id=0` and POSTed a result the server silently ignored. Now skips the test with a `warn!` so the issue is visible in agent logs.
- **Panic-free DNS failure in `get_system_domain`** — on Windows the inner `getaddrinfo` iterator called `.unwrap()` on the `AddrInfo` result; replaced with `.ok()?` so a failed DNS lookup returns `None` instead of panicking.
- **Config file written on every load even when unchanged** — `get_config()` unconditionally re-saved the file after each `normalize()` call, causing pointless disk writes and mtime churn that could confuse file-integrity monitors. `normalize()` now returns `(Config, changed: bool)`; callers save only when `changed` is true.

### Changed (scmclient)
- **`reqwest::Client` built once and reused across heartbeats** — the HTTP client was reconstructed every heartbeat cycle, discarding reqwest's connection pool and TLS session cache. Client is now built once in `main()` and passed by reference to `send_system_info`, giving persistent TCP+TLS reuse at no behaviour cost.
- **`send_system_info` decomposed into four named helpers** — the 200-line heartbeat function now delegates to `load_or_create_identity`, `collect_system_info`, `post_heartbeat`, and `dispatch_server_command`; the top-level function reads as a 12-line flow. No behaviour change.
- **Generic `calculate_hash::<H>` replaces duplicate SHA helpers** — `calculate_sha1` / `calculate_sha2` were byte-for-byte identical loops differing only in hasher type; collapsed into one generic function. `file` and `directory` owner/group/permission arms unified through shared `check_path_owner` / `check_path_group` / `check_path_permission` helpers, eliminating six near-identical 15-line blocks.

---

## [0.3.6] - 2026-05-16

### Fixed
- **`init_tera_with_overrides` crashed on startup when an override extended `base.html` and base.html was not itself an override** — Tera 1.x validates `extends` parents at `add_raw_template` time, but the loader added overrides *before* CE templates. As long as `base.html` was in the override list (its previous SaaS use), the order accidentally worked; once SaaS started inheriting CE's `base.html` directly, the first child override (`admin_tenants.html`) failed with `MissingParent { current: "admin_tenants.html", parent: "base.html" }` and `main()` returned `Err`, causing the SaaS service to crash-restart in a tight loop. Reversed the loader order — CE templates load first; overrides replace them by name afterwards.

---

## [0.3.5] - 2026-05-16

### Added
- **`is_saas` template context flag** — new `scmserver::handlers::enable_saas_mode()` lets the SaaS binary flip a process-wide flag at startup. `render_template` exposes it as `{{ is_saas }}` so SaaS-only chrome (tenant chip, Support menu, Platform Admin treeview) can live directly in the shared `base.html` instead of forking the whole template. CE rendering is unchanged (flag defaults to `false`).

### Fixed
- **Stale `comparison` template references** — `tests.html` and `tests_edit.html` still read `tc.comparison` / `ac.comparison` after the v11→v12 column rename, causing a "Variable not found in context" render error whenever a tenant had any test conditions or applicability rules. Renamed all four references back to `condition`.

---

## [0.3.4] - 2026-05-16

### Added
- **Policy Import / Export** — every policy now has a stable `external_id` (32-char hex) and an optional `author` field. New `GET /policies/export/{id}` downloads a JSON file containing the policy, every linked test, and each test's conditions/applicability rules — ids and tenant references are stripped so files are portable across installations. New `POST /policies/import` (multipart upload) restores a file: if the `external_id` matches an existing policy in the tenant, the policy is updated; otherwise it is inserted as a new policy with name-collision handling (`(imported)`, `-2`, `-3`, …). Import button and per-policy export icon added to the policies page; author shown on each policy card and editable from the add / edit forms.
- **Per-test stable identity (`tests.external_id`)** — tests now also carry a 32-char hex `external_id`, auto-generated on creation and exported alongside each test. On import, tests are matched by `external_id`: a match updates the existing row in place (preserving results history and any cross-policy links) and replaces its conditions; no match inserts a new test. Tests previously linked to the policy but absent from the imported file are **unlinked** from this policy (but kept in the tests table) so re-imports become non-destructive across policies. Export format bumped to v3; older v1/v2 files still importable (missing test ids are generated).

### Changed
- **Schema version bumped to 15** — v13→v14 adds `policies.author` and `policies.external_id` and backfills existing policies; v14→v15 adds `tests.external_id` and backfills existing tests; fresh installs stamp at v15.
- **axum `multipart` feature enabled** — required by the new policy import endpoint.

---

## [0.3.3] - 2026-05-15

### Fixed
- **Offline badge missing on Systems page after DataTables redraw** — the offline indicator (row dimming + "Offline" badge) was applied via jQuery on document ready, so any DataTables interaction (search, sort, pagination) wiped it out for the affected rows. Moved the badge into the Tera template so it renders server-side as part of the cell, and replaced the JS-applied row dimming with a pure CSS rule (`tr[data-offline="true"] td:not(:last-child) { opacity: 0.5; }`) that survives DOM redraws.
- **Agent results not stored — `missing field 'type'` deserialization error** — the v10→v11 MySQL-compatibility migration renamed `test_conditions.type` → `ctype` and `test_conditions.condition` → `comparison` on the server, but the scmclient agent still expected the original JSON field names. Every heartbeat that returned tests caused the agent to fail deserializing, so no compliance results were ever sent back. Fixed by reverting both columns to their original names (`type`, `condition`) via a new v11→v12 migration; the Rust struct field names match again so the JSON wire format is identical to what the agent expects, with no `serde(rename)` shims.

### Added
- **Auto-delete inactive systems** — new admin setting `auto_prune_inactive` (in minutes) automatically removes active systems whose `last_seen` is older than the configured threshold. `0` disables the feature (default). Runs every 60 seconds inside the existing scheduler loop. Per-tenant setting, exposed in the General tab of the Admin Settings page.

### Changed
- **`test_conditions.type` and `test_conditions.condition` restored** — the MySQL-era column names (`ctype`, `comparison`) reverted to the originals via migration v11→v12. SQLite identifier quoting (backticks) used in raw SQL where `type` collides with parser keywords. No external API change.
- **Schema version bumped to 13** — fresh installs are stamped at v13; existing installs run the new v11→v12 (column rename) and v12→v13 (seed `auto_prune_inactive` for all tenants) migrations on startup.

---

## [0.3.2] - 2026-05-15

### Changed
- **`db_compat` module deleted** — the entire multi-backend compatibility shim is removed. All 52 `adapt_sql()` call sites converted to direct SQL literals; remaining helpers (`format_datetime_col`, `unix_diff_col`, `date_group_col`, `group_concat_col`, `last_insert_id_sql`, `upsert_*_sql`, `admin_role_trigger_sql`, `rename_table_sql`, `table_exists_sql`) inlined at their call sites; `column_exists` moved as a private function into `schema.rs`.
- **`render_template` DB round-trips halved** — the four per-page queries (pending count, notify count, notifications list, tenant name) batched into two: a single sub-select retrieves pending count + tenant name; a window-function query retrieves notifications + total count simultaneously.
- **`initialize_database` split into focused helpers** — the 560-line function broken into three private helpers (`create_tables`, `create_indexes`, `seed_lookup_data`) called by a thin coordinator.
- **`recalculate_current_compliance` split into focused helpers** — the 195-line aggregation function broken into `purge_ghost_results`, `update_test_stats`, `update_system_stats`, `update_policy_stats`, all sharing one transaction.
- **Compliance verdict centralised** — `handlers::is_system_passed(pass, fail)` replaces the inline `fail_count == 0 && pass_count > 0` expression in `reports.rs`, `policies.rs`, and `systems.rs`.
- **Stale comments removed** — scaffolding annotations (`// <--- ADD THIS LINE`, `// Added`, `// Alias for …`) cleaned from `models.rs`; `lib.rs` header updated to remove EE references.

---

## [0.3.1] - 2026-05-15

### Changed
- **SQLite-only — MySQL and PostgreSQL support dropped** — CE reverts to `sqlx::SqlitePool` exclusively. The multi-backend `AnyPool`, `DbBackend` enum, `set_db_backend`, `MYSQL_SUPPORT`, and `row_get_string` / `row_get_opt_string` helpers have been removed.
- **SaaS drops EE dependency** — SaaS (0.2.2) now depends directly on `scmserver` (CE) instead of `openscm-ee`. `create_core_router` replaces `create_ee_router`. The admin→superuser promotion migration is inlined in SaaS `main.rs`. The `sqlx` feature set is trimmed back to `sqlite` only.

### Fixed
- **Unscanned tests shown as FAIL in system compliance report** — tests with no entry in the `results` table were mapped to `"FAIL"` by `normalize_status()`. Added a `"not_scanned"` arm so unrun tests are counted in the N/A bucket and rendered as the grey *Not Scanned* badge.

---

## [0.3.0] - 2026-05-14

### Added
- **MySQL and PostgreSQL support (EE / SaaS)** — EE and SaaS can now connect to MySQL or PostgreSQL instead of SQLite by setting `db_type = "mysql"` / `"postgres"` and the corresponding `mysql_url` / `postgres_url` in the server config. SQLite remains the default; existing installs require no configuration change.
- **`db_compat` module** — new backend-agnostic SQL helper library used by all query sites: `adapt_sql` (rewrites `AUTOINCREMENT`, `INSERT OR IGNORE`, `DEFAULT datetime('now')`), `last_insert_id_sql`, `format_datetime_col`, `unix_diff_col`, `date_group_col`, `group_concat_col`, `table_exists_sql`, `upsert_results_sql`, `upsert_schedule_sql`, `upsert_setting_sql`, `rename_table_sql`, `column_exists`, `schema_info_exists_sql`, and `admin_role_trigger_sql`. Each emits the correct SQL dialect for SQLite, MySQL, or PostgreSQL.
- **`DatabaseConfig` multi-backend fields** — `db_type`, `mysql_url`, and `postgres_url` added to the server config struct.

### Fixed
- **Bootstrap admin created with wrong role on fresh CE install** — the initial admin user was assigned role `admin` instead of `superuser`, leaving no superuser on a brand-new CE installation. Fixed to assign `superuser` at install time.
- **All-NA policy verdict shown as FAILED** — when every test result for a system was NA, both the live policy report and archived policy report showed FAILED / NON-COMPLIANT. Both views now show a grey "NOT APPLICABLE" state, consistent with the existing system-level report behaviour.
- **Archived policy reports failed to load after schema update** — reports saved before `pass_count` / `fail_count` were added to `SystemReport` crashed with `missing field` on deserialization. Fixed with `#[serde(default)]` on both fields plus a backfill step that recomputes counts from the stored results vec.
- **Agent re-registration loop after server DB reset** — the `INSERT … SELECT last_insert_rowid()` sequence was not atomic through AnyPool, causing the rowid to always return 0 and the agent to re-register on every heartbeat. Wrapped in a transaction to make it atomic.
- **Stale server public key caused permanent signature verification failure** — after a server DB reset (new signing keys), clients holding the old cached server public key failed all signature checks indefinitely. The client now drops the stale key file on first verification failure and re-handshakes on the next heartbeat.
- **Non-deterministic wire format broke Ed25519 signatures** — `#[serde(flatten)]` on `TestWithConditions` produced inconsistent JSON key ordering when serialized for signing. Replaced with a flat `TestPayload` struct for deterministic serialization.
- **AnyPool DATETIME decode error** — AnyPool could not decode `DATETIME` columns directly. All affected queries now `CAST` datetime columns to `TEXT` before binding to Rust `String` fields.
- **`PolicySchedule.enabled` Bool type mismatch** — AnyPool maps `BOOLEAN`/`INTEGER` to `BIGINT`; changed the field from `bool` to `i64` and added `CAST(enabled AS INTEGER)` in all schedule queries. Tera templates treat `0`/`1` as falsy/truthy.
- **`SELECT EXISTS(…)` returned BIGINT not bool** — `query_scalar::<_, bool>` for existence checks failed at runtime. Changed to `i64` with `.unwrap_or(0) > 0`.
- **`email_verified` column referenced in CE login query** — CE's login handler referenced a SaaS-only column, causing SQL errors. Column reference removed from CE.
- **Severity prefix cluttered test selection in Add Policy form** — removed the `[SEVERITY]` prefix from test options in the dual-listbox so only the test name is shown.
- **macOS client config file path incorrect** — fixed the config file lookup path on macOS.
- **PostgreSQL `DATETIME` type unsupported** — `adapt_sql()` now converts `DATETIME` column declarations to `TIMESTAMP` for PostgreSQL; without this all `CREATE TABLE` statements would have failed on PG.
- **PostgreSQL `column_exists()` used native `$1`/`$2` placeholders** — AnyPool requires `?` for all backends; using `$1`/`$2` directly caused a runtime panic during the v3→v4 migration on PostgreSQL.
- **MySQL `ALTER TABLE … RENAME TO` syntax unsupported** — the v2→v3 schema migration used SQLite/PostgreSQL rename syntax. Replaced with a new `db_compat::rename_table_sql()` helper that emits `RENAME TABLE … TO` on MySQL.

### Internal
- **CE AnyPool migration** — CE core (`scmserver`) migrated from `SqlitePool` to `AnyPool` throughout. All SQLite-specific SQL in `client.rs`, `dashboard.rs`, `install.rs`, `policies.rs`, `schema.rs`, `settings.rs`, `systems.rs`, and `tests.rs` replaced with `db_compat` helpers. `sqlx` Cargo features extended to include `mysql` and `postgres` so all drivers are compiled in.
- **EE multi-backend pool** — EE `main.rs` reads `db_type` from config, sets `DbBackend` at startup, and connects to the appropriate backend. SQLite PRAGMAs are guarded behind a backend check.
- **SaaS multi-backend pool** — SaaS aligned with EE: `main.rs` now reads `db_type` from config and supports SQLite (default), MySQL, and PostgreSQL. All SaaS source files migrated from `SqlitePool` to `AnyPool`.

---

## [0.2.8] - 2026-05-11

### Added
- **Linux client for s390x (IBM Z / LinuxONE)** — `scmclient` is now built and packaged (deb + rpm) for `s390x-unknown-linux-gnu`. The server is not yet supported on s390x.
- **Linux client for LoongArch64** — `scmclient` is now built and packaged (deb + rpm) for `loongarch64-unknown-linux-musl`, targeting LoongArch-based servers.
- **Linux client for i686 (32-bit x86)** — `scmclient` is now built and packaged (deb + rpm) for `i686-unknown-linux-musl`, covering legacy 32-bit x86 servers.

### Internal
- **Source code documentation** — all 15 `scmserver` source files now carry a file-level description header and a per-function banner documenting the HTTP route, purpose, and minimum required role. No behaviour change.

---

## [0.2.7] - 2026-05-10

### Fixed
- **NA results rendered as FAIL in PDF reports** — the per-rule breakdown in PDF exports showed NA results in red with "FAIL" text. They now render in grey with "NA" text, matching the on-screen report view.
- **`is_passed` verdict incorrect for saved reports** — when saving a report, the system pass/fail verdict is now consistent with the live policy report view: a system is compliant only when it has no FAIL results **and** at least one PASS. Systems where every test returned NA are correctly marked as non-compliant.
- **Admin Settings save silently discarded for tenants without pre-seeded rows** — the settings save handler used `UPDATE`, which affects 0 rows when no settings exist yet (e.g. new SaaS tenants). Changed to `INSERT … ON CONFLICT DO UPDATE` so settings are always written regardless of whether rows pre-exist.
- **Windows installer missing Organization field** — the custom installer page only asked for Server URL and hardcoded `Organization = default`. SaaS users had to manually edit the registry after installation. The installer now asks for both Server URL and Organization, pre-filled from the existing registry values on upgrade.

---

## [0.2.6] - 2026-05-07

### Added
- **Superuser role** — new role level above Admin that grants access to platform-level tenant management. The initial admin user is automatically promoted to Superuser on first EE/SaaS startup. Superuser can be assigned to other users via the Users page.
- **Tenant management (EE/SaaS)** — Superusers can list, create, view, suspend, activate, and delete tenants via the new Platform Admin section in the sidebar. The `default` and `platform` tenants are protected from suspension or deletion.
- **Organization field on EE login page** — multi-tenant users can now specify their organization at login. Leaving the field blank logs in as a platform-level (Superuser) account.
- **Tenant user management (EE/SaaS)** — Superusers can add new users to a tenant, edit their name/email/role, reset their password, and delete them — all from the tenant detail page via inline modals. No separate pages required.
- **SMTP email relay (CE/EE/SaaS)** — Admin Settings now has an Email tab for configuring an SMTP relay (host, port, TLS mode, credentials, from address, app URL). In SaaS, if SMTP is configured new users must verify their email before logging in; if not configured, accounts are activated immediately. Replaces the previous Resend API key approach.
- **Bootstrap admin protection** — the initial admin account (id=1, default tenant) is now protected from role changes at three layers: the edit UI shows a disabled lock icon, the server always preserves the DB role regardless of submitted form data, and a SQLite trigger (`protect_bootstrap_admin_role`) raises an abort if any code path attempts a direct update. Schema migration v8→v9 adds the trigger to existing installations.
- **Clean Database action** — Superusers can permanently delete all operational data (systems, groups, tests, policies, reports, scan results, users) while preserving the admin account, settings, SMTP configuration, and signing keys. Requires typing `RESET` to confirm. Located in the new **Danger Zone** tab in Admin Settings.
- **Danger Zone tab in Settings** — Superuser-only tab that consolidates destructive actions, replacing the previous card appended at the bottom of the page.
- **Plan field on tenants (EE/SaaS)** — tenants now have a `plan` field (`free`, `starter`, `pro`, `enterprise`) used by EE/SaaS to enforce per-plan resource limits. CE is unaffected.
- **Platform Admin → Plans page (EE/SaaS)** — Superusers can configure the maximum number of systems, groups, policies, and reports per plan. Zero means unlimited. Accessible from the Platform Admin sidebar section.
- **Plan limit display on dashboard (SaaS)** — the Active Inventory, Active Policies, and Scan Reports info boxes now show the current count alongside the plan limit (e.g. "5 of 25"). Displays "Unlimited" when the plan limit is set to 0. Invisible in CE where the `plan_limits` table is absent.

### Fixed
- **SMTP settings are now global** — SMTP configuration (`smtp_*` keys and `app_url`) is always read from and written to the `default` tenant, regardless of which tenant the logged-in user belongs to. This fixes support ticket and verification emails in SaaS where the platform admin (in the `platform` tenant) previously saved settings that `Mailer` could not find.
- **Account locked out if verification email fails (SaaS)** — if SMTP is configured but the verification email cannot be delivered, the account is immediately activated so the user can still log in. A clear message is shown on the login page explaining what happened.
- **NA results counted as failures in policy report view** — when saving a report, any NA result incorrectly flipped the system verdict to Non-Compliant. Only explicit FAIL results now affect the verdict.
- **NA results counted as violations in policy PDF report** — the violation count in the PDF summary used `total − PASS`, which included NA. It now counts only FAIL results. NA tests also now render as grey "N/A" in the per-rule breakdown instead of red "FAIL".
- **ARM7 deb packages missing from releases** — the CI build workflow used `ARCH=arm7` which is not a valid dpkg architecture. Fixed to `ARCH=armhf` so `.deb` packages are correctly built and published for ARMv7.
- **Superuser role rejected when adding a new user** — the server-side role allowlist was missing `superuser`, causing the form submission to return "Invalid role selected" even for a legitimate value.
- **Role descriptions missing in user edit form** — the role dropdown in the edit form now shows the same human-readable labels as the add form (e.g. "Administrator (Full System Access)"). Role select width also increased to 340 px so full descriptions are visible.

---

## [0.2.5] - 2026-05-05

### Added
- **System compliance report snapshots** — save and download (PDF) archived compliance reports per system. The Reports page now has two tabs: Policy Reports and System Reports.
- **Policy coverage list in system report** — the system header card now shows a collapsible "View Policy Coverage" section listing all policies the system is under, with their descriptions. Mirrors the "View Policy Scope" section in the policy report.
- **Policy description in system report cards** — each per-policy card in the system report shows the policy description below the test table when one is set.
- **PDF download from live system report** — a "Download PDF" button is now available on the live system compliance report page, matching the existing button on the live policy report. The PDF includes policy descriptions.
- **"View Live Report" button on saved report pages** — archived policy and system report snapshots now include a "View Live Report" button linking back to the current live report. If the policy or system has since been deleted, the button is replaced with a greyed-out "Policy Deleted" / "System Deleted" badge.

### Fixed
- **Database indexes not applied on existing installs** — the 11 composite indexes added in v0.2.3 were only created by the first-run installer, so upgraded installs never received them. They are now applied via the v6→v7 migration on the next server startup.
- **Post-save redirect** — saving a compliance report (policy or system) now returns to the same live report page with a success banner, instead of redirecting away to the Reports list or Policies list.
- **Offline row dimming no longer greys action buttons** — in the Systems table, the opacity/greyscale effect now applies only to data cells; the action buttons in the last column stay fully opaque and remain clickable.
- **Dashboard report count includes system reports** — the Reports counter on the dashboard now sums both policy reports and system compliance report snapshots.
- **Fresh install unnecessarily ran all migrations** — a new installation stamped `schema_info` at version 0, causing all 7 migrations to execute on first startup. Fresh installs now stamp the current schema version directly so no migrations are needed.
- **Navigating to a deleted system or policy report now redirects gracefully** — previously returned a blank 404; now redirects to the Systems or Policies list with a "not found" error banner.
- **Consistent report action buttons** — all four report pages (live policy, live system, archived policy, archived system) now use identical button labels, icons, colours, and order: Back · Download PDF · Save Report · View Live Report.
- **PDF cell padding** — all table cells in every PDF report now have uniform padding so text no longer touches the cell border lines.
- **PDF disclaimer page** — all PDF reports (live policy, archived policy, live system, archived system) now end with the disclaimer on its own dedicated last page, at font size 10, prefixed with "Note:".

---

## [0.2.4] - 2026-05-04

### Fixed
- **v0.2.2 clients rejected with 401 after server upgrade to v0.2.3** — the signature verification function re-serialized the deserialized payload struct before checking the signature. When a v0.2.2 client sent the wire field as `tenant_id`, the server deserialized it into the renamed `organization` field and re-serialized it back — producing different JSON bytes from what the client had signed, causing every pre-v0.2.3 client to be rejected. Fixed by verifying signatures against the raw received JSON bytes rather than a re-serialized struct. All client versions are now accepted by the same server.
- **FreeBSD service stops silently after crash** — the RC script now uses `daemon -r -R 10` so the service automatically restarts after any unexpected exit with a 10-second cooldown. Previously a single crash would leave the service permanently stopped with no indication.
- **FreeBSD agent exits when local IP cannot be determined** — a failed `local_ip_address` lookup no longer aborts the heartbeat cycle. The agent logs a warning and continues with `0.0.0.0`, allowing it to keep running when the network interface is temporarily unavailable.

---

## [0.2.3] - 2026-05-03

### Added
- **CMD enabled warning** — scmclient logs a warning at startup when `cmd_enabled = true` to alert operators that the client will execute commands received from the server.

### Changed
- **`tenant_id` renamed to `organization`** — the client config field, Windows registry key, and wire protocol now use `organization` instead of `tenant_id`, aligning with standard terminology. The server accepts both names for backward compatibility with older clients. Existing config files and registry entries are migrated automatically on first run.
- **Self-healing config on every startup** — the client normalizes and rewrites its config on every startup. Missing settings are filled in with defaults, stale or renamed keys are removed, and legacy field names are rewritten in canonical form. Upgraded clients will automatically gain any new settings added in future releases.

### Fixed
- **CMD element captures stderr** — commands that write to stderr instead of stdout (e.g. macOS `softwareupdate`) now evaluate correctly against OUTPUT conditions. Previously they always returned False.
- **Policy verdict when all tests are NA** — a policy where every test returned NA (e.g. no applicable OS tests, or `cmd_enabled = false`) previously showed as COMPLIANT / PASSED. It now correctly shows as NOT APPLICABLE with a grey badge.

### Performance
- **Database indexes** — 11 composite indexes added covering the most frequent query patterns (results by tenant/test, systems by tenant/status/score, compliance history, notifications, reports). Existing installs gain the indexes automatically on first startup with no migration required.
- **SQLite WAL mode** — server now opens the database with WAL journal mode, `synchronous=Normal`, and a 5-second busy timeout. Readers no longer block writers, write throughput improves, and concurrent requests queue instead of returning an immediate busy error.

### SaaS
- **`[email]` config section** — new optional config block (`resend_api_key`, `from_address`, `app_url`) used by the SaaS edition for transactional email. CE and EE ignore it entirely.
- **`email_verified` user flag** — schema migration v5→v6 adds `email_verified` column to the users table (default `1` for all existing CE/EE users). The SaaS edition uses this to gate login until the user's email address is confirmed.

### Build
- Windows installer filename no longer includes the redundant `windows` label — e.g. `scmclient-0.2.3-1-x86_64.exe`.
- GitHub Actions workflow changed from draft to published release.

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
