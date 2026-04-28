# Changelog

All notable changes to OpenSCM are documented here.

## [0.1.8] - 2026-04-28

### Added
- **CMD element** — new test element type that runs a shell command and evaluates its output against a string condition. Disabled by default; opt in with `cmd_enabled = true` in server config so admins explicitly permit command execution on agents.
- **Username duplicate check** — creating a user now fails with a clear error if the username is already taken.

### Changed
- `scmserver` refactored into a library crate (`lib.rs`) with a thin `main.rs` entry point, enabling the Enterprise Edition binary to depend on it directly.
- CMD element output field renamed from `stdout` to `output`.

### Fixed
- Package existence check on Debian/Ubuntu now inspects dpkg output text instead of exit code (exit code is always 0, masking uninstalled packages).

---

## [0.1.7]

### Added
- Arch Linux agent support — `pacman` backend for `check_package_exists` and `get_package_version`.
- Arch Linux packaging: `.pkg.tar.zst` for x86_64, aarch64, and armv7h.
- Report scheduling — `schedule_type` column in `policy_schedules`; one scan schedule and one report schedule per policy enforced by `UNIQUE(policy_id, schedule_type)`.
- Schema migration v3.

### Fixed
- All-NA systems no longer return 100% compliance — compliance score returns -1 (Not Scanned) when all results are NA.
- Package existence check on Debian/Ubuntu (exit code vs. output string).

---

## [0.1.6]

### Added
- Full NA support throughout: `EvalResult` enum, compliance scoring, and UI indicators.
- Applicability conditions — `test_conditions` table, condition editor UI, and agent-side evaluation.
- Schema migration system (`schema_info` table, version-gated migrations).

### Fixed
- CPU spike when running file content checks against directories.
- Compliance score denominator now correctly excludes NA results.

---

## [0.1.5]

### Added
- Linux ARMv7 client support.
- macOS universal binary.
- Export options (PDF, Excel, CSV) in the Tests table.

### Fixed
- Compliance recalculation correctness fixes.
