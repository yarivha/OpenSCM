#!/usr/bin/env bash
# distribute.sh — Download a GitHub release, sign packages, and populate the local repo
#
# Usage:
#   ./distribute.sh <tag> [stable|testing]
#
# Examples:
#   ./distribute.sh v0.2.2
#   ./distribute.sh v0.2.2 testing

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
ok()      { echo -e "    ${GREEN}✓${RESET} $*"; }
warn()    { echo -e "    ${YELLOW}!${RESET} $*"; }
die()     { echo -e "${RED}Error:${RESET} $*" >&2; exit 1; }

# ── Arguments ─────────────────────────────────────────────────────────────────
TAG="${1:-}"
STAGE="${2:-stable}"

[[ -n "$TAG" ]]                      || die "Usage: $0 <tag> [stable|testing]"
[[ "$STAGE" == "stable" || "$STAGE" == "testing" ]] \
                                     || die "Stage must be 'stable' or 'testing'"

GITHUB_REPO="yarivha/OpenSCM"
REPO_BASE="/repo/openscm/${STAGE}"
GPG_KEY="OpenSCM <support@openscm.io>"

# ── Dependency check ──────────────────────────────────────────────────────────
for cmd in curl jq gpg rpmsign createrepo reprepro repo-add; do
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' not found — please install it first"
done

# ── Repo directories ──────────────────────────────────────────────────────────
mkdir -p \
    "$REPO_BASE/debian" \
    "$REPO_BASE/redhat" \
    "$REPO_BASE/arch" \
    "$REPO_BASE/freebsd" \
    "$REPO_BASE/macos" \
    "$REPO_BASE/windows"

# ── Download ──────────────────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

info "Downloading release assets for ${TAG} (${STAGE})..."

API_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/tags/${TAG}"
RELEASE_JSON=$(curl -fsSL "$API_URL") \
    || die "Failed to fetch release info for $TAG — check tag name and network"

mapfile -t ASSET_URLS < <(echo "$RELEASE_JSON" | jq -r '.assets[].browser_download_url')
[[ ${#ASSET_URLS[@]} -gt 0 ]] || die "No assets found for tag $TAG"
echo "    Found ${#ASSET_URLS[@]} asset(s)"

for url in "${ASSET_URLS[@]}"; do
    name=$(basename "$url")
    echo "    Downloading ${name}..."
    curl -fsSL -o "$WORK_DIR/$name" "$url"
done

# ── Process each asset ────────────────────────────────────────────────────────
info "Processing assets..."

RPM_ADDED=0
ARCH_ADDED=0

for file in "$WORK_DIR"/*; do
    name=$(basename "$file")
    echo -e "\n  ${BOLD}${name}${RESET}"

    case "$name" in

        # ── Debian package ────────────────────────────────────────────────────
        *.deb)
            reprepro -b "$REPO_BASE/debian" includedeb "$STAGE" "$file"
            ok "Added to Debian repo ($STAGE)"
            ;;

        # ── RPM package ───────────────────────────────────────────────────────
        *.rpm)
            rpmsign --addsign --key-id="$GPG_KEY" "$file"
            cp "$file" "$REPO_BASE/redhat/"
            ok "Signed and copied to RedHat repo"
            RPM_ADDED=1
            ;;

        # ── Arch Linux package ────────────────────────────────────────────────
        *.pkg.tar.zst)
            gpg --default-key "$GPG_KEY" --armor --detach-sign \
                --output "${file}.sig" "$file"
            cp "$file"          "$REPO_BASE/arch/"
            cp "${file}.sig"    "$REPO_BASE/arch/"
            ok "Signed and copied to Arch repo"
            ARCH_ADDED=1
            ;;

        # ── FreeBSD package ───────────────────────────────────────────────────
        *-freebsd-*.pkg)
            cp "$file" "$REPO_BASE/freebsd/"
            ok "Copied to FreeBSD repo"
            ;;

        # ── macOS package ─────────────────────────────────────────────────────
        *_macos.pkg)
            cp "$file" "$REPO_BASE/macos/"
            ok "Copied to macOS repo"
            ;;

        # ── Windows installer ─────────────────────────────────────────────────
        *.exe)
            cp "$file" "$REPO_BASE/windows/"
            ok "Copied to Windows repo"
            ;;

        *)
            warn "Skipped (unknown type)"
            ;;
    esac
done

# ── Post-processing ───────────────────────────────────────────────────────────

# Rebuild RPM repo metadata and sign repomd.xml
if [[ $RPM_ADDED -eq 1 ]]; then
    echo
    info "Updating RedHat repo metadata..."
    createrepo --update "$REPO_BASE/redhat/"
    gpg --default-key "$GPG_KEY" --armor --detach-sign \
        --output "$REPO_BASE/redhat/repodata/repomd.xml.asc" \
        "$REPO_BASE/redhat/repodata/repomd.xml"
    ok "repomd.xml updated and signed"
fi

# Rebuild Arch repo database
if [[ $ARCH_ADDED -eq 1 ]]; then
    echo
    info "Updating Arch repo database..."
    repo-add --sign --key "$GPG_KEY" \
        "$REPO_BASE/arch/openscm.db.tar.gz" \
        "$REPO_BASE/arch/"*.pkg.tar.zst
    ok "openscm.db updated"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo
info "All done — ${TAG} distributed to ${REPO_BASE}"
