#!/usr/bin/env bash
# Build cursor-revoke packages (.deb, .rpm and Arch) with nfpm.
#
#   packaging/build.sh          stage the files, fetch nfpm if needed, build into dist/
#   packaging/build.sh stage    only create dist/stage/ (no network, no nfpm)
#
# The version is read from __version__ in cursor_revoke.py. Override the output
# folder with DIST=<dir> (only cursor-revoke* files in it are replaced) and the
# nfpm binary with NFPM=<path>.
set -euo pipefail

# Pinned nfpm release used when nfpm is not already on PATH.
NFPM_VERSION="2.47.0"
NFPM_TGZ="nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
NFPM_URL="${NFPM_URL:-https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/${NFPM_TGZ}}"
NFPM_SHA256="${NFPM_SHA256:-0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Resolve DIST to an absolute path: nfpm runs from inside the stage folder.
mkdir -p "${DIST:-$root/dist}"
dist="$(cd "${DIST:-$root/dist}" && pwd)"
stage="$dist/stage"

fail() { echo "build.sh: $*" >&2; exit 1; }

version() {
    local v
    v="$(sed -n 's/^__version__ = "\([^"]*\)"$/\1/p' "$root/cursor_revoke.py")"
    [ -n "$v" ] || fail "could not read __version__ from cursor_revoke.py"
    echo "$v"
}

put() {   # put <repo file> <path inside the package> <mode>
    [ -f "$root/$1" ] || fail "missing source file $1"
    install -D -m "$3" "$root/$1" "$stage$2"
}

do_stage() {
    local v f
    v="$(version)"
    # Check every input before touching dist/, so a failure leaves no half-staged tree.
    for f in cursor_revoke.py assets/logo.svg README.md CHANGELOG.md LICENSE packaging/cursor-revoke.desktop.in \
             packaging/cursor-revoke-audit.service.in packaging/cursor-revoke-audit.timer; do
        [ -f "$root/$f" ] || fail "missing source file $f"
    done
    rm -rf "$stage"
    put cursor_revoke.py /usr/bin/cursor-revoke 755
    put assets/logo.svg /usr/share/icons/hicolor/scalable/apps/cursor-revoke.svg 644
    put README.md /usr/share/doc/cursor-revoke/README.md 644
    put CHANGELOG.md /usr/share/doc/cursor-revoke/CHANGELOG.md 644
    put LICENSE /usr/share/doc/cursor-revoke/LICENSE 644
    put LICENSE /usr/share/doc/cursor-revoke/copyright 644     # the name Debian policy expects
    # A package cannot pick a terminal emulator at install time the way
    # install.sh does, so the desktop's default terminal is used.
    install -d -m 755 "$stage/usr/share/applications"
    sed -e 's|^Exec=.*|Exec=cursor-revoke --pause|' -e 's|^Terminal=false$|Terminal=true|' \
        "$root/packaging/cursor-revoke.desktop.in" > "$stage/usr/share/applications/cursor-revoke.desktop"
    chmod 644 "$stage/usr/share/applications/cursor-revoke.desktop"
    # systemd user units for the scheduled audit (off until the user enables them)
    install -d -m 755 "$stage/usr/lib/systemd/user"
    put packaging/cursor-revoke-audit.timer /usr/lib/systemd/user/cursor-revoke-audit.timer 644
    sed -e 's|@BIN@|/usr/bin/cursor-revoke|' "$root/packaging/cursor-revoke-audit.service.in" \
        > "$stage/usr/lib/systemd/user/cursor-revoke-audit.service"
    chmod 644 "$stage/usr/lib/systemd/user/cursor-revoke-audit.service"
    echo "staged $v in $stage"
}

find_nfpm() {
    if [ -n "${NFPM:-}" ]; then          # explicit binary (tests use a stub here)
        [ -x "$NFPM" ] || fail "NFPM=$NFPM is not executable"
        echo "$NFPM"
        return
    fi
    if command -v nfpm >/dev/null 2>&1; then
        command -v nfpm
        return
    fi
    local bin="$dist/tools/nfpm" tgz="$dist/tools/$NFPM_TGZ"
    if [ ! -x "$bin" ]; then
        [ "$(uname -m)" = "x86_64" ] || fail "no pinned nfpm for $(uname -m): install nfpm (https://nfpm.goreleaser.com) and re-run"
        mkdir -p "$dist/tools"
        echo "downloading nfpm $NFPM_VERSION" >&2
        curl -sSfL -o "$tgz" "$NFPM_URL"
        if ! echo "$NFPM_SHA256  $tgz" | sha256sum -c --status -; then
            rm -f "$tgz"
            fail "nfpm download does not match the pinned checksum, aborting"
        fi
        tar -xzf "$tgz" -C "$dist/tools" nfpm
        rm -f "$tgz"
    fi
    echo "$bin"
}

do_build() {
    do_stage
    local nfpm v
    nfpm="$(find_nfpm)"
    v="$(version)"
    # Only our own packages are replaced; DIST may hold other people's files.
    rm -f "$dist"/cursor-revoke*.deb "$dist"/cursor-revoke*.rpm "$dist"/cursor-revoke*.pkg.tar.zst "$dist/SHA256SUMS"
    for packager in deb rpm archlinux; do
        (cd "$stage" && VERSION="$v" "$nfpm" package --config "$root/packaging/nfpm.yaml" \
            --packager "$packager" --target "$dist/")
    done
    (cd "$dist" && sha256sum cursor-revoke*.deb cursor-revoke*.rpm cursor-revoke*.pkg.tar.zst > SHA256SUMS)
    echo
    echo "Packages in $dist:"
    (cd "$dist" && ls -1 cursor-revoke*.deb cursor-revoke*.rpm cursor-revoke*.pkg.tar.zst SHA256SUMS | sed 's|^|  |')
}

case "${1:-build}" in
    stage) do_stage ;;
    build) do_build ;;
    *) echo "usage: $0 [stage|build]" >&2; exit 2 ;;
esac
