set positional-arguments

# chat's version, chat-tui's: the release binaries', which their lists of builds and /update go by.
# chat-core has a version of its own. Each crate has its CHANGELOG.md, which its releases take their
# notes from; /changelog shows chat-tui's.
version := `sed -n 's/^version = "\(.*\)"$/\1/p' chat-tui/Cargo.toml | head -n 1`
# The binaries a release publishes (`just dist` puts them in dist/). Each carries the signed list
# of builds peers check its build against, which names 3 at most, all "v" holds: BUILDS for Linux
# and Windows, BUILDS-macos for the Macs.
pc_binaries := "chat-linux-x86_64 chat-windows-x86_64.exe"
mac_binaries := "chat-macos-aarch64 chat-macos-x86_64"
binaries := pc_binaries + " " + mac_binaries

# Each crate's own recipes: `just core::interop`, `just tui::demo`, and so on
mod core 'chat-core'
mod tui 'chat-tui'

# List recipes
default:
    @just --list --unsorted --list-submodules

# Build every crate: debug (default), release, or dist
[group('build')]
build profile="debug":
    #!/bin/sh
    set -eu
    case "$1" in
        debug) cargo build --workspace ;;
        release) cargo build --workspace --release ;;
        dist) cargo build --workspace --profile dist ;;
        *) echo "just build takes debug, release, or dist, not $1" >&2; exit 1 ;;
    esac

# Fast type-check of every crate, without code generation
[group('build')]
check:
    cargo check --workspace --all-targets

# Every crate's tests
[group('test')]
test *args:
    cargo test --workspace "$@"

# Formatting, then clippy with warnings as errors, across every crate
[group('test')]
lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

# Format every crate
[group('test')]
fmt:
    cargo fmt --all

# ---------------------------------------------------------------------------------------------
# Release

# Make the release signing key, or with backup its backup
[group('release')]
keygen which="":
    #!/bin/sh
    set -eu
    case "${1:-}" in
        "") pub=keys/minisign.pub; key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}" ;;
        backup) pub=keys/minisign-backup.pub; key="${CHAT_BACKUP_SIGNING_KEY:-$HOME/.minisign/chat-release-backup.key}" ;;
        *) echo "just keygen takes nothing, or backup" >&2; exit 1 ;;
    esac
    if [ -e "$pub" ] || [ -e "$key" ]; then echo "$pub or $key already exists" >&2; exit 1; fi
    mkdir -p "$(dirname "$key")" keys
    minisign -G -p "$pub" -s "$key"
    echo "commit $pub, put it in chat-core's minisign.rs, and back up $key somewhere safe${1:+, apart from the release key}"

# Which public key signed file (keys/minisign.pub, or keys/minisign-backup.pub), or fails if neither did
_signed-by file:
    #!/bin/sh
    set -eu
    for pub in keys/minisign.pub keys/minisign-backup.pub; do
        if [ -e "$pub" ] && minisign -Vq -p "$pub" -m "$1" >/dev/null 2>&1; then echo "$pub"; exit 0; fi
    done
    echo "$1 isn't signed with keys/minisign.pub's key or keys/minisign-backup.pub's" >&2
    exit 1

# Needs the targets and cargo-zigbuild (see README.md).
# Put standalone release binaries and SHA256SUMS in dist/
[group('release')]
dist:
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    rm -rf dist
    for f in {{binaries}}; do "$just" _dist-build "$f"; done
    "$just" _dist-lists
    echo "dist/ ready for v{{version}}"

# The Publish workflow writes them from the binaries the Build workflow made.
# Write SHA256SUMS, BUILDS and BUILDS-macos for the binaries in dist/
_dist-lists:
    #!/bin/sh
    set -eu
    (cd dist && sha256sum {{binaries}} > SHA256SUMS)
    (cd dist && { echo "chat v{{version}}"; sha256sum {{pc_binaries}} | cut -c1-64; } > BUILDS)
    (cd dist && { echo "chat v{{version}}"; sha256sum {{mac_binaries}} | cut -c1-64; } > BUILDS-macos)
    for l in BUILDS BUILDS-macos; do
        test "$(wc -l < "dist/$l")" -le 4 || { echo "$l names more than 3 binaries, all peers' list holds" >&2; exit 1; }
    done

# Paths in the binaries name no folder of this machine's, and the build stamp says when the commit
# was made (SOURCE_DATE_EPOCH), so building the same commit again, anywhere, with the same Rust and
# zig, gives the same binaries. The Build workflow builds each in a job of its own.
# Build release binary NAME, one of binaries, into dist/
_dist-build name:
    #!/bin/sh
    set -eu
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
    RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=cargo"
    export SOURCE_DATE_EPOCH RUSTFLAGS
    case "$1" in
        chat-linux-x86_64) target=x86_64-unknown-linux-musl bin=chat ;;
        chat-windows-x86_64.exe) target=x86_64-pc-windows-gnu bin=chat.exe ;;
        chat-macos-aarch64) target=aarch64-apple-darwin bin=chat ;;
        chat-macos-x86_64) target=x86_64-apple-darwin bin=chat ;;
        *) echo "no release binary $1 - binaries are {{binaries}}" >&2; exit 1 ;;
    esac
    case "$target" in
        # zig has no Apple SDK, so the frameworks a crate links come from macos-sdk/: stubs that only
        # say where each is on a Mac, since chat uses none of their symbols. They run on macOS 11 on.
        # -S keeps debug info out at link time: the linker hashes its output into the binary's UUID,
        # and the debug info names each object file's path and modification time, which no two
        # builds share.
        *-apple-darwin)
            export MACOSX_DEPLOYMENT_TARGET=11.0
            RUSTFLAGS="$RUSTFLAGS -C link-arg=-F$PWD/macos-sdk/System/Library/Frameworks -C link-arg=-Wl,-S"
            ;;
    esac
    cargo zigbuild --locked -p chat-tui --profile dist --target "$target"
    mkdir -p dist
    cp "target/$target/dist/$bin" "dist/$1"

# A published binary's SHA-256 without the list of builds its release appended to it, which is
# the hash `just dist` gives for the same commit
_core-hash file:
    #!/bin/sh
    set -eu
    size=$(wc -c < "$1")
    if [ "$(tail -c 8 "$1")" = CHATBLD1 ]; then
        len=$(tail -c 16 "$1" | head -c 8 | sed 's/^0*//')
        size=$((size - 16 - ${len:-0}))
    fi
    head -c "$size" "$1" | sha256sum | cut -c1-64

# Check out vVERSION first. The binaries GitHub has should be the ones built here, apart from the
# list appended to them, or someone changed them, or the build isn't reproducible yet.
# Build release VERSION again from its tag and compare it with the published binaries
[group('release')]
reproduce version:
    #!/bin/sh
    set -eu
    v="${1#v}"
    just={{quote(just_executable())}}
    test "$(git rev-parse HEAD)" = "$(git rev-parse "v$v^{commit}")" || { echo "HEAD isn't v$v - git checkout v$v first" >&2; exit 1; }
    test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }
    "$just" dist
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    same=1
    for f in {{binaries}}; do
        curl -fsSL -o "$dir/$f" "https://github.com/chat-labs/chat/releases/download/v$v/$f"
        mine=$(sha256sum < "dist/$f" | cut -c1-64)
        theirs=$("$just" _core-hash "$dir/$f")
        if [ "$mine" = "$theirs" ]; then echo "$f: the same ($mine)"; else echo "$f: DIFFERENT - built here $mine, published $theirs"; same=0; fi
    done
    test "$same" = 1

# What chat's updater checks before it installs a release, checked here from outside: GitHub's
# copy of SHA256SUMS signed with keys/minisign.pub's key (or the backup's) as chat vVERSION's, and
# each binary as published matching it.
# Check release VERSION's signature and binaries as GitHub has them
[group('release')]
verify version:
    #!/bin/sh
    set -eu
    v="${1#v}"
    just={{quote(just_executable())}}
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    for f in {{binaries}} SHA256SUMS SHA256SUMS.minisig; do
        curl -fsSL -o "$dir/$f" "https://github.com/chat-labs/chat/releases/download/v$v/$f"
    done
    pub=$("$just" _signed-by "$dir/SHA256SUMS")
    minisign -V -p "$pub" -m "$dir/SHA256SUMS" | grep -qx "Trusted comment: chat v$v" \
        || { echo "SHA256SUMS is signed, but not as chat v$v's" >&2; exit 1; }
    (cd "$dir" && sha256sum -c SHA256SUMS)
    echo "v$v: SHA256SUMS is signed with $pub's key, and the binaries match it"

# Peers send each other this list to check each other's builds with, so it may name 3 binaries at
# most. chat reads it from its own end: the list, its signature line, then the length of both in 8
# digits and CHATBLD1.
# Append LIST, signed (LIST.minisig), to the binaries it names, in a folder
_append-list dir list +files:
    #!/bin/sh
    set -eu
    cd "$1"
    list="$2"
    shift 2
    test "$(wc -l < "$list")" -le 4 || { echo "$list names more than 3 binaries" >&2; exit 1; }
    sig=$(sed -n 2p "$list.minisig")
    len=$(( $(wc -c < "$list") + ${#sig} + 1 ))
    for f in "$@"; do
        { cat "$list"; printf '%s\n%08dCHATBLD1' "$sig" "$len"; } >> "$f"
    done

# chat-core and chat-tui are released apart, each with its own version, changelog and tags: chat
# (chat-tui) as vVERSION, with the binaries, and chat-core as chat-core-vVERSION, with none. Either
# way it's a GitHub release titled "Release YYYYMMDD" that opens with both crates' versions, and a
# chat-core release is never GitHub's latest, which /update installs.
#
# The lines each release recipe starts with: its CRATE checked, and that crate's Cargo.toml,
# changelog and tag prefix.
crate_sh := '''
    case "$1" in tui|core) ;; *) echo "a release is of tui or core, not $1" >&2; exit 1 ;; esac
    c="$1"
    toml="chat-$1/Cargo.toml"
    log="chat-$1/CHANGELOG.md"
    if [ "$1" = tui ]; then tag=v; else tag=chat-core-v; fi
    crate_version() { sed -n 's/^version = "\(.*\)"$/\1/p' "$toml" | head -n 1; }
    base_version() { crate_version | sed 's/-.*//'; }
    published() { gh release view "$tag$1" >/dev/null 2>&1; }
'''

# What preparing and publishing a release need: a clean tree, and gh, to see what's published
_can-release:
    #!/bin/sh
    set -eu
    test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }
    gh auth status >/dev/null 2>&1 || { echo "gh isn't logged in - run gh auth login" >&2; exit 1; }

# CRATE's version, and Cargo.lock's record of it
_set-version crate version:
    #!/bin/sh
    set -eu
    {{crate_sh}}
    sed "s/^version = \".*\"\$/version = \"$2\"/" "$toml" > "$toml.tmp"
    mv "$toml.tmp" "$toml"
    cargo update --workspace --offline -q

#   just prepare tui patch          the patch after chat's last release, 0.6.0 -> 0.6.1
#   just prepare core minor         the minor after chat-core's, 0.1.0 -> 0.2.0
#   just prepare CRATE major        the major after it, 0.6.0 -> 1.0.0
#   just prepare CRATE              the version in its Cargo.toml without its pre-release, which
#                                   finishes its betas, or the patch after it once that one is out
#   just prepare CRATE 1.0.0        another version
#   just prepare CRATE beta [KIND]  a beta of the version just prepare CRATE KIND would get ready,
#                                   see _prepare-beta
# Gets the sections at the top of CRATE's changelog, "## Unreleased" and those of the betas (and
# pre-releases) since its last release, ready to release as VERSION: they become one
# "## VERSION" (see _fold-changelog), and its Cargo.toml gets the version. Betas of another
# version are folded in too, so a cycle of 0.6.1 betas can come out as 0.7.0. It prints the tag and
# commits nothing: the Prepare release workflow runs it and opens the release's pull request, and
# once that's merged, the Publish workflow publishes it when an admin approves.
# Get CRATE (tui or core) ready for a release: patch, minor, major, or beta [KIND]
[group('release')]
prepare crate what="" *args: _can-release
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    {{crate_sh}}
    shift
    if [ "${1:-}" = beta ]; then
        shift
        if [ $# -gt 1 ]; then echo "just prepare $c beta takes patch, minor, major or a version, not $*" >&2; exit 1; fi
        exec "$just" _prepare-beta "$c" "$@"
    fi
    if [ $# -gt 1 ]; then echo "just prepare $c takes patch, minor, major, beta or a version, not $*" >&2; exit 1; fi
    pending() { awk '/^## [0-9]+\.[0-9]+\.[0-9]+$/ { exit } /^## / { printf "%s%s", (n++ ? ", " : ""), substr($0, 4) }' "$log"; }
    v=$("$just" _next-version "$c" "${1:-}")
    echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || { echo "not a version: $v (want patch, minor, major or MAJOR.MINOR.PATCH)" >&2; exit 1; }
    if published "$v"; then echo "release $tag$v is already published" >&2; exit 1; fi
    older=$(printf '%s\n%s\n' "$v" "$(base_version)" | sort -V | head -n 1)
    if [ "$older" = "$v" ] && [ "$v" != "$(base_version)" ]; then
        echo "$tag$v is older than $(base_version), the version in $toml" >&2; exit 1
    fi
    test -n "$(pending)" || { echo "$log has no Unreleased or beta section to release" >&2; exit 1; }
    if git rev-parse -q --verify "refs/tags/$tag$v" >/dev/null; then
        echo "tag $tag$v already exists, but $log still has $(pending) above it" >&2; exit 1
    fi
    if grep -q "^## $v\$" "$log"; then echo "$log already has a section for $v" >&2; exit 1; fi
    awk '/^## [0-9]+\.[0-9]+\.[0-9]+$/ { exit } /^## / { on = 1; next } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
        "$log" || { echo "$log's $(pending) has nothing in it" >&2; exit 1; }
    echo "getting $log's $(pending) ready as $tag$v" >&2
    "$just" _fold-changelog "$c" "$v"
    "$just" _set-version "$c" "$v"
    echo "$tag$v"

# A beta is for testers: tagged as its release would be, with -beta.N, and published as one, but
# as a GitHub pre-release, which /update only installs with betas on (/set betas on). Testers turn
# that on or download it, and /update takes them on to VERSION once it's released. Releasing
# VERSION, or one after it, deletes the betas' GitHub releases, but not their tags. VERSION is
# the one `just prepare CRATE KIND` would get ready (see _next-version), so with no KIND it's the
# betas' own, and N counts up from 1 (or picks up a beta whose publishing failed). "## Unreleased"
# becomes "## VERSION-beta.N" and the crate's Cargo.toml gets VERSION-beta.N.
# Get CRATE ready for a beta of its next release, or of KIND's
_prepare-beta crate kind="":
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    {{crate_sh}}
    base=$("$just" _next-version "$c" "${2:-}")
    echo "$base" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || { echo "not a version: $base (want patch, minor, major or MAJOR.MINOR.PATCH)" >&2; exit 1; }
    if published "$base"; then echo "$tag$base is already released" >&2; exit 1; fi
    older=$(printf '%s\n%s\n' "$base" "$(base_version)" | sort -V | head -n 1)
    if [ "$older" = "$base" ] && [ "$base" != "$(base_version)" ]; then
        echo "$tag$base is older than $(base_version), the version in $toml" >&2; exit 1
    fi
    n=0
    for t in $(git tag -l "$tag$base-beta.*"); do
        m=${t#"$tag$base-beta."}
        case "$m" in ''|*[!0-9]*) continue ;; esac
        if [ "$m" -gt "$n" ]; then n=$m; fi
    done
    if [ "$n" -eq 0 ] || published "$base-beta.$n"; then n=$((n + 1)); fi
    v="$base-beta.$n"
    # Peers drop a version longer than 15 characters, and with it the build check: chat's, and
    # chat-json's, which is chat-core's.
    test ${#v} -le 15 || { echo "$v is longer than the 15 characters peers take" >&2; exit 1; }
    grep -q '^## Unreleased$' "$log" || { echo "$log has no Unreleased section to release as a beta" >&2; exit 1; }
    if git rev-parse -q --verify "refs/tags/$tag$v" >/dev/null; then
        echo "tag $tag$v already exists, but $log still has an Unreleased section" >&2; exit 1
    fi
    awk '$0 == "## Unreleased" { on = 1; next } on && /^## / { exit } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
        "$log" || { echo "the Unreleased section of $log is empty" >&2; exit 1; }
    echo "getting the Unreleased changes in $log ready as beta $tag$v" >&2
    awk -v v="$v" '$0 == "## Unreleased" && !done { print "## " v; done = 1; next } { print }' "$log" > "$log.tmp"
    mv "$log.tmp" "$log"
    "$just" _set-version "$c" "$v"
    echo "$tag$v"

# patch, minor and major count on from CRATE's last release published on GitHub (not this
# clone's tags, which needn't hold the releases), so after a failed publish the same KIND comes to
# the same version again. With no KIND it's the version in its Cargo.toml without its pre-release,
# or the patch after it once that one is published. Anything else is taken as the version.
# Print the version `just prepare CRATE KIND` gets ready
_next-version crate kind="":
    #!/bin/sh
    set -eu
    {{crate_sh}}
    case "${2:-}" in
        patch|minor|major)
            last=$(gh release list --exclude-pre-releases --limit 100 --json tagName -q '.[].tagName' \
                | grep -E "^$tag[0-9]+\.[0-9]+\.[0-9]+\$" | sed "s/^$tag//" | sort -V | tail -n 1)
            echo "${last:-0.0.0}" | awk -F. -v k="$2" '{
                if (k == "major") print $1 + 1 ".0.0"
                else if (k == "minor") print $1 "." $2 + 1 ".0"
                else print $1 "." $2 "." $3 + 1
            }'
            ;;
        "")
            v=$(base_version)
            if published "$v"; then v=$(echo "$v" | awk -F. '{ print $1 "." $2 "." $3 + 1 }'); fi
            echo "$v"
            ;;
        *) echo "$2" ;;
    esac

# The sections above the last release's, newest first, become one "## VERSION" holding each
# section's lines from the oldest on, under each ### heading once: Security, Added, Changed,
# Deprecated, Removed and Fixed in that order, then any others. Every line is kept, so a later
# beta's fix to something an earlier one added lists both: tidy their sections before releasing.
# A lone section is only renamed.
# Fold CRATE's changelog's Unreleased and beta sections into one for VERSION
_fold-changelog crate version:
    #!/bin/sh
    set -eu
    {{crate_sh}}
    awk -v v="$2" '
        function blank(s) { return s !~ /[^[:space:]]/ }
        function add(k, a, b,    i) {
            while (a <= b && blank(line[a])) a++
            while (b >= a && blank(line[b])) b--
            if (a > b) return
            if (!(k in body) && k != "") order[++kinds] = k
            for (i = a; i <= b; i++) body[k] = (k in body) ? body[k] "\n" line[i] : line[i]
        }
        function put(k) {
            if (!(k in body) || (k in done)) return
            done[k] = 1
            print ""
            print "### " k
            print body[k]
        }
        { line[NR] = $0 }
        END {
            for (first = 1; first <= NR && line[first] !~ /^## /; first++) print line[first]
            for (stop = first; stop <= NR && line[stop] !~ /^## [0-9]+\.[0-9]+\.[0-9]+$/; stop++)
                if (line[stop] ~ /^## /) head[++heads] = stop
            if (heads < 2) {
                for (i = first; i <= NR; i++) print (i == first && heads ? "## " v : line[i])
                exit
            }
            head[heads + 1] = stop
            for (h = heads; h >= 1; h--) {
                k = ""
                from = head[h] + 1
                for (i = from; i < head[h + 1]; i++)
                    if (line[i] ~ /^### /) { add(k, from, i - 1); k = substr(line[i], 5); from = i + 1 }
                add(k, from, head[h + 1] - 1)
            }
            print "## " v
            if ("" in body) { print ""; print body[""] }
            n = split("Security Added Changed Deprecated Removed Fixed", known, " ")
            for (j = 1; j <= n; j++) put(known[j])
            for (j = 1; j <= kinds; j++) put(order[j])
            for (i = stop; i <= NR; i++) { if (i == stop) print ""; print line[i] }
        }
    ' "$log" > "$log.tmp"
    mv "$log.tmp" "$log"

# What a merge publishes: the tag CRATE's Cargo.toml and changelog are ready to release as, if
# it isn't out yet. Its changelog's newest section has to be its version's, as the release pull
# request leaves it, and nothing is printed otherwise. The Publish workflow runs it on each merge
# that changes a Cargo.toml.
# Print the tag CRATE (tui or core) is ready to publish, if any
_pending crate:
    #!/bin/sh
    set -eu
    {{crate_sh}}
    v=$(crate_version)
    test "$(sed -n 's/^## //p' "$log" | head -n 1)" = "$v" || exit 0
    if published "$v"; then exit 0; fi
    echo "$tag$v"

# Both crates' versions, as each Cargo.toml has them, then the section for CRATE's version from
# its changelog. The Publish workflow shows them to the admin approving the release, too.
# Print the notes CRATE's release opens with
_notes crate:
    #!/bin/sh
    set -eu
    {{crate_sh}}
    v=$(crate_version)
    ver() { sed -n 's/^version = "\(.*\)"$/\1/p' "$1/Cargo.toml" | head -n 1; }
    section=$(awk -v v="$v" '$0 == "## " v { on = 1; next } on && /^## / { exit } on && (n || /[^[:space:]]/) { n = 1; print }' "$log")
    test -n "$(printf '%s' "$section" | tr -d '[:space:]')" || { echo "$log has no section for $v" >&2; exit 1; }
    echo "chat $(ver chat-tui) · chat-core $(ver chat-core)"
    echo
    printf '%s\n' "$section"

# The Publish workflow runs this once an admin approves, with the release key from the release
# environment, on the commit the release pull request's merge made; by hand, with the key, it's
# `just dist`, then this. For chat, dist/ has the binaries and their lists (see _dist-lists): each
# binary gets the signed list of its builds, which peers check builds with, BUILDS for Linux and
# Windows and BUILDS-macos for the Macs, and SHA256SUMS then covers the binaries as published,
# lists included, signed as "chat vVERSION", which /update checks. HEAD is tagged and only the tag
# is pushed, after signing; if a later step fails, running it again picks up from the tag.
# Sign and publish the release CRATE (tui or core) is ready for, on HEAD
_publish crate: _can-release
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    {{crate_sh}}
    v=$(crate_version)
    t="$tag$v"
    test "$("$just" _pending "$c")" = "$t" \
        || { echo "$t isn't ready to publish: it's out already, or $log's newest section isn't $v's" >&2; exit 1; }
    git fetch -q origin main
    git merge-base --is-ancestor HEAD FETCH_HEAD \
        || { echo "HEAD isn't on GitHub's main - merge the release pull request first" >&2; exit 1; }
    if git rev-parse -q --verify "refs/tags/$t" >/dev/null; then
        test "$(git rev-parse HEAD)" = "$(git rev-parse "$t^{commit}")" || { echo "tag $t isn't HEAD" >&2; exit 1; }
    fi
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    notes="$work/notes.md"
    "$just" _notes "$c" > "$notes"
    set --
    if [ "$c" = tui ]; then
        key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}"
        test -e keys/minisign.pub || { echo "no keys/minisign.pub - run just keygen" >&2; exit 1; }
        for f in {{binaries}} BUILDS BUILDS-macos; do
            test -s "dist/$f" || { echo "no dist/$f - just dist first" >&2; exit 1; }
        done
        test "$(head -n 1 dist/BUILDS)" = "chat v$v" || { echo "dist/ isn't v$v's" >&2; exit 1; }
        # Without a terminal, as on GitHub, minisign reads the key's password from stdin.
        sign() {
            if [ -n "${CHAT_SIGNING_PASSWORD:-}" ]; then
                printf '%s\n' "$CHAT_SIGNING_PASSWORD" | minisign "$@"
            else
                minisign "$@"
            fi
        }
        # One minisign signs both lists: two passwords in all.
        sign -S -s "$key" -m dist/BUILDS dist/BUILDS-macos -t "chat builds v$v"
        "$just" _signed-by dist/BUILDS >/dev/null
        "$just" _signed-by dist/BUILDS-macos >/dev/null
        "$just" _append-list dist BUILDS {{pc_binaries}}
        "$just" _append-list dist BUILDS-macos {{mac_binaries}}
        (cd dist && sha256sum {{binaries}} > SHA256SUMS)
        sign -S -s "$key" -m dist/SHA256SUMS -t "chat v$v"
        pub=$("$just" _signed-by dist/SHA256SUMS)
        {
            echo
            echo 'Check a download with `minisign -Vm SHA256SUMS -p '"$pub"'`, then `sha256sum -c --ignore-missing SHA256SUMS`.'
            echo
            echo '```'
            cat dist/SHA256SUMS
            echo '```'
        } >> "$notes"
        for f in {{binaries}} SHA256SUMS SHA256SUMS.minisig; do set -- "$@" "dist/$f"; done
    fi

    day=$(date -u +%Y%m%d)
    title="Release $day"
    names=$(gh release list --limit 100 --json name -q '.[].name')
    n=1
    while printf '%s\n' "$names" | grep -qxF "$title"; do n=$((n + 1)); title="Release $day.$n"; done
    case "$v" in *-*) pre=--prerelease ;; *) pre= ;; esac
    # chat-core's releases have nothing to install, so they're never the latest, which /update takes.
    if [ "$c" = core ]; then latest=--latest=false; else latest=; fi
    git rev-parse -q --verify "refs/tags/$t" >/dev/null || git tag "$t"
    # The release commit came through its pull request, so it's on GitHub already: only the tag goes.
    git push origin "refs/tags/$t"
    gh release create "$t" --title "$title" --notes-file "$notes" --verify-tag ${pre:+"$pre"} ${latest:+"$latest"} "$@"
    # The release replaces its crate's betas up to it as a download, its own and those of a version
    # it skipped. Their tags stay, as the history of the release.
    if [ -z "$pre" ]; then
        for b in $(gh release list --limit 100 --json tagName,isPrerelease -q '.[] | select(.isPrerelease) | .tagName'); do
            case "$b" in "$tag"[0-9]*) ;; *) continue ;; esac
            bv=${b#"$tag"}
            bv=${bv%%-*}
            if [ "$(printf '%s\n%s\n' "$bv" "$v" | sort -V | tail -n 1)" = "$v" ]; then gh release delete "$b" --yes; fi
        done
    fi
