set positional-arguments

# Every crate's version (the workspace's), and the changelog /changelog shows and releases take
# their notes from.
version := `sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1`
changelog := "chat-tui/CHANGELOG.md"
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

# Paths in the binaries name no folder of this machine's, and the build stamp says when the commit
# was made (SOURCE_DATE_EPOCH), so building the same commit again, anywhere, with the same Rust and
# zig, gives the same binaries. Needs the targets and cargo-zigbuild (see README.md).
# Put standalone release binaries and SHA256SUMS in dist/
[group('release')]
dist:
    #!/bin/sh
    set -eu
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
    RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=cargo"
    export SOURCE_DATE_EPOCH RUSTFLAGS
    cargo zigbuild --locked -p chat-tui --profile dist --target x86_64-unknown-linux-musl
    cargo zigbuild --locked -p chat-tui --profile dist --target x86_64-pc-windows-gnu
    # zig has no Apple SDK, so the frameworks a crate links come from macos-sdk/: stubs that only
    # say where each is on a Mac, since chat uses none of their symbols. They run on macOS 11 on.
    # -S keeps debug info out at link time: the linker hashes its output into the binary's UUID, and
    # the debug info names each object file's path and modification time, which no two builds share.
    for t in aarch64-apple-darwin x86_64-apple-darwin; do
        MACOSX_DEPLOYMENT_TARGET=11.0 RUSTFLAGS="$RUSTFLAGS -C link-arg=-F$PWD/macos-sdk/System/Library/Frameworks -C link-arg=-Wl,-S" \
            cargo zigbuild --locked -p chat-tui --profile dist --target "$t"
    done
    rm -rf dist
    mkdir dist
    cp target/x86_64-unknown-linux-musl/dist/chat dist/chat-linux-x86_64
    cp target/x86_64-pc-windows-gnu/dist/chat.exe dist/chat-windows-x86_64.exe
    cp target/aarch64-apple-darwin/dist/chat dist/chat-macos-aarch64
    cp target/x86_64-apple-darwin/dist/chat dist/chat-macos-x86_64
    (cd dist && sha256sum {{binaries}} > SHA256SUMS)
    (cd dist && { echo "chat v{{version}}"; sha256sum {{pc_binaries}} | cut -c1-64; } > BUILDS)
    (cd dist && { echo "chat v{{version}}"; sha256sum {{mac_binaries}} | cut -c1-64; } > BUILDS-macos)
    for l in BUILDS BUILDS-macos; do
        test "$(wc -l < "dist/$l")" -le 4 || { echo "$l names more than 3 binaries, all peers' list holds" >&2; exit 1; }
    done
    echo "dist/ ready for v{{version}}"

# A published binary's SHA-256 without the list of builds `just release` appended to it, which is
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

# Release preconditions
_can-release:
    #!/bin/sh
    set -eu
    test -e keys/minisign.pub || { echo "no keys/minisign.pub - run just keygen" >&2; exit 1; }
    test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }
    gh auth status >/dev/null 2>&1 || { echo "gh isn't logged in - run gh auth login" >&2; exit 1; }
    command -v cargo-zigbuild >/dev/null || { echo "no cargo-zigbuild - see README.md" >&2; exit 1; }

# Every crate's version (the workspace's), and Cargo.lock's record of it
_set-version version:
    #!/bin/sh
    set -eu
    sed "s/^version = \".*\"\$/version = \"$1\"/" Cargo.toml > Cargo.toml.tmp
    mv Cargo.toml.tmp Cargo.toml
    cargo update --workspace --offline -q

#   just release patch            the patch after the last release, 0.6.0 -> 0.6.1
#   just release minor            the minor after it, 0.6.0 -> 0.7.0
#   just release major            the major after it, 0.6.0 -> 1.0.0
#   just release                  the version in Cargo.toml without its pre-release, which finishes
#                                 its betas, or the patch after it once that one is published
#   just release 1.0.0            another version
#   just release beta [KIND]      a beta of the version just release KIND would release, see
#                                 _release-beta
# Releases the sections at the top of the changelog, "## Unreleased" and those of the betas (and
# pre-releases) since the last release, as VERSION: they become one "## VERSION" (see
# _fold-changelog), Cargo.toml gets the version, and they're committed and tagged vVERSION. Betas
# of another version are folded in too, so a cycle of 0.6.1 betas can come out as 0.7.0. Nothing
# is pushed until SHA256SUMS is signed; if a later step fails, running the same again picks up
# from the tag.
# Build, sign and publish a release: patch, minor, major, or beta [KIND] (needs zig, minisign, gh)
[group('release')]
release what="" *args: _can-release
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    log={{quote(changelog)}}
    if [ "${1:-}" = beta ]; then
        shift
        if [ $# -gt 1 ]; then echo "just release beta takes patch, minor, major or a version, not $*" >&2; exit 1; fi
        exec "$just" _release-beta "$@"
    fi
    if [ $# -gt 1 ]; then echo "just release takes patch, minor, major, beta or a version, not $*" >&2; exit 1; fi
    base_version() { sed -n 's/^version = "\([0-9.]*\).*"$/\1/p' Cargo.toml | head -n 1; }
    published() { gh release view "v$1" >/dev/null 2>&1; }
    pending() { awk '/^## [0-9]+\.[0-9]+\.[0-9]+$/ { exit } /^## / { printf "%s%s", (n++ ? ", " : ""), substr($0, 4) }' "$log"; }
    v=$("$just" _next-version "${1:-}")
    echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || { echo "not a version: $v (want patch, minor, major or MAJOR.MINOR.PATCH)" >&2; exit 1; }
    if published "$v"; then echo "release v$v is already published" >&2; exit 1; fi
    older=$(printf '%s\n%s\n' "$v" "$(base_version)" | sort -V | head -n 1)
    if [ "$older" = "$v" ] && [ "$v" != "$(base_version)" ]; then
        echo "v$v is older than $(base_version), the version in Cargo.toml" >&2; exit 1
    fi

    if [ -n "$(pending)" ]; then
        if git rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
            echo "tag v$v already exists, but $log still has $(pending) above it" >&2; exit 1
        fi
        if grep -q "^## $v\$" "$log"; then echo "$log already has a section for $v" >&2; exit 1; fi
        awk '/^## [0-9]+\.[0-9]+\.[0-9]+$/ { exit } /^## / { on = 1; next } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
            "$log" || { echo "$log's $(pending) has nothing in it" >&2; exit 1; }
        echo "releasing $log's $(pending) as v$v"
        "$just" _fold-changelog "$v"
        "$just" _set-version "$v"
        git commit -q -m "Release $v" "$log" Cargo.toml Cargo.lock
        git tag "v$v"
    fi
    git rev-parse -q --verify "refs/tags/v$v" >/dev/null \
        || { echo "no tag v$v and no Unreleased section in $log to release" >&2; exit 1; }
    exec "$just" _publish "$v"

# A beta is for testers: tagged vVERSION-beta.N, signed and published like a release, but as a
# GitHub pre-release, which /update only installs with betas on (/set betas on). Testers turn
# that on or download it, and /update takes them on to VERSION once it's released. Releasing
# VERSION, or one after it, deletes the betas' GitHub releases, but not their tags. VERSION is
# the one `just release KIND` would release (see _next-version), so with no KIND it's the betas'
# own, and N counts up from 1 (or picks up a beta whose publishing failed). "## Unreleased" becomes
# "## VERSION-beta.N" and Cargo.toml gets VERSION-beta.N.
# Build, sign and publish a beta of the next release, or of KIND's (patch, minor, major or a version)
_release-beta kind="":
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    log={{quote(changelog)}}
    base_version() { sed -n 's/^version = "\([0-9.]*\).*"$/\1/p' Cargo.toml | head -n 1; }
    published() { gh release view "v$1" >/dev/null 2>&1; }
    base=$("$just" _next-version "${1:-}")
    echo "$base" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || { echo "not a version: $base (want patch, minor, major or MAJOR.MINOR.PATCH)" >&2; exit 1; }
    if published "$base"; then echo "v$base is already released" >&2; exit 1; fi
    older=$(printf '%s\n%s\n' "$base" "$(base_version)" | sort -V | head -n 1)
    if [ "$older" = "$base" ] && [ "$base" != "$(base_version)" ]; then
        echo "v$base is older than $(base_version), the version in Cargo.toml" >&2; exit 1
    fi
    n=0
    for t in $(git tag -l "v$base-beta.*"); do
        m=${t#"v$base-beta."}
        case "$m" in ''|*[!0-9]*) continue ;; esac
        if [ "$m" -gt "$n" ]; then n=$m; fi
    done
    if [ "$n" -eq 0 ] || published "$base-beta.$n"; then n=$((n + 1)); fi
    v="$base-beta.$n"
    # Peers drop a version longer than 15 characters, and with it the build check.
    test ${#v} -le 15 || { echo "$v is longer than the 15 characters peers take" >&2; exit 1; }

    if grep -q '^## Unreleased$' "$log"; then
        if git rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
            echo "tag v$v already exists, but $log still has an Unreleased section" >&2; exit 1
        fi
        awk '$0 == "## Unreleased" { on = 1; next } on && /^## / { exit } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
            "$log" || { echo "the Unreleased section of $log is empty" >&2; exit 1; }
        echo "releasing the Unreleased changes as beta v$v"
        awk -v v="$v" '$0 == "## Unreleased" && !done { print "## " v; done = 1; next } { print }' "$log" > "$log.tmp"
        mv "$log.tmp" "$log"
        "$just" _set-version "$v"
        git commit -q -m "Release $v" "$log" Cargo.toml Cargo.lock
        git tag "v$v"
    fi
    git rev-parse -q --verify "refs/tags/v$v" >/dev/null \
        || { echo "no tag v$v and no Unreleased section in $log to release" >&2; exit 1; }
    exec "$just" _publish "$v"

# patch, minor and major count on from the last release published on GitHub (not this clone's
# tags, which needn't hold the releases), so after a failed publish the same KIND comes to the
# same version again. With no KIND it's the version in Cargo.toml without its pre-release, or the
# patch after it once that one is published. Anything else is taken as the version.
# Print the version `just release KIND` releases
_next-version kind="":
    #!/bin/sh
    set -eu
    published() { gh release view "v$1" >/dev/null 2>&1; }
    case "${1:-}" in
        patch|minor|major)
            last=$(gh release list --exclude-pre-releases --limit 100 --json tagName -q '.[].tagName' \
                | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed 's/^v//' | sort -V | tail -n 1)
            echo "${last:-0.0.0}" | awk -F. -v k="$1" '{
                if (k == "major") print $1 + 1 ".0.0"
                else if (k == "minor") print $1 "." $2 + 1 ".0"
                else print $1 "." $2 "." $3 + 1
            }'
            ;;
        "")
            v=$(sed -n 's/^version = "\([0-9.]*\).*"$/\1/p' Cargo.toml | head -n 1)
            if published "$v"; then v=$(echo "$v" | awk -F. '{ print $1 "." $2 "." $3 + 1 }'); fi
            echo "$v"
            ;;
        *) echo "$1" ;;
    esac

# The sections above the last release's, newest first, become one "## VERSION" holding each
# section's lines from the oldest on, under each ### heading once: Security, Added, Changed,
# Deprecated, Removed and Fixed in that order, then any others. Every line is kept, so a later
# beta's fix to something an earlier one added lists both: tidy their sections before releasing.
# A lone section is only renamed.
# Fold the changelog's Unreleased and beta sections into one for VERSION
_fold-changelog version:
    #!/bin/sh
    set -eu
    log={{quote(changelog)}}
    awk -v v="$1" '
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

# Signing happens here, offline, so a compromised GitHub account can't publish an update that chat
# will install.
# Build, sign and publish tag vVERSION, which HEAD must be at, as a GitHub release
_publish version:
    #!/bin/sh
    set -eu
    v="$1"
    just={{quote(just_executable())}}
    log={{quote(changelog)}}
    key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}"
    test {{quote(version)}} = "$v" || { echo "Cargo.toml says {{version}}, not $v" >&2; exit 1; }
    test "$(git rev-parse HEAD)" = "$(git rev-parse "v$v^{commit}")" || { echo "HEAD is not tag v$v" >&2; exit 1; }

    "$just" dist
    # Each binary gets the signed list of its builds, which peers check builds with: BUILDS for
    # Linux and Windows, BUILDS-macos for the Macs. SHA256SUMS then covers the binaries as
    # published, lists included. One minisign signs both lists: two prompts in all.
    minisign -S -s "$key" -m dist/BUILDS dist/BUILDS-macos -t "chat builds v$v"
    "$just" _signed-by dist/BUILDS >/dev/null
    "$just" _signed-by dist/BUILDS-macos >/dev/null
    "$just" _append-list dist BUILDS {{pc_binaries}}
    "$just" _append-list dist BUILDS-macos {{mac_binaries}}
    (cd dist && sha256sum {{binaries}} > SHA256SUMS)
    minisign -S -s "$key" -m dist/SHA256SUMS -t "chat v$v"
    pub=$("$just" _signed-by dist/SHA256SUMS)
    awk -v v="$v" '$0 == "## " v { on = 1; next } on && /^## / { exit } on { print }' "$log" > dist/notes.md
    grep -q '[^[:space:]]' dist/notes.md || { echo "$log has no section for $v" >&2; exit 1; }
    {
        echo
        echo 'Check a download with `minisign -Vm SHA256SUMS -p '"$pub"'`, then `sha256sum -c --ignore-missing SHA256SUMS`.'
        echo
        echo '```'
        cat dist/SHA256SUMS
        echo '```'
    } >> dist/notes.md

    # The branch goes too when there is one, so the release commit is on GitHub, not just its tag.
    branch=$(git symbolic-ref -q --short HEAD || true)
    git push --atomic origin ${branch:+"$branch"} "refs/tags/v$v"
    case "$v" in *-*) pre=--prerelease ;; *) pre= ;; esac
    (cd dist && gh release create "v$v" --title "v$v" --notes-file notes.md --verify-tag ${pre:+"$pre"} \
        {{binaries}} SHA256SUMS SHA256SUMS.minisig)
    # The release replaces the betas up to it as a download, its own and those of a version it
    # skipped. Their tags stay, as the history of the release.
    if [ -z "$pre" ]; then
        for t in $(gh release list --limit 100 --json tagName,isPrerelease -q '.[] | select(.isPrerelease) | .tagName'); do
            b=${t#v}
            b=${b%%-*}
            if [ "$(printf '%s\n%s\n' "$b" "$v" | sort -V | tail -n 1)" = "$v" ]; then gh release delete "$t" --yes; fi
        done
    fi
