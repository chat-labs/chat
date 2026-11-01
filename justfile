set positional-arguments

version := `sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p; s/^set(CHAT_PRERELEASE "\(.*\)")$/\1/p' CMakeLists.txt | tr -d '\n'`

# List recipes
default:
    @just --list --unsorted

# ---------------------------------------------------------------------------------------------
# Build

#   just build                       native binary in build/
#   just build linux                 static musl Linux binary in build-static/ (needs zig)
#   just build windows               Windows binary in build-win/ (needs zig; win works too)
#   just build macos                 macOS binaries in build-macos-aarch64/ and -x86_64/ (needs zig)
#   just build android               Android binaries in build-android-arm64-v8a/ and -x86_64/ (needs the NDK)
#   just build all                   native and Windows binaries
#   just build test [system] [args]  test builds, see _build-test
# Build chat: native (default), linux, windows, macos, android, all, or test [all|linux|windows]
[group('build')]
build what="native" *args:
    #!/bin/sh
    set -eu
    what="$1"
    shift
    just={{quote(just_executable())}}
    if [ "$what" != test ] && [ $# -gt 0 ]; then echo "just build $what takes no further arguments" >&2; exit 1; fi
    # A build dir remembers its toolchain file; if that moved or went away, configuring it fails
    drop_stale() {
        [ -f "$1/CMakeCache.txt" ] || return 0
        # CMakeSystem.cmake keeps its own copy of the path, which can outlive the cache entry
        tc=$(cat "$1/CMakeCache.txt" "$1"/CMakeFiles/*/CMakeSystem.cmake 2>/dev/null |
            sed -n -e 's/^CMAKE_TOOLCHAIN_FILE:[A-Z]*=//p' -e 's/^include("\(.*\)")$/\1/p' |
            while read -r f; do [ -f "$f" ] || { echo "$f"; break; }; done)
        if [ -n "$tc" ]; then
            echo "removing stale $1 (toolchain $tc is gone)"
            rm -rf "$1"
        fi
    }
    case "$what" in
        native)
            cmake -B build
            cmake --build build -j {{num_cpus()}}
            ;;
        linux)
            drop_stale build-static
            cmake -B build-static -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/zig-linux-musl.cmake
            cmake --build build-static -j {{num_cpus()}}
            ;;
        windows|win)
            drop_stale build-win
            cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/zig-windows.cmake
            cmake --build build-win -j {{num_cpus()}}
            ;;
        macos|mac)
            for arch in aarch64 x86_64; do
                drop_stale build-macos-$arch
                cmake -B build-macos-$arch -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/zig-macos-$arch.cmake
                cmake --build build-macos-$arch -j {{num_cpus()}}
            done
            ;;
        android)
            # The NDK named, else the newest in an SDK: named, Android Studio's, or chat-gui's
            ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
            for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Android/Sdk" "$HOME/.local/share/android-sdk"; do
                [ -z "$ndk" ] && [ -n "$sdk" ] && ndk=$(ls -d "$sdk"/ndk/*/ 2>/dev/null | sort -V | tail -n 1)
            done
            toolchain="${ndk%/}/build/cmake/android.toolchain.cmake"
            if [ -z "$ndk" ] || [ ! -f "$toolchain" ]; then
                echo "no Android NDK: set ANDROID_NDK_HOME, or ANDROID_HOME to an SDK with one" >&2
                exit 1
            fi
            for abi in arm64-v8a x86_64; do
                drop_stale build-android-$abi
                cmake -B build-android-$abi -DCMAKE_TOOLCHAIN_FILE="$toolchain" -DANDROID_ABI=$abi -DANDROID_PLATFORM=android-28
                cmake --build build-android-$abi -j {{num_cpus()}}
            done
            ;;
        all)
            "$just" build
            "$just" build windows
            ;;
        test) exec "$just" _build-test "$@" ;;
        *) echo "just build takes native, linux, windows, macos, android, all or test, not $what" >&2; exit 1 ;;
    esac

# just build test [all|linux|windows] [chat args], all by default. This system's binary builds
# natively, the other is cross-built with zig. With all, a failed cross build only leaves that binary out. Only with a
# terminal to answer on does it ask; any further arguments go to chat if it runs. Each binary is
# chat-<build id>-<system>-<arch>, the build id saying which source it's from and when it was built.
# Each says "testing <build id>" over its console.
# Build into test-builds/<date>-<time>/ (all, linux or windows), then offer to run this system's binary
_build-test target="all" *args:
    #!/bin/sh
    set -eu
    export CHAT_TEST_BUILD=1
    target="$1"
    shift
    case "$target" in
        win) target=windows ;;
        all|linux|windows) ;;
        *) echo "just build test takes all, linux or windows, not $target" >&2; exit 1 ;;
    esac
    just={{quote(just_executable())}}
    host={{os()}}
    dir="test-builds/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dir"
    native=
    have_zig() {
        command -v "${ZIG:-zig}" >/dev/null 2>&1 || { echo "no zig on PATH - can't cross-build for $1" >&2; return 1; }
    }
    # Copies $2, built in $1, into $dir as chat-<build id>-$3 and leaves its path in $out. The
    # build id is CHAT_BUILD_ID from that build's stamp.
    keep() {
        id=$(sed -n 's/^#define CHAT_BUILD_ID "\(.*\)"$/\1/p' "$1/build_stamp.h")
        [ -n "$id" ] || { echo "no CHAT_BUILD_ID in $1/build_stamp.h" >&2; return 1; }
        out="$dir/chat-$id-$3"
        cp "$2" "$out"
    }
    build_linux() {
        if [ "$host" = linux ]; then
            "$just" build || return 1
            keep build build/chat linux-{{arch()}} || return 1
            native="$out"
        else
            have_zig Linux && "$just" build linux || return 1
            keep build-static build-static/chat linux-x86_64 || return 1
        fi
    }
    build_windows() {
        if [ "$host" = windows ]; then
            "$just" build || return 1
            # A multi-config generator (Visual Studio) puts it under Release/.
            for exe in build/chat.exe build/Release/chat.exe; do
                if [ -f "$exe" ]; then
                    keep build "$exe" windows-{{arch()}}.exe || return 1
                    native="$out"
                    return 0
                fi
            done
            echo "no chat.exe in build/" >&2
            return 1
        else
            have_zig Windows && "$just" build windows || return 1
            keep build-win build-win/chat.exe windows-x86_64.exe || return 1
        fi
    }
    fail() { echo "$1" >&2; rmdir "$dir" 2>/dev/null || true; exit 1; }
    case "$target" in
        linux)   build_linux || fail "the Linux build failed" ;;
        windows) build_windows || fail "the Windows build failed" ;;
        all)
            # This system's first: without it there's nothing to run.
            if [ "$host" = windows ]; then
                build_windows || fail "the Windows build failed"
                build_linux || echo "the Linux build failed - $dir only has the Windows binary" >&2
            else
                build_linux || fail "the Linux build failed"
                build_windows || echo "the Windows build failed - $dir only has the Linux binary" >&2
            fi
            ;;
    esac
    echo
    ls -1 "$dir" | sed "s|^|$dir/|"
    if [ -n "$native" ] && [ -t 0 ] && [ -t 1 ]; then
        printf 'run %s now? [y/N] ' "$native"
        read -r answer || answer=
        case "$answer" in
            [yY]|[yY][eE][sS]) exec "$native" "$@" ;;
        esac
    fi

# Build, then run chat with the given arguments
[group('build')]
run *args: build
    ./build/chat "$@"

# Remove build directories, test builds and release output
[group('build')]
clean:
    rm -rf build build-static build-win build-macos-aarch64 build-macos-x86_64 build-android-arm64-v8a build-android-x86_64 build-test build-fuzz build-asan build-win-test test-builds dist

# ---------------------------------------------------------------------------------------------
# Test

# Sessions handshake and chat over an in-memory network. -v also prints every session line and
# check, then the summary. It's built in build/, with the dependencies already built there, and
# `just build` leaves it out.
# Build and run the engine test (-v for everything)
[group('test')]
test *flags:
    cmake -B build -DCHAT_TESTS=ON
    cmake --build build -j {{num_cpus()}} --target engine_test
    ./build/tests/engine_test "$@"

# This build and OLD, another chat executable (an older release, say), as two peers in one room on
# this computer, through what docs/protocol.md promises older versions. CI runs it against the latest
# release and beta.
# Build, then check it against an older chat binary (tests/interop/interop.sh)
[group('test')]
interop old: (build "native")
    tests/interop/interop.sh build/chat "$1"

# Build and run the engine test under AddressSanitizer and UndefinedBehaviorSanitizer (needs clang)
[group('test')]
test-sanitized *flags:
    cmake -B build-asan -DCHAT_TESTS=ON -DCHAT_SANITIZE=ON -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug
    cmake --build build-asan -j {{num_cpus()}} --target engine_test
    ./build-asan/tests/engine_test "$@"

# Fuzz one target (bencode, json, pgp, text, engine, image, toml, save, ctap2 or tpm2) for a number of seconds (needs clang)
[group('test')]
fuzz target="engine" seconds="300":
    cmake -B build-fuzz -DCHAT_FUZZ=ON -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug
    cmake --build build-fuzz -j {{num_cpus()}} --target fuzz_{{target}}
    mkdir -p fuzz-corpus/{{target}}
    ASAN_OPTIONS=detect_leaks=0 ./build-fuzz/tests/fuzz_{{target}} fuzz-corpus/{{target}} \
        $(test -d tests/fuzz/seeds/{{target}} && echo tests/fuzz/seeds/{{target}}) -dict=tests/fuzz/fuzz.dict -max_total_time={{seconds}}

# ---------------------------------------------------------------------------------------------
# Release

# keys/minisign.pub gets committed; the password-protected secret key stays offline and backed up,
# never in the repo. Set CHAT_SIGNING_KEY to keep it somewhere other than ~/.minisign.
# `just keygen backup` makes the backup key, keys/minisign-backup.pub and CHAT_BACKUP_SIGNING_KEY's
# file: builds from then on take a release it signed too, for when the first is lost or stolen.
# Its secret key goes somewhere apart from the first's, so one mishap can't take both.
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
    echo "commit $pub; back up $key somewhere safe${1:+, apart from the release key}"

# Which public key signed file (keys/minisign.pub, or keys/minisign-backup.pub), or fails if neither did
_signed-by file:
    #!/bin/sh
    set -eu
    for pub in keys/minisign.pub keys/minisign-backup.pub; do
        if [ -e "$pub" ] && minisign -Vq -p "$pub" -m "$1" >/dev/null 2>&1; then echo "$pub"; exit 0; fi
    done
    echo "$1 isn't signed with keys/minisign.pub's key or keys/minisign-backup.pub's" >&2
    exit 1

# The build stamp says when the commit was made, not when it was built (SOURCE_DATE_EPOCH), so
# building the same commit again, anywhere, with the same zig, gives the same binaries.
# Put standalone release binaries and SHA256SUMS in dist/
[group('release')]
dist:
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
    export SOURCE_DATE_EPOCH
    "$just" build linux
    "$just" build windows
    rm -rf dist
    mkdir dist
    cp build-static/chat dist/chat-linux-x86_64
    cp build-win/chat.exe dist/chat-windows-x86_64.exe
    strip dist/chat-linux-x86_64
    (cd dist && sha256sum chat-linux-x86_64 chat-windows-x86_64.exe > SHA256SUMS)
    (cd dist && { echo "chat v{{version}}"; sha256sum chat-linux-x86_64 chat-windows-x86_64.exe | cut -c1-64; } > BUILDS)
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
# Build release VERSION again from its tag and compare it with the published binaries (needs zig, curl)
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
    for f in chat-linux-x86_64 chat-windows-x86_64.exe; do
        curl -fsSL -o "$dir/$f" "https://github.com/chat-labs/chat/releases/download/v$v/$f"
        mine=$(sha256sum < "dist/$f" | cut -c1-64)
        theirs=$("$just" _core-hash "$dir/$f")
        if [ "$mine" = "$theirs" ]; then echo "$f: the same ($mine)"; else echo "$f: DIFFERENT - built here $mine, published $theirs"; same=0; fi
    done
    test "$same" = 1

# Peers send each other this list to check each other's builds with (docs/security.md, "Modified
# clients"), so it may name 3 binaries at most. Chat reads it from its own end: the list, its
# signature line, then the length of both in 8 digits and CHATBLD1.
# Append BUILDS, signed (BUILDS.minisig), to the binaries in a folder
_append-list dir:
    #!/bin/sh
    set -eu
    cd {{quote(dir)}}
    test "$(wc -l < BUILDS)" -le 4 || { echo "BUILDS names more than 3 binaries" >&2; exit 1; }
    sig=$(sed -n 2p BUILDS.minisig)
    len=$(( $(wc -c < BUILDS) + ${#sig} + 1 ))
    for f in chat-linux-x86_64 chat-windows-x86_64.exe; do
        { cat BUILDS; printf '%s\n%08dCHATBLD1' "$sig" "$len"; } >> "$f"
    done

# Release preconditions
_can-release:
    #!/bin/sh
    set -eu
    test -e keys/minisign.pub || { echo "no keys/minisign.pub - run just keygen" >&2; exit 1; }
    test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }
    gh auth status >/dev/null 2>&1 || { echo "gh isn't logged in - run gh auth login" >&2; exit 1; }

#   just release patch            the patch after the last release, 0.5.0 -> 0.5.1
#   just release minor            the minor after it, 0.5.0 -> 0.6.0
#   just release major            the major after it, 0.5.0 -> 1.0.0
#   just release                  the version in CMakeLists.txt, which finishes its betas, or the
#                                 patch after it once that one is published
#   just release 1.0.0            another version
#   just release beta [KIND]      a beta of the version just release KIND would release, see
#                                 _release-beta
# Releases the sections at the top of CHANGELOG.md, "## Unreleased" and those of the betas since
# the last release, as VERSION: they become one "## VERSION" (see _fold-changelog), CMakeLists.txt
# gets the version, and both are committed and tagged vVERSION. Betas of another version are
# folded in too, so a cycle of 0.5.1 betas can come out as 0.6.0. Nothing is pushed until
# SHA256SUMS is signed; if a later step fails, running the same again picks up from the tag.
# Build, sign and publish a release: patch, minor, major, or beta [KIND] (needs zig, minisign, gh)
[group('release')]
release what="" *args: _can-release
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    if [ "${1:-}" = beta ]; then
        shift
        if [ $# -gt 1 ]; then echo "just release beta takes patch, minor, major or a version, not $*" >&2; exit 1; fi
        exec "$just" _release-beta "$@"
    fi
    if [ $# -gt 1 ]; then echo "just release takes patch, minor, major, beta or a version, not $*" >&2; exit 1; fi
    cmake_version() { sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt; }
    published() { gh release view "v$1" >/dev/null 2>&1; }
    pending() { awk '/^## [0-9]+\.[0-9]+\.[0-9]+$/ { exit } /^## / { printf "%s%s", (n++ ? ", " : ""), substr($0, 4) }' CHANGELOG.md; }
    v=$("$just" _next-version "${1:-}")
    echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || { echo "not a version: $v (want patch, minor, major or MAJOR.MINOR.PATCH)" >&2; exit 1; }
    if published "$v"; then echo "release v$v is already published" >&2; exit 1; fi
    older=$(printf '%s\n%s\n' "$v" "$(cmake_version)" | sort -V | head -n 1)
    if [ "$older" = "$v" ] && [ "$v" != "$(cmake_version)" ]; then
        echo "v$v is older than $(cmake_version), the version in CMakeLists.txt" >&2; exit 1
    fi

    if [ -n "$(pending)" ]; then
        if git rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
            echo "tag v$v already exists, but CHANGELOG.md still has $(pending) above it" >&2; exit 1
        fi
        if grep -q "^## $v\$" CHANGELOG.md; then echo "CHANGELOG.md already has a section for $v" >&2; exit 1; fi
        awk '/^## [0-9]+\.[0-9]+\.[0-9]+$/ { exit } /^## / { on = 1; next } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
            CHANGELOG.md || { echo "CHANGELOG.md's $(pending) has nothing in it" >&2; exit 1; }
        echo "releasing CHANGELOG.md's $(pending) as v$v"
        "$just" _fold-changelog "$v"
        sed -e "s/^project(chat VERSION [0-9.]*/project(chat VERSION $v/" -e 's/^set(CHAT_PRERELEASE ".*")$/set(CHAT_PRERELEASE "")/' \
            CMakeLists.txt > CMakeLists.txt.tmp
        mv CMakeLists.txt.tmp CMakeLists.txt
        git commit -q -m "Release $v" CHANGELOG.md CMakeLists.txt
        git tag "v$v"
    fi
    git rev-parse -q --verify "refs/tags/v$v" >/dev/null \
        || { echo "no tag v$v and no Unreleased section in CHANGELOG.md to release" >&2; exit 1; }
    exec "$just" _publish "$v"

# A beta is for testers: tagged vVERSION-beta.N, signed and published like a release, but as a
# GitHub pre-release, which :update only installs with betas on (:set betas on). Testers turn
# that on or download it, and :update takes them on to VERSION once it's released. Releasing
# VERSION, or one after it, deletes the betas' GitHub releases, but not their tags. VERSION is
# the one `just release KIND` would release (see _next-version), so with no KIND it's the betas'
# own, and N counts up from 1 (or picks up a beta whose publishing failed). "## Unreleased" becomes
# "## VERSION-beta.N" and CMakeLists.txt gets the version, with "-beta.N" as CHAT_PRERELEASE.
# Build, sign and publish a beta of the next release, or of KIND's (patch, minor, major or a version)
_release-beta kind="":
    #!/bin/sh
    set -eu
    just={{quote(just_executable())}}
    cmake_version() { sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt; }
    published() { gh release view "v$1" >/dev/null 2>&1; }
    base=$("$just" _next-version "${1:-}")
    echo "$base" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' \
        || { echo "not a version: $base (want patch, minor, major or MAJOR.MINOR.PATCH)" >&2; exit 1; }
    if published "$base"; then echo "v$base is already released" >&2; exit 1; fi
    older=$(printf '%s\n%s\n' "$base" "$(cmake_version)" | sort -V | head -n 1)
    if [ "$older" = "$base" ] && [ "$base" != "$(cmake_version)" ]; then
        echo "v$base is older than $(cmake_version), the version in CMakeLists.txt" >&2; exit 1
    fi
    n=0
    for t in $(git tag -l "v$base-beta.*"); do
        m=${t#"v$base-beta."}
        case "$m" in ''|*[!0-9]*) continue ;; esac
        if [ "$m" -gt "$n" ]; then n=$m; fi
    done
    if [ "$n" -eq 0 ] || published "$base-beta.$n"; then n=$((n + 1)); fi
    v="$base-beta.$n"
    # Peers drop a version longer than MAX_VERSION (src/core/chat.h), and with it the build check.
    test ${#v} -le 15 || { echo "$v is longer than the 15 characters peers take" >&2; exit 1; }

    if grep -q '^## Unreleased$' CHANGELOG.md; then
        if git rev-parse -q --verify "refs/tags/v$v" >/dev/null; then
            echo "tag v$v already exists, but CHANGELOG.md still has an Unreleased section" >&2; exit 1
        fi
        awk '$0 == "## Unreleased" { on = 1; next } on && /^## / { exit } on && /[^[:space:]]/ { found = 1 } END { exit !found }' \
            CHANGELOG.md || { echo "the Unreleased section of CHANGELOG.md is empty" >&2; exit 1; }
        echo "releasing the Unreleased changes as beta v$v"
        awk -v v="$v" '$0 == "## Unreleased" && !done { print "## " v; done = 1; next } { print }' CHANGELOG.md > CHANGELOG.md.tmp
        mv CHANGELOG.md.tmp CHANGELOG.md
        sed -e "s/^project(chat VERSION [0-9.]*/project(chat VERSION $base/" -e "s/^set(CHAT_PRERELEASE \".*\")\$/set(CHAT_PRERELEASE \"-beta.$n\")/" \
            CMakeLists.txt > CMakeLists.txt.tmp
        mv CMakeLists.txt.tmp CMakeLists.txt
        git commit -q -m "Release $v" CHANGELOG.md CMakeLists.txt
        git tag "v$v"
    fi
    git rev-parse -q --verify "refs/tags/v$v" >/dev/null \
        || { echo "no tag v$v and no Unreleased section in CHANGELOG.md to release" >&2; exit 1; }
    exec "$just" _publish "$v"

# patch, minor and major count on from the last release: the newest vMAJOR.MINOR.PATCH tag that's
# published on GitHub, so after a failed publish the same KIND comes to the same version again.
# With no KIND it's the version in CMakeLists.txt, or the patch after it once that one is
# published. Anything else is taken as the version.
# Print the version `just release KIND` releases
_next-version kind="":
    #!/bin/sh
    set -eu
    published() { gh release view "v$1" >/dev/null 2>&1; }
    case "${1:-}" in
        patch|minor|major)
            last=0.0.0
            for t in $(git tag -l --sort=-version:refname 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'); do
                if published "${t#v}"; then last=${t#v}; break; fi
            done
            echo "$last" | awk -F. -v k="$1" '{
                if (k == "major") print $1 + 1 ".0.0"
                else if (k == "minor") print $1 "." $2 + 1 ".0"
                else print $1 "." $2 "." $3 + 1
            }'
            ;;
        "")
            v=$(sed -n 's/^project(chat VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
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
# Fold CHANGELOG.md's Unreleased and beta sections into one for VERSION
_fold-changelog version:
    #!/bin/sh
    set -eu
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
    ' CHANGELOG.md > CHANGELOG.md.tmp
    mv CHANGELOG.md.tmp CHANGELOG.md

# Signing happens here, offline, so a compromised GitHub account can't publish an update that chat
# will install.
# Build, sign and publish tag vVERSION, which HEAD must be at, as a GitHub release
_publish version:
    #!/bin/sh
    set -eu
    v="$1"
    just={{quote(just_executable())}}
    key="${CHAT_SIGNING_KEY:-$HOME/.minisign/chat-release.key}"
    test {{quote(version)}} = "$v" || { echo "CMakeLists.txt says {{version}}, not $v" >&2; exit 1; }
    test "$(git rev-parse HEAD)" = "$(git rev-parse "v$v^{commit}")" || { echo "HEAD is not tag v$v" >&2; exit 1; }

    "$just" dist
    # Each binary gets the signed list of this release's binaries, which peers check builds with.
    # SHA256SUMS then covers the binaries as published, list included. Two signatures: two prompts.
    minisign -S -s "$key" -m dist/BUILDS -t "chat builds v$v"
    "$just" _signed-by dist/BUILDS >/dev/null
    "$just" _append-list dist
    (cd dist && sha256sum chat-linux-x86_64 chat-windows-x86_64.exe > SHA256SUMS)
    minisign -S -s "$key" -m dist/SHA256SUMS -t "chat v$v"
    pub=$("$just" _signed-by dist/SHA256SUMS)
    awk -v v="$v" '$0 == "## " v { on = 1; next } on && /^## / { exit } on { print }' CHANGELOG.md > dist/notes.md
    grep -q '[^[:space:]]' dist/notes.md || { echo "CHANGELOG.md has no section for $v" >&2; exit 1; }
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
    gh release create "v$v" --title "v$v" --notes-file dist/notes.md --verify-tag ${pre:+"$pre"} \
        dist/chat-linux-x86_64 dist/chat-windows-x86_64.exe dist/SHA256SUMS dist/SHA256SUMS.minisig
    # The release replaces the betas up to it as a download, its own and those of a version it
    # skipped. Their tags stay, as the history of the release.
    if [ -z "$pre" ]; then
        for t in $(gh release list --limit 100 --json tagName,isPrerelease -q '.[] | select(.isPrerelease) | .tagName'); do
            b=${t#v}
            b=${b%%-*}
            if [ "$(printf '%s\n%s\n' "$b" "$v" | sort -V | tail -n 1)" = "$v" ]; then gh release delete "$t" --yes; fi
        done
    fi
