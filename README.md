# chat

End-to-end encrypted rooms with no server and no accounts, through Tor by default.

| Folder | What it is |
| --- | --- |
| [chat-core](chat-core) | chat itself: the protocol, the encryption, Tor, the relays and UDP, as a Rust library, and `chat-json` for other languages |
| [chat-tui](chat-tui) | `chat`, the terminal UI |

The Android app is [chat-apk](https://github.com/chat-labs/chat-apk), in its own repository.
[ARCHITECTURE.md](ARCHITECTURE.md) has the rules for what goes where.

## Building

It's one Cargo workspace. [just](https://github.com/casey/just) runs the usual things; `just`
alone lists them.

| Recipe | What it does |
| --- | --- |
| `just build [release\|dist]` | every crate |
| `just test`, `just lint`, `just fmt` | tests, formatting and clippy, across every crate |
| `just core::...`, `just tui::...` | a crate's own recipes, such as `just core::interop` or `just tui::demo` |
| `just dist` | the release binaries, cross-built for Linux (static, musl), Windows and macOS 11 or later (Apple silicon and Intel), in `dist/` |
| `just prepare [patch\|minor\|major\|beta]` | the changelog and version ready for a release, or a beta, as the Prepare release workflow does in a pull request |
| `just release` | once that's merged: tag, build, sign and publish it on GitHub |
| `just verify VERSION`, `just reproduce VERSION` | check a published release's signature, or build it again from its tag and compare |

`/update` and `chat --update` install the newest release from
[GitHub](https://github.com/chat-labs/chat/releases), and with `/set betas on` betas too, once
their SHA256SUMS checks out against the release key in `keys/`.

The release recipes cross-build with zig. Rust is the version `rust-toolchain.toml` names, which
rustup fetches, targets included; zig and cargo-zigbuild should be the versions
[build.yml](.github/workflows/build.yml) pins, or a release won't build the same bytes as GitHub's
check of it. zig has no Apple SDK, so the Mac builds link Apple's frameworks through the stubs in
`macos-sdk/`, which only say where each framework is on a Mac: chat uses none of their symbols.
On Gentoo, for example:

```sh
sudo emerge --ask dev-util/rustup dev-lang/zig-bin app-crypt/minisign dev-util/github-cli
rustup-init -y --default-toolchain none
cargo install --locked cargo-zigbuild --version 0.24.1
```

## Checks on GitHub

| Workflow | When | What |
| --- | --- | --- |
| [CI](.github/workflows/ci.yml) | each pull request and push to main | `just lint`, the tests on Linux, macOS and Windows (built with zig as releases are, run on Windows), `chat-json` for chat-apk's Android ABIs, the oldest Rust the crates name, the API docs |
| [E2E](.github/workflows/e2e.yml) | each pull request and push, and nightly | the interop suites between real processes: two `chat-json`, and `chat-json` with `chat --json`; nightly, four minutes of rekeys and two rooms over the live Tor network |
| [Build](.github/workflows/build.yml) | pushes to main, tags, weekly, and pull requests that change the build | `just dist`'s binaries twice, each in a job of its own, on two systems in two folders, which must give the same bytes; the binaries, unsigned, as artifacts; the Mac builds started on a Mac |
| [Prepare release](.github/workflows/prepare-release.yml) | started by hand, from the Actions tab | `just prepare`, opened as a "Release VERSION" pull request; merging it publishes nothing until `just release` |
| [Release](.github/workflows/release.yml) | each published release | `just verify` and `just reproduce`: it signs nothing, since the release key stays offline |
| [Audit](.github/workflows/audit.yml) | when the dependencies change, and daily | RustSec's advisories against `Cargo.lock` |
| [CodeQL](.github/workflows/codeql.yml) | each pull request and push to main, and weekly | code scanning of the Rust, the interop harness and the workflows, into the Security tab |

Dependabot opens weekly pull requests for the actions (pinned by commit) and the crates, but not
Arti, which is pinned exactly and moves on in a commit of its own.

Every crate in the workspace is in CI as it joins (each job takes `--workspace`), and the release
workflows go by the justfile: what `just dist` builds is what's built, checked and reproduced.
chat-gui, once it's started, adds its binaries to the justfile's `binaries`, their builds to
`_dist-build` and the Build workflow's matrix, and any system libraries its toolkit links to the
CI jobs. Each binary carries the signed list of builds peers check its build against, which holds
3 at most (`just dist` refuses more): `BUILDS` for Linux and Windows, `BUILDS-macos` for the
Macs. chat-gui's binaries get a list of their own. chat-apk has a CI of its own, which builds the
APK with this repository's main branch.

## License

[GPL-3.0-only](LICENSE). Copyright © 2026 finlay@tuta.com.
