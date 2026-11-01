# chat

[![test](https://github.com/chat-labs/chat/actions/workflows/test.yml/badge.svg)](https://github.com/chat-labs/chat/actions/workflows/test.yml)
[![build](https://github.com/chat-labs/chat/actions/workflows/build.yml/badge.svg)](https://github.com/chat-labs/chat/actions/workflows/build.yml)
[![release](https://img.shields.io/github/v/release/chat-labs/chat?include_prereleases&sort=semver)](https://github.com/chat-labs/chat/releases)
[![license](https://img.shields.io/badge/license-GPL--3.0--only-blue)](LICENSE)

An end-to-end encrypted group chat for the terminal, with no server and no accounts. Peers find
each other over the BitTorrent DHT (IPv4 and IPv6) and UDP broadcast on the LAN, then talk
directly. If a NAT gets in the way, chat asks the router to forward a port, and public Nostr
relays can carry the traffic. You can also send everything through Tor instead. Nothing is
written to disk unless you ask for it.

> This README was written by AI.

> Eventually, I will rewrite this myself, when I have more time.

> A big goal for this was to minimise the dependency requitements as much as possible. with this in mind, the src for this is quite heavy, since I had to write much of the tooling myself.

> Also, I am not Terry Davis (god rest his soul), and much of this may not be that good, I have optimised and improved where I can. Pretty much all the code (except for the TUI, because I suck at frontend) is hand written. I have used claude for documentation, review, (some) optimisation, sanity checking, commenting, test writing, and autocompletions where the suggestions were acceptable. Other than that, this is artisanal, organic, vegan, gluten free, etc. C code.

> Thank you for reading.

It's written in C, runs on Linux and Windows, builds for macOS (see
[macOS](docs/building.md#macos)), and only links static crypto libraries.

## Features

- **Post-quantum, end-to-end encryption.** X25519 and ML-KEM-768 together for key agreement,
  XChaCha20-Poly1305, and a ratchet per message for forward secrecy.
- **No server and no accounts.** A session's id and password are all it takes. Peers find each
  other over the BitTorrent DHT, the LAN and public Nostr relays, and talk directly.
- **Tor routing.** Onion services hide your IP address from peers and everyone else, with bridges
  for networks that block Tor.
- **Traffic that says little.** Every UDP datagram is masked and the same size, and goes out in a
  peer's regular slots whether there's anything to send or not.
- **Verify codes.** Compare a code with each peer over something else, and nothing need go to a
  peer until you have. A signing identity (an AGE or PGP key) carries the check over to later
  sessions.
- **Files and pictures.** Fetched in the same slots, and kept only if their SHA-256 matches the
  offer. A picture goes without what could tell where, when or with what it was made.
- **Nothing on disk unless you ask.** `:install` seals settings and keys under a passphrase, and
  can lock them to the device, a security key or an authenticator app too, with a shadow
  passphrase and self-destruct.
- **Hard to snoop on.** A sandbox on Linux, keys and messages locked out of swap, pictures decoded
  in a child process, a lock screen and a panic key.
- **And more:** moving a room (`:move`), calls between verified keys, direct messages, replies,
  message timers and kept rooms.

## Quick start

To try chat without keeping it, the runner at [chat.vin.moe](https://chat.vin.moe) downloads the
latest release, checks its signature and hash, runs it, and deletes it when chat exits:

```sh
curl -fsSL https://chat.vin.moe | sh     # Linux
irm https://chat.vin.moe | iex           # Windows PowerShell
```

To keep a copy, download a release from the [releases
page](https://github.com/chat-labs/chat/releases) and check it against
[`keys/minisign.pub`](keys/minisign.pub), as [Getting started](docs/getting-started.md) shows. Then:

1. Run `chat`, and press **Start chatting** (or `Esc`) on the settings page it opens on.
2. `Ctrl+N` starts a session. `:invite` copies its id and password as one invite to pass on.
3. Others press `Ctrl+J` and paste the invite (or type the id and password), then compare verify
   codes with you (`:verify NICK`).

## Documentation

| Page | What's in it |
| --- | --- |
| [Getting started](docs/getting-started.md) | Downloading and checking a release, where to put it, and a first session |
| [Usage](docs/usage.md) | The full-screen UI, keys, commands, settings, command line options and updating |
| [Security and privacy](docs/security.md) | Encryption, verify codes, signing identities, `:move`, calls, the lock screen and panic key, and what chat can't hide |
| [Routing](docs/routing.md) | UDP, the DHT, LAN discovery, port mapping, Nostr relays, Tor and bridges, and what each one sees |
| [Files and pictures](docs/files.md) | Sending, fetching and showing files, and what a picture says about you |
| [Saving settings and keys](docs/saves.md) | `:install`: saves, device locks, security keys and authenticator apps, histories, kept rooms, and the shadow passphrase |
| [Wire protocol](docs/protocol.md) | What chat sends over the network, byte by byte |
| [JSON interface](docs/json.md) | `--json`, for another program to drive a session |
| [Building](docs/building.md) | Building from source, cross builds for Windows and macOS, and the tests |
| [Releasing](docs/releasing.md) | How releases are made, signed and reproduced, and the backup key |
| [Architecture](docs/architecture.md) | How the source is laid out |
| [SECURITY.md](SECURITY.md) | The threat model, and how to report a vulnerability |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release |

## Building

You need CMake 3.15 or later and a C compiler. CMake fetches and statically builds libsodium,
liboqs, Mbed TLS and libsecp256k1.

```sh
cmake -B build
cmake --build build
./build/chat --nick you
```

[Building](docs/building.md) has the cross builds, the [`justfile`](justfile) recipes and the
tests.

## Security

> **Note:** the cryptography here has not been independently audited.

[SECURITY.md](SECURITY.md) has the threat model (what chat protects, from whom, and where that
stops) and how to report a vulnerability privately.

## License

[GPL-3.0-only](LICENSE). Copyright © 2026 finlay@tuta.com.

The word list verify codes are read out with is
[Bytewords](https://developer.blockchaincommons.com/bytewords/) (BCR-2020-012), Copyright © 2019
Blockchain Commons, LLC, under the [BSD-2-Clause Plus Patent
License](https://spdx.org/licenses/BSD-2-Clause-Patent.html), whose full text is in
[`src/common/bytewords.c`](src/common/bytewords.c). Releases also link
[libsodium](https://libsodium.org) (ISC), [liboqs](https://openquantumsafe.org) (MIT), [Mbed
TLS](https://www.trustedfirmware.org/projects/mbed-tls/) (Apache-2.0) and
[libsecp256k1](https://github.com/bitcoin-core/secp256k1) (MIT), each under its own license.
