# chat-core

The core of chat: end-to-end encrypted group chat with no server and no accounts. It's the
protocol and the system that every chat UI builds on: [chat-tui](../chat-tui), and later chat-apk
and chat-gui.

## Layout

[ARCHITECTURE.md](../ARCHITECTURE.md) has how chat-core and its interfaces fit together, and the
rules for what goes where.

```
src/
├── lib.rs        a map of the crate, and the API a UI uses
├── protocol/     the engine, with no I/O: rooms, handshakes, encryption, messages
├── net/          the runtime: rooms on Tor, the Nostr relays, and direct UDP
├── json.rs            one room served over JSON Lines (chat_core::json::serve)
└── bin/chat-json.rs   that, as a program of its own, for any language
```

## Plugging a UI in

The crate root has all a UI needs: `Client`, `Room`, `RoomConfig`, and the `Event`s and
`Command`s that cross the boundary, all of which serialize.

```rust
let client = chat_core::Client::new();
let (room, mut events) = client.join(chat_core::RoomConfig::create("alice")).await?;
room.send("hello").await?;
while let Some(event) = events.recv().await { /* Message, PeerJoined, Delivery, Net, ... */ }
```

- **Rust (TUI, GUI)**: depend on `chat-core`, as chat-tui does (`chat-core = { path = "../chat-core" }`).
- **Any language, as a process**: run `chat-json`, which speaks chat's JSON interface (version 1):
  events come out on stdout, one JSON object a line, and commands go in on stdin.
- **In-process (a phone's app)**: the same JSON interface through a C ABI (`ffi`,
  `include/chat.h`): `chat_open` a room, `chat_send` it commands and `chat_recv` its events, a
  JSON object each. `just lib TARGET` builds the shared library.

## Routing

| | How peers connect | Who sees your IP address |
| --- | --- | --- |
| **Tor** (the default) | onion services, embedded (Arti); nothing to install | nobody, peers included |
| **direct** (`Route { mode: RouteMode::Direct, .. }`) | UDP between peers, found on the LAN and through the BitTorrent DHT | every peer, and the DHT |

Either way, the **Nostr relays** carry traffic when a peer can't be reached otherwise. On Tor
they're reached through Tor, on circuits of their own. They make **discovery faster**: members meet
on them at once, while onion services take a minute or two to publish and be found. They're also
where members on the two routings meet. `/relays fallback` (the default) uses them only while
they're needed, `always` keeps them on, and `off` turns them off.

Tor's state (its entry guards and its copy of the directory) goes in a private folder that's
deleted on exit, unless you give it one to keep (`--tor-dir`). Keeping one makes Tor start faster,
and it keeps the same entry guards for months, as Tor intends. Onion keys are kept in memory only.

## Dependencies: audited, and built in

The binaries need nothing installed. The crypto and TLS libraries are compiled in, and so are
Mozilla's root certificates.

| Library | For | Why it |
| --- | --- | --- |
| libsodium 1.0.22 (`libsodium-sys-stable`, the source checked against its author's minisign key at build time) | BLAKE2b, Argon2id, XChaCha20-Poly1305, X25519, Ed25519, SHA-2 | Audited, so every derivation matches byte for byte |
| AWS-LC (`aws-lc-rs`) | ML-KEM-768, and TLS's crypto | FIPS 140-3 validated; its ML-KEM is mlkem-native, which is formally verified |
| libsecp256k1 (`secp256k1`) | Nostr events' BIP-340 signatures | Bitcoin Core's audited implementation |
| rustls + webpki-roots | TLS to relays | Audited; no system TLS library or certificate store |
| Arti (`arti-client`) | Tor, embedded | The Tor Project's own Rust implementation. It's built with rustls and a bundled SQLite, and pinned to an exact version because hosting a service with our own key uses its experimental API |
| image-rs (`image`: `png`, `zune-jpeg`, `gif`) | Showing pictures peers send | Memory-safe Rust decoders, fuzzed upstream. Only PNG, JPEG and GIF are built in, told the format from the picture's first bytes, with size and memory limits |

On Linux the release `chat-json` (about 24 MB with Tor and the picture decoders) link only to libc, libm and libgcc_s. For a fully static one, `just static`
builds for musl: it needs `rustup target add x86_64-unknown-linux-musl` and a musl C compiler (or
`cargo zigbuild`).

## What's here

- Room keys from the id and password (Argon2id, 512 MiB), and invites (`chat:ID:PASSWORD:CHECK`).
- The hybrid X25519 + ML-KEM-768 handshake, with cookies (hi, ck, hi2, kx). Per-message chains
  and verify codes (in Bytewords and hex). Rekeys every 5 minutes, announced with `rk`.
- Traffic shape: masked 1004-byte UDP datagrams, room frames split into cells, one datagram per
  peer per cover slot.
- Messages, replies (`mr`, with a quote for older builds), long messages (split into parts for
  builds without `l`), mentions, and direct messages (`pm`). Messages are passed on through peers
  that can reach others, with each one shown once.
- Nicks, colours, message timers, the history flag, `bye` and `off`.
- Signing identities: AGE keys (made here or imported), session signatures, and verified and
  ignored keys shared across rooms. A peer's build is checked against the release key's signed
  list.
- Tor: each room's own onion service, and the room's six derived onion services, knocked on to find the room. Frames go over Tor streams. `ta`
  announces a member's onion, and `px` passes onions on. `:newtor` gets new circuits and a new
  onion, keeping the streams peers already opened.
- The Linux sandbox (`net::sandbox`), put up on every thread once a save's settings are known,
  before chat first reaches the network: Landlock lets chat write only in the home folder's
  folders that aren't hidden or on PATH, its own and the temporary ones (until a save makes chat's
  folder, the folder it goes in, narrowed once it's there), and run only tor and its transport
  programs; seccomp refuses the calls chat never makes (ptrace, mount, bpf, io_uring, keyrings,
  kernel modules, setting the clock...).
- A tor that's already running (`net::tor_ext`, `Client::set_tor_use`), in place of the built-in
  one: torlaunch auto uses one whose control port lets chat log in (with no password, its
  password, or its cookie, SAFECOOKIE too), never uses only one, and always the built-in one. Its
  SOCKS port carries the streams, isolated by room, and its control port hosts the onion
  services (ADD_ONION, with the room's own keys), which go when chat does.
  With `torpath` set, chat's own tor is that program, started with an empty torrc, two free local
  ports, a control password only chat knows, and its bridges, and gone when chat is; otherwise
  it's the built-in one.
- Tor bridges (`Client::set_bridges`), for a network that blocks Tor: with any set, Tor reaches
  the Tor network only through them, and a running Tor switches at once. obfs4, webtunnel and
  meek_lite need lyrebird (or obfs4proxy, without webtunnel), snowflake needs snowflake-client,
  found in a folder given for them (`Client::set_transports`) or on PATH, and only if only root
  or you can change them. Only the count and the transports are ever shown, never the lines.
- Finding peers directly: static peers, LAN beacons, the BitTorrent DHT (IPv4 and IPv6, read-only, with a
  new key and node id every hour), Nostr relays (one connection per ten-minute tag, a throwaway
  key per event), and peer exchange (`px`). A peer whose UDP path goes quiet falls back to the
  relays, and moves back when UDP works again.
- Router port mapping for direct routing (PCP, then NAT-PMP, then UPnP-IGD; `portmap: false`
  turns it off): the router forwards the room's UDP port, the DHT is given the forwarded port,
  and the mapping is renewed, then removed when the room closes.
- Files (`fo`, `fg`, `fd`, `fx`): offers, fetches a window of chunks at a time in the slots that
  would carry a nop (two a slot through the relays), checked against the offer's SHA-256 before
  they're kept, and saved under a name that never replaces a file. One file at a time from each
  sender, the rest queued; fast transfers; a size limit; fetching to show a picture rather than
  save it; withdrawing an offer. Pictures are offered cleaned of where, when and with what they
  were made, with invisible noise unless that's turned off: pictures are cleaned and
  checked byte for byte.
- Signing identities as AGE or PGP keys: made here, made from a password with this device's id
  (and the nick), or read from a key file. PGP keys are exported and imported as armored v4 EdDSA
  keys, and a password gives the same key deterministically.
  Calls (`:call`): the room only two verified keys can work out, for one day.
- Invites as QR codes (in `ready` and `moved`).
- Saves (`net::saves`): settings, the signing key, verified keys, room histories and Tor's state,
  each file sealed under one passphrase (Argon2id, 512 MiB, then XChaCha20-Poly1305) in
  `~/.config/chat` (`saves/NAME` for more than one). A save can ask for an authenticator app's
  code too, delete itself after 3, 5 or 10 wrong passphrases in a row, and have a shadow
  passphrase that opens a decoy in its place. Every save carries a spare the size of a decoy, so
  having one says nothing.
- Room histories as a save keeps them (`net::history`): a line for each chat line, up to 256 KB a
  room, the oldest first to go, and none older than the room's message timer.
- Links in text (`protocol::text::links`): addresses and bare names like `example.com/page`, without
  the punctuation around them, and the address each opens.
- A room's UDP port moved while it's open (`Room::port`), with its port mapping.
- Tor's guards and directory kept in a save (`Client::tor_state`, `Client::with_tor_state`), so the
  built-in Tor keeps the same entry guards from run to run and connects in seconds.
- A save locked to this device (`net::device::lock`), through systemd's credential service (the
  TPM where there is one, and systemd's key) or, without it, the TPM itself (`net::tpm2`: a
  session salted to its storage key, the secret encrypted on the bus, every answer's HMAC
  checked), or to FIDO2 security keys (`net::seckey`: up to four,
  over Linux's hidraw, with the hmac-secret extension, a touch, and the key's PIN where it asks).
- Settings (`net::settings`): every row a `set NAME VALUE` takes, as a save keeps them (TOML inside
  the seal, only what differs from the defaults), with the kept rooms, sessions to reopen and
  ignored keys; and the settings page every interface shows them on: its sections and groups,
  labels and help, which rows are listed when, what each row steps through, the search, and the
  signing identity's choices.
- Moving the room (`mv`, `mk`, `mp`): the peers whose codes were compared go to a new room with a
  new id and password, each asked first, and everyone else stays behind without being told
  where. Keys shown in the old room sign the sessions in the new one, so codes compared there
  count there. The old room stays only until the keys are exchanged, and a mover that has
  already left still has its key carried over.

### Reliable sending and connectivity

Every improvement is sender-side, so nothing changes on the wire:

- **Every message is acked and retried until it arrives.** Our messages keep trying while the
  peer is connected (steady at first, then backing off). Copies passed on for others are tried
  a few times too (instead of just once).
- **A peer that drops and comes back with the same session gets what it missed.** Its unacked
  messages are kept for 10 minutes. Its last address is tried again at once.
- **Per-peer delivery receipts.** Each peer that receives a message produces a `Delivered` event,
  followed by `Settled` once nothing more will be heard.
- **Re-handshakes don't lose messages.** While a new chain is unconfirmed, records go on the old
  chain the peer can still read, and nops go on the new one. The last working chain survives
  overlapping attempts. Handshake frames get priority while a re-handshake runs, and a superseded
  one is replaced in the queue. A `hi2` answering a cookie from before our rekey still counts.
  Everything waiting for an ack is resent the moment the new chain is confirmed.

  Measured through rekeys at 2.5 times the normal rate, with messages every 2 s: no losses,
  a p99 of 4–5 s, and a worst case of about 8 s.

### Not here yet

- **Device locks and security keys on macOS** (the Secure Enclave, IOHID). Windows has both: its
  TPM through NCrypt (DPAPI without one), and security keys through WebAuthn.

## Releases

chat-core has its own version, and its releases are tagged `chat-core-vVERSION`, with what each
changed in [CHANGELOG.md](CHANGELOG.md). [The top README](../README.md#releases) has how a release
is made. A program that isn't chat-json sets its own version with `net::update::set_version` as
it starts: it's what it updates from, and what peers are told its build is.

## Building and testing

[just](https://github.com/casey/just) runs the usual things, in this folder or as `just core::...`
from the top; `just` alone lists them. What's built goes in the workspace's `target/`.

| Recipe | What it does |
| --- | --- |
| `just build [release]` | chat-core, and chat-json |
| `just static` | a static Linux chat-json (musl) |
| `just json [OPTIONS]` | run chat-json |
| `just doc` | the API documentation |
| `just test` | unit, known-answer, simulated-network and relay tests |
| `just lint`, `just fmt` | formatting and clippy |
| `just trace` | two peers through fast rekeys, every handshake step printed |
| `just interop [ROUNDS] [PEER]` | two chat-json processes in one room over loopback UDP |
| `just interop-files [PEER]` | files between two processes both ways: saved and shown, cleaned pictures, fast and normal rate, withdrawn |
| `just interop-move [PEER]` | `:move` between two processes, each moving the room and the other following |
| `just interop-rekey [SECONDS] [PEER]` | two processes through constant rekeys, with latencies |
| `just tor-pair` | two rooms meeting over the live Tor network |

- `tests/kat.rs`: known-answer test vectors (room keys, verify codes, chains,
  signatures, the room's onion services).
- `tests/engine.rs`: sessions on an in-memory network with simulated time, loss and cut links,
  Tor's onion services included. It covers handshakes, relaying, DMs, replies, rekeys (with
  latency bounds), drops and comebacks, the LAN, and relay-only rooms.
- `tests/relay.rs`: two real rooms meeting only through a websocket relay.
- `tests/files.rs`: transfers on the simulated network, through loss and rekeys, with a disk in
  memory: saving, showing, queueing, limits, withdrawn and changed files.
- `tests/picture.rs`: the picture cleaner output, byte for byte.
- `tests/interop/`: the scripts the interop recipes run. `PEER` is another chat-json build to run
  the second process (another version, say); it defaults to this one.

## License

[GPL-3.0-only](LICENSE). Copyright © 2026 finlay@tuta.com.

Bytewords (BCR-2020-012), the word list verify codes are read out with, is © 2019 Blockchain Commons, under the BSD-2-Clause Plus Patent License.
