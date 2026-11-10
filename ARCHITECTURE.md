# How chat is built

chat is one repository, a Cargo workspace with a crate for each part, and the Android app in a
repository of its own. **chat-core** is chat: the protocol, the encryption, the networking and
everything else that makes it work. The others are interfaces to it, and nothing more.

```
chat/                    this repository: one Cargo.lock, one target folder, shared build profiles
├── chat-core/           the core: a Rust library, and chat-json
├── chat-tui/            the terminal UI      chat-core = { path = "../chat-core" }
└── chat-gui/            the desktop UI       chat-core = { path = "../chat-core" }
chat-apk/                the Android app, its own repository: chat-core through chat-json or a binding
```

| Part | What it is | How it uses chat-core |
| --- | --- | --- |
| chat-core | The protocol engine, the runtime that puts it on the network, and the API every interface uses. Also `chat-json`, which serves that API to programs in other languages. | |
| chat-tui | The terminal UI (the `chat` binary). | A Rust dependency, by path. |
| chat-gui | A desktop UI, in Rust. Not started. | A Rust dependency, by path, as chat-tui. |
| chat-apk | The Android app. Not started. | `chat-json` as a process, or the in-process binding once it exists. |

## What goes where

**If two interfaces would need it, it belongs in chat-core.** That's:

- the wire protocol: rooms, handshakes, rekeys, messages, replies, DMs, delivery and retries
- the cryptography: room keys, ratchets, verify codes, signing identities, verified and ignored keys
- networking: Tor (with bridges), the Nostr relays, UDP, the LAN, the DHT, port mapping
- files: offers, transfers, saving, and cleaning and decoding pictures
- invites, QR codes, calls and moving a room
- what text from peers may contain, and the rules for nicks
- settings, and what's saved on disk

An interface keeps only what's about being that interface: drawing, layout, keys and gestures,
notifications, the clipboard, opening links, picking files, and how it words its own screens.

## Inside chat-core

```
src/
├── lib.rs        the public API: Client, Room, RoomConfig, Event, Command, ...
├── protocol/     the engine: no I/O at all
├── net/          the runtime: every socket, file and clock
└── bin/chat-json.rs   the API over JSON Lines
```

- **`protocol/`** is the engine. A `Session` is one member of one room. It's handed datagrams, the
  time and commands, and gives back what to send and what happened. It never opens a socket,
  reads a clock or touches a file, so it's deterministic, and the tests run it on a simulated
  network with simulated time.
- **`net/`** is the runtime. It runs a `Session` for each room on tokio, over Tor, the relays and
  UDP, and does the filesystem work (saving files, Tor's folder). It's the only place with I/O.
- **`lib.rs`** is the API. `protocol/` never depends on `net/`; `net/` builds on `protocol/`; the
  API and `chat-json` build on both.

## Plugging an interface in

- **In Rust** (chat-tui, chat-gui): depend on chat-core by path. Make one `Client`, `join` a room for
  a `Room` and its `RoomEvents`, send `Command`s (or call `Room`'s methods for them), and draw the
  `Event`s as they come.

  ```rust
  let client = chat_core::Client::new();
  let (room, mut events) = client.join(chat_core::RoomConfig::create("alice")).await?;
  room.send("hello").await?;
  while let Some(event) = events.recv().await { /* draw it */ }
  ```

- **In another language, as a process** (chat-apk now): run `chat-json`. Events come out on stdout
  and commands go in on stdin, one JSON object a line. It's version 1 of chat's JSON interface.
- **In-process on a phone** (chat-apk later): `chat-core`'s C ABI (`ffi`, `include/chat.h`),
  next to `chat-json` and speaking the same JSON interface, so every platform gets the same API.

## Rules

1. **The boundary is data.** Everything that crosses it (`Event`, `Command`, `RoomConfig`,
   `RoomInfo` and what they hold) serializes with serde. A new feature adds to those types, so the
   Rust API, `chat-json` and a binding all get it at once.
2. **Interfaces don't reimplement chat.** When one needs something chat-core knows (reading an
   invite, wording a timer, cleaning a nick, drawing a QR code, decoding a picture), it uses
   chat-core's public helper for it, or adds one there. The helpers it may use are the public
   items of `protocol` and `net`, such as `protocol::names`, `protocol::text`, `protocol::qr`,
   `protocol::picture` and `net::files`.
3. **Interfaces go through `Client` and `Room`.** They never drive a `protocol::session::Session`
   themselves.
4. **chat-core has no interface.** It never draws, prompts, reads a terminal or assumes there is
   one. The text it does produce (notices, the network report) is plain, and reads right anywhere.
5. **`protocol/` does no I/O.** Anything that needs a socket, a file, the clock or a long wait goes
   in `net/`, and reaches the engine as data.
6. **One change updates every interface.** A change to the API updates chat-tui, `chat-json` and
   any other interface in the same commit. `chat-json` stays compatible within its interface
   version.
7. **The wire stays compatible.** chat-core keeps speaking the protocol peers already speak. New
   behaviour on the wire is announced with a capability (a letter in `k`) and used only with peers
   that announce it too.
8. **Nothing to install.** Every binary runs as it is: its libraries are compiled in, Tor
   included. Where there's a choice, a dependency is an audited one, and its version is pinned
   when chat relies on its details (Arti is pinned exactly). An interface adds only what it needs
   to draw.
9. **Each crate stands on its own.** It has a README and a justfile with the same recipe names
   (`build`, `test`, `lint`, `fmt`, ...), run in its folder or from the top as a module
   (`just core::test`); the top justfile runs them across the workspace. It has its own version
   and `CHANGELOG.md`, and is released on its own. Every crate is GPL-3.0-only, Rust edition
   2024, with the same `rust-version`. No code, test or document refers
   to any other implementation of chat.
10. **Behaviour is tested in chat-core**: unit tests, known answers, the simulated network, and
    pairs of `chat-json` processes. An interface tests its own presentation.
