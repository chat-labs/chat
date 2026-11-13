# Changelog

## Unreleased

chat-core released on its own, with a version of its own: chat's protocol, encryption and
networking as a Rust library, with the API every interface uses, and `chat-json`, version 1 of
chat's JSON interface.

### Added

- `protocol::text::console_marks`: the parts of a line of chat's own text (a note, or the
  network's log) to highlight, and what each one is (a `Mark`), for an interface to colour.
- `net::update::set_version` and `net::update::version`: the version of the program chat-core
  runs in, which it updates from and tells peers its build is. An interface with its own version
  sets it as it starts; chat-json's is chat-core's.
- chat-json's `suggest`, before `start`: a new room's id and password, made up as `start`
  makes them, for a program to show and let its user change.
- A call keeps what's sent while its peer is away, and what they haven't acked, in an outbox,
  and sends it once they're back and trusted (`RoomConfig::call`, `RoomConfig::outbox`,
  `Event::Outbox`, `CommandError::OutboxFull`; up to 64 messages). A save keeps it sealed
  (`Save::outbox`, `Save::set_outbox`), and chat-json says it in `outbox` and takes it back in
  `start`'s `outbox`, with `call`.
- A call's history id comes from the two keys (`IdentityKeypair::contact_id`) rather than the
  day's room, so its history is the same from one day to the next.
- Settings keep the calls to reopen, by the verified key each is with (`[calls]`).

### Changed

- `/update`, with betas on, takes the newest of chat's releases, not chat-core's.

### Fixed

- chat-json's `start` uses the tor in its route's `tor` (`socks`, `control`, `password`,
  `launch` and `path`), which it read past before, so a room always took the defaults.
- Logging in to a running tor with its cookie (SAFECOOKIE) works: tor's challenge is in capital
  hex, which was taken as malformed.
- chat-json's `start` for a new room with an id and no password makes one up in words, as
  without the id, instead of opening it with an empty password.
