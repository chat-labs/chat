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

### Changed

- `/update`, with betas on, takes the newest of chat's releases, not chat-core's.

### Fixed

- chat-json's `start` uses the tor in its route's `tor` (`socks`, `control`, `password`,
  `launch` and `path`), which it read past before, so a room always took the defaults.
- Logging in to a running tor with its cookie (SAFECOOKIE) works: tor's challenge is in capital
  hex, which was taken as malformed.
