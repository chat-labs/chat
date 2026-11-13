# chat-tui

chat in the terminal: end-to-end encrypted rooms with no
server and no accounts. It's a UI and nothing more. Everything else (the protocol, encryption,
Tor and networking) is [chat-core](../chat-core), and chat-core's
[ARCHITECTURE.md](../ARCHITECTURE.md) has the rules for what goes where.

```
╭─ ◆ chat ────── v0.6 ─╮─ console ─────────────────────────────────────────────╮
│ SESSIONS           1 │ 10:47 alice (unverified) joined (2 online)            │
│ ❯ DT2BYMPV4M     ● 2 ├─ DT2BYMPV4M · 1 other here · Tor ─────────── 10:48 ─┤
│                      │ 10:47 bob: hi @alice ✓                                │
│ PEERS              2 │ 10:47 alice: ↪ bob: hi @alice · welcome!              │
│ ● bob                │ 10:47 alice → you: psst, a direct one                 │
│   ◆ you              │                                                       │
│ ● alice              │                                                       │
│   ✓ code compared    │                                                       │
│                      ├───────────────────────────────────────────────────────┤
│ NETWORK              │ ❯ Message DT2BYMPV4M                                  │
│ route   tor          ┴───────────────────────────────────────────────────────╯
 INSERT  ✓ signed age  bob            enter send · / commands · esc normal · f1 help
```

## Using it

```sh
chat                      # Tor: nobody learns your IP address, peers included
chat --direct             # faster, but shows your IP address to peers
chat --simple             # plain lines in, plain lines out, for scripts and basic terminals
chat --json               # one room as JSON Lines, for another program to drive
chat --help               # every option
```

- `Ctrl+N` starts a room, with a random password filled in (or type your own); `/invite` copies
  its invite, and shows it as a QR code for a phone to scan. `Ctrl+J` joins one: a room kept in
  the save, an invite, or a room's id and then its password.
- `Tab` switches rooms, or completes an `@name`. `PgUp`/`PgDn` (or the mouse wheel) scroll.
- The line has three modes, shown at the bottom left: INSERT types; `Esc` goes to NORMAL, where
  vim's keys move about the line (`h l 0 $ x`, `i a I A` to type again), `j`/`k` switch rooms and
  `s`, `c` and `C` show or hide the sidebar, console and chat (`Ctrl+B`, `Ctrl+O` and `Ctrl+T` from
  anywhere); and `/` on an empty line (or `:` in NORMAL) opens the command line, with a menu over
  it of what can go next: `Tab` completes, `Up`/`Down` pick.
- The console, over the chat, has the room's notes and the network's; warnings go in the chat
  too.
- `/msg NAME TEXT` sends a direct message. `/reply NAME TEXT` answers NAME's last message, quoting it.
- `/verify NAME` opens the verify-code check (`/verify NAME ok` or `no` answers it at once). The
  sidebar's PEERS then marks each peer: ✓ code compared, ? compare code, ✗ codes differ or key
  changed, h keeps history, ! modified client, i ignored.
- Your own messages get a ✓ once every peer has them, or say who missed them.
- `/send PATH` offers a file (`/send` alone picks it in a file browser). Nobody gets it unless they fetch it: `/download N` saves it (in
  Downloads, or `/downloads FOLDER`), `/show N` draws a picture right in the chat, `/files` lists
  them all and how they're going, and `/saveto N` picks the folder in a file browser. A picture goes without what could tell where, when or with
  what it was made (`/send asis PATH` sends it as it is).
- `/fast on` speeds up what you send while a transfer runs (visible as a burst); `/limit 50M`
  changes the size over which a download needs `anyway`.
- `/identity` gives you a signing key: `/identity age` (or `pgp`) makes it from a password, the same
  key every time on this device; `/identity new age` makes one for this run; `/identity file PATH`
  reads yours; the settings page's Signing identity also picks a key file in a file browser, or
  takes one pasted in. Once someone has verified you (`/verify`), they needn't compare codes with
  you again, in any room. `/verified` lists the keys you verified.
- `/call NICK` opens a room only you and NICK (a key you verified) can work out, for today; they
  `/call` you too. What you send while they're away waits for them (sealed in your save, if one's
  open) and goes once they're back, its history carries on from day to day, and `/set reopen on`
  opens it again next time.
- `/move` takes the people whose codes you compared to a new room with a new password, and leaves
  everyone else behind; each is asked first. Codes compared here still count there.
- `/install` saves your settings, signing key and verified keys on this computer, sealed with a
  passphrase you type twice; chat asks for it as it starts (or reads `CHAT_INSTALL_PASSWORD`), and
  `Esc` goes on without it. `/save` saves what's in use, `/set autosave on` saves changes as they
  happen, and `/uninstall [NAME]` deletes a save. `--save NAME` picks one of several.
- `/keep [LABEL]` keeps the room in the save, so `/join LABEL` opens it again.
- chat starts on the settings page, and nothing goes on the network until `Start chatting` (or
  `Esc`); a save with settings in it starts at once.
- `Ctrl+S` (or `/set`) opens the settings page: a page for each section, listed on the left
  (`Tab` or `1`-`5` goes through them), rows under their headings, and the picked row's help and
  `/set` command at the bottom. `h`/`l` change a row, `Enter` edits or opens it, `/` searches every
  row, and the last page has them all. `/set NAME VALUE` changes one setting.
  `/set history on` keeps each room's history in the save, `/set reopen on` opens the same rooms
  next time, and `/set destroy 5`, `/set shadow on` and `/set authenticator on` change how the save
  is unlocked.
- `Ctrl+F` (or `/files`) opens the files page: save, show or stop each one.
- `/open` shows the newest link in the room (or the Nth, or one you type) before opening it.
- `Ctrl+L` (or `/lock`) locks the screen until the save's passphrase (or a PIN) unlocks it, and
  `/set lock 5m` locks it by itself. `Ctrl+\` panics: chat quits at once, clearing the screen and
  saving nothing.
- Desktop notifications follow `/set notify all|mentions|none`, and show who and what only as far
  as `/set preview` allows. They never name the room.
- `/port [N]`, `/copyid`, `/history [forget [all]]`, `/quitall` and `/changelog` do what they say.
- `F1` (or `?` in NORMAL) lists every key and command; `Enter` on a command puts it on the command
  line.

Rooms go through Tor unless you choose `/route direct` (or start with `--direct`). The Nostr
relays, reached through Tor too, find members faster; `/relays off` turns them off. Tor is built
in, so there's nothing to install. Its state goes in a private folder deleted on exit, unless you
give `--tor-dir` one to keep. Where Tor is blocked, `/bridges LINE; LINE` (from
[bridges.torproject.org](https://bridges.torproject.org)) makes it go only through bridges;
obfs4 and snowflake ones need lyrebird or snowflake-client installed (`/transports FOLDER` if
they aren't on PATH). They're asked for again each run.

## Building

chat-tui builds with chat-core, from the same workspace. [just](https://github.com/casey/just)
runs the usual things, in this folder or as `just tui::...` from the top; `just` alone lists them.
What's built goes in the workspace's `target/`.

| Recipe | What it does |
| --- | --- |
| `just build [release]` | build `chat` |
| `just static` | a static Linux `chat` (musl) |
| `just run [OPTIONS]` | run it |
| `just install` | install it in `~/.cargo/bin` |
| `just demo` | two TUIs side by side in tmux, talking over loopback, nothing leaving this machine |
| `just test`, `just lint`, `just fmt` | tests, formatting and clippy |

## License

[GPL-3.0-only](LICENSE). Copyright © 2026 finlay@tuta.com.
