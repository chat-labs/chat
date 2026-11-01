# Usage

```
chat [--nick NAME] [--colour NAME|#HEX] [--identity age|pgp[-nonick|:KEYFILE]] [--simple | --json]
     [--routing udp|tor] [--nodht] [--noipv6] [--nolan] [--noportmap]
     [--nostr off|fallback|always] [--relay wss://HOST ...]
     [--tor-launch auto|always|never] [--tor-path PATH] [--tor-socks HOST:PORT]
     [--tor-control HOST:PORT] [--verify-required] [--file-limit SIZE]
     [--fast-files] [--betas] [--nosandbox]
     [--session ID --port UDP_PORT --peer HOST:PORT ...]
chat --update [--betas] | --version
```

## The full-screen UI

In a terminal, `chat` opens a full screen UI. The sidebar on the left lists your sessions
(switch with Tab / Shift+Tab), the peers in the selected one and how each is verified, and how
that session reaches them: route, port or tor, relays, port mapping, DHT and traffic. The rest
of the screen is the selected session's chat, with its console above it, and you type in the
box at the bottom.

In the chat, a symbol after a name stands for what chat adds to it: `◆` you, `✓` code compared, `?`
code not compared, `✗` codes differ. Under each peer, the sidebar spells out the symbols that apply
to them, with `h` for a peer keeping a history, `!` for a modified client and `i` for one you
ignore. When the sidebar is too short for that, the symbols go next to each name instead. With more
sessions or peers than fit, those lists scroll with the mouse wheel, a row says how many more are
above or below, and the sessions keep the selected one in view as you switch.

A faint `•` after a message of yours means every peer it went to has it: each acked it. Acks
were always sent, so nothing new goes on the network. If a peer still hasn't after the last try,
or left first, it says `not reached: bob` in yellow instead. Copies others pass on to peers
you're not connected to aren't acked back to you, so it's about the peers you're connected to.
There are no read receipts: they'd tell people when you look.

> NOTE: This TUI was heavily assisted by UI, as I have mentioned across most my projects, I hate, and suck at, UI / Front-End development. If any front-end devs would like to improve the functionality, performance, and/or aesthetic of this, be my guest!

A session with unread messages shows how many next to its name, in yellow with an `@` if one
mentions you. With the sidebar hidden, the chat's title shows how many are new in other
sessions. When you go back to that session, a `N new` line marks where they start, until you
leave or send something. Your nick is highlighted wherever someone mentions it.

It uses the terminal's own colours (foreground, background and the 16 colour palette), so it
matches whatever theme the terminal has, light or dark, and follows it if it changes. Peers'
colours are exact, but chat asks the terminal for its background colour and adjusts any that
wouldn't be readable on it. `NO_COLOR` limits it to bold, faint and reverse.

It starts on the settings page, so routing, nickname, colour, signing identity and the rest are
all set up in one place. **Start chatting**, on the **Start** page after the sections (or `Esc`),
goes to your sessions.
Nothing goes on the network before that: no tor is looked for or started, and no `--peer` name
is looked up (in Tor mode it never is, since that would go around Tor). Once `:install` has
saved your settings, it starts on your sessions, and `Ctrl+S` opens the page.

## Keys

| Key | Action |
| --- | --- |
| `Ctrl+N` | create a new session, with a random password filled in (type to use your own) |
| `Ctrl+J` | join an existing session (id, then password, or an invite from `:invite`), or with rooms kept, pick one of them |
| `Tab` / `Shift+Tab` | next / previous session (`j` / `k` in NORMAL too) |
| `PgUp` / `PgDn` | scroll the chat back / forward (`Ctrl+U` / `Ctrl+D` in NORMAL, `G` the newest) |
| `Up` / `Down` | scroll the chat by a message (they move through lists elsewhere) |
| mouse wheel | scroll what it's over: the console a line at a time, the sidebar's sessions or peers when there are more than fit, otherwise the chat by a message (or a list). chat has the terminal report the mouse, so hold `Shift` to select text (`Option` in iTerm2) |
| `Ctrl+B` / `Ctrl+O` / `Ctrl+T` | toggle sidebar / console / chat pane (`s` / `c` / `C` in NORMAL) |
| `Ctrl+F` | the files page: what's been offered here and yours, to show, save or stop (`f` in NORMAL) |
| `Ctrl+S` | settings |
| `F1` | list all commands and keybinds (`?` in NORMAL, and `:help`, too) |
| `Ctrl+C` | quit, after a box saying what's open and what isn't saved: `Ctrl+C` again (or `y`) quits. Every session leaves cleanly first, or with `:set reopen on` goes offline, to open again as chat starts |
| `Ctrl+L` | lock the screen until the save's passphrase, or a PIN, unlocks it (`:lock` too; see [Lock screen](security.md#lock-screen)) |
| `Ctrl+\` | panic: clear the screen and quit at once, without asking (see [Panic key](security.md#panic-key)) |

## The bottom row and the input line

The bottom row is the same on every screen: a chip for where you are (`INSERT`, `NORMAL`,
`COMMAND`, `SETTINGS`, ...), whether you're signing, your nick, the reply to what you just did
(until your next key), and what the keys do there. When the keys don't all fit, the first ones stay,
and so does the last: the way out of where you are, or to the help.

The input line is a small vim. It starts in NORMAL (`h`/`l` move, `0`/`$` go to the ends, `x`
deletes, `j`/`k` switch session, `s`/`c`/`C` toggle the sidebar/console/chat, `f` opens the
files, `o` the newest link). `i`/`a`/`I`/`A` go to INSERT, where Enter sends, `Ctrl+W` deletes the word before the
cursor and `Ctrl+U`
everything before it, and `Esc` goes back to NORMAL. The input box border is the mode's colour,
and the box grows a row at a time as what you type wraps, up to six rows (fewer on a short
terminal), then scrolls. The count under it goes red once a message is over 880 bytes, and `Enter`
then leaves it in the box instead of sending it cut off. A peer on 0.5.0's betas or older only
reads 250 bytes of a message, so a longer one goes to them in parts, cut between words, each a
message of its own. Anything chat asks for (a password, a
session id, a new setting value, whether to carry on) comes up in a box over the screen, titled
with what it's for and with its keys on the bottom edge. `Enter` confirms, `Esc` cancels, and
your draft comes back after. Yes/no questions take `y` or `n`.

Typing `@` and the start of a nick shows the rest of the name dimmed, and `Tab` completes it.

## Links

Links in messages are underlined: `http://` and `https://` addresses, and domain names like
`ieji.de/@ida` or `chat.vin.moe`, which open as `https://`. A file name that ends like a domain
(`notes.md`, `chat.sh`) is underlined too.

In a terminal that takes hyperlinks (OSC 8: kitty, WezTerm, foot, iTerm2, Windows Terminal, GNOME
Terminal and others), a link can be clicked, the way that terminal opens links. chat has the
terminal report the mouse, so most want `Shift` held as well. The terminal opens it, without asking
chat.

`o` in NORMAL (or `:open`) shows the newest link in a box: the whole address it opens, and who sent
it when. `j` / `k` go to older and newer links, `y` opens it in your browser, `c` copies it, and
`n` or `Esc` closes the box. `:open N` starts at the Nth newest, and `:open LINK` takes a link you
type or paste. On Linux the desktop portal opens it, so the [sandbox](security.md#sandbox-linux)
stays as it is; without a portal chat runs `xdg-open`, which the sandbox doesn't allow. macOS uses
`open`, and Windows the browser it has set for links.

However it's opened, your browser fetches the link directly, not through chat's Tor or relays: the
site sees your IP address, and when you opened it. When the link comes from a peer, that site may
be theirs.

## Pasting

chat asks the terminal to mark where a paste starts and ends (bracketed paste), so a
paste is only ever text. It goes into the input box, from NORMAL too, its lines run together with a
space between them, and nothing is sent until you press `Enter`. Nothing in a paste can run a
command, answer a y/n question or press a key: in a box it only goes into the field, without its
line ends (bridge lines pasted into **Bridges** are kept apart with `;`), and anywhere else it's
ignored. A terminal without bracketed paste sends a paste as if it were typed, line ends and all.

## Commands

`/` on an empty line, in INSERT or NORMAL (or `:` in NORMAL), opens the command line, with a
menu of matching commands. After `set ` it lists the settings and their current values, and
after `set NAME ` the values that setting takes. After a command that takes a nick (`verify `)
it lists online peers whose nick starts with what you've typed, with the rest dimmed like with
`@`. `Up` / `Down` pick from the menu, `Tab` completes, `Enter` runs (a part typed command runs
whatever the menu has picked, so `/se` runs `/set`) and `Esc` goes back. A line starting with
`/` that can't be a command (`/shrug`, `/usr/bin`) turns back into text as you type, and
`Enter` sends it like a normal message. `//` does the same straight away. Anything else is sent
as a message. `:help` opens a page with every key and command, and `Enter` on a command there
puts it on the command line. The pane under the list shows the selected one in full, which a narrow
terminal cuts off in the list.

| Command | Action |
| --- | --- |
| `:new`, `:join` | create / join a session (same as `Ctrl+N` / `Ctrl+J`) |
| `:call NICK` | open the room only you and a verified key can work out, which they open with `:call` too (see [Calls](security.md#calls)) |
| `:keep [LABEL\|forget]` | keep this room in the open save, under LABEL (or its id), to join it again from `Ctrl+J`; `forget` lets it go (see [Kept rooms](saves.md#kept-rooms)) |
| `:quit` (`:q`) | leave this session; quits when none is open |
| `:quitall` (`:qa`) | leave every session and quit, keeping none to reopen |
| `:lock` | lock the screen until the save's passphrase, or a PIN, unlocks it (the lock key, `Ctrl+L`, does the same) |
| `:set [NAME [VALUE]]` | change a setting (see below); on its own, opens the settings page (`Ctrl+S`) |
| `:verify NICK [ok\|no]` | show a peer's verify code and identity fingerprint; `ok` once the code matches theirs, `no` if it doesn't |
| `:verified [forget NICK\|all]` | list the signing keys you verified, with nicks and fingerprints, or remove them |
| `:timer [off\|10m\|2h\|1d]` | messages in this session go off every screen that keeps to it after that long; alone, says which timer is kept to (see [Message timer](saves.md#message-timer)) |
| `:reply NICK TEXT` (`:re`) | answer NICK's last message in the room, quoting the start of it (faint, after `↪`) |
| `:ignore [NICK [off]]` | hide what a peer says, here and wherever they sign with the same key, on your screen only; `off` shows it again, and alone it lists who's ignored (see [Ignoring someone](security.md#ignoring-someone)) |
| `:msg NICK TEXT` (`:dm`) | a direct message to one peer you're connected to: nobody else gets it, and it's never passed on (see [Direct messages](security.md#direct-messages)) |
| `:move` | move to a new room with the peers whose verify codes you compared, leaving the rest behind; each is asked first (see [Moving a room](security.md#moving-a-room)). With a request to move waiting, shows it again |
| `:peers` | who's online, with verify codes and builds |
| `:net` | network report and diagnosis |
| `:port [N]` | show or change this session's UDP port (`0` picks a free one) |
| `:copyid` | copy the session id to the clipboard, which it comes off again after 30 seconds |
| `:invite` | copy the session's id and password to the clipboard as one invite, which `Ctrl+J` takes in place of the id (see [Security](security.md#session-ids-passwords-and-invites)); it comes off after 30 seconds |
| `:newtor` | new Tor circuits and a new onion address for every session in Tor mode (see [Routing](routing.md#new-circuits)) |
| `:update` | install the latest release |
| `:install [NAME]` | save your settings and signing key on this computer, after telling you what that leaves on disk; a new save asks for its name (blank picks a random one), and with NAME it's a save of that name (see [Installing](saves.md)) |
| `:save` | save what's in use now to the save that's open, after asking (`:install` if none is) |
| `:uninstall [NAME]` | delete what `:install` saved (the save in use, or the one called NAME) |
| `:exportkey` | write your signing key, unencrypted, to a new file in a folder you pick, after asking, to load it on another device (see [Signing identities](security.md#signing-identities)) |
| `:history [forget [all]]` | whether this session's history is kept; `forget` deletes it, `forget all` every session's (see [History](saves.md#history)) |
| `:changelog` | show changelog (`:news`); built in, so it works offline |
| `:send [asis] [PATH]` | offer a file, or pick one in a file browser without PATH; a picture goes without what could tell where, when or with what it was made, unless `asis` (see [Files and pictures](files.md)) |
| `:files` | the files page (`Ctrl+F`): the files offered here and yours, to show, save or stop; with `--simple`, a list |
| `:download [N] [anyway] [FOLDER]` | save file N in `~/Downloads` or FOLDER (`:dl`); the newest file without N; `anyway` if it's over your size limit |
| `:saveto N [anyway]` | pick a folder in a file browser and save file N there |
| `:show N [anyway]`, `:hide N` | draw picture N in the chat where it was offered (yours too), or hide it |
| `:cancel N` | stop fetching file N or take it off the queue, or stop offering one of yours |
| `:open [N\|LINK]` | the newest link in the chat (`o` in NORMAL), the Nth newest, or LINK, in a box that opens it in your browser or copies it (see [Links](#links)) |

## Settings

Every setting is a row on the settings page, and applies straight away to every open session
and any you open after. `:set NAME VALUE` sets a row without opening the page, and `:set NAME`
opens the page on that row. The command line menu lists the names after `:set `, and the values
after a name. Under each row's help, the page shows the `:set` command that does the same thing.

| Name | Values |
| --- | --- |
| `routing` | `udp`, `tor` |
| `dht`, `dht6`, `portmap`, `lan` | `on`, `off` |
| `nostr` | `fallback` (only while needed), `always`, `off` |
| `relays` | up to 6 `wss://` URLs |
| `torlaunch` | `auto`, `always`, `never` |
| `torpath`, `torsocks`, `torcontrol` | a path, `HOST:PORT`, `HOST:PORT` |
| `torpassword` | only on the page, where it's hidden |
| `bridges` | bridge lines for chat's own tor, separated by `;` (the console only shows how many) |
| `transports` | the folder with lyrebird and snowflake-client, or empty to look next to tor and on `PATH` |
| `torguards` | `on` (chat's own tor keeps its guards and directory in the save), `off` |
| `nick`, `colour` | a name; a colour name or `#RRGGBB` |
| `sign` | `off`, an `age` or `pgp` key made from a password typed on the page and your nick, `age-nonick` / `pgp-nonick` for one made from the password alone, or `age:PATH` / `pgp:PATH` for a key file; a pasted key is picked on the page |
| `autosave` | `on` (once installed, a setting or verified key you change is saved straight away), `off` (it's kept until `:save`) |
| `devicelock` | `on` (the save only opens on this device), `off` |
| `securitykey` | `on` (the save needs your FIDO2 security key too), `off` |
| `authenticator` | `on` (the save asks for an authenticator app's code too), `off` |
| `destroy` | `off`, `3`, `5`, `10` (the save is deleted after that many wrong passphrases in a row) |
| `shadow` | `on` (asks for a second passphrase, which opens a decoy in the save's place), `off` |
| `lock` | `off`, `1m`, `5m`, `15m`, `30m` (the screen locks after that long without a key; with no save open, it asks for a PIN first) |
| `lockkey` | `ctrl+l`, `ctrl+g`, `ctrl+k`, `f9` (the key that locks the screen), `off` |
| `panickey` | `ctrl+\`, `ctrl+q`, `ctrl+x`, `f12` (the key that panics), `off` |
| `panicwipe` | `on` (the panic key deletes the open save too), `off` |
| `panichistory` | `on` (the panic key writes the history kept first), `off` |
| `sandbox` | `on` (Linux: once chat reaches the network, it can only write to the folders in your home that aren't hidden or on `PATH`, its own and the temporary folders, and only run tor and its transport programs), `off`; from the next start |
| `updater` | `on` (Linux, with the sandbox on: `chat-updater`, a second process started just before the sandbox goes up, does `:update`'s work outside it), `off` (no second process, and `:update` sends you to `chat --update`); off stops it now, on starts it from the next start |
| `verify` | `required` (nothing goes to a peer until you've compared its code), `optional` |
| `filelimit` | the biggest file fetched without `anyway`: `8M`, `500K`, `1G` |
| `fastfiles` | `on` (what you send goes in quick bursts; through the relays, as fast as they allow), `off` (chat's regular slots) |
| `noise` | `on` (a JPEG you send gets noise nobody can see, so no two copies match), `off` |
| `notify` | `all`, `mentions`, `none` |
| `preview` | what a notification shows: `off` (only that a message came), `nick` (who from), `message` (who, and what); never the session |
| `history` | `on` (each session's messages are kept, sealed in the save that's open, and everyone in it is told), `off` |
| `reopen` | `on` (the sessions open are kept, sealed in the save that's open, and open again as chat starts; `Ctrl+C` then goes offline in them rather than leaving), `off` |
| `net` | `normal`, `verbose` (every handshake packet, relay and Tor event), `off` (none of the network's news, such as lookups, relays and Tor starting up: only problems that keep a session from connecting) |
| `port` | the UDP port for new sessions (`0` picks a free one) |
| `betas` | `on` (`:update` installs betas too), `off` (only releases) |

The settings page shows one section at a time (Network, Profile, Security and Chat, listed on the
left), with its rows grouped under headings. **Done** comes last in that list (**Start** on the page
chat opens on): its button closes the page, and under it every setting chat is using is listed by
section, where `Enter` on a row opens it in its own section. `j`/`k` go on from one
section into the next. The settings page, the pages under it (the signing identity picker and the
key file browser) and the help page all use the same keys: `j`/`k` move, `g`/`G` go to the
top/bottom, `Tab` / `Shift+Tab` (or `PgDn` / `PgUp`) go to the next / previous section, round from
the last to the first, and `1`-`9` go to a section by its place in the list. On the settings page
that's the row you were on there last. `Enter` picks, `h`/`l` change a value or go out of / into a
page, `Esc` goes back and `q` closes the page. In the file browser, `~` goes to the home folder, and
in the key file browser `/` types a path instead.

On the settings page, `/` searches every section: type part of a setting's name, its `:set` name or
a word from its help, and the matches are listed best first, with where each one is. `Up`/`Down`
(or `Tab` / `Shift+Tab`) pick one and `Enter` opens it in its section. A setting that doesn't apply
right now (a Tor one with UDP routing) is marked hidden, and `Enter` on it says why.

With `--simple`, `:set` only covers `nick`, `colour`, `notify`, `preview` and `net`.

## Updating

`:update` in chat, or `chat --update` from the shell without opening chat, checks the
[latest GitHub release](https://github.com/chat-labs/chat/releases/latest). If it's newer than
the build you're running, chat checks the release's `SHA256SUMS` has a valid signature from the
release key built into chat, downloads the binary for your platform, checks its SHA-256 against
`SHA256SUMS`, and replaces the executable in place. A release without a valid signature is
refused. Restart chat to run the new version. In chat, `:update` shows each step in a box as it
goes, with a progress bar for the download. Esc hides the box and the update keeps going.
`chat --update` exits with status 1 if the update failed. It needs `curl` (on `PATH` on Linux,
or on Windows the one built into Windows 10+ in `System32`) and write access to the folder the
executable is in.

Betas, the test builds of the next release, are opt-in: with `betas` on (`:set betas on`, or
`--betas` for one run), `:update` and `chat --update` install the newest release on the
[releases page](https://github.com/chat-labs/chat/releases), betas included. A beta is signed
and checked the same way as a release. With `betas` off, a beta you're running stays until its
release is out, and `:update` then takes you on to that.

## Options

Options given here override what `:install` saved, for that run.

| Option | Meaning |
| --- | --- |
| `--nick NAME` | Display name (random `swift-otter42` style name if left out) |
| `--colour NAME\|#HEX` | Display colour (random by default; `--color` works too) |
| `--routing` | `udp` or `tor`, preset on the settings page (see [Routing](routing.md)) |
| `--nodht` | Don't use the BitTorrent DHT (IPv4 and IPv6) |
| `--noipv6` | Don't use the IPv6 DHT |
| `--nolan` | Don't use LAN broadcast discovery |
| `--noportmap` | Don't ask the router to forward a port |
| `--nostr` | The Nostr relays: `fallback` (only while they're needed, the default), `always` or `off` |
| `--verify-required` | Send nothing to a peer until you've compared its verify code |
| `--file-limit SIZE` | The biggest file fetched without `anyway` (default `8M`, up to `1G`) |
| `--fast-files` | Send files in quick bursts instead of chat's regular slots (through the relays, as fast as they allow) |
| `--relay URL` | A Nostr relay (`wss://...`) to use instead of the defaults; up to 6 |
| `--tor-launch auto\|always\|never` | Which tor Tor mode uses: a running one if there is one, otherwise chat's own (`auto`); always chat's own; or only a running one |
| `--tor-path PATH` | The tor program chat starts (default: `tor` on `PATH` or in the usual folders) |
| `--tor-socks`, `--tor-control` | Where to look for a running tor's SOCKS and control ports (`HOST:PORT`) |
| `--identity ...` | `age` or `pgp` for a key made from a password (asked for, or `CHAT_SIGN_PASSWORD`) and your nick, `age-nonick` or `pgp-nonick` for one made from the password alone, or `age:KEYFILE` or `pgp:KEYFILE` for your own (see [Security](security.md#signing-identities)); for that run, instead of a key `:install` saved |
| `--save NAME` | Open the save called NAME, without the list of saves (`default` is the one in `~/.config/chat` itself); if there isn't one, start from the defaults and let `:install` make it (see [Installing](saves.md)) |
| `--simple` | Plain `[HH:MM] ...` lines, one session, stdin, `:name` runs a command. Used automatically when stdout isn't a tty |
| `--json` | One session for another program to drive, with JSON Lines on stdin and stdout (see [JSON interface](json.md)). It opens no save |
| `--nosandbox` | Don't put the sandbox up for that run (Linux; `:set sandbox off` keeps it down) |
| `--session ID` | Join a session at startup (with `--port`, `--peer`) |
| `--update` | Install the latest release and exit, without opening chat (see [Updating](#updating)) |
| `--betas` | Let `:update` and `--update` install betas too, for that run (`:set betas on` keeps it) |
| `--version` | Print the version and exit |
