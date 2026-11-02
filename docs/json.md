# JSON interface

`chat --json` runs one session for another program to drive, such as a graphical client or a bot.
Both ways it's [JSON Lines](https://jsonlines.org/): one JSON object per line, in UTF-8. What
happens comes out on stdout, each object with its type in `"t"`. Commands go in on stdin, each
named by `"cmd"`.

```sh
chat --json [OPTIONS]
```

- It opens no save, and writes nothing to disk but the files you ask it to save. The program on the
  other end keeps whatever it wants kept, such as a history or a list of rooms.
- The room's password and a signing key come in on stdin (`start`, `identity`), never in the
  arguments, where other programs can read them. The other options (`--routing`, `--tor-socks`,
  `--nostr` and the rest) are defaults that `start` can override.
- One process is one room. To be in several rooms, run one `chat --json` for each.
- Closing stdin quits, like `quit`. So does a program that stops reading stdout: chat leaves the
  room instead of waiting on it.
- New fields and types may be added in later versions, so ignore any you don't know. `"v"` in
  `hello` is the version of this interface, 1 for what's described here.

A short session, `>` for what goes in and `<` for what comes out:

```
< {"t":"hello","v":1,"version":"0.5.5","built":"2026-10-30 20:10:28 UTC, v0.5.5"}
> {"cmd":"start","create":true,"nick":"alice","route":{"mode":"tor"}}
< {"t":"ready","room":"NH7Q5KS2ZX","password":"item oboe foxy sets","created":true,"invite":"chat:NH7Q5KS2ZX:...","qr":["1111111001...",...],"me":{"id":"9f...","nick":"alice","colour":"#5fafd7"},"route":"tor","history":false}
< {"t":"peers","list":[]}
< {"t":"net","ready":false,"online":0,"pending":0,"tor":"looking"}
< {"t":"line","at":"20:41","kind":"message","text":"hi alice","mid":"ff7db1fd","from":"3c...","mine":false,"nick":"bob","peer":"3c...","colour":"#d7875f"}
> {"cmd":"send","text":"hello bob"}
< {"t":"line","at":"20:41","kind":"message","text":"hello bob","mid":"0a12c4e9","from":"9f...","mine":true,"nick":"alice","own":1,"colour":"#5fafd7"}
< {"t":"delivery","own":1,"settled":true}
> {"cmd":"quit"}
< {"t":"bye"}
```

## Commands

### Before a room

| `cmd` | Fields | What it does |
| --- | --- | --- |
| `identity` | `kind`: `age`, `pgp` or `none`; `new`: `true`, `password` (with optional `device`, `with_nick`, `nick`), or `key`: the secret key as text (and optional `created`, `export`) | Makes a new signing key, derives one from a password, reads one (`AGE-SECRET-KEY-1...`, or an unencrypted armored PGP EdDSA secret key), or (`none`) stops signing. It's used from then on, and the answer is an `identity` object. Also works in a room |
| `start` | see below | Opens the room. The answer is `ready`, or an `error` and `bye` |
| `quit` | | Ends without a room |

`start` takes these fields, all of them optional:

| Field | Meaning |
| --- | --- |
| `room`, `password` | The room's id and password. Without `room`, chat makes a new one, and without `password` for a new room, a random one in words, as the NEW box does. Without either for a room you join, the password is `CHAT_PASSWORD`, or blank |
| `invite` | An invite (`chat:ID:PASSWORD:CHECK`, as `:invite` gives it) in place of `room` and `password`. A mistyped or cut off one is an `error`, since its check doesn't match |
| `call`, `day` | A verified peer's signing public key (64 hex digits), and optionally the UTC day (`chat_contact_day` without it), in place of `room` and `password`, as `:call` opens it. Requires an `identity`, and forces `verify` to `required` |
| `create` | `true` for a new room (the default without `room`): it opens at once instead of waiting for someone to answer |
| `nick`, `colour` | Your name and colour here (`"#rrggbb"` or a colour's name); random without them |
| `route` | `mode` (`udp` or `tor`), `dht`, `ipv6`, `lan` and `portmap` (`false` turns each off), `nostr` (`off`, `fallback` or `always`), `relays` (a list of `wss://` addresses) and `tor`: `socks` and `control` (`host:port` of a running tor), `password` (its control port's `HashedControlPassword`; without it, its cookie), `launch` (`auto`, `always` or `never`, as `--tor-launch`) and `path` (the tor to start) |
| `port`, `peers` | The UDP port (0 picks one), and peers to reach straight away (`"host:port"`, not with Tor) |
| `verify` | `optional` (the default: messages go to peers whose code wasn't compared yet) or `required` |
| `notify` | `mode` (`none`, `mentions` or `all`) and `preview` (`off`, `nick` or `message`): what makes a `notify` object, and what's in it |
| `files` | `dir`, the folder files are saved in (default your Downloads); `limit`, the largest file fetched without `anyway`, in bytes; `fast` and `noise` as `:set fastfiles` and `:set noise` |
| `picture` | `max`, the largest side of a `picture` object (16 to 1024, the default), and `background`, the colour drawn under transparency |
| `history` | `true` tells everyone in the room you keep a history of it, as `:set history on` does. Keeping it is up to you |
| `timer` | A message timer to ask for, in seconds (60 to 604800) |
| `kept` | `true`: when you quit, peers are told you went offline, not that you left, as for a kept room |
| `identity` | `kind` and `key`, as the `identity` command takes |
| `trust`, `ignored` | Lists of `{source, pub, nick}` entries (`source`: `age`, `pgp` or `key`; `pub`: 64 hex digits) for verified and ignored signing keys |
| `net_log` | `normal`, `verbose` or `off`, as `:set net` |

### In a room

Peers are named by their `id`, as `peers` lists them.

| `cmd` | Fields | What it does |
| --- | --- | --- |
| `send` | `text` | Sends a message to the room. Text starting with `:` is sent as it is |
| `reply` | `mid`, `text` | Answers the message with that id, quoting the start of it. An `error` if it's too old to answer |
| `dm` | `peer`, `text` | A direct message, as `:msg` |
| `verify` | `peer`, `same` | `true` once you've compared the verify code and it matches, `false` if it doesn't (`:verify NICK ok`, `:verify NICK no`) |
| `ignore` | `peer`, `on` | Hides what a peer says, or (`false`) shows it again |
| `fetch` | `num`, `show`, `anyway` | Fetches a file to save it in `files.dir`, or with `show`, a picture to show: its `picture` object comes once it's here. `anyway` fetches one over the limit |
| `offer` | `path`, `asis` | Offers a file. A picture goes cleaned unless `asis` |
| `cancel` | `num` | Stops a file coming, or withdraws one of yours |
| `timer` | `seconds` | Asks for a message timer, 0 for none |
| `history` | `on` | Tells everyone you keep a history, or that you've stopped |
| `settings` | `nick`, `colour`, `verify`, `notify`, `files`, `route`, `net_log` | Changes them on the running session, as in `start` (`route` updates live toggles and `relays`) |
| `identity` | as above | Signs with another key from now on, or (`none`) stops signing |
| `trust`, `ignored` | `list` | Replaces the verified or ignored signing keys (`{source, pub, nick}`) and rechecks peers |
| `move` | `answer` | Without `answer`: a `move_plan` object. `true` moves the room (or goes, when a peer asked), `false` stays. See `moved` |
| `newtor` | | New Tor circuits and a new onion address (`:newtor`) |
| `command` | `line` | Any of the room's commands, as typed after `:`. What it says comes as `line` objects |
| `state` | | Sends `peers`, `net`, `files`, `timer` and `move` again in full |
| `quit` | `kept` | Leaves the room, or with `kept`, goes offline from it. Then `bye` |

A command that can't be read or run gets an `error` object.

## Objects

| `t` | Fields | When |
| --- | --- | --- |
| `hello` | `v`, `version`, `built` | First, once |
| `identity` | `kind`, `pub`, `fingerprint`, `created` (PGP), `public` (an AGE recipient, or an armored PGP public key), `secret` (for a key made here or with `export`) | After `identity` |
| `ready` | `room`, `password`, `created`, `call` and `day` (for a call), `invite`, `qr`, `me` (`id`, `nick`, `colour`), `route`, `port` (UDP), `history` | The room is open |
| `moved` | as `ready`, and `from` | `:move` took you to a new room. This process runs that one from now on |
| `line` | `at` (`HH:MM`), `kind`, `text`, `colour`, and for a message the fields below | Something to show in the room |
| `log` | `at`, `text` | chat's own notes, such as the sandbox going up or tor connecting |
| `notify` | `nick`, `text`, `mention` | A message that should get a notification. `nick` and `text` are only there if `notify.preview` allows them |
| `delivery` | `own`, then `missed` (a peer's name) or `settled` | What became of a message of yours: a peer it went to never acked it, or every peer has it now, or as many as will |
| `peers` | `list` | The peers, whenever anything about them changes |
| `trust`, `ignored` | `list` | Verified or ignored signing keys (`{source, pub, fingerprint, nick}`), when they change |
| `net` | `ready`, `online`, `pending`, `rx`, then `tor`, `onion` (Tor) or `dht`, `dht_found`, `portmap` (UDP), and `relays` (`used`, `up`, `total`) | How the room reaches its peers, when it changes |
| `files` | `list` | The files offered here and yours, when they change, at most twice a second |
| `picture` | `num`, `name`, `w`, `h`, `src_w`, `src_h`, `rgb`, or `error` | A picture fetched with `show` |
| `timer` | `seconds`, `who` | The message timer kept to here, and who asked for it, when it changes |
| `move` | `seq`, `from`, `coming`, `names`, `at` | A peer asks you to move the room (`seq` 0: nothing is asked any more). Answer with `move` |
| `move_plan` | `coming`, `coming_names`, `left`, `left_names` | After `move`: who'd come, and who'd stay behind |
| `error` | `text` | A command failed, or the room couldn't open |
| `bye` | | Last: chat exits after it |

A `line`'s `kind` is `message`, `note` (joins, leaves, command output) or `warn` (something to see
at once, such as a verified peer's key changing). A message also has:

| Field | Meaning |
| --- | --- |
| `mid` | The message's id, for `reply`. A file's offer has none |
| `from`, `nick`, `mine` | Who wrote it: their id and nick, and whether it's yours. For a message passed on by another peer, they're what that peer says |
| `peer` | The peer it came from, or a direct message is to or from |
| `own` | Yours: its number, which `delivery` uses |
| `direct`, `mention` | A direct message; a message for you (a mention, a reply to you, or a direct message to you) |
| `quote` | A reply: how many bytes at the start of `text` are the quote |
| `file` | An offer: the file's number |

Each of `peers`' `list`:

| Field | Meaning |
| --- | --- |
| `id`, `name`, `nick`, `colour` | `name` is the nick as chat shows it, with `#` and the start of the id when another looks the same |
| `identity`, `signed`, `fingerprint` | How it signs (`none`, `native`, `age`, `pgp`), whether its signature checked out (`unverified`, `verified`, `failed`), and its key's fingerprint |
| `code` | `state` (`nothing`, `compare`, `compared`, `differs`, `key-changed`), and once there is one, the verify code in `words` and `hex` |
| `build` | `state` (`unknown`, `unchecked`, `official`, `modified`) and `label`, as `:peers` says it |
| `history`, `ignored`, `dm` | It keeps a history; you ignore it; its build reads direct messages |

Each of `files`' `list`: `num`, `name`, `size`, `mine`, `from` (who offered it), `image`, `at`, and
`state`: `offered`, `fetching` (with `got`, and `eta` in seconds or `waiting`: `sender` or
`verify`), `queued` (`after` the file it waits for), `done` or `failed` (`why`). `show` is whether
it's fetched to be shown, `saved` where it was saved, and for yours, `sending` (`count`, the `name`
of the one furthest along, `permille`) and `sent_to`.

## Pictures

A peer's picture is never handed over as the file it sent. chat's own PNG, JPEG and GIF readers
decode it in their sandbox, as for the full-screen UI, and `picture` has the result: `rgb` is
base64 of `w` × `h` × 3 bytes, red, green and blue, row by row from the top. So the program showing
it doesn't parse anything a peer made. `src_w` and `src_h` are the picture's own size.

## QR codes

`qr` in `ready` and `moved` is the invite as a QR code: one string per row, top to bottom, `1` for a
dark module. A scanner needs a light border four modules wide around it.
