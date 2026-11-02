# Changelog

All notable changes to chat, newest first. Each beta (`X.Y.Z-beta.N`) has a section of its own until
its release, which folds them into one. A release's notes on GitHub are its section here.

## 0.5.6

### Added
- `--json` runs one session for another program to drive, with JSON Lines both ways: messages with
  who wrote them and their ids, replies, direct messages, peers with their verify codes and builds,
  files, delivery, notifications and the network come out as objects, and commands go in to answer
  them. A picture comes as pixels, decoded by chat's own readers in their sandbox, so the program
  showing it parses nothing a peer made. It opens no save, and takes the room's password and any
  signing key on stdin, never in its arguments. [JSON interface](docs/json.md) has every object.
- chat builds for Android 9 and later with the NDK (`just build android`), for an app to drive with
  `--json`. [Building](docs/building.md#android) says what it does differently there.

### Fixed
- With `--simple`, a line longer than 1023 bytes was split into more than one message, and lines
  that came faster than chat read them could be dropped. Now a line stays whole, and the rest wait
  their turn.

## 0.5.5

### Changed
- `wss://relay.snort.social` replaces `wss://nostr.mom` among the default relays, as nostr.mom turns
  away connections over Tor. A relay list you've saved yourself keeps what's in it.

## 0.5.4

### Added
- `/` on the settings page searches every section, by name, `:set` name or a word from the help,
  and `Enter` opens the match in its section.
- Links in messages are underlined: `http://` and `https://` addresses, and domain names like
  `ieji.de/@ida`. A terminal that takes hyperlinks (OSC 8) opens one when it's clicked. `o` in
  NORMAL, or `:open [N|LINK]`, shows the newest link in a box with the whole address, who sent it
  and when (`j` / `k` for older ones): `y` opens it in your browser, `c` copies it. The box says
  first that the browser fetches it directly, so the site sees your IP address. On Linux the
  desktop portal opens it, so the sandbox stays as it is.

### Fixed
- The help page lists every command again: `:port`, `:send`, `:download` and `:cancel` were cut off
  its end.

### Changed
- The settings page's **Done** button (**Start chatting** on the page chat opens on) has a page of
  its own after Chat in the list on the left, so `Tab` from Chat, then `Enter`, closes it. Under the
  button, every setting chat is using is listed by section, and `Enter` on one opens it in its own.

## 0.5.3

### Changed
- The sidebar and the left column of the settings, help and files pages are one width, so the line
  beside them stays put going from the chat to a page and back. A box over the screen keeps inside
  the frame on a narrow terminal, where its margin used to cover the frame's sides.
- The files page keeps its shape while nothing's been offered, and says so in the middle, as the
  chat does before its first message. A folder browser in an empty folder keeps its left column too.
- The help page's pane shows the selected key or command in full, which a narrow terminal cuts off
  in the list. A setting's help that's longer than its pane ends in `…` instead of mid-sentence.
- When the bottom row's keys don't all fit, the last one stays (the way out, such as `esc start` on
  the first settings page, or `? help`) and the ones before it go first.
- The sidebar's NETWORK values are all lowercase (`dht off`, `tor connected`), the files page no
  longer offers `d download` next to `enter download`, and the quit box names the session it
  leaves and says nobody else is online rather than `0 peers`.
- The network log is shorter. `:net` gives a line each to the route and its peers, the DHT or
  tor, the relays, port mapping, what has arrived, and from where, with `·` between the parts
  instead of run-on `|` lists. A peer over the relays shows as its short id (`e58bb589 over the
  relays`) instead of a 40-character address, the hellos to Tor's room slots are one line instead
  of six, a stream to a room slot says which slot, and chat's own tor says why it starts in the
  same line that starts it. Tor's bootstrap steps (25%, 50%...) are verbose only, as the sidebar
  shows them.

### Fixed
- With the DHT on, its answers counted as unreadable packets, so `:net` could diagnose a session
  nobody had joined yet as the wrong id or password. They're counted apart, and left out of the
  senders.
- The DHT's lookup line called the nodes it asked "reached", and counted a peer again for every
  node that gave its address. It now says how many of them answered, and counts each address once.
- The note about using a running tor while bridges are set said "which torlaunch never doesn't
  start". It says that torlaunch never keeps chat's own tor from starting.

## 0.5.2

### Added
- `:exportkey`, or **Export signing key** in settings, writes your signing key to a new file in a
  folder you pick, after a box warns that it isn't encrypted: an AGE key as `age-keygen` writes
  one, a PGP key made here armored, as `gpg --export-secret-keys` writes it. It's the same key and
  fingerprint, so another device can pick the file and peers who verified you still see you as
  verified. The file is only yours to open, and nothing already there is written over. A PGP key
  from a file or a paste isn't exported, since chat doesn't keep its user ids and signatures.

### Changed
- A **Native** signing key is made from your nick too, as well as the password and the machine id,
  so the same password gives a different key for each nick. `--identity age` and `pgp` make the
  key once the nick is settled, so a saved nick counts. Changing your nick opens a box that asks
  for the password to make the key again with the new one, and `Esc` keeps the key you have.
  A Native key made by an earlier version comes out differently now: pick **Native, without
  nick** (`:set sign age-nonick` or `pgp-nonick`, `--identity age-nonick` or `pgp-nonick`) to
  make it from the password alone, as before. A key `:install` saved stays as it was saved, but
  one made with the nick can't be opened by earlier versions.

## 0.5.1

### Added
- `:move` moves the room. With no server, nobody can be put out of a room and a leaked password
  can't be changed. Instead, `:move` takes the peers whose verify codes you compared to a new room,
  with an id and password chat makes up, and leaves everyone else in the old one. A box first says who
  would come and who wouldn't, and why. The new room goes only to the peers asked along, over their
  encrypted sessions, and each of them is asked in a box whether to go: `y` goes and leaves the old
  room, `n` stays, and `Esc` puts the request away until `:move`. Someone who hasn't compared your
  code yet is asked once they have. Codes compared in the old room count in the new one, since
  everyone moving signs its sessions there with a key it showed the others over the old room. The
  new room's console shows its id and password once, for coming back or inviting someone. Those left
  behind keep the old room and everything said in it, and aren't told where you went. With
  `--simple`, `:move yes` and `:move no` answer. Versions before this one can't move, so a move
  leaves them behind.
- A lock screen. `Ctrl+L` (or `:lock`) locks chat's screen at once, and `:set lock 5m` (or `1m`,
  `15m`, `30m`) locks it after that long without a key. Locked, chat draws nothing but a box for the
  open save's passphrase, or with no save open, a PIN it asks for first and keeps hashed in memory
  until it exits. Sessions carry on behind it, and notifications show no preview. Wrong passphrases
  count toward self-destruct, and the shadow passphrase panics, leaving the decoy in the save's
  place.
- A panic key. `Ctrl+\` clears the screen and quits at once, from anywhere in chat, the lock screen
  too: every session says bye, nothing is saved, memory is wiped and chat's own tor stops.
  `:set panicwipe on` makes it delete the open save as well, and `:set panichistory on` writes the
  history kept first. `:set lockkey` and `:set panickey` choose other keys, or none. In `--simple`,
  the terminal's `Ctrl+\` panics. It used to end chat there, and in the full screen UI, with no
  bye and nothing cleaned up.
- A sandbox, on Linux. Once chat starts reaching the network, Landlock lets it, and tor, write only
  under the folders in your home that aren't hidden or on PATH, its own folder and the temporary
  folders, and run only tor, and seccomp refuses the calls chat never makes (ptrace, mount, bpf,
  io_uring...). A bug in how chat reads what peers, DHT nodes or relays send can then plant nothing
  that runs later. Landlock needs Linux 5.13 or later, and without it chat carries on with seccomp
  alone. While it's up, `:update` can't replace chat (`chat --update` can). `:set sandbox off` or
  `--nosandbox` leave it down.
- Direct messages. `:msg NICK TEXT` (or `:dm`) sends a message to one peer alone: a `pm` record
  over your session with them, acked and retried like a message, in the same slots, and never
  passed on. It only goes to a peer you're connected to directly whose build reads it (the `p`
  letter), and an older build is refused rather than sent it. Both sides show who it's between,
  and it counts as a mention.
- Pictures go without what could tell where, when or with what they were made. A PNG, JPEG or GIF
  you send keeps only what drawing it needs: no Exif (location, camera, serial numbers, times), XMP,
  IPTC, comments, PNG text or times, thumbnails, MPF pictures or the video a motion photo hides
  after its end. An Orientation other than 1 is kept, alone. A camera's or screenshot's name, which
  gives away the time, becomes `photo.jpg` or `image.png`. The cleaned copy is offered from memory,
  and the reply says what went. With **Noise in pictures** on, a baseline JPEG also gets noise
  nobody can see, so no two copies are the same bytes. `:send asis` sends a file as it is, and a
  HEIC, raw, video, PDF or office file says it can't be cleaned.
- Bridges for chat's own tor, for networks that block Tor. `:set bridges LINE; LINE` (the
  **Bridges** row) takes bridge lines from bridges.torproject.org or a friend. With any set, chat
  starts its own tor with its network off, gives it the bridges over its control port and only then
  lets it connect, so it never reaches the Tor network except through them, and stops it rather
  than connect without them. The lines never go on tor's command line or on disk: they're sealed in
  the save with the other settings, and the console only says how many there are. obfs4, webtunnel
  and meek_lite need lyrebird (or obfs4proxy, without webtunnel), and snowflake snowflake-client,
  found next to tor (as the Tor Expert Bundle and Tor Browser have them), on PATH, or in the folder
  `:set transports` names. The sandbox lets tor run them.
- `:set torguards on` (**Keep tor's guards**) keeps chat's own tor's entry guards and its copy of
  the directory in the open save, sealed: written when tor stops, once it has connected, and put
  back before the next one starts. It keeps the same guards from run to run, as Tor's design
  expects, and connects in seconds. A box first says what it adds to the save: which guards you
  use, in tens of MB, mostly the directory. The decoy never gets them, and turning it off deletes them.
- Kept rooms. `:keep [LABEL]` keeps the room on screen in the open save, with its id and password,
  so nobody has to remember a short password to come back. With rooms kept, `Ctrl+J` lists them by
  label: `Enter` joins one, `s` marks it to be joined as chat starts, `d` forgets it, and **another
  room...** asks for an id as before. `:keep forget` lets one go. They're kept in the sealed settings
  file, which is now padded to a multiple of 4 KB, so neither a file of their own nor its size says
  how many there are. The decoy keeps none.
- Calls. Once two people have verified each other's signing keys, `:call NICK` opens a room only
  their two keys can work out, from X25519 between them and the day (UTC), and the other opens the
  same one with `:call`, with nothing to swap. Nobody compares codes there, nothing goes to anyone but
  the verified key, and a call nobody else is in moves to the next day's room at midnight. It shows
  as `@NICK`. Both need a signing identity, AGE or PGP.
- A faint `•` after a message of yours once every peer it went to has acked it, and `not reached:
  bob` in yellow for a peer that still hadn't after the last try, or left first. The acks were
  always sent, so nothing new goes on the network, and there are no read receipts. Direct messages
  get it too. `--simple` prints `* not reached: bob`.
- Replies. `:reply NICK TEXT` (or `:re`) answers NICK's last message in the room, quoting the start of
  it after a `↪`, faint, and a reply to you counts as a mention. It's an `mr` record with the id of
  the message it answers, passed on like any message, and a peer whose build doesn't read it (the
  `q` letter) gets the quote in the text instead. Direct messages are never quoted.
- A message timer for each session. `:timer 10m` (or `2h`, `1d`) asks for messages there to go after
  that long: chat takes them off the screen and wipes them from memory, pictures shown with them too,
  and a history keeps no longer. It's announced in `k` the way history is (the `t` letter with the
  seconds), every chat that keeps to timers takes the shortest one asked for by someone whose code it
  compared, and the chat's title says so. It's a request: a modified chat, or a screenshot, can keep
  anything.
- The mouse wheel scrolls the chat, and the lists on pages and in boxes. chat asks the terminal to
  send the wheel as Up and Down (mode 1007), and gives back the terminal's own setting when it
  leaves. On the chat screen Up and Down scroll the chat by a message. Selecting text with the
  mouse works as before.
- `:newtor` gives every session in Tor mode new circuits and a new onion address. It closes the
  streams to peers' onion services and the connections to the Nostr relays, which open again with
  new SOCKS logins, so on new circuits and through new exits. Each session then publishes a new
  onion address, sends it to its peers and removes the old one. Streams peers opened to you, the
  room's onion services and tor's entry guards stay the same. It works in `--simple` too.
- `:set reopen on` (**Reopen sessions**) keeps the sessions you have open in the open save, sealed
  like the rooms `:keep` keeps, and opens them again when chat starts. The save follows what's
  open: `:quit` takes a session out, and turning the setting off empties the list. With it on,
  `Ctrl+C` closes chat without leaving: peers see you go offline, through a new `off` record (`o`
  in `k`), and older versions get a bye as before. `:quitall` still leaves every session.
- `:set net off` (**Network log**: off) keeps the network's news out of the console: lookups,
  relays dropping and coming back, port mapping, and Tor starting up and connecting. Problems that
  keep a session from connecting, such as a tor that won't start, still show.
- The mouse wheel scrolls the console when it's over it, a line at a time, and the chat anywhere
  else. While it's scrolled back, the console's title says how many newer lines are below, and it
  stays on the lines in view as new ones come. `G` in NORMAL goes back to the newest line as well
  as the newest message.
- The sidebar's sessions and peers scroll when there are more than fit, with the mouse wheel over
  them, and a row says how many more are above or below. The sessions follow the selected one as
  `Tab`, `Shift+Tab` and `j`/`k` switch, and the network section stays at the bottom instead of
  being pushed off.
- `:invite` copies the session's id and password to the clipboard as one invite,
  `chat:ID:PASSWORD:CHECK`, and the JOIN box (`Ctrl+J`) takes one in place of the id. The check
  catches an invite that was mistyped or cut off, which used to leave you alone in a room nobody
  else was in. An invite is never shown, only copied, since it holds the password. A call has none,
  and nor does a session whose id has a `:` in it.
- A session id or an invite you copy comes off the clipboard again after 30 seconds, or as soon as
  chat quits, locks its screen or panics. On Windows chat sets the clipboard itself for these,
  marked to stay out of clipboard history, the cloud clipboard and clipboard managers, and leaves it
  alone if something else was copied since. Elsewhere the terminal clears it (OSC 52), and that also
  takes off anything copied since.

- `:ignore NICK` hides what a peer says, sends you directly or offers, without notifying you, and
  `:ignore NICK off` shows it again. It's only on your screen: nothing is sent, and what they say
  still goes on to peers who only reach them through you. A peer that signs has its key ignored in
  every session too, kept in the open save as verified keys are. The sidebar marks them `i`, and
  `:peers` says so.

- A backup release key. A build made with `keys/minisign-backup.pub` (`just keygen backup`) takes an
  update, and a peer's list of release builds, signed by either the release key or the backup,
  which is kept offline apart from it. If the release key is lost or stolen, the backup signs the
  next release, and that release can stop taking the old key.

- `tests/interop/interop.sh` (`just interop OLD`) runs this build and an older one as two peers in
  one room, and checks what an older version is promised: messages both ways, a long one, a reply, a
  direct message or its refusal, a file each way and a leave. GitHub Actions runs it on every push
  against the latest release and the newest beta.

### Changed
- Routing is two settings, named the same on the settings page, with `:set` and on the command
  line. **Routing** (`routing`, `--routing`) is `udp` (`dht` before) or `tor`. **Nostr relays**
  (`nostr`, `--nostr`) is `fallback` (`on` before), `always` or `off`, and means the same with
  either: a Tor session now leaves the relays a minute after it last needed them, as a UDP one
  does, so `always` is what keeps it findable by UDP members of a room whose Tor members already
  reach each other. `--routing dht+nostr` and `dht`, `--nonostr` and `--nostr-always` are gone,
  and `--simple` asks only UDP or Tor. Saves are unaffected: the old names were the defaults,
  which a save never holds.
- `:update` works with the sandbox up. Just before the sandbox goes up, chat starts itself again
  as the updater, a second process `:update` asks to do the update, shown as `chat-updater` in the
  process list. It holds none of chat's keys, saves, messages or passwords, and has a sandbox of
  its own that only lets it write in the executable's folder and run curl. It still installs only
  what the release key signed. `:set updater off` stops it and keeps it from starting. Before, the
  sandbox kept chat from replacing itself, and `:update` sent you to `chat --update`.
- `just release patch`, `minor` and `major` release the next patch, minor or major version after
  the last published release, and `just release beta patch`, `minor` or `major` a beta of it.
  `just release` and `just release beta` still release the version in `CMakeLists.txt` (the
  betas' own) or the patch after it. A release folds in, and deletes the GitHub releases of, the
  betas of any version up to it, so a cycle of `0.5.1` betas can come out as `0.6.0`.
- A second `Ctrl+C` quits from the QUIT box, as `y` does.
- The sidebar's NETWORK box says whose tor the route uses (`tor (own)` or `tor (running)`) and how
  far it has got (`Connecting (24%)`, then `Connected`). In UDP mode the route carries the port
  (`udp/PORT`) and the DHT says `Connecting` until a node answers, then `Connected`.
- chat has the terminal report the mouse (modes 1000 and 1006) instead of sending the wheel as Up
  and Down (mode 1007), since that's the only way to know which pane the wheel is over. Plain
  clicks don't reach the terminal any more: hold Shift to select text, as in other full-screen
  programs. A key's sequence split between two reads (Windows passes input on a few dozen
  characters at a time) waits for the rest instead of ending up as text.
- Releases are meant to be reproducible. `just dist` stamps the binaries with their commit's time,
  not when they were built, so a release's `--version` says when its commit was made, and they no
  longer name the folders they were built in, nor (on Windows) when they were linked. When a release
  is published, GitHub Actions builds it again and compares it with the published binaries, and
  `just reproduce VERSION` does the same on any computer with zig.
- On Linux, a picture shown is decoded in a child process that seccomp lets do nothing but allocate
  memory, write the thumbnail back and exit, so a bug in chat's picture readers can't reach a file,
  the network or chat's keys. chat checks the thumbnail it gets back, and a child that takes more
  than 10 seconds is killed.
- A paste is only text. chat turns on bracketed paste, so the terminal marks where a paste starts
  and ends: it goes into the input box, from NORMAL too, with its lines run together, and waits for
  `Enter`. Before, each line of a paste was sent as it came, a line starting with `/` ran as a
  command, a paste in NORMAL ran its letters as keys, and one could answer a y/n box. In a box a
  paste only goes into the field, and anywhere else it's ignored.
- The NEW SESSION box (`Ctrl+N`) starts with a random password, eight words (64 bits), shown so you
  can pass it on. The first key you type replaces it with a password of your own, and `Ctrl+U` clears
  it to none. The id is often passed around in the open, so the password is what stands in the way of
  guessing, and the box used to start empty.
- A session takes half the locked memory it did: a scrollback's lines share one 96 KB ring of text
  instead of a kilobyte each, and peers no longer keep a key they never read. Under the usual 8 MiB
  limit on locked memory, about 11 sessions' keys and messages stay out of swap, where past about 5
  they quietly didn't.
- The release keys are in `keys/` now (`keys/minisign.pub`, `keys/minisign-backup.pub`), and the
  documentation in `docs/`, with the README an overview of it.

### Fixed
- The help for **Start chat's own tor** said its tor takes a cookie login. It never has: its
  control port only takes a password made at random each run that only chat knows, with only its
  hash on tor's command line, and no cookie file another program could read. The help says so now,
  and so does the console as chat starts it.
- A peer whose key you verified could be warned about as signing "with a key with an invalid
  signature" for a moment around a rekey, and show as verified again soon after. Its key hadn't
  changed: the signature it sends with it was checked against our newest session key, not the one
  of the session it came in. It's checked against the session it was made for now, or the one just
  before a re-handshake, and signed for the session it goes out in.
- In a room you moved to (`:move`), someone who came along from a room where you'd compared verify
  codes could be shown with a code to compare, until chat said a moment later that they'd come along.
  Their join now waits for their proof of that, a few seconds at most.
- Closing a kept room just after a rekey could show peers that you'd left, not that you'd gone
  offline.

## 0.5.0

### Security
- Nothing on disk or on screen says whether a save has a decoy any more. Every save has a `spare`
  file: the decoy, sealed under the shadow passphrase, or random bytes with the same size and
  header when there's no decoy, and a sealed `spare-lock` file says which. The betas kept a decoy in
  `shadow-*` files that only a save with a decoy had. Every passphrase now runs Argon2id twice, for
  the save and for its spare, where the betas ran it once for the real passphrase and three times
  for the shadow one, and a save that opens is written the same way whichever passphrase opened it.
  A decoy follows the save when its device lock, security key or code changes, where the betas' kept
  needing what the save needed when it was set, and the shadow passphrase can't be the save's own. A
  decoy the betas made still opens, and when its save opens chat says how to move it to the spare.

### Added
- A device lock for saves. `:set devicelock on` (the **Device lock** row) locks a save to the
  device it's on: its key then needs a secret only this device can unseal as well as the
  passphrase, so a copy of its files, from a backup, a synced folder or the disk, can't be opened
  anywhere else, even with the passphrase. On Linux, systemd's credential service (systemd 256 or
  later) seals the secret with the TPM 2.0 and systemd's own key, for your user only, without
  needing the `tss` group. Without that service (runit, OpenRC, s6, or an older systemd), chat
  speaks to the TPM itself through `/dev/tpmrm0`: it seals the secret under the TPM's storage key,
  sends it across the TPM's bus encrypted in a session salted to that key, checks every answer's
  HMAC, and refuses a storage key other than the one it sealed under. That needs the `tss` group,
  and the greyed-out row says how to join it. On Windows, an RSA key the TPM makes for the save,
  which never leaves it, seals it. Without a TPM it's systemd's key alone, or DPAPI on Windows, and the box that
  turns it on says what that leaves. With no save open it applies to the next save `:install`
  makes, and the open save is sealed again after a box asks. A save is only locked once the
  device has unsealed its secret again. The list of saves says which ones are locked. Where the
  device can't lock a save at all, the row is greyed out and its help says why. Older versions of
  chat can't open a locked save.
- A locked save is gone for good if what the device keeps for it is wiped, so before anything is
  locked, a box lists what does that: the TPM being cleared (in the firmware settings, from
  Windows, or by some firmware updates), a new motherboard or CPU, a reinstall, systemd's key or
  the machine id changing, the save's `device` file being deleted, and the computer breaking. If
  the machine id is made anew at each boot, it says a restart would lose the save. For a new save,
  `:install` shows this box before asking for a passphrase. It says to turn the lock off before
  any of these you can see coming, and the console says so again once a save is locked.
- A security key for saves. `:set securitykey on` (the **Security key** row) makes a save need a
  FIDO2 security key with hmac-secret (a YubiKey 5, say) as well as its passphrase: registering it
  takes two touches, and opening the save one more each time. The secret the key gives for the
  save's salt goes into the key its files are sealed with, so without the security key the
  passphrase opens nothing, wherever the files are, and a guess at it can't be checked. On Linux
  chat speaks CTAP 2 itself over `/dev/hidraw`, with the secret encrypted on the bus (PIN/UV auth
  protocol 2, or 1), the PIN asked for only where the key wants it, and only the key with the
  save's credential blinking. On Windows, Windows asks for the touch and PIN in its own window
  (WebAuthn API 4 or later). Before it's turned on, a box lists what loses the save for good: the
  key lost, broken or reset, or the save's `securitykey` file deleted.
- An authenticator app for saves. `:set authenticator on` (the **Authenticator app** row) shows a
  QR code and the secret to add to any TOTP app, checks a code from it, and from then on opening
  the save asks for the code it shows. The box and the help say what it is: a check chat makes,
  since the codes' secret has to be kept in the save (sealed with it), so it stops someone who
  knows the passphrase opening the save in chat, not someone reading the files with their own
  program. A window too short for both the QR code and the text shows the text, and Tab swaps the
  QR code in for it. A wrong code waits a moment before the next.
- A save can need any mix of the device lock, the security key and a code. The list of saves says
  which, the unlock box asks for each in turn (in the terminal with `--simple`), and a save left
  part way through a change to them is finished with all of them when it opens.
  `CHAT_INSTALL_PASSWORD` gives the passphrase of a save that needs a security key or a code, and
  those are still asked for. Older versions of chat can't open a save that needs either.
- `just release beta` releases the Unreleased section as a beta of the next version,
  `vVERSION-beta.N`, signed like a release and published as a GitHub pre-release, which `:update`
  doesn't install. On a beta, `:update` installs the release it's a beta of once that's out.
  `just release` folds the betas' sections since the last release into the new version's.
- Beta releases are opt-in: with the new `betas` setting on (Chat > Updates, `:set betas on`, or
  `--betas` for one run), `:update` and `chat --update` install the newest release, betas
  included. It's off by default, so `:update` still only installs releases. A newer beta of the
  same version counts as an update, so testers go from `-beta.1` to `-beta.2`.
- chat builds for macOS, Apple silicon and Intel (macOS 11 and later), cross-built with zig like
  the Linux and Windows releases (`just build macos`). It shares the Linux platform code, with the
  Mac's hardware UUID as the machine id, `PT_DENY_ATTACH` against debuggers and its private TMPDIR
  for chat's own tor. Locking a save to the device, security keys, desktop notifications and PCP or
  NAT-PMP port mapping don't work there yet (they need Apple's frameworks), and releases don't
  include it until it's been used on a Mac. CI runs the engine test and chat itself on macOS.
- History, off unless you turn it on: `:set history on` (Chat > History) keeps each session's
  messages, sealed in the save that's open, and shows them when you join that session again with the
  same id and password. Each session's is a file of its own named from its id and password, so the
  name doesn't say which session it is, up to 256 KB of it, sealed again with the rest when the
  save's device lock, security key or code changes, and deleted with the save or by a decoy taking
  its place. Everyone in the session is told while you keep it (`[keeps history]` when you join, a
  warning in the chat, the sidebar and `:peers`), straight away when you turn it on or off, and you're
  told the same of them. `:history` says whether it's kept, and `:history forget` (or `forget all`)
  deletes it. Only the full-screen UI keeps it.
- A message can be 880 bytes long, up from 250: as much as one frame holds, so nothing about how
  messages travel changes. A peer on 0.5.0's betas or older only reads 250 bytes of one (its `k`
  doesn't have the new `l`), so a longer message goes to it in parts, cut between words, each a
  message of its own. A part a peer like that passes on is shown once, even to someone who got the
  whole message.
- Verify codes come as words to read out over a call: 16 four-letter words, one for each byte of the
  code, from Bytewords (a list made to be hard to mishear), like `iron when sets good · deli axis road
  exam · ...`. The prompt to compare codes when a peer joins and `:verify NICK` show them, with the
  same code in hex after them for a peer on an older version, which only shows hex.
- `PROTOCOL.md` describes the wire protocol: the keys and what they're made from, the frames, the
  handshake, rekeys, every record and the timers. `SECURITY.md` has the threat model and how to
  report a vulnerability.
- The shadow passphrase and self-destruct, in 0.5.0's betas but not their notes. `:set shadow on`
  (the **Shadow password** row) gives the open save a second passphrase that opens a decoy in its
  place: a clean save with no key or verified keys, needing the same device, security key and code,
  whose files replace or delete the real save's. `:set destroy 3` (or `5` or `10`, the
  **Self-destruct** row) deletes a save after that many wrong passphrases in a row. The README says
  what they can't do: deleting isn't erasing, and the count is kept unsealed next to the save.

### Changed
- The settings page shows one section at a time, picked in the list on the left, with its rows
  grouped under headings: Network (DHT or Tor, Relays, Advanced), Profile (Keys), a new Security
  section for autosave and what a save needs to open (Unlocking, Duress), and Chat (Files). The
  network log and the UDP port for new sessions moved to Network. Each section ends with **Done**
  (**Start chatting** on startup), and `j`/`k` go on into the next one. `Tab` / `Shift+Tab` (or
  `PgDn` / `PgUp`) go straight to the next / previous section, round from the last to the first,
  back to the row you were on there, and `1`-`4` go to a section by its place in the list. The
  settings file is the same as before.
- On the help page, `Shift+Tab` goes straight to the previous section instead of to the top of
  this one first, `Tab` / `Shift+Tab` go round from the last section to the first, and `PgDn` /
  `PgUp` and `1`-`9` go to a section too.
- The command line is blanked once chat has read it, so a session id, `--peer` address, nick or
  save named there no longer stays readable in `ps`, `/proc` or Task Manager.
  `CHAT_PASSWORD`, `CHAT_INSTALL_PASSWORD` and `CHAT_SIGN_PASSWORD` leave the environment as chat
  starts, so tor and curl never inherit them.
- chat's own tor takes a control port password chat makes when it starts it, and tor only gets
  its hash. It used to write a cookie file that any program running as you could read, and then
  log in to tor with and see which onion services chat publishes and connects to.
- On Linux, notifications go to the desktop over D-Bus from chat itself instead of through
  notify-send, which put their title and text on a command line every user can read. notify-send
  is no longer used.
- On Windows, other programs, even ones running as you, can no longer read chat's memory, run code
  in it or open its threads: its process and threads only let them see it, wait for it and end
  it. chat also raises its working set, so the keys and conversation it locks in memory stay out
  of the page file (before, the default was too small for most of them).
- Reading a save no longer updates its access time (Linux).
- `:install` asks for a new save's name every time, not only when there are saves already, and a
  blank name picks a random one, like `swift-otter42`, shown in the box before you choose. A
  first save used to go in `~/.config/chat` itself as `default`. Now it goes in
  `~/.config/chat/saves/NAME` like the rest. Typing `default` still makes the old kind, and saves
  made there before keep working.
- Turning on **Device lock**, **Security key** or **Authenticator app** with no save open no
  longer just flips the row on, waiting for a later `:install`: a box says it needs chat installed
  first (or a save open, if there are saves here) and asks to install now. Yes goes through
  `:install`, which sets it up for the new save as it makes it (the device lock's box, the key's
  two touches, the QR code), or asks to set it up for a save it opens instead. No, or cancelling
  `:install` part way, leaves the row off. Started from the settings page, `:install`'s boxes stay
  over it and go back to it. `:uninstall` of the open save turns the three rows off too.
- `just release` deletes the GitHub releases of the version's betas once the release is
  published, so the release is the one left to download. The betas' tags stay.
- The engine's unused plain-text session log is gone. Its flag in the handshake now says a peer
  keeps a history, which 0.4.0 and the betas show as `[logging chat locally]`.
- Tab on an argument in the command line's menu adds a space after it when another argument can
  follow, so that one's menu comes up straight away, as it already did after a command's name:
  `:verify NICK` lists `ok` and `no`, `:verified forget` the verified nicks, `:download N` `anyway`
  and folders, and `:show N` and `:saveto N` `anyway`. Enter still runs the line without them.
- The list of saves says when each was last opened or saved, since opening a save now writes its
  files again.
- The full-screen UI marks a name in the chat with a symbol in a column of its own, where it added
  words that could push everyone's messages halfway across the chat: `◆` you, `✓` code compared, `?`
  code not compared, `✗` codes differ. The name column is as wide as the longest nick in view, up to
  a quarter of the chat (a third before), and a longer name, like a relayed one, goes on its own row
  above its message. Lines from a history kept by an older version show the symbols too.
- The sidebar spells out the symbols that apply to each peer on rows under it: its verify state,
  `h keeps history` and `! modified client`. When the sidebar is too short for that, they go next to
  the nick as before.
- Messages from a peer whose verify code you compared say `(code compared)` after its name, in
  `--simple` and notifications too. Only `(code not compared)` and `(codes differ)` were shown before.

### Fixed
- With more than one save and no `--save`, `CHAT_INSTALL_PASSWORD` is tried on each save in turn,
  and each save it didn't open counted it as a wrong passphrase: a few runs could delete a save set
  to self-destruct that it was never meant for, and a save whose shadow passphrase it happened to be
  lost its real save to the decoy. Saves it's tried on that way no longer count it, or open a decoy.

## 0.4.0

### Security
- Verify codes and identity fingerprints are 128 bits, shown in groups of four hex digits. A
  room member between two peers picks the keys for both handshakes, so it could search two sets
  of 64-bit codes for a matching pair. The first 16 digits are the same as what 0.3.1 shows.
- chat only logs in to a tor control port with SAFECOOKIE or a password. The old COOKIE login
  sent the cookie file's contents to whatever answered on the port, and while tor isn't running
  any local program can listen there and name any file chat can read. The cookie file is only
  read if it's a regular file of the right size.
- On Linux, `:update` only runs curl, and notifications only run notify-send, from an absolute
  `PATH` entry or a standard folder, and only if the program can't be changed by anyone but root
  or you, the same as for tor. A relative `PATH` entry such as `.` could run one from the
  current folder. A program or folder writable by a group other than root's or yours is also
  refused.
- Desktop notifications only say that a message came in, or that you were mentioned. They used
  to show the sender, the text and the session id. Desktops keep notifications (Windows writes
  them to disk), and with a blank password the id is all someone needs to join.
  **Notification preview** on the settings page (`:set preview off|nick|message`, also in
  `--simple`) shows the sender, or the sender and the text, if you want them. A notification
  never names the session.
- Everything chat sends over UDP is masked with a key made from the session id and password, so
  on the network each datagram is random bytes. Before, the ratchet counter at the start of
  every session frame, and the marker, id and numbering at the start of every handshake piece,
  were sent in the clear. That was enough to pick out chat's traffic, and to follow a peer from
  one address to the next by its counter. Addresses, ports, sizes and timing are still visible.
  The relays and Tor already hide what they carry, and carry it as before.
- LAN beacons go to a UDP port specific to the room (49152-65535, made from its id and
  password), not to 47474, which told everyone on the network that chat was running.
- The DHT lookup key changes every hour. It used to stay the same for as long as the room
  existed, so anyone who saw it once, such as a DHT node or a crawler, could watch who joined
  the room for as long as it was used. For ten minutes either side of the hour, the other
  hour's key is looked up as well.
- Because of the three changes above, 0.3.1 and this version can't find each other through the
  DHT or on the LAN, or reach each other over UDP. They can still meet through the Nostr relays,
  which are on by default, or over Tor.
- Each relay connection subscribes under its own id. Using the same id at every relay, kept
  across reconnections, let relays that share data link one member's connections together,
  including over Tor circuits.
- Mbed TLS is built as a TLS client with forward secret key exchanges only. There's no server or
  DTLS code, no renegotiation, no static RSA or DH key exchange, no legacy ciphers, and no PSA
  key store, which would keep keys in files.
- The conversation and console on screen, and the screen buffers, are locked in memory like the
  keys, so they aren't written to swap (as far as `RLIMIT_MEMLOCK` allows).
- On Windows, a crash ends chat immediately, so Windows Error Reporting can't write a dump of
  its memory to disk.
- Cookie challenges are rate limited, so hellos replayed from a forged address can't turn chat
  into a traffic reflector. A session frame from an address no peer has is tried against every
  peer's keys at a limited rate, so junk of the right size can't use up the CPU.
- LAN beacons are only accepted from real broadcasts, not from room members over the relays or
  Tor.
- Desktop notifications on Linux are transient. The desktop shows them but doesn't keep them in
  its notification history, which used to record when messages came in (and, with previews on,
  what they said) after chat had exited.
- Every datagram chat sends to a connected peer goes in one of that peer's slots, one every 1.5
  to 1.9 seconds, whether or not there's anything to send. Messages, acks, messages passed on to
  other members, nick changes and re-handshake pieces all wait for a slot. This means the
  timing and size of traffic no longer show when someone typed, or who sent a message first in
  a group. A message sent to several members no longer goes out to all of them at the same
  moment. A message takes up to two slots to arrive, and its ack the same to come back.
- Every UDP datagram is one 1004-byte cell. A session frame fills one cell, and a room frame is
  split into pieces padded to whole cells. Before, session frames were 428 bytes and pieces were
  1008, 1008 and 608, which made chat easy to pick out from other traffic.
- The `hi` sent to every connected peer every 10 seconds is gone. It was three pieces, and it
  marked chat's traffic as clearly as a header would. A peer now only gets a `hi` when it has
  gone quiet, or hasn't re-handshaken with new keys.
- Verify codes: when a peer joins, chat shows a code to compare with them over another channel.
  Anyone with a session's id and password could sit between two members and read what they
  said, and the code only matches on both ends if nobody is in the middle. `:verify NICK ok`
  marks it as matching, and `:verify NICK no` marks a code that didn't match: that peer then
  gets nothing. By default what you send goes to every other peer, compared or not.
  **Compare verify codes** on the settings page (`:set verify required`, `--verify-required`)
  holds it back from a peer until you've marked its code `ok`. Until then, that peer's messages
  show `(code not compared)`, the sidebar says `compare code`, and the input box says your
  messages aren't being sent to them (`:verify NICK` shows the code). If a peer's signing
  identity was confirmed this way and it comes back with a fresh handshake signed by the same
  key, you don't need to compare again.
- DHT routing only connects to the Nostr relays while it needs them: before anyone is reached,
  while a peer is only reachable through them, or while a peer's UDP has gone quiet. It
  disconnects a minute after. Before, every DHT-routed member's address stayed connected to
  the relays for the whole session. `:set nostr always` (or `--nostr-always`) keeps the old
  behaviour, for rooms with Tor members, who can only meet DHT members on the relays.
- Each ten-minute relay tag gets its own connections, which only ask for that tag. A new
  connection to each relay opens a minute or two before the ten minutes start, and the last one
  closes a minute or two after they end. Before, each connection asked for the previous,
  current and next tags and moved on under the same subscription, which let a relay link each
  ten minutes to the next. A relay still sees the address a connection comes from.
- The DHT node id changes with the lookup key every hour. Using the same id for a whole session
  linked one hour's key to the next for every node that saw both. Around the change of hour,
  each hour's key is looked up under its own id.
- DHT queries set `ro` (BEP 43). chat is a read-only node and never answered queries, and now
  other nodes don't expect it to.
- A DHT lookup starts from the nodes that answered earlier lookups, and only asks the bootstrap
  servers while it knows fewer than eight. Before, every lookup (every 30 seconds while alone)
  went to the same four bootstrap servers with the room's lookup key.

### Added
- A page listing every key and command: `F1`, `?` in NORMAL, or `:help`. `Enter` on a command
  puts it on the command line.
- The command line shows a menu of commands that match what's typed, the settings (with their
  current values) after `set `, and a setting's values after its name. `Up` / `Down` pick,
  `Tab` completes, and `Enter` on a partly typed name runs what the menu has selected. After a
  command that takes a nick (`verify `), it lists the online peers that match, with each one's
  verify state, and shows the rest of the selected nick dimmed, like `@` does.
- `/` on an empty line, in INSERT or NORMAL, opens the command line, like other chat programs.
  A line that can't be a command (`/shrug`, `/usr/bin`) turns back into text as you type and is
  sent as a message, rather than refused as an unknown command. `//` does the same straight
  away.
- `PgUp` / `PgDn` scroll the chat back and forward (`Ctrl+U` / `Ctrl+D` in NORMAL, `G` back to
  the newest), and the edge of the chat shows how many newer messages are below.
- In NORMAL, `s`, `c` and `C` show or hide the sidebar, the console and the chat, like `Ctrl+B`,
  `Ctrl+O` and `Ctrl+T`.
- `Tab` / `Shift+Tab` move between sections on the settings and help pages.
- `Ctrl+U` in INSERT deletes everything before the cursor.
- `NO_COLOR` limits the UI to bold, faint and reverse.
- `:install` saves your settings and signing key so they're there the next time chat starts.
  It asks first, and says what it leaves on disk, which shows chat is used on that machine. The
  settings you've changed go in `~/.config/chat/settings` (`%LOCALAPPDATA%\chat` on Windows),
  using the names `:set` uses, and the key goes in `~/.config/chat/key`. Both are sealed with
  one passphrase you choose (Argon2id, XChaCha20-Poly1305), which it asks for even with no key
  to save, and nothing in them is stored in the clear. A key installed later is sealed under
  the same passphrase without asking for it again. After that, chat starts on your sessions
  instead of the settings page. On startup it asks for the passphrase, or reads it from
  `CHAT_INSTALL_PASSWORD`, and says so if it's wrong. Command line options override what's
  saved, for that run. `:uninstall` deletes it all. Sessions, messages, peers and files are
  never saved.
- `:send` without a path opens a file browser to pick the file to offer.
- **Files and pictures**: `:send PATH` offers a file to the session. Nothing is transferred
  until someone fetches it with `:download N` (saved in `~/Downloads`), or, for a PNG or JPEG,
  `:show N`, which draws it in the chat under the line that offered it (`:hide N` hides it).
  `:files` lists them and `:cancel N` stops one. A file is only kept if its SHA-256 matches the
  offer. It's saved under a cleaned up name and never replaces an existing file. A picture
  that's shown is never written to disk. Files are sent in chat's regular slots, so they don't
  show up as a transfer on the network, but this is slow (about 25 KB a minute). **Fast file
  transfers** (`:set fastfiles on`, `--fast-files`) sends your files in quick bursts instead.
  Through the relays, where Tor and DHT members meet, a slot carries two chunks, since every
  relay event is sealed to the same size anyway. Fast transfers there go as often as the relays
  allow, about twice the normal rate. While a file downloads, a row under the line that offered
  it shows progress and roughly how long is left. Lost chunks are requested again once the rest
  of their run has arrived, a transfer continues through rekeys, and a fetch waits up to two
  minutes for a sender who drops out, then resumes if they come back.
  **File size limit** (`:set filelimit`, `--file-limit`, 8 MB by default) is the largest file
  fetched without adding `anyway`. Files can be up to 1 GB. Pictures are decoded by chat's own
  PNG and baseline JPEG decoders, which never hold the full size image in memory.
- `:changelog` (or `:news`) shows this changelog on its own page. It's built into chat so it
  works offline, and the Markdown is rendered: headings, bold, italic and `code`, links, nested
  lists, numbered items, quotes, code blocks and rules. In `--simple` it's printed.
- **Unread counts**: a session with messages you haven't seen shows how many next to its name
  in the sidebar. It's yellow with an `@` when one of them mentions you. With the sidebar
  hidden, the chat title shows how many new messages there are in other sessions. When you go
  back to a session, a `N new` line marks where the new messages start, until you leave it or
  send something.
- Your nick is highlighted wherever a message mentions it (`@nick`), not just the time next to
  it.
- More than one save. `:install NAME` saves your settings and signing key as a save called
  NAME, in `~/.config/chat/saves/NAME`, with its own passphrase. `:install` alone keeps using
  the save in use, and the save in `~/.config/chat` itself is called `default`.
  `:uninstall NAME` deletes that save. With more than one save, chat lists them when it starts,
  with what each one holds and when it was last saved, and you pick the one to open before its
  passphrase is asked for. Esc on the passphrase goes back to the list. `--simple` and `--update`
  list them in the terminal and take a number or a name. `--save NAME` opens that save without
  the list, and if there's no save called NAME yet, chat starts from its defaults and
  `:install` makes it. Without `--save`, `CHAT_INSTALL_PASSWORD` opens the first save it fits.
  With only one save, chat asks for its passphrase straight away, as before.
- Verified keys. For a peer that signs with an identity, `:verify NICK ok` keeps its signing
  key and nick as verified, for every session in the run. A peer that signs a later handshake
  with a verified key needs no code comparing. `:install` saves the keys in a `verified` file,
  sealed with the settings of the save in use. `:verified` lists them with their fingerprints,
  and `:verified forget NICK` (or `all`) removes them.
- When a peer has the nick of a verified key but signs with another key, or none, chat prints
  a warning in the chat (bold yellow, and in yellow in `--simple`) as well as the console, and
  the sidebar shows `key changed`. The peer counts as not compared until you compare codes
  again. `:verify NICK ok` then replaces the key kept for that nick.
- `:save` saves what's in use now to the save that's open, after asking, command line options
  included. With no save open, it does what `:install` does.
- An `autosave` setting, off by default. On, a setting you change, and a key you verify or
  forget, is saved as you change it. Off, they last until chat exits, and the reply to a
  setting you change ends in `· not saved (autosave is off)`. `:save` saves them, and turning
  autosave on saves the ones changed meanwhile. The `autosave` row is always saved itself, so
  turning it on lasts. Either way, the signing key is only saved by `:save` or `:install`.
- A files page. `Ctrl+F` (`f` in NORMAL, or `:files`) lists the files offered in the session,
  theirs then yours, newest first, with what each one is doing and the selected one's details
  beside the list, so nothing needs its number typed. `Enter` shows a picture or saves a file in
  Downloads, `d` saves in Downloads, `s` in a folder you pick, `v` shows or hides a picture in
  the chat, `y` copies where a file was saved and `n` sends one. `x` stops a fetch, or stops
  offering one of yours, after a box asks. A file over your size limit is fetched once a box asks
  (with roughly how long it takes), instead of needing `anyway`.
- Pictures on a page of their own, as big as the terminal allows (up to 200 by 120 pixels, where
  the chat shows 64 by 48). `Enter` on the files page opens one, fetching it first if it isn't
  here and showing how far it's got until it comes. `j` / `k` go to the next and previous picture.
- A picture you send shows in your own chat straight away, and `:show N` works for your own
  pictures, from the file you offered as long as it hasn't changed.
- Progressive JPEGs and GIFs are pictures too, shown with `:show N` like a PNG. An animated GIF
  shows its first frame, still. They're read by chat's own decoders, with the same checks as
  the others.

### Changed
- `just build test` names each binary after its build id, as `chat-<build id>-<system>-<arch>`.
  The build id is the source it was built from (`git describe`) and the build time in UTC, as
  shown by `chat --version`.
- The full-screen UI is drawn as one rounded frame split by lines, with each part titled in its
  border. There's a sidebar with the sessions, their peers and how the selected one reaches
  them, the console above the chat, and the input below it, outlined in the mode's colour. A
  bottom row shows the mode, whether you sign, your nick and what the keys do.
- The UI uses the terminal's own colours, so it matches the terminal's theme, light or dark,
  and follows it when it changes (if the terminal reports that). Peers' colours stay the same,
  but are adjusted to be readable on the terminal's background once the terminal has reported
  what that is.
- The chat is laid out in columns (time, nick, text). A run of messages from one peer in the
  same minute shows the time and nick once. A new session, one still connecting, and one with no
  messages yet say so, and what to do next.
- The peers list shows whether each peer is verified, and whether it's a modified client, in
  words while there's room. A lookalike's `#id` and its state are never cut off to fit its nick.
- The settings page lists its sections on the left, draws switches and choices as such, and
  shows each row's `:set` command under its help text. Text rows are edited in place. The
  settings page chat opens on ends with **Start chatting**.
- Release binaries are less than half the size: Linux is 1.3 MB instead of 2.9 MB, and Windows
  1.2 MB instead of 3.0 MB. libsecp256k1 keeps only its signing tables, Mbed TLS only the client,
  unused code in every dependency is left out at link time, and builds are stripped when
  linked.
- The full-screen UI sends nothing to the terminal while the screen hasn't changed. It used to
  redraw the whole screen every second, which was a constant stream of data over SSH.
- Every prompt now opens in a box over the screen, titled with what it's for and with its keys
  shown in the bottom edge. This covers a new session's password, the id and password to join
  one, a setting's new value, a native key's password, a pasted key, and `:install`'s
  questions. Before, these used the input box at the bottom, or a field in the row being
  changed.
- The settings page no longer has a Layout section. `Ctrl+B`, `Ctrl+O` and `Ctrl+T` (`s`, `c`
  and `C` in NORMAL) show and hide the sidebar, the console and the chat. `:set sidebar`,
  `console` and `chat` are gone.
- The input box grows one row at a time as the text wraps, up to six rows (fewer on a short
  terminal), instead of scrolling the line sideways.
- Direct routing is now called DHT routing: `--routing dht+nostr` and `--routing dht`, and
  `dht` on the settings page. `--routing direct+nostr` and `--routing direct` still work.
- A handshake takes a few seconds, and a re-handshake up to half a minute, since each step waits
  for a slot. Through the relays it takes about a minute. A rekey waits for any re-handshake
  still in progress, so two can't overlap (when they did, they broke each other's cookies), and
  a peer in the middle of one gets extra time before it's dropped for going quiet.
- Binaries from `just build test` say so: `testing <build id>` on the right of the console's top
  edge, and in `--version`.
- `just build` takes what to build: `just build linux` (was `just build-static`),
  `just build windows` or `win` (was `build-win`), `just build all` (was `all`) and
  `just build test [all|linux|windows]` (was `test-build`). Build directories keep their names.
- `:update` opens a box over the chat that shows the update while it runs. At the top is a
  console with each step: what it fetched from GitHub, the signature and SHA-256 checks, and
  where it installed. Under that is a progress bar for the download, then a line saying what
  it's doing now ("Checking GitHub for a newer release", "Release v0.4.0 found",
  "Downloading v0.4.0", "Installing v0.4.0"). Esc hides the box and the update keeps going.
  `:update` shows it again. The result still goes to the console.
- For a signing key from a file, `:install` saves the file's path rather than the key, and chat
  reads the file again each time it starts. If the file is gone, or holds a different key, the
  console says so. A pasted key has no file, so `:install` seals the key itself.
- The signing identity picker has a **Type a key file path** row under AGE and PGP, for when
  you'd rather not use the file browser. In the browser, `/` does the same, starting with the
  selected file. `:set sign age:PATH` and `:set sign pgp:PATH` work too. `~` is your home folder.
- The picker, the browser, the path field and the paste box say why chat needs your secret key:
  it signs your handshakes, and only the secret key can make a signature. It stays in memory and
  is never sent.
- The file browser (for a key file, and for `:send`) is drawn as a tree: the folder you're in
  and the folders above it, one level per row, with its folders and then its files under it.
  Hidden ones come last, and there's no `..` row (`h` goes up). How many levels get their own row
  depends on the terminal's width. The levels above those are joined into the top row's path,
  cut from the left with `…` if it's still too long. The top line says how many folders and files
  there are. On a wide terminal, a column left of the tree lists the parent folder, with the
  folder you're in selected and the parent's path above it. The sidebar shows the selected
  entry: whether it's a file, folder or link, its size or number of entries, when it was changed
  and its permissions. In the key file browser it also says whether a small file holds an AGE or
  PGP secret key, and if one does but others can read the file, says to `chmod 600` it. Going up
  selects the folder you came from, and `~` goes to the home folder. The key file browser opens
  in the folder of the key file in use.
- `:install` while nothing saved is open (`Esc` at the start) asks whether to use what's saved.
  Yes asks for its passphrase, after picking a save from a list when there's more than one, and
  from then on that save is in use, as if it had been opened at the start. Settings changed
  before that which it doesn't have, and keys verified before that, are kept and saved to it.
  A command line option doesn't undo a setting changed in that run, and keys from a save
  uninstalled in that run are left out.
  No makes a new save, with a name and a passphrase of its own. `:install NAME` for another save
  while one is open asks whether to save over it, then asks for that save's passphrase.
- A picture that was shown is kept in memory (up to 128 MB in all, the oldest dropped first)
  and wiped when the session closes. `:download N` saves it from there straight away, and
  `:show N` draws it again, without fetching it a second time.
- `:download N` for a file that's already saved says where it is instead of fetching it again,
  as long as the saved file still matches the offer. `:show N` of a picture saved earlier draws
  it from the saved file.
- `:download N FOLDER` saves in a folder other than Downloads, copying from an earlier save or a
  shown picture when there is one. `:saveto N` picks the folder in a file browser: Enter opens a
  folder and `s` saves in the one shown.
- `:download` without a number takes the newest file that isn't saved yet.
- Asking for a second file from a sender while one is coming queues it, and it starts by itself
  once the first is done, instead of being refused. The row under its offer and `:files` say
  what it's waiting for, and `:cancel N` takes it off the queue.
- `:download N` while a picture is coming to be shown, or `:show N` while it's coming to be
  saved, does both once it's here.
- `:files` says where each file was saved, and the message when a file is saved gives its size
  and how long it took.
- The Windows exe has version information and a manifest (Properties, Details shows them).
  Antivirus heuristics count an exe without them against it, and Malwarebytes flagged
  0.4.0-beta.2 as Malware.Heuristic.2062.
- On Windows, tor starts inside the job that ends it with chat, instead of being started
  suspended, added to the job, then resumed. This needs Windows 10 1607 or later.
- `Ctrl+C` asks before quitting, in a box that says how many sessions and peers are open, and
  what quitting loses: files still downloading, settings or a signing key that aren't saved,
  and an update that's still running. `y` quits, and `n` or `Esc` stays. In `--simple`, a
  second `Ctrl+C` within 3 seconds quits, and from a script it still quits at once.
- The row under the line that offered a file stays once the fetch is over: where it was saved,
  or why it failed and how to try again. Under one of yours it shows who's fetching it and how
  far they've got, then who it has gone to in full. The console says so too.
- The reply to `:download`, `:show`, `:cancel` and `:send` goes on the bottom bar as well as the
  console, so it isn't missed with the console hidden.
- `:files` with `--simple` says why a fetch failed, and for yours, who's fetching it or has.

### Fixed
- A message sent just before a peer rekeyed or rejoined could be lost, because the re-handshake
  discarded its retries.
- Joining or creating a session without the 512 MiB of free memory its key needs quit chat
  immediately, leaving the terminal in raw mode and the other sessions without a goodbye. The
  session now doesn't start, and chat says why.
- In Tor mode, a long session stopped reaching new members once it had seen 58 onion addresses.
  The least recently used one is now dropped to make room.
- The DHT bootstrap lookup, which runs on a thread, could write into a session after it closed.
- A key file or Tor cookie file that was a FIFO or a device made chat hang.
- A native build (`just build`, `just build test`) always used the build machine's CPU features
  in liboqs, so a copy could crash on a CPU without them. It now picks AVX2 code at run time.
- `--simple` writing to a pipe that closes no longer kills chat before its sessions leave, and a
  terminal resize no longer cuts a frame short.
- libsodium's build started a compiler for every file at once, which could run a small machine
  out of memory.
- `--nonostr` and `--nostr-always` were overridden by the routing choice. `--simple` without a
  terminal, or `--routing dht+nostr` given after them, went back to the relay fallback, so
  `--nonostr` still connected to the Nostr relays. They now apply whatever the routing, and
  `--simple --nonostr` without a terminal uses DHT only. The routing line says when the relays
  are always on.
- `Enter` on a message over the 250-byte limit sent it with the end cut off. It now stays in the
  box, where the count is already red, and the bottom row says how far over the limit it is.

## 0.3.1

### Changed
- Checking a peer's build no longer contacts GitHub. Each release binary carries a list of that
  release's binaries, signed with the release key, and sends it along with its hash; peers
  check the list against the release key built into chat. A build without a signed list, such
  as one from source, shows as modified. 0.3.0 peers are checked against 0.3.0's published
  hashes, which are built in. 0.3.0 shows newer peers' builds as unknown.
- `just release` signs the list and appends it to each binary before making `SHA256SUMS`, so it
  asks for the release key's password twice.
- `:peers` shows a build that checks out as "says official v0.3.1": a client altered to lie
  about its hash still passes, so that's only the peer's word.

## 0.3.0

### Added
- Sessions reach people direct with a Nostr relay fallback, direct only, or over Tor, chosen
  on the settings page chat opens on. `--routing direct+nostr|direct|tor` presets it.
- IPv6 DHT (BEP 32). Lookups run on the IPv4 and IPv6 DHTs side by side, and IPv6 peers
  connect directly. `--noipv6` turns it off.
- Router port mapping: chat asks the router to forward the session's UDP port (PCP, then
  NAT-PMP, then UPnP-IGD), renews it, tells the DHT the forwarded port, and removes the
  mapping when the session ends. `--noportmap` turns it off.
- Nostr relay fallback: when UDP between two peers can't get through, public Nostr relays
  carry their traffic. Each event is signed with its own one-off key, has a random ephemeral
  kind and a timestamp a few seconds off, and holds one fixed-size payload encrypted under a
  fresh nonce. It carries a room tag that changes every ten minutes. Relays that rate-limit get
  fewer events, and relays whose policy refuses throwaway keys are only read from. `--relay`
  picks relays; `--nonostr` turns it off.
- Tor routing: onion services. Each session publishes its own onion service and one of six room
  onion services derived from the session id and password. In Tor mode chat sends no UDP and
  connects nowhere directly.
- Tor and direct members of a room meet on the Nostr relays, the only place they can: both
  need the relays on. A Tor session reaches them only
  through Tor's SOCKS port, with a circuit per relay and the relay's name resolved at the exit,
  and doesn't connect to any relay until it has a tor. Between Tor members the traffic moves to
  their onion services once those connect. The **Nostr relays** setting and `--nonostr` now
  apply in both modes. When nobody answers and relays are off, chat says members using the
  other routing can't reach this session.
- Tor mode uses a tor that's already running (system service or Tor Browser) when its control
  port lets chat log in, since that one keeps its entry guards and bridges. Otherwise chat
  starts its own: tor from `PATH`, or `--tor-path`, provided no one but root or the user can
  change it. It runs with an empty configuration, on random 127.0.0.1 ports with cookie login,
  in a private temporary folder (in memory under `$XDG_RUNTIME_DIR` where there is one). chat
  deletes the folder on exit, tor quits by itself if chat crashes, and the next chat deletes
  what a crash left. `--tor-launch auto|always|never` chooses. `--tor-socks` and
  `--tor-control` say where to look for a running tor.
- A settings page (`Ctrl+S` or `:set`): routing and each part of it, the relays and Tor
  ports, nickname, colour, signing identity, notifications, the network log, the UDP port for
  new sessions, and the layout. Routing toggles apply to open sessions at once. The mode and
  the Tor settings apply to sessions opened afterwards. Nothing is written to disk.
- `--nolan` turns off LAN discovery.
- `:net` reports port mapping, relay and Tor status, and IPv4 and IPv6 lookups separately.
- A fuzz target for relay JSON and UPnP gateway replies (`just fuzz json`).
- `just test-build [all|linux|windows]` builds the Linux and Windows binaries, or one of them,
  into `test-builds/<date>-<time>/`. It builds this system's natively and cross-builds the
  other with zig, then offers to run this system's when there's a terminal to ask on, passing
  it any further arguments.
- A native AGE or PGP signing key is made from a password and this OS install's machine id,
  so the same password on the same device and OS always gives the same key and fingerprint,
  without storing anything. Always use the same password to keep an established signing
  identity. The settings picker asks for it after **Native**, and `--identity age|pgp` asks
  at startup or takes `CHAT_SIGN_PASSWORD`. A blank password makes a new random key, as
  before. `:set sign age|pgp` opens the picker to type it there, where it's hidden.
- Peers tell each other which version they run and the SHA-256 of their executable, and each
  checks it against the signed `SHA256SUMS` of that version's release. A peer that isn't
  running one of that release's binaries, or names a version with no signed release, is marked
  modified: a warning when it's found, `modified` next to its name, and its build in `:peers`.
  The first time a version comes up, its checksums are fetched from GitHub, through Tor in Tor
  mode. A client altered to lie about its hash still passes.

### Changed
- In Tor mode, `:update` and `--update` download through Tor's SOCKS port.
- Peers are reached on the best path that works: direct UDP, then Tor, then the relays. A
  worse path takes over only once the better one goes quiet. When a connected peer's hello
  arrives over a better path (UDP punched through, or a Tor stream, after the relays), chat
  answers with an encrypted frame on it, so both sides move there once it's proven.
- `--nodht` now turns off both DHTs.
- Candidate addresses stop getting hellos once their peer is connected.
- Mbed TLS 3.6.7 and libsecp256k1 0.7.1 are fetched and linked statically, and on Windows
  chat also links crypt32 (the system root certificates) and iphlpapi (the default gateway).
- Commands only run from COMMAND mode: `Esc`, then `:name`. Everything typed in INSERT is sent
  as a message, including lines that start with `/` or `:`. `--simple` takes `:name` instead
  of `/name`.
- Commands do things and settings hold values. Every setting is a row on the settings page,
  and `:set NAME VALUE` sets one without opening it (`:set nick bob`, `:set net verbose`);
  `:set` opens the page and `:set NAME` opens it on that row. `:nick`, `:colour`, `:notify`,
  `:netverbose`, `:sign` and `:settings` are gone. `--simple` has `:set` for `nick`, `colour`,
  `notify` and `net`.
- The network log setting is `normal` or `verbose`, and "Start chat's own tor" is `auto`,
  `always` or `never`, matching `--tor-launch`.
- The settings page, the signing identity picker and the key file browser take the same keys:
  `j`/`k` move, `g`/`G` go to the ends, `Enter` chooses, `h`/`l` change a value or go out of /
  into a page, `Esc` goes back, `q` closes. `Tab` no longer moves down a list. The picker and
  browser show where they are in the title (settings › signing identity › folder) and explain
  the selected choice under the list.
- The bottom bar is the same on every screen: a chip saying where you are, what the keys do,
  and the reply to what you just did until the next key. Settings changes and `:set` answer
  there, instead of on a line of the settings page.
- The time is at the right end of the top bar instead of the bottom bar.
- The signing identity picker lists Off, then AGE and PGP, each with Native, a key file and a
  key paste. Your own AGE key (as `age-keygen` writes it) can sign now, from a file, pasted in,
  or with `--identity age:KEYFILE`, and keeps its `age1...` recipient. `pgp` (`--identity pgp`,
  `:set sign pgp`) makes a new PGP key, whose public key the settings copy for `gpg --import`.
  The plain native key is gone: `--identity native` and `:set sign native` are refused.
- `Ctrl+W` deletes the word before the cursor, as in vim and readline, instead of closing the
  session; `:q` closes it. In NORMAL, `j` and `k` switch sessions.
- The input line starts in NORMAL; `i` (or `a`, `I`, `A`) starts typing.
- Nothing reaches the network while the settings page chat opens on is up: a tor is looked for
  or started, and `--peer` names are looked up, only after **Done**, whatever the page is
  switched to. In Tor mode a `--peer` name isn't looked up at all, since the lookup would go
  around Tor. With `--simple`, the lookup waits for the routing answer.
- chat opens on the settings page, so everything is set up in one place before the first
  session, and a **Done** button at the bottom (or `Esc`) goes on to the sessions.
- The signing identity is chosen on the settings page itself instead of at the input line:
  off, a new native or AGE key, or a PGP key picked in a file browser or pasted in. A native
  key used to need `--identity native`. `:set sign` opens the same choice. A key file that
  doesn't load, or a paste that doesn't parse, says so on the page.
- An **AGE recipient** row in settings shows the `age1...` string and copies it to the
  clipboard.
- Settings that don't apply right now are left off the page instead of greyed out: the DHT,
  LAN and port mapping switches in Tor mode, the Tor ones in direct mode, the relay list while
  the relays are off, and the AGE recipient without an AGE identity.

### Fixed
- A second Ctrl+C, SIGTERM or SIGHUP soon after the first killed chat immediately, before
  sessions said bye, keys were wiped and the terminal was restored: the quit handler was reset
  after the first signal (glibc's `signal()` does that with `_POSIX_C_SOURCE`, and the Windows
  C runtime always does). The handler now stays in place.
- Cross builds passed a relative toolchain path to the dependencies' builds, which only
  worked with an existing build directory.
- A peer could join as `anon (unverified)` in the console while the sidebar showed its real
  nick as verified: the join was announced on the peer's first frame to open, and when the one
  carrying its nick and signing identity was lost or overtaken, another got there first. Now
  `* joining: peer ID` shows as soon as the connection is made, and the usual `joined` line
  follows once the nick and identity are in (or after 5 seconds, so nobody joins unannounced).
  The modified-client warning waits for the join.
- The version on the bottom bar could run into the prompt.

## 0.2.1

### Security
- Importing a PGP key could read past the end of a buffer when the key block decoded to more
  than 4 KiB. The armor is now parsed properly: header lines are skipped and the CRC-24
  checksum line is checked.
- A PGP key that failed to import could overwrite the secret half of the current signing key
  but not the public half, so signatures stopped verifying. A failed import now leaves the
  current key as it was.
- Text from peers is decoded as strict UTF-8. Overlong forms, surrogates and stray bytes are
  dropped. Before, an overlong sequence could carry a byte that an 8-bit terminal reads as the
  start of a control sequence. The Arabic letter mark (U+061C), a bidi control, is now stripped
  like the other bidi controls.
- Programs that chat starts (curl for `/update`, notify-send) no longer inherit its sockets. On
  Windows, curl inherits only its standard handles. On Linux, chat sets no_new_privs.
- Packets with a length that chat never sends are dropped before any decryption is tried, so
  junk packets cost less CPU.
- More key material is wiped after use, and each peer's chain keys, the signing key and typed
  passwords are locked in memory where the memory lock limit allows.
- Stack variables start zeroed where the compiler supports it (`-ftrivial-auto-var-init=zero`).
- New session ids are uniformly random. Before, some characters were slightly more likely than
  others.
- A peer can no longer fill the list of chat's own addresses with replays of chat's own hi.
- Messages with a malformed message id are ignored.
- SIGTERM and SIGHUP now shut chat down like Ctrl+C does: sessions say bye, keys are wiped and
  the terminal is restored.

### Fixed
- A message whose first packet was lost could never be delivered if any later packet (cover
  traffic, say) reached the peer first, because each retry resent a frame the peer could no
  longer open. Each retry is now encrypted again with the next message key.
- If every retry slot was taken, a message wasn't sent at all to the remaining peers. It is now
  sent once, without retries.
- Bencode lists that contained lists or dictionaries were read wrongly.
- Non-ASCII text in the full-screen UI: line wrapping, padding and the cursor position now count
  screen columns, not bytes, and wide characters (CJK, most emoji) take two columns. Leftover
  characters no longer show at the ends of rows.
- The input line scrolls sideways when the text is longer than the screen, so the cursor stays
  visible. Password prompts show one dot per character, not per byte.
- Ctrl+arrow keys, function keys and other unknown key sequences are ignored instead of typing
  part of the sequence into the input line. Esc followed quickly by another key still counts
  as Esc.
- Leaving the full-screen UI restores the cursor's shape and visibility.
- A session whose socket couldn't be opened left its LAN socket open.
- `--port` rejects values outside 0-65535 instead of wrapping them. More than 16 `--peer`
  options is an error instead of the extras being dropped silently.

### Changed
- A pasted PGP key is checked for its END line only at the end of the paste so far, so long
  pastes no longer slow down.
- Redrawing the peer list no longer recomputes every nick's lookalike form for every peer.
- `just test` runs the new engine test, and `just fuzz` runs the new fuzz targets (see the
  README).
- `just release` releases the Unreleased section of this changelog: it names the section after
  the new version (the next patch unless one is given), sets that version in `CMakeLists.txt`,
  commits and tags it, and pushes only once the release is signed.

## 0.2.0

### Security
- `/peers` could overflow a stack buffer once about 25 peers were online.
- A room member could make a message appear to come from someone else. A message now shows
  the nick of the peer that sent it. A message passed on for a peer you aren't connected to
  shows as `nick (via relayer)`. A passed-on copy of a message from a peer you are connected
  to is ignored, because that peer's own copy arrives directly.
- Nicks can no longer contain `(`, `)`, `#`, `:` or `@`, so a nick can't fake "(verified)",
  "(you)" or an id. The sidebar shortens a long nick instead of hiding a peer's status.
- chat warns when a peer's signing identity changes, disappears or stops verifying after a
  re-handshake.
- Peer addresses shared by other peers must be IP addresses. Before, a room member could
  make everyone look up any hostname.
- The PGP key browser hides file names that contain terminal control characters.
- On Windows, `/update` runs `curl.exe` from `System32` only. Before, a `curl.exe` in the
  same folder as `chat.exe` or in the current folder would run instead.
- `/update` makes curl ignore `.curlrc`.
- The peer verify code is 16 hex digits instead of 8. The first 8 still match the code that
  older versions show.
- Hardening against outsiders who replay recorded packets or send junk: re-handshakes with
  new keys, or from a new address mid-handshake, must answer a cookie first. A replayed
  `kx` can no longer lock in bad keys. Junk packets from unknown addresses cost less CPU.
- Releases are signed. `/update` and `--update` install a release only if its `SHA256SUMS`
  carries a valid minisign signature from the release key built into chat, made for that
  release's tag. Control of the GitHub account alone is no longer enough to push an update.
- Before a peer rekeys, it announces its new key over the current session. A new key that a
  peer never announced is refused, so a room member between two peers can't swap in its own
  key at a rekey. This works between peers that both run this version.
- When a peer drops and comes back, chat says if its verify code changed.
- Nicks that look alike (case, `l`/`I`/`1`, `0`/`O`, Cyrillic or Greek letters, fullwidth
  forms) show with `#` and the peer's id. Invisible characters are removed from nicks.
- Candidate addresses from the DHT and from other peers are rate-limited, at most 4 per
  host, so chat can't be used to flood an address with handshake traffic.
- `--simple` without `--session` on a non-terminal starts a new random session instead of
  joining the fixed `lobby` session, which anyone could join.

### Added
- `/port [N]` shows this session's UDP port, or moves the session to port `N` without
  leaving it (`0` picks a free one). Connected peers follow the new port automatically.
- `--update` installs the latest release from the shell and exits, without opening chat.
  It exits with status 1 if the update fails, so `sudo chat --update` works for a copy
  in a system folder.

### Changed
- The Linux release binary is statically linked against musl, so it runs on any x86_64
  Linux distribution without depending on the system's glibc version.
- Building with [just](https://github.com/casey/just) is supported: `just build`,
  `just run`, and `just dist` for release binaries.
- chat is deliberately not packaged, to leave no trace beyond the executable. The README
  explains where to keep it so updates keep working.
- `/peers` prints one line per peer.
- Releases are built and published with `just release`. CI builds every push, but doesn't
  publish releases.

### Fixed
- On Linux, `:update` saved the new binary as `chat (deleted)` instead of replacing
  `chat` when the executable had been replaced (for example rebuilt) while chat was running.

## 0.1.1

### Added
- `@` nick completion: typing `@` and the start of an online peer's nick shows the rest
  dimmed; `Tab` completes it.
- The version number is shown in the status bar, after the identity badge.
- `/help` lists every command with its arguments.

### Changed
- Every command works both as `/name` in INSERT and as `:name` in COMMAND mode, from one
  shared command table, so `/new`, `/join`, `/sign`, `/copyid`, `/update` and `/quitall`
  (`/qa`) now work typed too.
- `/nick` changes your nickname in every open session.
- `/quit` (`/q`) leaves the current session and quits when none is left open.
- `/colour`, `/notify` and `/netverbose` without an argument show the current setting.
- Password and session-id prompts are plain fields (`Enter` confirms, `Esc` cancels), and
  the draft you were typing comes back afterwards.

## 0.1.0

First versioned release.

- `:update` checks the GitHub releases page, downloads the binary for your platform,
  verifies its SHA-256 against `SHA256SUMS`, and replaces the executable.
- `--version` prints the version number.
