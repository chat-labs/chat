# Changelog

## 0.6.0

- chat in the terminal, built on chat-core: rooms with no server and no accounts, end-to-end
  encrypted, through Tor by default (built in, nothing to install), or direct for speed.
- Messages, replies, mentions, direct messages and delivery marks; verify codes; signing keys
  (AGE or PGP, made here, from a password, or from a file); calls between verified keys; moving a
  room with the people whose codes you compared.
- Files and pictures, cleaned of where, when and with what they were made; QR codes for invites.
- Saves: settings, keys, kept rooms and histories sealed with a passphrase, with an authenticator
  app, self-destruct and a shadow passphrase; the lock screen and the panic key.
- Tor bridges, router port mapping, new Tor circuits on demand.
- The settings page: a page for each section with the sections on the left, rows under their
  headings, the picked row's help and /set command, search, the signing identity's own page, and
  a last page with every row. chat starts on it, and goes on the network once it's left.
- A file browser for picking a signing key file, a file to send (`/send` alone), the folder to
  save a file in (`/saveto N`, or `s` on the files page) and the folder to export the signing key
  to (`/exportkey`, after asking); and a box to paste a signing key into.
- The chat screen's modes (INSERT, NORMAL and COMMAND), the command line's menu, the console over
  the chat, showing or hiding the sidebar, console and chat, the mouse wheel, and the help page.
- `/install` says what it saves and asks first, offers a save that's there already, and sets up the
  device lock, a security key or the authenticator it was asked for; the device lock says what
  would lose the save before it locks it.
- Notifications for files offered; colours made readable on the terminal's background, and the
  picked row shaded.
- `--simple` (plain lines in and out, also when there's no terminal) and `--json`, and the rest
  of the command line's options.
- The files page as a page: what's offered and yours, what each is doing, the details on the
  left; a picture opens on a page of its own. Links in the chat are underlined, and open on a
  click where the terminal takes OSC 8.
- Using a tor that's already running (`torlaunch`, `torsocks`, `torcontrol`, `torpassword`); the
  Linux sandbox; a device lock that speaks to the TPM itself where systemd's credential service
  isn't there.
- Ctrl+N fills in a random password first; Ctrl+J lists the rooms kept in the save.
- `/update` and `chat --update`: the newest release from GitHub (with `/set betas on`, betas too),
  installed only once its SHA256SUMS checks out against the release key, and downloaded through
  Tor in Tor mode (`chat --update`: when the save it opens, or `--routing`, chose Tor). Peers are
  told which build this is, so they can check it. With the sandbox up, chat-updater, a second process, does the
  installing. The terminal's theme is followed as it changes, and where the limit on locked
  memory is finite, keys and the conversation still stay out of swap.
