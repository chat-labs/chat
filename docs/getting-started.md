# Getting started

## Download

To try chat without keeping it, use the runner at [chat.vin.moe](https://chat.vin.moe). It
downloads the latest release, checks its signature and hash the same way as below, runs it, and
deletes it when chat exits:

```sh
curl -fsSL https://chat.vin.moe | sh     # Linux
irm https://chat.vin.moe | iex           # Windows PowerShell
```

You can read the scripts before running them at [chat.vin.moe/chat.sh](https://chat.vin.moe/chat.sh)
and [chat.vin.moe/chat.ps1](https://chat.vin.moe/chat.ps1). The page lists each one's SHA-256 to
compare with what your shell would get.

To keep a copy, prebuilt Linux and Windows x86_64 binaries are on the [releases
page](https://github.com/chat-labs/chat/releases), with a `SHA256SUMS` file and its
[minisign](https://jedisct1.github.io/minisign/) signature. Check the signature against
[`keys/minisign.pub`](../keys/minisign.pub) (or
[`keys/minisign-backup.pub`](../keys/minisign-backup.pub), if the release notes say the backup key
signed it, see [Releases](releasing.md#the-backup-key)), then the hashes:

```sh
minisign -Vm SHA256SUMS -p minisign.pub
sha256sum -c --ignore-missing SHA256SUMS
```

## Installing the executable

I'm not packaging chat on purpose. The point is to leave nothing behind: apart from the
executable, nothing stays on the machine unless you ask for it with `:install` (see
[Installing](saves.md)). A package manager would record the install and put files outside
your control, so there are no packages (AUR or anything else).

Put the executable wherever you want. I'd recommend a folder you own that's on your `PATH`, like
`~/.local/bin`, because updating replaces the executable in place and needs write access to its
folder. Some systems already have an unrelated `chat` program (the modem dialer from `ppp`, for
example), so rename it if it clashes:

```sh
install -Dm755 chat-linux-x86_64 ~/.local/bin/chat   # or another name, e.g. ~/.local/bin/e2chat
```

If you put it in a system folder like `/usr/local/bin` or `/usr/bin` instead, you'll probably
need root to update it:

```sh
sudo chat --update
```

This depends on your system, and doesn't matter if you never plan on updating.

## Your first session

1. Run `chat`. It opens on the settings page, where routing, your nick, colour and signing identity
   are set up in one place (see [Settings](usage.md#settings)). **Start chatting**, on the **Start**
   page after the sections (`Tab` from Chat), or
   `Esc`, goes to your sessions. Nothing goes on the network before that.
2. `Ctrl+N` starts a new session, with a random password filled in. Until someone joins, the chat
   shows the session's id. `:invite` copies the id and password together as one invite, which comes
   off the clipboard again after 30 seconds.
3. Whoever you invite presses `Ctrl+J` and types the id, then the password, or pastes the invite.
4. When they join, chat shows a verify code. Compare it with them over something else, in person or
   on a call, and mark it with `:verify NICK ok` (see
   [Comparing verify codes](security.md#comparing-verify-codes)).

Without a terminal that can show the full-screen UI, or with `--simple`, chat prints plain lines
instead and asks for the session id, its password and the routing in turn. [Usage](usage.md) has
every key, command, setting and option, and [Saving settings and keys](saves.md) how to keep them
between runs.
