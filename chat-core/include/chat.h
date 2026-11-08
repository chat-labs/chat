// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// chat-core in-process: the JSON interface (version 1) that chat-json serves on stdin and stdout,
// through C calls instead, a room a handle. Each command and each event is one JSON object in
// UTF-8 ending in NUL. Built with `just core::lib TARGET`.
#ifndef CHAT_CORE_H
#define CHAT_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ChatRoom ChatRoom;

// A room to drive, served on a thread of its own; its first event is "hello". NULL if it can't start.
ChatRoom *chat_open(void);

// A command (one object, or several a line each). 0, or -1 if it isn't UTF-8 or the room has ended.
int chat_send(ChatRoom *room, const char *line);

// The next event, waited for up to timeout_ms (below 0: however long it takes). NULL if none came in
// time, or once the room has ended (its last event is "bye"). Give each back with chat_free.
char *chat_recv(ChatRoom *room, int timeout_ms);

// An event from chat_recv, wiped and freed.
void chat_free(char *line);

// Leaves the room, as "quit" does, waits for it to end, and frees the handle.
void chat_close(ChatRoom *room);

#ifdef __cplusplus
}
#endif

#endif
