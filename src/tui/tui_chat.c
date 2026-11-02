// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The chat screen: the messages, the console, the sidebar, and the input box under them.
#include "tui/tui_draw.h"

#define G_HEAVY   "\xe2\x94\x81"   // ━

#define G_DOTTED  "\xe2\x97\x8c"   // ◌

#define G_UP      "\xe2\x86\x91"   // ↑

#define G_UPPER   "\xe2\x96\x80"   // ▀

// Bytes of s (len of them) that go on one row of width columns: up to the last space that leaves
// the row at least a third full, otherwise as much as fits.
size_t wrap_chunk(const char *s, size_t len, int width) {
    if (width < 1) width = 1;
    size_t n = utf8_fit_cols(s, len, width, NULL);
    if (n >= len) return len;
    if (n == 0) {
        // A character wider than the whole row still has to go somewhere.
        size_t adv;
        utf8_char_cols(s, len, 0, &adv);
        return adv;
    }
    size_t sp = n;
    while (sp > 0 && s[sp] != ' ') sp--;
    if (sp > n / 3) return sp;
    return n;
}

// Splits text into rows, the first first_w columns wide and the rest rest_w. Returns how many.
int wrap_rows(const char *text, int first_w, int rest_w, size_t *off, size_t *len, int max) {
    int n = 0;
    const char *tx = text;
    size_t remain = strlen(text);
    while (remain > 0 && n < max) {
        size_t take = wrap_chunk(tx, remain, n == 0 ? first_w : rest_w);
        off[n] = (size_t)(tx - text);
        len[n] = take;
        n++;
        tx += take; remain -= take;
        while (remain > 0 && *tx == ' ') { tx++; remain--; }
    }
    if (n == 0) { off[0] = 0; len[0] = 0; n = 1; }
    return n;
}

// ---- the chat and the console ----

// A chat line's name, the nick and what the UI adds to it.
#define NAME_BUF 96

// A chat line's name (its first color_len bytes, minus a mention's "@ " and the ':' after it) and
// the text after it. 0 for a line that isn't a chat line.
static int split_chat_line(const tui_scrollback_t *sb, const tui_line_t *l, char *name, size_t cap,
                           const char **body) {
    const char *text = tui_line_text(sb, l);
    size_t n = l->len;
    if (l->color_len <= 1 || (size_t)l->color_len > n || text[l->color_len - 1] != ':') return 0;
    const char *s = text;
    size_t len = (size_t)l->color_len - 1;
    if (l->mention && len >= 2 && s[0] == '@' && s[1] == ' ') { s += 2; len -= 2; }
    copy_slice(name, cap, s, len);
    const char *b = text + l->color_len;
    while (*b == ' ') b++;
    *body = b;
    return 1;
}

// What a peer is marked with: a symbol after its name in the chat, spelled out under it in the
// sidebar, in words that fit the narrowest sidebar. The engine ends a chat line's name with one in
// brackets ("ida (code compared)"), which the chat shows as the symbol.
enum { MK_YOU, MK_DIFFERS, MK_KEY_CHANGED, MK_INVALID, MK_TO_COMPARE, MK_COMPARED, MK_VERIFIED, MK_UNVERIFIED,
       MK_HISTORY, MK_MODIFIED, MK_IGNORED };
static const struct { const char *glyph, *word, *chat; style_t st; } MARKS[] = {
    [MK_YOU]         = { G_DIAMOND, "you",             "(you)",               S_FAINT },
    [MK_DIFFERS]     = { G_CROSS,   "codes differ",    "(codes differ)",      S_RED_BOLD },
    [MK_KEY_CHANGED] = { G_CROSS,   "key changed",     NULL,                  S_RED_BOLD },
    [MK_INVALID]     = { G_CROSS,   "bad signature",   NULL,                  S_RED_BOLD },
    [MK_TO_COMPARE]  = { "?",       "compare code",    "(code not compared)", S_YELLOW_BOLD },
    [MK_COMPARED]    = { G_CHECK,   "code compared",   "(code compared)",     S_GREEN },
    [MK_VERIFIED]    = { G_CHECK,   "verified",        NULL,                  S_GREEN },
    [MK_UNVERIFIED]  = { "?",       "unverified",      NULL,                  S_FAINT },
    [MK_HISTORY]     = { "h",       "keeps history",   NULL,                  S_YELLOW_BOLD },
    [MK_MODIFIED]    = { "!",       "modified client", NULL,                  S_RED_BOLD },
    [MK_IGNORED]     = { "i",       "ignored",         NULL,                  S_FAINT },
};

// A mark's symbol after a name, in the column the chat keeps for them.
#define MARK_COLS 2

static void draw_mark(pen_t *p, int mark) {
    if (mark < 0) return;
    ptext(p, S_PLAIN, " ");
    ptext(p, MARKS[mark].st, MARKS[mark].glyph);
}

// A chat line's name as it's drawn: the nick, what's added to tell it apart (a "#id", who relayed
// it), and the mark that ended it, or -1. No nick can contain '(' or '#', so those are always the UI's.
typedef struct {
    char nick[NAME_BUF], extra[NAME_BUF];
    int mark;
} chat_name_t;

static int split_name(const char *name, chat_name_t *n) {
    size_t cut = strlen(name), rest = cut;
    n->mark = -1;
    const char *open = strrchr(name, '(');
    for (int i = 0; open && i < (int)COUNT_OF(MARKS); i++) {
        if (!MARKS[i].chat || strncmp(open, MARKS[i].chat, strlen(MARKS[i].chat)) != 0) continue;
        n->mark = i;
        cut = (size_t)(open - name);
        rest = cut + strlen(MARKS[i].chat);
        break;
    }
    while (cut > 0 && name[cut - 1] == ' ') cut--;
    // A relayed line's mark is inside its "(via ...)", whose ')' stays.
    char bare[NAME_BUF];
    copy_slice(bare, sizeof bare, name, cut);
    size_t bl = strlen(bare);
    copy_str(bare + bl, name + rest, sizeof bare - bl);
    size_t nick = strcspn(bare, "#(");
    while (nick > 0 && bare[nick - 1] == ' ') nick--;
    copy_slice(n->nick, sizeof n->nick, bare, nick);
    copy_str(n->extra, bare + nick, sizeof n->extra);
    return utf8_str_cols(n->nick) + utf8_str_cols(n->extra);
}

// The nick in its colour, and what's added to it faint.
static void draw_name(pen_t *p, const chat_name_t *n, const uint8_t *rgb) {
    if (rgb) sty_rgb(p->w, rgb, 1, 0);
    else sty(p->w, S_BOLD);
    p->used += wapp_trunc(p->w, n->nick, p->room - p->used);
    ptext(p, S_FAINT, n->extra);
}

#define SB_AT(sb, k) (&(sb)->lines[((sb)->head - 1 - (k) + TUI_SCROLLBACK * 2) % TUI_SCROLLBACK])

// Lines from the bottom of nrows grid rows upwards, newest last, skipping the skip newest. Chat
// lines are laid out in columns (time, name, text), and a run from one person in the same minute
// shows the time and name once. The console's lines are faint, and its warnings yellow (bold in the chat).
// A picture's rows at width cols: each is two of its pixel rows, the upper one as the colour of a
// half block and the lower one as the colour behind it, scaled to the width by nearest pixel.
// The picture's size in pixels at most cols wide, keeping its shape.
static void image_fit(const tui_image_t *im, int cols, int *w, int *h) {
    *w = im->w < cols ? im->w : cols;
    *h = (int)(((int64_t)im->h * *w + im->w / 2) / im->w);
    if (*h < 1) *h = 1;
}

static int image_rows(const tui_image_t *im, int cols) {
    if (!im || im->w < 1 || im->h < 1 || cols < 1) return 0;
    int w, h;
    image_fit(im, cols, &w, &h);
    return (h + 1) / 2;
}

void draw_image_row(pen_t *p, const tui_image_t *im, int cols, int r) {
    int w, h;
    image_fit(im, cols, &w, &h);
    if (!g_color) {
        // It can't be drawn without colour.
        if (r == 0) ptext(p, S_FAINT, "(a picture: it needs a terminal with colour)");
        return;
    }
    int y0 = r * 2, y1 = r * 2 + 1;
    size_t stride = (size_t)im->w * 3;
    const uint8_t *top_row = im->rgb + (size_t)((int64_t)y0 * im->h / h) * stride;
    const uint8_t *bot_row = y1 < h ? im->rgb + (size_t)((int64_t)y1 * im->h / h) * stride : top_row;
    uint8_t last[6] = { 0 };
    for (int x = 0; x < w && p->used < p->room; x++) {
        size_t sx = (size_t)((int64_t)x * im->w / w) * 3;
        const uint8_t *top = top_row + sx, *bot = bot_row + sx;
        if (x > 0 && memcmp(last, top, 3) == 0 && memcmp(last + 3, bot, 3) == 0) wapp(p->w, G_UPPER);
        else if (y1 < h) wapp(p->w, "\x1b[38;2;%u;%u;%u;48;2;%u;%u;%um" G_UPPER, top[0], top[1], top[2], bot[0], bot[1], bot[2]);
        else wapp(p->w, "\x1b[0;38;2;%u;%u;%um" G_UPPER, top[0], top[1], top[2]);
        memcpy(last, top, 3);
        memcpy(last + 3, bot, 3);
        p->used++;
    }
    wapp(p->w, SGR_RESET);
}

// A progress bar width columns wide, permille of it lit: heavier, and in the accent colour.
void draw_bar(pen_t *p, int permille, int width) {
    int lit = clamp_permille(permille) * width / 1000;
    sty(p->w, S_ACCENT);
    for (int i = 0; i < lit; i++) wapp(p->w, G_HEAVY);
    sty(p->w, S_FAINT);
    for (int i = lit; i < width; i++) wapp(p->w, G_H);
    p->used += width;
}

// What a file is doing: a progress bar (heavier without colour) and its text, or the text after
// its mark.
static void draw_progress(pen_t *p, const tui_progress_t *pg) {
    if (pg->kind != TUI_PROGRESS_BAR) {
        if (pg->kind == TUI_PROGRESS_DONE) ptext(p, S_GREEN, G_CHECK " ");
        else if (pg->kind == TUI_PROGRESS_FAILED) ptext(p, S_RED, G_CROSS " ");
        pell(p, S_FAINT, pg->text, p->room - p->used);
        return;
    }
    int room = p->room - p->used;
    int bw = room >= 40 ? 16 : room >= 24 ? 8 : 0;
    if (bw) {
        draw_bar(p, pg->permille, bw);
        ptext(p, S_PLAIN, " ");
    }
    pell(p, S_FAINT, pg->text, p->room - p->used);
}

// The links in a chat line's text, after its quote.
#define LINE_LINKS_MAX 16
typedef struct { const char *text; size_t at[LINE_LINKS_MAX], len[LINE_LINKS_MAX]; int n; } line_links_t;

static void find_links(line_links_t *lk, const char *text, size_t n, size_t from) {
    lk->text = text;
    lk->n = 0;
    while (lk->n < LINE_LINKS_MAX && link_next(text, n, &from, &lk->at[lk->n], &lk->len[lk->n])) lk->n++;
}

// What a row needs besides a link's address to open and close OSC 8 around it, and its styles.
#define OSC8_ROOM 64

// Part of a link (len bytes of t), underlined, and for terminals that take OSC 8, something to click
// that opens the whole link. Only while the row has room for both: an escape cut off would swallow
// the rest of the screen.
static void draw_link(pen_t *p, style_t st, const char *t, size_t len, const char *link, size_t link_len) {
    char piece[TUI_LINE_MAX + 1], target[LINK_URL_MAX];
    copy_slice(piece, sizeof piece, t, len);
    wbuf_t *w = p->w;
    int osc = link_target(link, link_len, target, sizeof target) == 0 && w->len + strlen(target) + len + OSC8_ROOM < w->cap;
    if (osc) wapp(w, "\x1b]8;;%s\x1b\\", target);
    sty(w, st);
    wapp(w, "\x1b[4m");
    p->used += wapp_trunc(w, piece, p->room - p->used);
    if (osc) wapp(w, "\x1b]8;;\x1b\\");
}

// A chat line's text in style st (t, from off in lk->text on), its links underlined, and each @nick
// that names self highlighted, as mention_len matches them. The match looks at the whole line, so a
// longer name cut by the wrap isn't lit on the row that ends with self's part of it.
static void draw_body(pen_t *p, style_t st, const char *t, size_t off, const line_links_t *lk, const char *self) {
    size_t tn = strlen(t);
    char run[TUI_LINE_MAX + 1];
    size_t rn = 0;
    for (size_t i = 0; i < tn; ) {
        int li = 0;
        while (li < lk->n && !(off + i >= lk->at[li] && off + i < lk->at[li] + lk->len[li])) li++;
        if (li < lk->n) {
            size_t end = lk->at[li] + lk->len[li] - off;
            if (end > tn) end = tn;
            run[rn] = '\0';
            ptext(p, st, run);
            rn = 0;
            draw_link(p, st, t + i, end - i, lk->text + lk->at[li], lk->len[li]);
            i = end;
            continue;
        }
        size_t ml = self && t[i] == '@' ? mention_len(lk->text + off + i, self) : 0;
        if (!ml) {
            if (rn < sizeof run - 1) run[rn++] = t[i];
            i++;
            continue;
        }
        run[rn] = '\0';
        ptext(p, st, run);
        rn = 0;
        if (ml > tn - i) ml = tn - i;
        char nick[TUI_LINE_MAX + 1];
        copy_slice(nick, sizeof nick, t + i, ml);
        ptext(p, S_YELLOW_BOLD, nick);
        i += ml;
    }
    run[rn] = '\0';
    ptext(p, st, run);
}

// A divider across the pane with label on it, lead columns in, or in the middle if lead is -1.
static void draw_rule(grid_t *g, int row, const char *label, int lead, style_t line, style_t text) {
    gpen_t gp;
    grid_open(g, row, &gp);
    pen_t *p = &gp.p;
    int lw = (int)strlen(label);
    if (lead < 0) lead = (p->room - lw) / 2;
    sty(p->w, line);
    for (; p->used < lead && p->used < p->room; p->used++) wapp(p->w, G_H);
    if (p->used + lw <= p->room) ptext(p, text, label);
    sty(p->w, line);
    for (; p->used < p->room; p->used++) wapp(p->w, G_H);
    grid_close(g, row, &gp);
}

// The line above the n messages that came in while the session wasn't on screen.
static void draw_new_rule(grid_t *g, int row, int n) {
    char label[24];
    snprintf(label, sizeof label, " %d new ", n);
    draw_rule(g, row, label, 4, S_ACCENT, S_ACCENT_BOLD);
}

// The time column, "HH:MM" and a gap, in a pane at least TIME_MIN_W wide.
#define TIME_COLS (HHMM_LEN - 1 + 2)
#define TIME_MIN_W 36
#define WRAP_ROWS_MAX 64

static void draw_lines(grid_t *g, int first, int nrows, const tui_scrollback_t *sb, int skip, int console,
                       const tui_view_t *v) {
    if (!sb || nrows <= 0 || sb->count == 0) return;
    int W = g->w;
    if (skip >= sb->count) skip = sb->count - 1;
    if (skip < 0) skip = 0;
    // The line goes above the oldest of the new messages, and only if there are older ones above it.
    int fresh = !console && v && v->new_lines > 0 && v->new_lines < sb->count ? v->new_lines : 0;
    const char *self = !console && v ? v->self : NULL;
    int time_w = W >= TIME_MIN_W ? TIME_COLS : 0;
    // The name column: as wide as the widest name in view, up to a quarter of the pane, then a column
    // for the marks if a name in view has one. A name wider than that goes on its own row, so it
    // doesn't take up space in the column.
    int nw = 0, mw = 0;
    if (!console) {
        for (int k = skip; k < sb->count && k < skip + nrows; k++) {
            char name[NAME_BUF];
            const char *body;
            chat_name_t cn;
            if (!split_chat_line(sb, SB_AT(sb, k), name, sizeof name, &body)) continue;
            int c = split_name(name, &cn);
            if (c > nw && c <= W / 4) nw = c;
            if (cn.mark >= 0) mw = MARK_COLS;
        }
    }
    int aligned = W - time_w - nw - mw - 2 >= 16;
    int bottom = first + nrows - 1;
    for (int k = skip; k < sb->count && bottom >= first; k++) {
        const tui_line_t *l = SB_AT(sb, k);
        if (l->rule) {
            char label[TUI_LINE_MAX + 3];
            snprintf(label, sizeof label, " %s ", tui_line_text(sb, l));
            if (bottom < g->rows) draw_rule(g, bottom, label, -1, S_FAINT, S_PLAIN);
            bottom--;
            if (k + 1 == fresh && bottom >= first && bottom < g->rows) draw_new_rule(g, bottom--, fresh);
            continue;
        }
        char name[NAME_BUF];
        const char *body = tui_line_text(sb, l);
        int chat = split_chat_line(sb, l, name, sizeof name, &body);
        if (!chat && body[0] == '*' && body[1] == ' ') body += 2;
        chat_name_t cn = { .mark = -1 };
        int name_c = chat ? split_name(name, &cn) : 0;

        // A name wider than the column ("carol#1a2b3c4d (via bob)", or a long nick in a narrow pane)
        // goes on its own row above the text, so the text still lines up. Cutting it off could lose
        // what the chat adds to it.
        int stacked = chat && aligned && name_c > nw;
        int first_pre, rest_pre;
        if (chat && aligned) first_pre = rest_pre = time_w + nw + mw + 2;
        else if (chat) { first_pre = time_w + name_c + (cn.mark >= 0 ? MARK_COLS : 0) + 1; rest_pre = time_w; }
        else first_pre = rest_pre = time_w;
        if (first_pre > W - 1) first_pre = W - 1 > 0 ? W - 1 : 0;
        if (rest_pre > W - 1) rest_pre = W - 1 > 0 ? W - 1 : 0;

        // Your message's mark goes after its text, faint, or yellow for who it didn't reach.
        char text[TUI_LINE_MAX + TUI_MARK_MAX + 8];
        size_t body_len = strlen(body);
        style_t mark_style = l->delivery == TUI_MISSED ? S_YELLOW : S_FAINT;
        if (chat && l->own && l->delivery != TUI_SENDING)
            snprintf(text, sizeof text, "%s %s", body, l->delivery == TUI_MISSED ? l->mark : G_BULLET);
        else
            copy_str(text, body, sizeof text);
        size_t off[WRAP_ROWS_MAX], len[WRAP_ROWS_MAX];
        int nch = wrap_rows(text, W - first_pre, W - rest_pre, off, len, WRAP_ROWS_MAX);
        size_t qend = chat && l->quote > 0 && (size_t)l->quote <= body_len ? (size_t)l->quote : 0;
        line_links_t lk = { .n = 0 };
        if (chat) find_links(&lk, body, body_len, qend);
        // A picture shown under the line that offers it, lined up with the text.
        const tui_image_t *im = chat && l->file && v && v->image ? v->image(v->image_ctx, l->file) : NULL;
        int img_cols = W - rest_pre - 1 < TUI_IMAGE_MAX_W ? W - rest_pre - 1 : TUI_IMAGE_MAX_W;
        // At most half the pane's height, and narrower if needed, so the line above it stays in view.
        int img_most = nrows / 2 > 4 ? nrows / 2 : 4;
        if (im && image_rows(im, img_cols) > img_most) {
            img_cols = (int)((int64_t)im->w * img_most * 2 / im->h);
            if (img_cols < 1) img_cols = 1;
        }
        int nimg = image_rows(im, img_cols);
        // A file being downloaded: a row under the line, above where the picture will go if it is one.
        const tui_progress_t *pg = chat && l->file && v && v->progress ? v->progress(v->image_ctx, l->file) : NULL;
        int under = nimg + (pg ? 1 : 0);

        // Continues the line above: same person, same minute, that line is in view to show who, and
        // there's no separator line between them.
        int grouped = 0;
        if (chat && k + 1 < sb->count && k + 1 != fresh && bottom - nch - under >= first) {
            const tui_line_t *older = SB_AT(sb, k + 1);
            char oname[NAME_BUF];
            const char *ob;
            grouped = memcmp(older->hhmm, l->hhmm, HHMM_LEN - 1) == 0 && older->mention == l->mention
                   && split_chat_line(sb, older, oname, sizeof oname, &ob) && strcmp(oname, name) == 0;
        }

        int head = stacked && !grouped;

        int warn = !chat && starts_with(body, "warning:");
        style_t body_style = l->mention ? S_BOLD : warn ? (console ? S_YELLOW : S_YELLOW_BOLD) : console ? S_FAINT : S_PLAIN;
        int body_rgb = !chat && l->has_color && !warn;

        int hrow = bottom - under - nch;
        if (head && hrow >= first && hrow < first + nrows && hrow < g->rows) {
            gpen_t gp;
            grid_open(g, hrow, &gp);
            if (time_w) ptext(&gp.p, l->mention ? S_YELLOW_BOLD : S_FAINT, l->hhmm);
            pspace(&gp.p, time_w);
            draw_name(&gp.p, &cn, l->has_color ? l->rgb : NULL);
            draw_mark(&gp.p, cn.mark);
            grid_close(g, hrow, &gp);
        }

        for (int r = 0; r < nimg; r++) {
            int row = bottom - (nimg - 1 - r);
            if (row < first || row >= first + nrows || row >= g->rows) continue;
            gpen_t gp;
            grid_open(g, row, &gp);
            pspace(&gp.p, rest_pre);
            draw_image_row(&gp.p, im, img_cols, r);
            grid_close(g, row, &gp);
        }
        int prow = bottom - nimg;
        if (pg && prow >= first && prow < first + nrows && prow < g->rows) {
            gpen_t gp;
            grid_open(g, prow, &gp);
            pspace(&gp.p, rest_pre);
            draw_progress(&gp.p, pg);
            grid_close(g, prow, &gp);
        }
        for (int c = 0; c < nch; c++) {
            int row = bottom - under - (nch - 1 - c);
            if (row < first || row >= first + nrows || row >= g->rows) continue;
            gpen_t gp;
            grid_open(g, row, &gp);
            pen_t *p = &gp.p;
            if (c == 0 && !head) {
                if (time_w && !grouped) ptext(p, l->mention ? S_YELLOW_BOLD : S_FAINT, l->hhmm);
                pspace(p, time_w);
                if (chat && !grouped) {
                    if (aligned) pspace(p, time_w + nw - name_c);
                    draw_name(p, &cn, l->has_color ? l->rgb : NULL);
                    draw_mark(p, cn.mark);
                }
                pspace(p, first_pre);
            } else {
                pspace(p, rest_pre);
            }
            // A reply's quote is faint, then the text, then your message's mark.
            size_t from = off[c], to = off[c] + len[c];
            size_t q = qend < from ? from : qend > to ? to : qend;
            size_t cut = body_len < q ? q : body_len > to ? to : body_len;
            char piece[sizeof text];
            if (q > from) {
                copy_slice(piece, sizeof piece, text + from, q - from);
                ptext(p, S_FAINT, piece);
            }
            copy_slice(piece, sizeof piece, text + q, cut - q);
            if (body_rgb) {
                sty_rgb(p->w, l->rgb, 0, 0);
                p->used += wapp_trunc(p->w, piece, p->room - p->used);
            } else if (chat) {
                draw_body(p, body_style, piece, q, &lk, self);
            } else {
                ptext(p, body_style, piece);
            }
            if (to > cut) {
                copy_slice(piece, sizeof piece, text + cut, to - cut);
                ptext(p, mark_style, piece);
            }
            grid_close(g, row, &gp);
        }
        bottom -= nch + under + head;
        if (k + 1 == fresh && bottom >= first && bottom < g->rows) draw_new_rule(g, bottom--, fresh);
    }
}

int tui_chat_link(const tui_scrollback_t *sb, unsigned upto, int nth, tui_link_t *out) {
    int found = 0;
    for (int k = 0; k < sb->count; k++) {
        if (sb->total - 1 - (unsigned)k >= upto) continue;
        const tui_line_t *l = SB_AT(sb, k);
        char name[NAME_BUF];
        const char *body;
        if (!split_chat_line(sb, l, name, sizeof name, &body)) continue;
        size_t n = strlen(body);
        line_links_t lk;
        find_links(&lk, body, n, l->quote > 0 && (size_t)l->quote <= n ? (size_t)l->quote : 0);
        for (int i = lk.n - 1; i >= 0; i--, found++) {
            if (found != nth) continue;
            copy_slice(out->text, sizeof out->text, body + lk.at[i], lk.len[i]);
            chat_name_t cn;
            split_name(name, &cn);
            copy_str(out->from, cn.nick, sizeof out->from);
            size_t fl = strlen(out->from);
            copy_str(out->from + fl, cn.extra, sizeof out->from - fl);
            memcpy(out->hhmm, l->hhmm, HHMM_LEN);
            out->own = l->own != 0;
        }
    }
    return found;
}

// Splits text at its newlines into at most max lines. Returns how many.
int split_lines(const char *text, const char **lines, size_t *lens, int max) {
    int n = 0;
    for (const char *s = text; s && *s && n < max; ) {
        const char *nl = strchr(s, '\n');
        lines[n] = s;
        lens[n++] = nl ? (size_t)(nl - s) : strlen(s);
        if (!nl) break;
        s = nl + 1;
    }
    return n;
}

// Where n rows start to sit a little above the middle of nrows rows from first.
int center_top(int first, int nrows, int n) {
    int top = first + (nrows - n) / 2 - nrows / 10;
    return top < first ? first : top;
}

// Lines centred across the grid, a little above the middle: the first bold and the rest faint,
// except a line that's just emph (the session's id, to share), which is highlighted.
static void draw_center(grid_t *g, int first, int nrows, const char *text, const char *emph) {
    const char *lines[12];
    size_t lens[12];
    int n = split_lines(text, lines, lens, (int)COUNT_OF(lines));
    int top = center_top(first, nrows, n);
    for (int i = 0; i < n && top + i < first + nrows; i++) {
        char buf[TUI_LINE_MAX];
        copy_slice(buf, sizeof buf, lines[i], lens[i]);
        int c = utf8_str_cols(buf);
        if (c > g->w) c = g->w;
        gpen_t gp;
        grid_open(g, top + i, &gp);
        pspace(&gp.p, (g->w - c) / 2);
        style_t st = i == 0 ? S_BOLD : emph && strcmp(buf, emph) == 0 ? S_ACCENT_BOLD : S_FAINT;
        pell(&gp.p, st, buf, g->w);
        grid_close(g, top + i, &gp);
    }
}

// No session yet: what chat is, and the keys that start one.
static void draw_welcome(grid_t *g, int first, int nrows) {
    static const char *const KEYS[][2] = {
        { "ctrl+n", "start a new session" },
        { "ctrl+j", "join a session" },
        { "ctrl+s", "settings" },
        { "/help", "keys and commands" },
    };
    // The keys in a column, and what they do in one about as wide as the longest.
    enum { KEY_COLS = 9, DOES_COLS = 20 };
    int nkeys = (int)COUNT_OF(KEYS);
    int W = g->w;
    int top = center_top(first, nrows, 2 + nkeys);
    gpen_t gp;
    if (top < first + nrows) {
        grid_open(g, top, &gp);
        pspace(&gp.p, (W - utf8_str_cols(BRAND)) / 2);
        ptext(&gp.p, S_ACCENT_BOLD, BRAND);
        grid_close(g, top, &gp);
    }
    int block = KEY_COLS + DOES_COLS;
    int left = block < W ? (W - block) / 2 : 0;
    for (int i = 0; i < nkeys; i++) {
        int row = top + 2 + i;
        if (row >= first + nrows) break;
        grid_open(g, row, &gp);
        pspace(&gp.p, left);
        ptext(&gp.p, S_ACCENT_BOLD, KEYS[i][0]);
        pspace(&gp.p, left + KEY_COLS);
        ptext(&gp.p, S_PLAIN, KEYS[i][1]);
        grid_close(g, row, &gp);
    }
}

static void draw_chat_pane(grid_t *g, int first, int nrows, const tui_scrollback_t *sb, const tui_view_t *v) {
    if (!v->title) draw_welcome(g, first, nrows);
    else if ((!sb || sb->count == 0) && v->empty) draw_center(g, first, nrows, v->empty, v->title);
    else draw_lines(g, first, nrows, sb, v->scroll, 0, v);
}

static const char HIDDEN_HINT[] = "Chat and console are hidden\nctrl+t shows the chat" DOT_SEP "ctrl+o the console";

// A session's state: a ring while it starts, dotted while it connects, a dot once it's live.
static void state_mark(pen_t *p, tui_session_state_t state) {
    static const char *const GLYPH[] = { G_RING, G_DOTTED, G_DOT };
    static const style_t STYLE[] = { S_FAINT, S_YELLOW, S_GREEN };
    unsigned st = (unsigned)state < COUNT_OF(GLYPH) ? (unsigned)state : TUI_SESSION_LIVE;
    ptext(p, STYLE[st], GLYPH[st]);
}

// The session's state and name, unread counts for other sessions while the sidebar is hidden, and
// the subtitle.
static void chat_title(span_t *t, const tui_view_t *v, int sidebar_shown) {
    if (!v->title) { ptext(&t->p, S_BOLD, "welcome"); return; }
    state_mark(&t->p, v->state);
    ptext(&t->p, S_PLAIN, " ");
    ptext(&t->p, S_BOLD, v->title);
    if (!sidebar_shown && v->elsewhere > 0) {
        char n[48];
        snprintf(n, sizeof n, "%s%d new elsewhere", v->elsewhere_mention ? "@" : "", v->elsewhere);
        ptext(&t->p, S_FAINT, DOT_SEP);
        ptext(&t->p, v->elsewhere_mention ? S_YELLOW_BOLD : S_ACCENT_BOLD, n);
    }
    if (v->subtitle && v->subtitle[0]) {
        ptext(&t->p, S_FAINT, DOT_SEP);
        ptext(&t->p, S_FAINT, v->subtitle);
    }
}

// The console over the chat takes a quarter of the box, within these, and leaves the chat CHAT_ROWS_MIN.
#define CONSOLE_ROWS_MIN 3
#define CONSOLE_ROWS_MAX 8
#define CHAT_ROWS_MIN 4
#define CONSOLE_TITLE "console"

// Where each area is in the last chat frame, its edges or heading included, and how far it can
// scroll there, for the mouse wheel.
static rect_t g_area_at[TUI_AREA_N];
static int g_area_most[TUI_AREA_N];

tui_area_t tui_area_at(int row, int col) {
    for (int a = TUI_AREA_NONE + 1; a < TUI_AREA_N; a++) {
        const rect_t *r = &g_area_at[a];
        if (row >= r->top && row < r->top + r->h && col >= r->left && col < r->left + r->w) return (tui_area_t)a;
    }
    return TUI_AREA_NONE;
}

int tui_area_most(tui_area_t a) { return a > TUI_AREA_NONE && a < TUI_AREA_N ? g_area_most[a] : 0; }

// The console scrolls back until its oldest line is at the top, laid out as draw_lines() does.
static int console_skip(const tui_scrollback_t *sb, int scroll, int w, int nrows) {
    int pre = w >= TIME_MIN_W ? TIME_COLS : 0, rows = 0, *most = &g_area_most[TUI_AREA_CONSOLE];
    if (pre > w - 1) pre = w - 1 > 0 ? w - 1 : 0;
    *most = 0;
    for (int k = sb->count - 1; k >= 0; k--) {
        const char *body = tui_line_text(sb, SB_AT(sb, k));
        if (body[0] == '*' && body[1] == ' ') body += 2;
        size_t off[WRAP_ROWS_MAX], len[WRAP_ROWS_MAX];
        rows += wrap_rows(body, w - pre, w - pre, off, len, WRAP_ROWS_MAX);
        if (rows > nrows) {
            *most = k + 1 < sb->count ? k + 1 : k;
            break;
        }
    }
    return scroll < *most ? scroll : *most;
}

// The console above the chat, sharing an edge, in one box. Either one fills it if shown alone.
static void draw_main(wbuf_t *w, rect_t m, int boxed, int sidebar_shown, const tui_scrollback_t *sb,
                      const tui_scrollback_t *console, const tui_view_t *v) {
    int show_con = console && v->console, show_chat = v->chat;
    if (!boxed) {
        grid_reset(&g_grid, m.h, m.w);
        if (show_chat) draw_chat_pane(&g_grid, 0, m.h, sb, v);
        else if (show_con) {
            draw_lines(&g_grid, 0, m.h, console, console_skip(console, v->console_scroll, m.w, m.h), 1, NULL);
            g_area_at[TUI_AREA_CONSOLE] = m;
        } else draw_center(&g_grid, 0, m.h, HIDDEN_HINT, NULL);
        grid_emit(w, &g_grid, m.top, m.left, 0);
        return;
    }
    const char *bs = border_sgr(-1);
    int inner = m.h - 2;
    int con_h = 0;
    if (show_con && show_chat) {
        con_h = inner / 4;
        if (con_h < CONSOLE_ROWS_MIN) con_h = CONSOLE_ROWS_MIN;
        if (con_h > CONSOLE_ROWS_MAX) con_h = CONSOLE_ROWS_MAX;
        if (inner - con_h - 1 < CHAT_ROWS_MIN) con_h = inner - 1 - CHAT_ROWS_MIN;
        if (con_h < 1) show_con = 0;
    }
    int kskip = show_con ? console_skip(console, v->console_scroll, m.w - 4, show_chat ? con_h : inner) : 0;
    span_t clock, ctitle, ktitle, kright;
    span_init(&clock, m.w);
    if (v->clock) ptext(&clock.p, S_FAINT, v->clock);
    span_init(&ctitle, title_room(m.w, clock.p.used));
    if (show_chat) chat_title(&ctitle, v, sidebar_shown);
    else if (!show_con) ptext(&ctitle.p, S_FAINT, "hidden");
    span_init(&kright, title_room(m.w, 0) - (int)(sizeof CONSOLE_TITLE - 1) - TITLE_PAD);
    int clock_room = show_chat ? 0 : clock.p.used + 2;
    if (v->build_label) pell(&kright.p, S_FAINT, v->build_label, kright.p.room - clock_room);
    if (!show_chat && v->clock) {
        if (kright.p.used) ptext(&kright.p, S_FAINT, "  ");
        ptext(&kright.p, S_FAINT, v->clock);
    }
    span_init(&ktitle, title_room(m.w, kright.p.used));
    ptext(&ktitle.p, S_FAINT, CONSOLE_TITLE);
    if (kskip > 0) {
        char t[32];
        snprintf(t, sizeof t, G_DOWN " %d newer", kskip);
        ptext(&ktitle.p, S_FAINT, DOT_SEP);
        ptext(&ktitle.p, S_ACCENT_BOLD, t);
    }
    // Its bottom edge is the input box's top, which draw_input() draws.
    if (show_con) edge(w, m.top, m.left, m.w, top_left(m), G_TR, bs, &ktitle, &kright);
    else edge(w, m.top, m.left, m.w, top_left(m), G_TR, bs, &ctitle, &clock);
    sides(w, m.top + 1, inner, m.left, m.w, bs);

    int row = m.top + 1;
    if (show_con) {
        grid_reset(&g_grid, show_chat ? con_h : inner, m.w - 4);
        draw_lines(&g_grid, 0, g_grid.rows, console, kskip, 1, NULL);
        grid_emit(w, &g_grid, row, m.left + 1, 1);
        row += g_grid.rows;
        g_area_at[TUI_AREA_CONSOLE] = (rect_t){ m.top, m.left, row - m.top, m.w };
        if (show_chat) edge(w, row++, m.left, m.w, G_LT, G_RT, bs, &ctitle, &clock);
    }
    if (show_chat || !show_con) {
        grid_reset(&g_grid, m.top + m.h - 1 - row, m.w - 4);
        if (show_chat) draw_chat_pane(&g_grid, 0, g_grid.rows, sb, v);
        else draw_center(&g_grid, 0, g_grid.rows, HIDDEN_HINT, NULL);
        grid_emit(w, &g_grid, row, m.left + 1, 1);
    }
}

// ---- the sidebar: sessions, the peers in the selected one, and how it reaches them ----

enum { L_BLANK, L_HEAD_SESSIONS, L_NO_SESSIONS, L_SESSION, L_HEAD_PEERS, L_PEER, L_PEER_MARKS, L_HEAD_NET, L_NET,
       L_ABOVE, L_BELOW };

// A list with more entries than rows scrolls, with a row saying how many are above and one saying
// how many are below while there are any, given LIST_ROWS_MIN rows for them.
#define LIST_ROWS_MIN 3

typedef struct { int top, shown, above, below, most; } list_view_t;

static list_view_t list_view(int n, int rows, int top) {
    list_view_t v = { 0, n < rows ? n : rows, 0, 0, 0 };
    if (v.shown < 0) v.shown = 0;
    if (n <= rows || rows <= 0) return v;
    int marks = rows >= LIST_ROWS_MIN;
    v.most = marks ? n - rows + 1 : n - rows;
    v.top = top < 0 ? 0 : top > v.most ? v.most : top;
    v.above = marks && v.top > 0;
    v.shown = rows - v.above;
    if (marks && v.top + v.shown < n) {
        v.below = 1;
        v.shown--;
    }
    return v;
}

// Scrolled so entry sel is in view.
static list_view_t list_view_at(int n, int rows, int top, int sel) {
    list_view_t v = list_view(n, rows, top);
    if (sel < 0 || sel >= n) return v;
    if (sel < v.top) v = list_view(n, rows, sel);
    while (sel >= v.top + v.shown && v.top < v.most) v = list_view(n, rows, v.top + 1);
    return v;
}

// Each list's two rows, the entries split between them: either gets all it needs while that leaves
// the other half, otherwise they share them evenly.
static void split_rows(int rows, int a, int b, int *ra, int *rb) {
    if (rows < 0) rows = 0;
    int half = rows / 2;
    if (a + b <= rows) { *ra = a; *rb = b; }
    else if (a <= rows - half) { *ra = a; *rb = rows - a; }
    else if (b <= half) { *ra = rows - b; *rb = b; }
    else { *ra = rows - half; *rb = half; }
}

static int list_cramped(int rows, int n) { return rows < n && rows < LIST_ROWS_MIN; }

// Where the sessions and the peers are scrolled to, the selected session they're for, and the rows
// the sessions had.
static int g_list_top[TUI_AREA_N], g_list_sel = -1, g_list_rows = -1;

void tui_scroll_list(tui_area_t a, int dir) {
    if (a != TUI_AREA_SESSIONS && a != TUI_AREA_PEERS) return;
    int v = g_list_top[a] + dir;
    g_list_top[a] = v < 0 ? 0 : v > g_area_most[a] ? g_area_most[a] : v;
}

static void heading(pen_t *p, const char *title, int count) {
    ptext(p, S_FAINT, title);
    if (count >= 0) {
        char n[16];
        snprintf(n, sizeof n, "%d", count);
        pspace(p, p->room - (int)strlen(n));
        ptext(p, S_FAINT, n);
    }
}

// The mark before an entry in a list: a pointer on the selected one.
void pointer(pen_t *p, int on) { ptext(p, on ? S_ACCENT_BOLD : S_PLAIN, on ? G_PTR " " : "  "); }

// A session: its name, then a badge with how many messages came in while it wasn't on screen
// (yellow, with '@' first, if one mentions you; past BADGE_MAX, a '+'), its state and how many
// peers are online.
#define BADGE_MAX 99

static void session_line(pen_t *p, const tui_session_row_t *s, int sel) {
    char count[16], badge[16] = "";
    snprintf(count, sizeof count, "%d", s->online);
    if (!sel && s->unread > 0)
        snprintf(badge, sizeof badge, " %s%d%s ", s->mention ? "@" : "", s->unread > BADGE_MAX ? BADGE_MAX : s->unread,
                 s->unread > BADGE_MAX ? "+" : "");
    int bw = badge[0] ? (int)strlen(badge) + 1 : 0;
    int right = 2 + (int)strlen(count) + bw;
    pointer(p, sel);
    pell(p, sel ? S_ACCENT_BOLD : badge[0] ? S_BOLD : S_PLAIN, s->label, p->room - p->used - right - 1);
    pspace(p, p->room - right);
    if (badge[0]) {
        sty_pill(p->w, s->mention ? TUI_TONE_COMMAND : TUI_TONE_PAGE);
        p->used += wapp_trunc(p->w, badge, p->room - p->used);
        ptext(p, S_PLAIN, " ");
    }
    state_mark(p, s->state);
    ptext(p, S_FAINT, " ");
    ptext(p, S_FAINT, count);
}

// What applies to a peer: who it is or its verify state, most urgent first (codes that differ, a
// key that isn't the one verified for the nick, a bad signature, a code still to compare), then a
// history kept, a modified client and an ignored one.
#define PEER_MARKS_MAX 4

static int peer_marks(const tui_peer_row_t *pr, int mk[PEER_MARKS_MAX]) {
    int n = 0;
    if (pr->you) mk[n++] = MK_YOU;
    else if (pr->code == TUI_CODE_DIFFERS) mk[n++] = MK_DIFFERS;
    else if (pr->code == TUI_CODE_KEY_CHANGED) mk[n++] = MK_KEY_CHANGED;
    else if (pr->verify == TUI_VERIFY_BAD) mk[n++] = MK_INVALID;
    else if (pr->code == TUI_CODE_TO_COMPARE) mk[n++] = MK_TO_COMPARE;
    else if (pr->code == TUI_CODE_COMPARED) mk[n++] = MK_COMPARED;
    else if (pr->verify == TUI_VERIFY_OK) mk[n++] = MK_VERIFIED;
    else mk[n++] = MK_UNVERIFIED;
    if (pr->history) mk[n++] = MK_HISTORY;
    if (pr->modified) mk[n++] = MK_MODIFIED;
    if (pr->ignored) mk[n++] = MK_IGNORED;
    return n;
}

static int mark_cols(int m, int word) {
    return utf8_str_cols(MARKS[m].glyph) + (word ? 1 + utf8_str_cols(MARKS[m].word) : 0);
}

static void mark_item(pen_t *p, int m, int word) {
    ptext(p, MARKS[m].st, MARKS[m].glyph);
    if (!word) return;
    ptext(p, MARKS[m].st, " ");
    ptext(p, MARKS[m].st, MARKS[m].word);
}

// The rows under a peer that spell out its marks, room columns wide, as the first mark on each.
// Marks share a row while they fit.
static int mark_rows(const int *mk, int n, int room, int first[PEER_MARKS_MAX + 1]) {
    int rows = 0, used = 0;
    for (int i = 0; i < n; i++) {
        int c = mark_cols(mk[i], 1);
        if (rows > 0 && used + 2 + c <= room) { used += 2 + c; continue; }
        first[rows++] = i;
        used = c;
    }
    first[rows] = n;
    return rows;
}

// The marks are indented under the nick, past the dot before it.
#define MARK_INDENT 2

static int peer_mark_rows(const tui_peer_row_t *pr, int room) {
    int mk[PEER_MARKS_MAX], first[PEER_MARKS_MAX + 1];
    int n = peer_marks(pr, mk);
    return mark_rows(mk, n, room - MARK_INDENT, first);
}

static void peer_marks_line(pen_t *p, const tui_peer_row_t *pr, int row) {
    int mk[PEER_MARKS_MAX], first[PEER_MARKS_MAX + 1];
    int n = peer_marks(pr, mk);
    if (row >= mark_rows(mk, n, p->room - MARK_INDENT, first)) return;
    pspace(p, MARK_INDENT);
    for (int i = first[row]; i < first[row + 1]; i++) {
        if (i > first[row]) pspace(p, p->used + 2);
        mark_item(p, mk[i], 1);
    }
}

// A peer's nick, and unless its marks are spelled out under it, the marks after it: in words while
// they fit, then as symbols, the verify state last. The nick is cut to make room for them, never the
// other way.
static void peer_line(pen_t *p, const tui_peer_row_t *pr, int spelled) {
    int mk[PEER_MARKS_MAX], word[PEER_MARKS_MAX];
    int n = spelled ? 0 : peer_marks(pr, mk);
    int tag_w = utf8_str_cols(pr->tag);
    int nick_w = utf8_str_cols(pr->nick);
    int room = p->room - 2 - tag_w - 1, want = nick_w < 6 ? nick_w : 6;
    int right = n > 0 ? n - 1 : 0;
    for (int i = 0; i < n; i++) { word[i] = 1; right += mark_cols(mk[i], 1); }
    // From the second mark round to the first, so the verify state keeps its word longest.
    for (int i = 1; i <= n && room - right < want; i++) {
        int k = i % n;
        right -= mark_cols(mk[k], 1) - mark_cols(mk[k], 0);
        word[k] = 0;
    }
    sty_rgb(p->w, pr->color, 0, 0);
    p->used += wapp_trunc(p->w, G_DOT " ", p->room - p->used);
    int nick_room = p->room - p->used - tag_w - right - 1;
    prgb(p, pr->color, pr->you, pr->nick, nick_room < 1 ? 1 : nick_room);
    ptext(p, S_FAINT, pr->tag);
    pspace(p, p->room - right);
    for (int i = 1; i <= n; i++) {
        if (i > 1) ptext(p, S_PLAIN, " ");
        mark_item(p, mk[i % n], word[i % n]);
    }
}

static void draw_sidebar(wbuf_t *w, rect_t r, const tui_session_row_t *sessions, int n_sessions, int selected,
                         const tui_peer_row_t *peers, int n_peers, const tui_kv_t *net, int n_net) {
    const char *bs = border_sgr(-1);
    span_t title, right;
    brand(&title, &right, r.w);
    box(w, r, bs, &title, &right, NULL);
    int h = r.h - 2;
    if (h > MAX_ROWS) h = MAX_ROWS;
    static int kind[MAX_ROWS], arg[MAX_ROWS];
    int n = 0;
#define ADD(k, a) do { if (n < h) { kind[n] = (k); arg[n] = (a); n++; } } while (0)
    // Each peer's marks are spelled out on rows under it while every peer's fit above the network
    // section: the sessions and a blank row and heading before the peers, a blank row and heading
    // before the network.
    int room = r.w - 4, under = 0;
    for (int i = 0; i < n_peers; i++) under += peer_mark_rows(&peers[i], room);
    int s_need = n_sessions > 0 ? n_sessions : 1, p_head = n_peers > 0 ? 2 : 0, net_rows = n_net > 0 ? 2 + n_net : 0;
    int spelled = 1 + s_need + 2 + n_peers + under + net_rows <= h;
    // Too many sessions or peers to fit, and they scroll. Rather than lists too short for that, the
    // network goes.
    int s_rows, p_rows;
    split_rows(h - 1 - p_head - net_rows, s_need, n_peers, &s_rows, &p_rows);
    if (net_rows && (list_cramped(s_rows, s_need) || list_cramped(p_rows, n_peers))) {
        net_rows = 0;
        split_rows(h - 1 - p_head, s_need, n_peers, &s_rows, &p_rows);
    }
    // The sessions follow the selected one as it changes (there's no clicking on one), and when they
    // have more rows or fewer.
    if (selected != g_list_sel) {
        g_list_sel = selected;
        g_list_top[TUI_AREA_PEERS] = 0;
        g_list_rows = -1;
    }
    if (s_rows != g_list_rows) {
        g_list_rows = s_rows;
        g_list_top[TUI_AREA_SESSIONS] = list_view_at(n_sessions, s_rows, g_list_top[TUI_AREA_SESSIONS], selected).top;
    }
    list_view_t sv = list_view(n_sessions, s_rows, g_list_top[TUI_AREA_SESSIONS]);
    list_view_t pv = list_view(n_peers, p_rows, g_list_top[TUI_AREA_PEERS]);
    g_list_top[TUI_AREA_SESSIONS] = sv.top;
    g_list_top[TUI_AREA_PEERS] = pv.top;
    g_area_most[TUI_AREA_SESSIONS] = sv.most;
    g_area_most[TUI_AREA_PEERS] = pv.most;

    ADD(L_HEAD_SESSIONS, 0);
    if (n_sessions == 0) ADD(L_NO_SESSIONS, 0);
    if (sv.above) ADD(L_ABOVE, sv.top);
    for (int i = sv.top; i < sv.top + sv.shown; i++) ADD(L_SESSION, i);
    if (sv.below) ADD(L_BELOW, n_sessions - sv.top - sv.shown);
    if (sv.most > 0) g_area_at[TUI_AREA_SESSIONS] = (rect_t){ r.top + 1, r.left, n, r.w };
    if (n_peers > 0) {
        ADD(L_BLANK, 0);
        int head = n;
        ADD(L_HEAD_PEERS, 0);
        if (pv.above) ADD(L_ABOVE, pv.top);
        for (int i = pv.top; i < pv.top + pv.shown; i++) {
            ADD(L_PEER, i);
            int rows = spelled ? peer_mark_rows(&peers[i], room) : 0;
            for (int j = 0; j < rows; j++) ADD(L_PEER_MARKS, i * PEER_MARKS_MAX + j);
        }
        if (pv.below) ADD(L_BELOW, n_peers - pv.top - pv.shown);
        if (pv.most > 0) g_area_at[TUI_AREA_PEERS] = (rect_t){ r.top + 1 + head, r.left, n - head, r.w };
    }
    if (net_rows) {
        // At the bottom when there's room, otherwise straight after the rest.
        int start = h - n_net - 1;
        if (start < n + 1) start = n + 1;
        while (n < start && n < h) ADD(L_BLANK, 0);
        ADD(L_HEAD_NET, 0);
        for (int i = 0; i < n_net; i++) ADD(L_NET, i);
    }
#undef ADD
    int lw = 0;
    for (int i = 0; i < n_net; i++) {
        int c = utf8_str_cols(net[i].label);
        if (c > lw) lw = c;
    }
    for (int i = 0; i < h; i++) {
        int k = i < n ? kind[i] : L_BLANK, a = i < n ? arg[i] : 0;
        int sel = k == L_SESSION && a == selected;
        row_select(sel);
        pen_t p;
        inner_begin(w, &p, r.top + 1 + i, r.left + 1, r.w - 2);
        switch (k) {
            case L_HEAD_SESSIONS: heading(&p, "SESSIONS", n_sessions > 0 ? n_sessions : -1); break;
            case L_NO_SESSIONS:   ptext(&p, S_FAINT, "none yet" DOT_SEP "ctrl+n"); break;
            case L_SESSION:       session_line(&p, &sessions[a], sel); break;
            case L_HEAD_PEERS:   heading(&p, "PEERS", n_peers); break;
            case L_PEER:          peer_line(&p, &peers[a], spelled); break;
            case L_PEER_MARKS:    peer_marks_line(&p, &peers[a / PEER_MARKS_MAX], a % PEER_MARKS_MAX); break;
            case L_HEAD_NET:      heading(&p, "NETWORK", -1); break;
            case L_ABOVE:
            case L_BELOW: {
                char t[32];
                snprintf(t, sizeof t, "%s %d more", k == L_ABOVE ? G_UP : G_DOWN, a);
                ptext(&p, S_FAINT, t);
                break;
            }
            case L_NET:
                ptext(&p, S_FAINT, net[a].label);
                pspace(&p, lw + 2);
                pell(&p, S_PLAIN, net[a].value, p.room - p.used);
                break;
            default: break;
        }
        inner_end(&p);
        row_select(0);
    }
}

// The input box holds at most this many rows of text, fewer on a short screen.
#define INPUT_ROWS_MAX 6

// The input box's height in the last full chat frame, or 0 after anything else was drawn.
int g_input_h;

// The sidebar is the left hand box, if the chat keeps CHAT_COLS_MIN.
#define CHAT_COLS_MIN 44

// One frame, split by lines: the sidebar's right side is the chat's left, and the chat's bottom
// edge is the input box's top. The box is as tall as the wrapped text, up to a third of the space
// inside the frame, so the chat keeps most of the screen.
static void chat_layout(int rows, int cols, const tui_view_t *v, const tui_bar_t *bar, rect_t *side, rect_t *main_r,
                        rect_t *input, int *boxed) {
    *boxed = rows >= BOXED_ROWS && cols >= BOXED_COLS;
    int sbw = *boxed && v->sidebar ? left_width(cols, CHAT_COLS_MIN) : 0;
    *side = (rect_t){ 1, 1, rows - 1, sbw };
    int x = sbw > 0 ? sbw : 1, ih = 1;
    if (*boxed) {
        int most = (rows - 8) / 3;
        ih = 2 + input_rows(bar, cols - x + 1, most < INPUT_ROWS_MAX ? most : INPUT_ROWS_MAX);
    }
    *input = (rect_t){ rows - ih, x, ih, cols - x + 1 };
    *main_r = (rect_t){ 1, x, rows - ih - (*boxed ? 0 : 1), cols - x + 1 };
}

void tui_render(int rows, int cols,
                const tui_session_row_t *sessions, int n_sessions, int selected,
                const tui_peer_row_t *peers, int n_peers, const tui_kv_t *net, int n_net,
                const tui_scrollback_t *sb, const tui_scrollback_t *console,
                const tui_view_t *view, const tui_bar_t *bar, int color_enabled) {
    wbuf_t w = frame_init(&rows, &cols, color_enabled);
    rect_t side, main_r, input;
    int boxed;
    chat_layout(rows, cols, view, bar, &side, &main_r, &input, &boxed);
    g_input_h = input.h;
    memset(g_area_at, 0, sizeof g_area_at);
    memset(g_area_most, 0, sizeof g_area_most);

    begin_frame(&w);
    if (side.w > 0) draw_sidebar(&w, side, sessions, n_sessions, selected, peers, n_peers, net, n_net);
    draw_main(&w, main_r, boxed, side.w > 0, sb, console, view);
    int cr, cc;
    draw_input(&w, input, boxed, bar, view, main_r, &cr, &cc);
    finish_frame(&w, rows, cols, bar, cr, cc);
}

int tui_render_bar(int rows, int cols, const tui_view_t *view, const tui_bar_t *bar, int color_enabled) {
    wbuf_t w = frame_init(&rows, &cols, color_enabled);
    rect_t side, main_r, input;
    int boxed;
    chat_layout(rows, cols, view, bar, &side, &main_r, &input, &boxed);
    // A change in the input's height moves the chat's bottom edge, which needs a full frame. So does
    // a dialog.
    if (input.h != g_input_h || bar->dialog) return -1;

    begin_frame(&w);
    int cr, cc;
    draw_input(&w, input, boxed, bar, view, main_r, &cr, &cc);
    draw_status(&w, rows, cols, bar);
    place_cursor(&w, cr, cc, bar->input);
    end_frame(&w, 0);
    return 0;
}
