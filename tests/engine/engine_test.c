// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The engine test: every test, in order, each on the state the one before leaves. harness.h has
// what they share.
#include "harness.h"

int main(int argc, char **argv) {
    verbose = argc > 1 && (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0);
    double t_start = now_seconds();
    crypto_setup();
    net_startup();
    uint16_t to_b[1] = { 40002 }, to_a[1] = { 40001 };
    printf("deriving session keys (Argon2id, 512 MiB each)...\n");
    make_release();
    // The sessions keep to this clock, which runs as the tests say, not as the computer's does.
    double t = g_now = now_seconds();
    start(&A, &log_a, "alice", 40001, to_b, 1, 1, BUILD_ALICE, 1);
    start(&B, &log_b, "bob", 40002, to_a, 1, 0, BUILD_BOB, 1);

    struct { const char *name; void (*fn)(double *); } tests[] = {
        { "connect", test_connect }, { "verify gate", test_verify_gate }, { "message", test_message },
        { "long message", test_long_message },
        { "constant rate", test_constant_rate }, { "lost message", test_lost_message },
        { "rekey", test_rekey }, { "rekey mid-message", test_message_across_rekey }, { "cookie rate", test_cookie_rate },
        { "udp masked", test_udp_masked },
        { "junk", test_junk }, { "lookalike nick", test_lookalike_nick }, { "delivered", test_delivered },
        { "third peer", test_third_peer }, { "direct message", test_direct_message }, { "reply", test_reply }, { "ignore", test_ignore },
        { "timer", test_timer },
        { "candidates settle", test_candidates_settle }, { "builds", test_builds },
        { "parsers", test_parsers }, { "toml", test_toml }, { "dht keys", test_dht_keys }, { "dht", test_dht }, { "read file", test_read_file },
        { "identity keys", test_identity_keys }, { "call room", test_contact_room }, { "invite", test_invite },
        { "passphrase seal", test_passphrase_seal }, { "device lock", test_device_lock },
        { "factor locks", test_factor_locks }, { "totp", test_totp }, { "bytewords", test_bytewords }, { "links", test_links }, { "mentions", test_mentions }, { "qr", test_qr }, { "save factors", test_save_factors }, { "duress", test_duress }, { "lock screen", test_lock_screen }, { "sandbox", test_sandbox }, { "history", test_history }, { "tor state", test_tor_state }, { "rooms", test_rooms }, { "images", test_images }, { "file names", test_file_names }, { "clean", test_clean }, { "files", test_files }, { "clean offer", test_clean_offer },
        { "verified keys", test_trust }, { "move", test_move }, { "went offline", test_offline },
    };
    size_t n_tests = sizeof tests / sizeof tests[0];
    int failed[sizeof tests / sizeof tests[0]], n_failed = 0;
    for (size_t i = 0; i < n_tests; i++) {
        int before = failures;
        double t0 = now_seconds();
        if (verbose) printf("\n== %s\n", tests[i].name);
        // Rekeys come at random, so the test before may have left one going. During a test, only the ones
        // it asks for (next_rekey = 0) happen: re-handshakes are the rekey tests'.
        RUN_UNTIL(&t, 60, !rehandshaking_any());
        for (int k = 0; k < N_ALL; k++) ALL[k]->next_rekey = t + 3600.0;
        tests[i].fn(&t);
        int ok = failures == before;
        if (!ok) failed[n_failed++] = (int)i;
        printf("%s %-18s %6.0f ms\n", ok ? "ok  " : "FAIL", tests[i].name, (now_seconds() - t0) * 1000.0);
    }
    for (int i = 0; i < N_ALL; i++) if (live_mask & (1 << i)) chat_shutdown(ALL[i]);

    printf("\n%zu tests: %zu passed, %d failed | %d checks, %d failed | %.1f s\n",
           n_tests, n_tests - (size_t)n_failed, n_failed, checks, failures, now_seconds() - t_start);
    if (n_failed) {
        printf("failed:");
        for (int i = 0; i < n_failed; i++) printf("%s %s", i ? "," : "", tests[failed[i]].name);
        printf("\n");
    }
    return failures ? 1 : 0;
}
