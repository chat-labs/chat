// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Known answers for crypto: verifies keys, codes, ratchets, and signatures from known inputs.

use chat_core::protocol::crypto::{self, Ratchet, RoomKeys, identity::IdentityKeypair};
use chat_core::protocol::{hex, names};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn room_keys_match_expected() {
    let k = RoomKeys::derive("NH7Q5KS2ZX", "correct horse").unwrap();
    assert_eq!(
        k.master.to_vec(),
        h("0ddc759ec3bf58ae8f2973822b818ddda0ca13717a07354e4bad38a66baf373f")
    );
    assert_eq!(
        k.room.to_vec(),
        h("31e4393fde8680bafdae546c489f1b248d07f29fff153af25a9507da2c3e5f22")
    );
    assert_eq!(
        k.udp.to_vec(),
        h("5266991411e39d387a34adf35e37198a6bc404d9579598ec5651504ef25b4011")
    );
    assert_eq!(
        k.dht.to_vec(),
        h("51a3e5ee0d984b2c7493335645c59998aeb38fb23a9b86c30afff649609761ec")
    );
    assert_eq!(
        crypto::dht_infohash(&k.dht, 494000).to_vec(),
        h("b66e023269cd18271279e1ae8dff15d821d09fbe")
    );
    assert_eq!(k.lan_port, 64263);
    assert_eq!(
        k.nostr_tag.to_vec(),
        h("56190f27246c9983ac9b1e767f89e68319e20e91e0f32feabfdf56e4c4946959")
    );
    assert_eq!(
        k.nostr_wrap.to_vec(),
        h("1b2754cc3cc7f268ea84c9279ef3d647fbbc748c974e9c7747c073da6644f64c")
    );
    assert_eq!(
        crypto::nostr_tag(&k.nostr_tag, 2964000),
        "8584ab0b84c54a9cc91e27a93bc0662735530ff2af091e50bc7ba9da9943ff31"
    );
    assert_eq!(k.history_id().to_vec(), h("344183e30eab2bcb037aaf5d4f9bfb3e"));

    let mut d: Vec<u8> = (0..64u8).collect();
    assert!(crypto::udp_mask(&k.udp, &mut d));
    assert_eq!(
        d,
        h(
            "32341c969de34c24d61c2cae0cd0aa2b7860e2fca3295ab0ce04fc1d0c3c5edd9329d1ac90ff8acffaae2aaf68760b43303132333435363738393a3b3c3d3e3f"
        )
    );
}

#[test]
fn session_keys_match_expected() {
    let master: [u8; 32] = h("0ddc759ec3bf58ae8f2973822b818ddda0ca13717a07354e4bad38a66baf373f")
        .try_into()
        .unwrap();
    let shared: [u8; 32] = std::array::from_fn(|i| i as u8);
    let my_pub: [u8; 32] = std::array::from_fn(|i| 100 + i as u8);
    let their_pub: [u8; 32] = std::array::from_fn(|i| 50 + i as u8);
    let ss: [u8; 32] = std::array::from_fn(|i| 200 + i as u8);
    let my_id: [u8; 16] = std::array::from_fn(|i| 10 + i as u8);
    let their_id: [u8; 16] = std::array::from_fn(|i| 20 + i as u8);

    let partial = crypto::session_prk_partial(&master, &shared, &my_pub, &my_id, &their_pub, &their_id);
    assert_eq!(
        partial.to_vec(),
        h("7f010c22499ff30c0a724c16890108afc0922043e210209b19d4e253a2c526cb")
    );
    let swapped = crypto::session_prk_partial(&master, &shared, &their_pub, &their_id, &my_pub, &my_id);
    assert_eq!(*swapped, *partial);
    let prk = crypto::session_prk(&partial, &ss);
    assert_eq!(prk.to_vec(), h("1522cb11061ee5544188eda27e768fbbc9feebb125c57bf544eac60568bce6c5"));
    let vfy = crypto::verify_code(&prk);
    assert_eq!(vfy.to_vec(), h("abd188fb7ce3d85fb8618dd5d1316851"));
    assert_eq!(
        names::bytewords(&vfy),
        "play tent logo zero \u{b7} kite vial trip hope \u{b7} redo huts lung toil \u{b7} tent each iris gray"
    );

    let chain = Ratchet::seed(&prk, &my_pub);
    let (mk0, _) = chain.peek(0).unwrap();
    assert_eq!(mk0.to_vec(), h("514f61ea351869e9a752268616f0af0116e0ae98d09532622a3471df6349cd67"));
    let (mk5, _) = chain.peek(5).unwrap();
    assert_eq!(mk5.to_vec(), h("40ff0f5f0ab86580c10b52764adc73657d7b37589665c5e159a142e0771b1b06"));

    assert_eq!(
        crypto::cookie(&shared, "192.168.1.2:4000", &their_id, &their_pub).to_vec(),
        h("e6b7f545b5912cbff3fb58faf9adcb7a")
    );
    assert_eq!(crypto::fingerprint(&their_pub).to_vec(), h("d2f184e49c1ff158e6c82068f376a2f0"));
    assert_eq!(crypto::invite_check("NH7Q5KS2ZX", "item oboe").to_vec(), h("6c1bbb74"));
    assert_eq!(
        crypto::build_proof(&shared, &my_id, &their_id).to_vec(),
        h("86bc1e247b589059532b1484ca924714d74d5906dffde69d9e64fe0ba34e6f59")
    );
}

#[test]
fn identities_match_expected() {
    let my_pub: [u8; 32] = std::array::from_fn(|i| 100 + i as u8);
    let their_pub: [u8; 32] = std::array::from_fn(|i| 50 + i as u8);
    let my_id: [u8; 16] = std::array::from_fn(|i| 10 + i as u8);
    let their_id: [u8; 16] = std::array::from_fn(|i| 20 + i as u8);
    let sec: [u8; 32] = std::array::from_fn(|i| (7 * i + 1) as u8);

    let age = IdentityKeypair::from_x25519(&sec).unwrap();
    assert_eq!(
        age.public.to_vec(),
        h("22a51202e4e28893e58c12a34f1c42655b53395bd38fb98ddc462abdb78e80a8")
    );
    assert_eq!(
        age.sign_session(&my_pub, &my_id, &their_pub, &their_id).to_vec(),
        h(
            "be7800ee8b26cbefaa8878a7478c062dd39aebc1dcdd8d211e02c9d0f2b3ea42d52d04c50ed5c080cf49fb7288458a77db6d7e6e1da3a8c06771360a7e1e8200"
        )
    );

    let seeded = IdentityKeypair::from_seed(&sec);
    assert_eq!(
        seeded.public.to_vec(),
        h("e4030998cfd5ad1723c169f956aa0b9eb8619b5992bd612c2af428ebc79f8df0")
    );
    assert_eq!(
        seeded.sign_session(&my_pub, &my_id, &their_pub, &their_id).to_vec(),
        h(
            "38d7b21a4bccb778ef822d7980b75b729d3455434695889c1a71a529f27633025eb551780bb84d0be3dcd8fcb0a1e9f67d9ba4576bf4e66c5639cdbd77cc390b"
        )
    );
    assert_eq!(
        seeded.sign_move(&my_pub, &my_id, &their_pub, &their_id).to_vec(),
        h(
            "3f9d5ea3466f0aec14df21c039d31b4ede9233eca37e02f423ce83bcaf1ea4013f663720dc39b752309b2abe41cde0656f04a5383ba984ec8ec9b550641b740b"
        )
    );
    assert_eq!(
        seeded.contact_secret(&age.public, 20000).unwrap().to_vec(),
        h(
            "fcc4ec45fd374d3fdb78f05d6c8d250ae0d0d9540f678b1e873d344de927bb2e1a10d617d92bcac684c140eb23d9e43606b8c5b93c354a16c8824a90bd103ef3"
        )
    );
}

#[test]
fn tor_room_keys_match_expected() {
    let master: [u8; 32] = h("0ddc759ec3bf58ae8f2973822b818ddda0ca13717a07354e4bad38a66baf373f")
        .try_into()
        .unwrap();
    let (expanded, pub0) = crypto::tor_room_key(&master, 0);
    assert_eq!(
        expanded.to_vec(),
        h(
            "90ed27e862913d454b3da42322b7b7cdcbe9b4b357702fb0ce9b5ba7b9116f7835544304b790c57240df1c096fd3994ba72cd9d58a1fbf0d7bdd6061334db46e"
        )
    );
    assert_eq!(pub0.to_vec(), h("62c8fc858a7ffbb05f6782749102e51556f0f42ae7e57b2ce806e75c42bf24cf"));
    // The addresses as Python's own SHA3-256 and base32 make them.
    let want = [
        "mlepzbmkp753ax3hqj2jcaxfcvlpb5bk47sxwlhia3tvyqv7ethwyoad",
        "mrywcaq66nggazssyiryumdrfbj5sam6aeaaa6a27cjkqwlfuno7spad",
        "gszczqvsuyxbuvev47qwdo2g6ly246bmh3pujsbbaq4o3c5z7ivwkiid",
        "buwet6c3lzij2r7zeuxccvhkefe4sf3vclwvtvveazxqzlzuppqdd3yd",
        "wkqlejneslzuce2vjbdtf4atyjm5ncyy5rwmjb4yahtexladxu6q4zid",
        "cqrmoaw5l563f432sy5gjyj34evuqczdnxqzwxizaiw6yav3k64e42ad",
    ];
    for (slot, onion) in want.iter().enumerate() {
        let (_, public) = crypto::tor_room_key(&master, slot as u8);
        assert_eq!(&crypto::onion_address(&public), onion);
        assert_eq!(crypto::onion_key(onion), Some(public));
    }
    // A well-known service's address checks out; one changed character doesn't.
    assert!(crypto::onion_key("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad").is_some());
    assert!(crypto::onion_key("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczae").is_none());
}

/// PGP keys made from a password as the JSON interface writes them for
/// {"cmd":"identity","kind":"pgp","password":"correct horse","device":"0123...cdef","with_nick":...}:
/// the same key, and byte for byte the same armored public and secret keys.
#[test]
fn pgp_keys_from_a_password_match_expected() {
    use chat_core::protocol::crypto::pgp;
    let dir = "tests/data/pgp";
    let device = "0123456789abcdef0123456789abcdef";
    for (file, nick, public) in [
        ("derived", None, "70cb3cfd7a412b2e1290fbad34b912dd0d8d7eee72c46f45b4e9ee1ff055b4e0"),
        (
            "derived-nick",
            Some("alice"),
            "1d7a0893df51cafbedfd69848b9cb22226d5234a4c990f6b0643949d88da12bc",
        ),
    ] {
        let kp = IdentityKeypair::from_password("correct horse", device, nick).unwrap();
        assert_eq!(hex::encode(&kp.public), public);
        let want_pub = std::fs::read_to_string(format!("{dir}/{file}.pub.asc")).unwrap();
        let want_sec = std::fs::read_to_string(format!("{dir}/{file}.sec.asc")).unwrap();
        let (got_pub, fp) = pgp::export_public(&kp, "chat", pgp::DERIVED_CREATED);
        assert_eq!(got_pub, want_pub, "{file}: public key");
        let (got_sec, _) = pgp::export_secret(&kp, "chat", pgp::DERIVED_CREATED).unwrap();
        assert_eq!(*got_sec, want_sec, "{file}: secret key");
        assert_eq!(pgp::import_secret(&want_sec).unwrap().public, kp.public);
        assert_eq!(fp.len(), 20);
    }
}

/// Invites' QR codes as drawn in "ready" (versions 3, 4 and 9):
/// the same modules.
#[test]
fn qr_codes_match_expected() {
    let data = std::fs::read_to_string("tests/data/qr.json").unwrap();
    let cases: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap();
    assert_eq!(cases.len(), 3);
    for c in cases {
        let invite = c["invite"].as_str().unwrap();
        let want: Vec<String> = c["qr"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        let qr = chat_core::protocol::qr::encode(invite).unwrap();
        assert_eq!(qr.rows(), want, "{invite}");
    }
    assert!(chat_core::protocol::qr::encode(&"x".repeat(300)).is_none());
}
