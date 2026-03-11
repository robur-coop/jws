open OUnit2
open Jws

let msg_to_failure = function Ok v -> v | Error (`Msg msg) -> failwith msg

(* RFC 7515 Appendix A.2 - RSA key components *)

let rfc7515_n64 =
  "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp"
  ^ "-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwO"
  ^ "WvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYU"
  ^ "sLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9"
  ^ "kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk"
  ^ "2PAcDTW9gb54h4FRWyuXpoQ"

let rfc7515_e64 = "AQAB"

let rfc7515_d64 =
  "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_G"
  ^ "Q5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKV"
  ^ "RUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9J"
  ^ "YanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoF"
  ^ "aFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjn"
  ^ "czT0QU91p1DhOVRuOopznQ"

let rfc7515_p64 =
  "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBds"
  ^ "s1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ"
  ^ "5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"

let rfc7515_q64 =
  "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHA"
  ^ "jLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLt"
  ^ "XlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"

let rfc7515_dp64 =
  "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE"
  ^ "2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_"
  ^ "YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"

let rfc7515_dq64 =
  "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDo"
  ^ "RwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGN"
  ^ "pmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"

let rfc7515_qi64 =
  "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0Em"
  ^ "pScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1c"
  ^ "q9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"

(* RFC 7515 A.2 - Expected values *)
let rfc7515_header64 = "eyJhbGciOiJSUzI1NiJ9"

let rfc7515_payload64 =
  "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
  ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"

let rfc7515_signature64 =
  "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7"
  ^ "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX"
  ^ "4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7"
  ^ "K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPq"
  ^ "vhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVr"
  ^ "Bp0igcN_IoypGlUPQGe77Rw"

(* Construct RSA keys from RFC 7515 A.2 *)
let rfc7515_rsa_priv =
  let n = Base64u.Z.decode rfc7515_n64 |> msg_to_failure in
  let e = Base64u.Z.decode rfc7515_e64 |> msg_to_failure in
  let d = Base64u.Z.decode rfc7515_d64 |> msg_to_failure in
  let p = Base64u.Z.decode rfc7515_p64 |> msg_to_failure in
  let q = Base64u.Z.decode rfc7515_q64 |> msg_to_failure in
  let dp = Base64u.Z.decode rfc7515_dp64 |> msg_to_failure in
  let dq = Base64u.Z.decode rfc7515_dq64 |> msg_to_failure in
  let qi = Base64u.Z.decode rfc7515_qi64 |> msg_to_failure in
  Mirage_crypto_pk.Rsa.priv ~e ~d ~n ~p ~q ~dp ~dq ~q':qi |> msg_to_failure

let rfc7515_rsa_pub =
  let n = Base64u.Z.decode rfc7515_n64 |> msg_to_failure in
  let e = Base64u.Z.decode rfc7515_e64 |> msg_to_failure in
  Mirage_crypto_pk.Rsa.pub ~e ~n |> msg_to_failure

(* RFC 7515 A.2: Verify the RFC signature *)

let test_rfc7515_a2_verify _ctx =
  let signing_input = rfc7515_header64 ^ "." ^ rfc7515_payload64 in
  let signature = Base64u.decode rfc7515_signature64 |> msg_to_failure in
  let verified =
    Jwk.verify ~alg:`RS256 (`RSA rfc7515_rsa_pub) signing_input signature
  in
  assert_bool "RFC 7515 A.2 RSA signature must verify" verified

(* RFC 7515 A.2: RSA PKCS1 signatures are deterministic *)

let test_rfc7515_a2_sign _ctx =
  let signing_input = rfc7515_header64 ^ "." ^ rfc7515_payload64 in
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let got = Jws.Pk.sign pk signing_input in
  let got64 = Base64u.encode got in
  assert_equal ~printer:Fun.id rfc7515_signature64 got64

(* RFC 7515 A.3: ECDSA P-256 SHA-256 verification *)

let rfc7515_a3_priv =
  let d =
    Base64u.decode "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
    |> msg_to_failure
  in
  match Mirage_crypto_ec.P256.Dsa.priv_of_octets d with
  | Ok k -> k
  | Error _ -> failwith "invalid P-256 private key"

let rfc7515_a3_pub = Mirage_crypto_ec.P256.Dsa.pub_of_priv rfc7515_a3_priv

let test_rfc7515_a3_key _ctx =
  let cs = Mirage_crypto_ec.P256.Dsa.pub_to_octets rfc7515_a3_pub in
  let x = String.sub cs 1 32 in
  let y = String.sub cs 33 32 in
  assert_equal ~printer:Fun.id "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    (Base64u.encode x);
  assert_equal ~printer:Fun.id "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    (Base64u.encode y)

let rfc7515_a3_signature64 =
  "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
  ^ "pmWQxfKTUJqPP3-Kg6NU1Q"

let test_rfc7515_a3_verify _ctx =
  let header64 = "eyJhbGciOiJFUzI1NiJ9" in
  let signing_input = header64 ^ "." ^ rfc7515_payload64 in
  let signature = Base64u.decode rfc7515_a3_signature64 |> msg_to_failure in
  let verified =
    Jwk.verify ~alg:`ES256 (`P256 rfc7515_a3_pub) signing_input signature
  in
  assert_bool "RFC 7515 A.3 ES256 signature must verify" verified

(* RFC 7515 A.4: ECDSA P-521 SHA-512 verification *)

let rfc7515_a4_priv =
  let d =
    Base64u.decode
      ("AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPA"
     ^ "xerEzgdRhajnu0ferB0d53vM9mE15j2C")
    |> msg_to_failure
  in
  match Mirage_crypto_ec.P521.Dsa.priv_of_octets d with
  | Ok k -> k
  | Error _ -> failwith "invalid P-521 private key"

let rfc7515_a4_pub = Mirage_crypto_ec.P521.Dsa.pub_of_priv rfc7515_a4_priv

let test_rfc7515_a4_key _ctx =
  let cs = Mirage_crypto_ec.P521.Dsa.pub_to_octets rfc7515_a4_pub in
  let x = String.sub cs 1 66 in
  let y = String.sub cs 67 66 in
  assert_equal ~printer:Fun.id
    ("AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_"
   ^ "NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk")
    (Base64u.encode x);
  assert_equal ~printer:Fun.id
    ("ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDl"
   ^ "y79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")
    (Base64u.encode y)

let rfc7515_a4_signature64 =
  "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq"
  ^ "wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp"
  ^ "EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"

let test_rfc7515_a4_verify _ctx =
  let header64 = "eyJhbGciOiJFUzUxMiJ9" in
  let payload64 = "UGF5bG9hZA" in
  let signing_input = header64 ^ "." ^ payload64 in
  let signature = Base64u.decode rfc7515_a4_signature64 |> msg_to_failure in
  let verified =
    Jwk.verify ~alg:`ES512 (`P521 rfc7515_a4_pub) signing_input signature
  in
  assert_bool "RFC 7515 A.4 ES512 signature must verify" verified

(* JWS Flattened JSON round-trips *)

let test_rsa_jws_roundtrip _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let payload = "hello world" in
  let nonce = "test-nonce-123" in
  let encoded = Jws.encode pk ~nonce payload in
  let pub = Jws.Pk.public pk in
  let decoded = Jws.decode_exn ~public:pub encoded in
  assert_equal ~printer:Fun.id payload (Jws.data decoded);
  assert_equal
    ~printer:Fmt.(to_to_string (Dump.option string))
    (Some nonce) (Jws.nonce decoded)

let test_rsa_jws_with_kid _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let payload = "test payload" in
  let nonce = "nonce-abc" in
  let kid = "https://example.com/acme/acct/1" in
  let encoded = Jws.encode ~kid pk ~nonce payload in
  let pub = Jws.Pk.public pk in
  let decoded = Jws.decode_exn ~public:pub encoded in
  assert_equal ~printer:Fun.id payload (Jws.data decoded);
  let kid_in_header = Jws.protected ~key:"kid" decoded Jsont.string in
  assert_equal
    ~printer:(fun x -> match x with Some s -> s | None -> "<none>")
    (Some kid) kid_in_header

let test_p256_jws_roundtrip _ctx =
  let priv, _pub = Mirage_crypto_ec.P256.Dsa.generate () in
  let pk : Jws.Pk.t = `P256 priv in
  let encoded = Jws.encode pk ~nonce:"p256-nonce" "P-256 test" in
  let decoded = Jws.decode_exn ~public:(Jws.Pk.public pk) encoded in
  assert_equal ~printer:Fun.id "P-256 test" (Jws.data decoded)

let test_p384_jws_roundtrip _ctx =
  let priv, _pub = Mirage_crypto_ec.P384.Dsa.generate () in
  let pk : Jws.Pk.t = `P384 priv in
  let encoded = Jws.encode pk ~nonce:"p384-nonce" "P-384 test" in
  let decoded = Jws.decode_exn ~public:(Jws.Pk.public pk) encoded in
  assert_equal ~printer:Fun.id "P-384 test" (Jws.data decoded)

let test_p521_jws_roundtrip _ctx =
  let priv, _pub = Mirage_crypto_ec.P521.Dsa.generate () in
  let pk : Jws.Pk.t = `P521 priv in
  let encoded = Jws.encode pk ~nonce:"p521-nonce" "P-521 test" in
  let decoded = Jws.decode_exn ~public:(Jws.Pk.public pk) encoded in
  assert_equal ~printer:Fun.id "P-521 test" (Jws.data decoded)

(* RFC 7520 Section 4.1: RSA v1.5 Signature *)

let rfc7520_payload =
  "It\xe2\x80\x99s a dangerous business, Frodo, going out your "
  ^ "door. You step onto the road, and if you don't keep your feet, "
  ^ "there\xe2\x80\x99s no knowing where you might be swept off " ^ "to."

let rfc7520_payload64 =
  "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH"
  ^ "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk"
  ^ "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm"
  ^ "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"

let test_rfc7520_payload_encoding _ctx =
  let got = Base64u.encode rfc7520_payload in
  assert_equal ~printer:Fun.id rfc7520_payload64 got

let rfc7520_rsa_priv =
  let decode_z str = Base64u.Z.decode str |> msg_to_failure in
  let e = decode_z "AQAB"
  and p =
    decode_z
      ("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR"
     ^ "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG"
     ^ "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" ^ "bUq0k")
  and q =
    decode_z
      ("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT"
     ^ "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an"
     ^ "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" ^ "s7pFc")
  in
  match Mirage_crypto_pk.Rsa.priv_of_primes ~e ~p ~q with
  | Ok p -> p
  | Error (`Msg msg) -> failwith msg

let rfc7520_4_1_protected64 =
  "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX"
  ^ "hhbXBsZSJ9"

let rfc7520_4_1_signature64 =
  "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK"
  ^ "ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J"
  ^ "IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w"
  ^ "W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP"
  ^ "xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f"
  ^ "cIe8u9ipH84ogoree7vjbU5y18kDquDg"

let test_rfc7520_4_1_verify _ctx =
  let signing_input = rfc7520_4_1_protected64 ^ "." ^ rfc7520_payload64 in
  let signature = Base64u.decode rfc7520_4_1_signature64 |> msg_to_failure in
  let pub = Mirage_crypto_pk.Rsa.pub_of_priv rfc7520_rsa_priv in
  let verified = Jwk.verify ~alg:`RS256 (`RSA pub) signing_input signature in
  assert_bool "RFC 7520 4.1 RSA signature must verify" verified

let test_rfc7520_4_1_sign _ctx =
  let signing_input = rfc7520_4_1_protected64 ^ "." ^ rfc7520_payload64 in
  let pk : Jws.Pk.t = `RSA rfc7520_rsa_priv in
  let got = Jws.Pk.sign pk signing_input in
  let got64 = Base64u.encode got in
  assert_equal ~printer:Fun.id rfc7520_4_1_signature64 got64

(* RFC 7520 Section 4.3: ECDSA P-521 Signature *)

let rfc7520_p521_priv =
  let d =
    Base64u.decode
      ("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb"
     ^ "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt")
    |> msg_to_failure
  in
  match Mirage_crypto_ec.P521.Dsa.priv_of_octets d with
  | Ok k -> k
  | Error _ -> failwith "invalid P-521 private key"

let rfc7520_p521_pub = Mirage_crypto_ec.P521.Dsa.pub_of_priv rfc7520_p521_priv

let test_rfc7520_4_3_key _ctx =
  let cs = Mirage_crypto_ec.P521.Dsa.pub_to_octets rfc7520_p521_pub in
  let x = String.sub cs 1 66 in
  let y = String.sub cs 67 66 in
  let rfc_x =
    "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjy"
    ^ "ekWF-7ytDyRXYgCF5cj0Kt"
  in
  let rfc_y =
    "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQ"
    ^ "rJmbnX9cwlGfP-HqHZR1"
  in
  assert_equal ~printer:Fun.id rfc_x (Base64u.encode x);
  assert_equal ~printer:Fun.id rfc_y (Base64u.encode y)

let rfc7520_4_3_protected64 =
  "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9"

let rfc7520_4_3_signature64 =
  "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNl"
  ^ "aAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mt"
  ^ "PBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBp"
  ^ "HABlsbEPX6sFY8OcGDqoRuBomu9xQ2"

let test_rfc7520_4_3_verify _ctx =
  let signing_input = rfc7520_4_3_protected64 ^ "." ^ rfc7520_payload64 in
  let signature = Base64u.decode rfc7520_4_3_signature64 |> msg_to_failure in
  let verified =
    Jwk.verify ~alg:`ES512 (`P521 rfc7520_p521_pub) signing_input signature
  in
  assert_bool "RFC 7520 4.3 ES512 signature must verify" verified

(* Security: wrong key must fail *)

let test_wrong_key_fails _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let encoded = Jws.encode pk ~nonce:"n" "secret" in
  let wrong_key =
    let priv = Mirage_crypto_pk.Rsa.generate ~bits:2048 () in
    `RSA (Mirage_crypto_pk.Rsa.pub_of_priv priv)
  in
  assert_raises (Failure "Invalid signature") (fun () ->
      Jws.decode_exn ~public:wrong_key encoded)

(* ACME (RFC 8555) tests *)

let test_jwk_embedded _ctx =
  let priv, _pub = Mirage_crypto_ec.P256.Dsa.generate () in
  let pk : Jws.Pk.t = `P256 priv in
  let encoded = Jws.encode pk ~nonce:"nonce1" "embedded jwk" in
  let decoded = Jws.decode_exn encoded in
  assert_equal ~printer:Fun.id "embedded jwk" (Jws.data decoded);
  assert_bool "jwk must be in protected header"
    (Jws.protected ~key:"jwk" decoded Jws.Jwk.t |> Option.is_some)

let test_acme_url_in_header _ctx =
  let priv, _pub = Mirage_crypto_ec.P256.Dsa.generate () in
  let pk : Jws.Pk.t = `P256 priv in
  let uri = "https://example.com/acme/new-order" in
  let extra = Jws.S.singleton "url" (Jsont.Json.string uri) in
  let encoded = Jws.encode ~extra pk ~nonce:"acme-nonce" "" in
  let decoded = Jws.decode_exn ~public:(Jws.Pk.public pk) encoded in
  assert_equal
    ~printer:Fmt.(to_to_string (Dump.option string))
    (Some uri)
    (Jws.protected ~key:"url" decoded Jsont.string)

let test_acme_post_as_get _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let kid = "https://example.com/acme/acct/1" in
  let encoded = Jws.encode ~kid pk ~nonce:"n1" "" in
  let decoded = Jws.decode_exn ~public:(Jws.Pk.public pk) encoded in
  assert_equal ~printer:Fun.id "" (Jws.data decoded)

let test_acme_nonce_preserved _ctx =
  let priv, _pub = Mirage_crypto_ec.P256.Dsa.generate () in
  let pk : Jws.Pk.t = `P256 priv in
  let nonce = "6S8IqOGY7eL2lsGoTZYifg" in
  let encoded = Jws.encode pk ~nonce "payload" in
  let decoded = Jws.decode_exn ~public:(Jws.Pk.public pk) encoded in
  assert_equal
    ~printer:Fmt.(to_to_string (Dump.option string))
    (Some nonce) (Jws.nonce decoded)

(* JWK round-trips *)

let test_jwk_roundtrip_rsa _ctx =
  let pub = `RSA rfc7515_rsa_pub in
  let encoded = Jwk.encode pub in
  let decoded = Jwk.decode encoded |> msg_to_failure in
  assert_equal ~printer:Fun.id encoded (Jwk.encode decoded)

let test_jwk_roundtrip_p256 _ctx =
  let _priv, pub = Mirage_crypto_ec.P256.Dsa.generate () in
  let encoded = Jwk.encode (`P256 pub) in
  let decoded = Jwk.decode encoded |> msg_to_failure in
  assert_equal ~printer:Fun.id encoded (Jwk.encode decoded)

let test_jwk_roundtrip_p384 _ctx =
  let _priv, pub = Mirage_crypto_ec.P384.Dsa.generate () in
  let encoded = Jwk.encode (`P384 pub) in
  let decoded = Jwk.decode encoded |> msg_to_failure in
  assert_equal ~printer:Fun.id encoded (Jwk.encode decoded)

let test_jwk_roundtrip_p521 _ctx =
  let _priv, pub = Mirage_crypto_ec.P521.Dsa.generate () in
  let encoded = Jwk.encode (`P521 pub) in
  let decoded = Jwk.decode encoded |> msg_to_failure in
  assert_equal ~printer:Fun.id encoded (Jwk.encode decoded)

let test_jwk_roundtrip_ed25519 _ctx =
  let _priv, pub = Mirage_crypto_ec.Ed25519.generate () in
  let encoded = Jwk.encode (`ED25519 pub) in
  let decoded = Jwk.decode encoded |> msg_to_failure in
  assert_equal ~printer:Fun.id encoded (Jwk.encode decoded)

let test_jwk_roundtrip_oct _ctx =
  let key = "super-secret-key-at-least-32-bytes-long!!" in
  let encoded = Jwk.encode (`Oct key) in
  let decoded = Jwk.decode encoded |> msg_to_failure in
  assert_equal ~printer:Fun.id encoded (Jwk.encode decoded)

(* Base64url *)

let test_base64u_roundtrip _ctx =
  let inputs = [ ""; "f"; "fo"; "foo"; "foob"; "fooba"; "foobar" ] in
  List.iter
    (fun input ->
      let encoded = Base64u.encode input in
      let decoded = Base64u.decode encoded |> msg_to_failure in
      assert_equal ~printer:Fun.id ~msg:("roundtrip: " ^ input) input decoded)
    inputs

let test_base64u_no_padding _ctx =
  let encoded = Base64u.encode "foobar" in
  assert_bool "no padding character '='" (not (String.contains encoded '='))

(* RFC 7515 Section 7.1: JWS Compact Serialization *)

let test_compact_rsa_roundtrip _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let compact = Jws.Compact.encode pk "hello compact" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "hello compact" (Jws.data decoded)

let test_compact_format _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let compact = Jws.Compact.encode pk "test" in
  let parts = String.split_on_char '.' compact in
  assert_equal ~printer:string_of_int 3 (List.length parts);
  List.iter
    (fun part ->
      assert_bool "no padding in compact parts" (not (String.contains part '=')))
    parts

let test_compact_rsa_interop _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let payload = "test interop" in
  let compact = Jws.Compact.encode pk payload in
  match String.split_on_char '.' compact with
  | [ h64; p64; s64 ] ->
      let h_raw = Base64u.decode h64 |> msg_to_failure in
      assert_bool "header is valid JSON" (h_raw.[0] = '{');
      let p_raw = Base64u.decode p64 |> msg_to_failure in
      assert_equal ~printer:Fun.id payload p_raw;
      let signing_input = h64 ^ "." ^ p64 in
      let signature = Base64u.decode s64 |> msg_to_failure in
      let verified =
        Jwk.verify ~alg:`RS256 (Jws.Pk.public pk) signing_input signature
      in
      assert_bool "signature verifies with standard signing input" verified
  | _ -> assert_failure "expected 3 parts"

let test_compact_p256_roundtrip _ctx =
  let priv, _pub = Mirage_crypto_ec.P256.Dsa.generate () in
  let pk : Jws.Pk.t = `P256 priv in
  let compact = Jws.Compact.encode pk "ES256 compact" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "ES256 compact" (Jws.data decoded)

let test_compact_p521_roundtrip _ctx =
  let priv, _pub = Mirage_crypto_ec.P521.Dsa.generate () in
  let pk : Jws.Pk.t = `P521 priv in
  let compact = Jws.Compact.encode pk "ES512 compact" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "ES512 compact" (Jws.data decoded)

let test_compact_with_extra_headers _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let extra =
    Jws.S.singleton "kid"
      (Jsont.String ("bilbo.baggins@hobbiton.example", Jsont.Meta.none))
  in
  let compact = Jws.Compact.encode pk ~extra "payload" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal (Some "bilbo.baggins@hobbiton.example")
    (Jws.protected ~key:"kid" decoded Jsont.string)

let test_compact_decode_malformed _ctx =
  assert_bool "only 2 parts" (Result.is_error (Jws.Compact.decode "abc.def"));
  assert_bool "only 1 part" (Result.is_error (Jws.Compact.decode "abc"))

let test_compact_wrong_key _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let compact = Jws.Compact.encode pk "secret" in
  let wrong_key =
    let priv = Mirage_crypto_pk.Rsa.generate ~bits:2048 () in
    `RSA (Mirage_crypto_pk.Rsa.pub_of_priv priv)
  in
  assert_bool "wrong key must fail"
    (Result.is_error (Jws.Compact.decode ~public:wrong_key compact))

(* RFC 7515 Section 4.1.11: crit header validation *)

let test_crit_empty_rejects _ctx =
  let crit = Jsont.Json.encode (Jsont.list Jsont.string) [] |> Result.get_ok in
  let props = Jws.S.singleton "crit" crit in
  assert_bool "empty crit" (Result.is_error (Jws.validate_crit props))

let test_crit_unknown_rejects _ctx =
  let crit =
    Jsont.Json.encode (Jsont.list Jsont.string) [ "x-custom" ] |> Result.get_ok
  in
  let props = Jws.S.singleton "crit" crit in
  assert_bool "unknown crit" (Result.is_error (Jws.validate_crit props))

let test_crit_understood_accepts _ctx =
  let crit =
    Jsont.Json.encode (Jsont.list Jsont.string) [ "x-custom" ] |> Result.get_ok
  in
  let props = Jws.S.singleton "crit" crit in
  assert_bool "understood"
    (Result.is_ok (Jws.validate_crit ~understood:[ "x-custom" ] props))

let test_crit_self_reference_rejects _ctx =
  let crit =
    Jsont.Json.encode (Jsont.list Jsont.string) [ "crit" ] |> Result.get_ok
  in
  let props = Jws.S.singleton "crit" crit in
  assert_bool "self-ref"
    (Result.is_error (Jws.validate_crit ~understood:[ "crit" ] props))

let test_crit_absent_accepts _ctx =
  assert_bool "absent" (Result.is_ok (Jws.validate_crit Jws.S.empty))

let test_compact_crit_rejects _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let crit =
    Jsont.Json.encode (Jsont.list Jsont.string) [ "x-nope" ] |> Result.get_ok
  in
  let extra = Jws.S.singleton "crit" crit in
  let compact = Jws.Compact.encode pk ~extra "payload" in
  let pub = Jws.Pk.public pk in
  assert_bool "unknown crit rejects"
    (Result.is_error (Jws.Compact.decode ~public:pub compact));
  assert_bool "understood crit accepts"
    (Result.is_ok
       (Jws.Compact.decode ~understood:[ "x-nope" ] ~public:pub compact))

(* RFC 7515 Appendix A.5: Unsecured JWS *)

let test_unsecured_jws_encode _ctx =
  let compact = Jws.Compact.Unsecured.encode "test payload" in
  let parts = String.split_on_char '.' compact in
  assert_equal ~printer:string_of_int 3 (List.length parts);
  (match parts with
  | [ _; _; s ] -> assert_equal ~printer:Fun.id "" s
  | _ -> assert_failure "expected 3 parts");
  match parts with
  | [ h64; _; _ ] ->
      let h = Base64u.decode h64 |> msg_to_failure in
      assert_equal ~printer:Fun.id "{\"alg\":\"none\"}" h
  | _ -> ()

let test_unsecured_jws_decode_requires_opt_in _ctx =
  let compact = Jws.Compact.Unsecured.encode "payload" in
  assert_bool "default rejects"
    (Result.is_error (Jws.Compact.Unsecured.decode compact));
  let decoded =
    Jws.Compact.Unsecured.decode ~allow_none:true compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "payload" (Jws.data decoded)

let test_unsecured_jws_roundtrip _ctx =
  let compact = Jws.Compact.Unsecured.encode "unsecured data" in
  let decoded =
    Jws.Compact.Unsecured.decode ~allow_none:true compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "unsecured data" (Jws.data decoded)

let test_unsecured_jws_nonempty_sig_rejects _ctx =
  let compact = "eyJhbGciOiJub25lIn0.dGVzdA.AAAA" in
  assert_bool "non-empty sig rejects"
    (Result.is_error (Jws.Compact.Unsecured.decode ~allow_none:true compact))

(* Signing input interop *)

let test_flattened_signing_input_interop _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let encoded = Jws.encode pk ~nonce:"n1" "interop test" in
  let json = Jsont_bytesrw.decode_string Jsont.json encoded |> Result.get_ok in
  let get_str key = function
    | Jsont.Object (members, _) ->
        List.find_map
          (fun ((k, _), v) ->
            if k = key then
              match v with Jsont.String (s, _) -> Some s | _ -> None
            else None)
          members
    | _ -> None
  in
  match
    (get_str "protected" json, get_str "payload" json, get_str "signature" json)
  with
  | Some p, Some pl, Some s ->
      let signature = Base64u.decode s |> msg_to_failure in
      let verified =
        Jwk.verify ~alg:`RS256 (Jws.Pk.public pk) (p ^ "." ^ pl) signature
      in
      assert_bool "flattened interop" verified
  | _ -> assert_failure "could not extract JWS fields"

(* RFC 7518: JWA algorithm round-trips *)

(* RS384 *)
let test_rs384_compact_roundtrip _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let compact = Jws.Compact.encode ~alg:`RS384 pk "RS384 test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "RS384 test" (Jws.data decoded)

(* RS512 *)
let test_rs512_compact_roundtrip _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let compact = Jws.Compact.encode ~alg:`RS512 pk "RS512 test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "RS512 test" (Jws.data decoded)

(* PS256 *)
let test_ps256_compact_roundtrip _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let compact = Jws.Compact.encode ~alg:`PS256 pk "PS256 test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "PS256 test" (Jws.data decoded)

(* PS384 *)
let test_ps384_compact_roundtrip _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let compact = Jws.Compact.encode ~alg:`PS384 pk "PS384 test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "PS384 test" (Jws.data decoded)

(* PS512 *)
let test_ps512_compact_roundtrip _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let compact = Jws.Compact.encode ~alg:`PS512 pk "PS512 test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "PS512 test" (Jws.data decoded)

(* HS256 *)
let test_hs256_compact_roundtrip _ctx =
  let key = String.make 32 'k' in
  let pk : Jws.Pk.t = `Oct key in
  let compact = Jws.Compact.encode pk "HS256 test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "HS256 test" (Jws.data decoded)

(* HS384 *)
let test_hs384_compact_roundtrip _ctx =
  let key = String.make 48 'k' in
  let pk : Jws.Pk.t = `Oct key in
  let compact = Jws.Compact.encode ~alg:`HS384 pk "HS384 test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "HS384 test" (Jws.data decoded)

(* HS512 *)
let test_hs512_compact_roundtrip _ctx =
  let key = String.make 64 'k' in
  let pk : Jws.Pk.t = `Oct key in
  let compact = Jws.Compact.encode ~alg:`HS512 pk "HS512 test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "HS512 test" (Jws.data decoded)

(* EdDSA (Ed25519) *)
let test_eddsa_compact_roundtrip _ctx =
  let priv, _pub = Mirage_crypto_ec.Ed25519.generate () in
  let pk : Jws.Pk.t = `ED25519 priv in
  let compact = Jws.Compact.encode pk "EdDSA test" in
  let decoded =
    Jws.Compact.decode ~public:(Jws.Pk.public pk) compact |> msg_to_failure
  in
  assert_equal ~printer:Fun.id "EdDSA test" (Jws.data decoded)

(* EdDSA sign/verify deterministic *)
let test_eddsa_deterministic _ctx =
  let priv, pub = Mirage_crypto_ec.Ed25519.generate () in
  let data = "hello ed25519" in
  let sig1 = Jws.Pk.sign ~alg:`EdDSA (`ED25519 priv) data in
  let sig2 = Jws.Pk.sign ~alg:`EdDSA (`ED25519 priv) data in
  assert_equal ~printer:Base64u.encode sig1 sig2;
  assert_bool "verify" (Jwk.verify ~alg:`EdDSA (`ED25519 pub) data sig1)

(* HMAC: wrong key must fail *)
let test_hs256_wrong_key_fails _ctx =
  let pk : Jws.Pk.t = `Oct (String.make 32 'a') in
  let compact = Jws.Compact.encode pk "secret" in
  let wrong_key = `Oct (String.make 32 'b') in
  assert_bool "wrong HMAC key must fail"
    (Result.is_error (Jws.Compact.decode ~public:wrong_key compact))

(* Algorithm/key mismatch *)
let test_alg_key_mismatch _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  assert_raises (Invalid_argument "Algorithm and private key mismatch")
    (fun () -> Jws.Pk.sign ~alg:`ES256 pk "test")

(* RSA key with non-default alg in flattened JSON *)
let test_flattened_rs384 _ctx =
  let pk : Jws.Pk.t = `RSA rfc7515_rsa_priv in
  let encoded = Jws.encode ~alg:`RS384 pk ~nonce:"n" "RS384 flat" in
  let decoded = Jws.decode_exn ~public:(Jws.Pk.public pk) encoded in
  assert_equal ~printer:Fun.id "RS384 flat" (Jws.data decoded)

(* All tests *)

let all_tests =
  [
    (* RFC 7515 Appendix A: signature verification *)
    "rfc7515_a2_verify" >:: test_rfc7515_a2_verify
  ; "rfc7515_a2_sign" >:: test_rfc7515_a2_sign
  ; "rfc7515_a3_key" >:: test_rfc7515_a3_key
  ; "rfc7515_a3_verify" >:: test_rfc7515_a3_verify
  ; "rfc7515_a4_key" >:: test_rfc7515_a4_key
  ; "rfc7515_a4_verify" >:: test_rfc7515_a4_verify; (* RFC 7520 *)
    "rfc7520_4_1_verify" >:: test_rfc7520_4_1_verify
  ; "rfc7520_4_1_sign" >:: test_rfc7520_4_1_sign
  ; "rfc7520_4_3_key" >:: test_rfc7520_4_3_key
  ; "rfc7520_4_3_verify" >:: test_rfc7520_4_3_verify
  ; "rfc7520_payload_encoding" >:: test_rfc7520_payload_encoding
  ; (* JWS Flattened JSON round-trips *)
    "rsa_jws_roundtrip" >:: test_rsa_jws_roundtrip
  ; "rsa_jws_with_kid" >:: test_rsa_jws_with_kid
  ; "p256_jws_roundtrip" >:: test_p256_jws_roundtrip
  ; "p384_jws_roundtrip" >:: test_p384_jws_roundtrip
  ; "p521_jws_roundtrip" >:: test_p521_jws_roundtrip
  ; "flattened_rs384" >:: test_flattened_rs384; (* Security *)
    "wrong_key_fails" >:: test_wrong_key_fails
  ; "alg_key_mismatch" >:: test_alg_key_mismatch; (* ACME (RFC 8555) *)
    "jwk_embedded" >:: test_jwk_embedded
  ; "acme_url_in_header" >:: test_acme_url_in_header
  ; "acme_post_as_get" >:: test_acme_post_as_get
  ; "acme_nonce_preserved" >:: test_acme_nonce_preserved; (* JWK round-trips *)
    "jwk_roundtrip_rsa" >:: test_jwk_roundtrip_rsa
  ; "jwk_roundtrip_p256" >:: test_jwk_roundtrip_p256
  ; "jwk_roundtrip_p384" >:: test_jwk_roundtrip_p384
  ; "jwk_roundtrip_p521" >:: test_jwk_roundtrip_p521
  ; "jwk_roundtrip_ed25519" >:: test_jwk_roundtrip_ed25519
  ; "jwk_roundtrip_oct" >:: test_jwk_roundtrip_oct; (* Base64url *)
    "base64u_roundtrip" >:: test_base64u_roundtrip
  ; "base64u_no_padding" >:: test_base64u_no_padding
  ; (* Compact Serialization *)
    "compact_rsa_roundtrip" >:: test_compact_rsa_roundtrip
  ; "compact_format" >:: test_compact_format
  ; "compact_rsa_interop" >:: test_compact_rsa_interop
  ; "compact_p256_roundtrip" >:: test_compact_p256_roundtrip
  ; "compact_p521_roundtrip" >:: test_compact_p521_roundtrip
  ; "compact_extra_headers" >:: test_compact_with_extra_headers
  ; "compact_decode_malformed" >:: test_compact_decode_malformed
  ; "compact_wrong_key" >:: test_compact_wrong_key; (* crit *)
    "crit_empty_rejects" >:: test_crit_empty_rejects
  ; "crit_unknown_rejects" >:: test_crit_unknown_rejects
  ; "crit_understood_accepts" >:: test_crit_understood_accepts
  ; "crit_self_reference_rejects" >:: test_crit_self_reference_rejects
  ; "crit_absent_accepts" >:: test_crit_absent_accepts
  ; "compact_crit_rejects" >:: test_compact_crit_rejects; (* Unsecured JWS *)
    "unsecured_jws_encode" >:: test_unsecured_jws_encode
  ; "unsecured_jws_decode_requires_opt_in"
    >:: test_unsecured_jws_decode_requires_opt_in
  ; "unsecured_jws_roundtrip" >:: test_unsecured_jws_roundtrip
  ; "unsecured_jws_nonempty_sig_rejects"
    >:: test_unsecured_jws_nonempty_sig_rejects; (* Signing input interop *)
    "flattened_signing_input_interop" >:: test_flattened_signing_input_interop
  ; (* RFC 7518 JWA: all algorithms *)
    "rs384_compact_roundtrip" >:: test_rs384_compact_roundtrip
  ; "rs512_compact_roundtrip" >:: test_rs512_compact_roundtrip
  ; "ps256_compact_roundtrip" >:: test_ps256_compact_roundtrip
  ; "ps384_compact_roundtrip" >:: test_ps384_compact_roundtrip
  ; "ps512_compact_roundtrip" >:: test_ps512_compact_roundtrip
  ; "hs256_compact_roundtrip" >:: test_hs256_compact_roundtrip
  ; "hs384_compact_roundtrip" >:: test_hs384_compact_roundtrip
  ; "hs512_compact_roundtrip" >:: test_hs512_compact_roundtrip
  ; "eddsa_compact_roundtrip" >:: test_eddsa_compact_roundtrip
  ; "eddsa_deterministic" >:: test_eddsa_deterministic
  ; "hs256_wrong_key_fails" >:: test_hs256_wrong_key_fails
  ]
