open OUnit2
open Jws

let msg_to_failure = function Ok v -> v | Error (`Msg msg) -> failwith msg

let n64 =
  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86"
  ^ "zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5"
  ^ "JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQ"
  ^ "MicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyr"
  ^ "dkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF4"
  ^ "4-csFCur-kEgU8awapJzKnqDKgw"

let e64 = "AQAB"
let n = Base64u.Z.decode n64 |> msg_to_failure
let e = Base64u.Z.decode e64 |> msg_to_failure

let pk =
  let p = Mirage_crypto_pk.Rsa.pub ~e ~n |> msg_to_failure in
  `RSA p

let test_encode _ctx =
  let got = Jwk.encode pk in
  let expected = Printf.sprintf {|{"kty":"RSA","e":"%s","n":"%s"}|} e64 n64 in
  assert_equal got expected

let test_signature _ctx =
  let got = Jwk.signature pk in
  let expected = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" in
  assert_equal got expected

let decode_example =
  let maybe_pub = Fmt.str {|{"e":"%s","kty":"RSA","n":"%s"}|} e64 n64 in
  let maybe_pub = Jwk.decode maybe_pub in
  match maybe_pub with
  | Ok (`RSA pub) -> pub
  | Ok _ -> assert false
  | Error (`Msg e) -> assert_failure e

let test_decode _ctx =
  let { Mirage_crypto_pk.Rsa.e= e'; n= n' } : Mirage_crypto_pk.Rsa.pub =
    decode_example
  in
  assert_equal (e', n') (e, n)

let test_decode_malformed _ctx =
  let s = "{" in
  assert_bool "Invalid JSON" (Result.is_error (Jwk.decode s))

let test_decode_invalid_n _ctx =
  let s = {|{"kty": "RSA", "e": "AQAB"}|} in
  assert_bool "Invalid n" (Result.is_error (Jwk.decode s))

let test_decode_invalid_e _ctx =
  let s = {|{"kty": "RSA", "e": 1}|} in
  assert_bool "Invalid e" (Result.is_error (Jwk.decode s))

let test_decode_invalid_kty _ctx =
  let s = {|{"kty": "invalid"}|} in
  assert_bool "Invalid kty" (Result.is_error (Jwk.decode s))

(* Error message tests *)

let assert_error_msg expected result =
  match result with
  | Ok _ ->
      assert_failure
        (Printf.sprintf "expected Error (`Msg %S), got Ok" expected)
  | Error (`Msg msg) -> assert_equal ~printer:Fun.id expected msg

let test_decode_malformed_msg _ctx =
  assert_error_msg "Invalid JWK" (Jwk.decode "{")

let test_decode_invalid_kty_msg _ctx =
  assert_error_msg "Invalid JWK" (Jwk.decode {|{"kty": "invalid"}|})

let test_decode_invalid_rsa_key_msg _ctx =
  let s = {|{"kty":"RSA","e":"AQAB","n":"AA"}|} in
  assert_error_msg "Invalid public RSA key" (Jwk.decode s)

let test_decode_invalid_ec_key_msg _ctx =
  let s = {|{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}|} in
  assert_error_msg "Invalid elliptic curve key" (Jwk.decode s)

let test_decode_invalid_ed25519_msg _ctx =
  let s = {|{"kty":"OKP","crv":"Ed25519","x":"AAAA"}|} in
  assert_error_msg "Invalid Ed25519 public key" (Jwk.decode s)

let all_tests =
  [
    "test_encode" >:: test_encode; "test_signature" >:: test_signature
  ; "test_decode" >:: test_decode
  ; "test_decode_malformed" >:: test_decode_malformed
  ; "test_decode_invalid_kty" >:: test_decode_invalid_kty
  ; "test_decode_invalid_e" >:: test_decode_invalid_e
  ; "test_decode_invalid_n" >:: test_decode_invalid_n; (* Error messages *)
    "decode_malformed_msg" >:: test_decode_malformed_msg
  ; "decode_invalid_kty_msg" >:: test_decode_invalid_kty_msg
  ; "decode_invalid_rsa_key_msg" >:: test_decode_invalid_rsa_key_msg
  ; "decode_invalid_ec_key_msg" >:: test_decode_invalid_ec_key_msg
  ; "decode_invalid_ed25519_msg" >:: test_decode_invalid_ed25519_msg
  ]
