open OUnit2

let msg_to_failure = function Ok v -> v | Error (`Msg msg) -> failwith msg

let assert_error_msg expected result =
  match result with
  | Ok _ ->
      assert_failure
        (Printf.sprintf "expected Error (`Msg %S), got Ok" expected)
  | Error (`Msg msg) -> assert_equal ~printer:Fun.id expected msg

(* Keys *)

let hmac_key = String.make 32 'k'
let pk : Jws.Pk.t = `Oct hmac_key

let g =
  let open Mirage_crypto_rng in
  create ~seed:(Base64.decode_exn "foo=") (module Fortuna)

let p256_priv, _p256_pub = Mirage_crypto_ec.P256.Dsa.generate ~g ()
let p256_pk : Jws.Pk.t = `P256 p256_priv

(* Basic round-trip *)

let test_roundtrip _ctx =
  let claims =
    Jwt.Claims.empty
    |> Jwt.Claims.sub "1234567890"
    |> Jwt.Claims.iss "https://example.com"
    |> Jwt.Claims.iat 1516239022.
  in
  let token = Jwt.encode pk claims in
  let jwt = Jwt.decode ~public:(Jws.Pk.public pk) token |> msg_to_failure in
  assert_equal
    ~printer:(fun x -> match x with Some s -> s | None -> "<none>")
    (Some "1234567890") (Jwt.sub jwt);
  assert_equal
    ~printer:(fun x -> match x with Some s -> s | None -> "<none>")
    (Some "https://example.com") (Jwt.iss jwt);
  assert_equal (Some 1516239022.) (Jwt.iat jwt)

(* Custom claims *)

let test_custom_claim _ctx =
  let claims =
    Jwt.Claims.empty
    |> Jwt.Claims.sub "user"
    |> Jwt.Claims.add "admin" Jsont.bool true
    |> Jwt.Claims.add "level" Jsont.int 42
  in
  let token = Jwt.encode pk claims in
  let jwt = Jwt.decode ~public:(Jws.Pk.public pk) token |> msg_to_failure in
  assert_equal (Some true) (Jwt.claim jwt ~key:"admin" Jsont.bool);
  assert_equal (Some 42) (Jwt.claim jwt ~key:"level" Jsont.int);
  assert_equal None (Jwt.claim jwt ~key:"missing" Jsont.string)

(* typ header is set *)

let test_typ_header _ctx =
  let claims = Jwt.Claims.empty |> Jwt.Claims.sub "test" in
  let token = Jwt.encode pk claims in
  let jwt = Jwt.decode ~public:(Jws.Pk.public pk) token |> msg_to_failure in
  assert_equal (Some "JWT") (Jws.value (Jwt.jws jwt) ~key:"typ" Jsont.string)

(* EC key round-trip *)

let test_ec_roundtrip _ctx =
  let claims = Jwt.Claims.empty |> Jwt.Claims.sub "ec-user" in
  let token = Jwt.encode p256_pk claims in
  let jwt =
    Jwt.decode ~public:(Jws.Pk.public p256_pk) token |> msg_to_failure
  in
  assert_equal (Some "ec-user") (Jwt.sub jwt)

(* exp validation *)

let test_exp_valid _ctx =
  let claims =
    Jwt.Claims.empty |> Jwt.Claims.sub "user" |> Jwt.Claims.exp 2000000000.
  in
  let token = Jwt.encode pk claims in
  let result = Jwt.decode ~now:1000000000. ~public:(Jws.Pk.public pk) token in
  assert_bool "not expired" (Result.is_ok result)

let test_exp_expired _ctx =
  let claims =
    Jwt.Claims.empty |> Jwt.Claims.sub "user" |> Jwt.Claims.exp 1000000000.
  in
  let token = Jwt.encode pk claims in
  assert_error_msg "Token expired"
    (Jwt.decode ~now:2000000000. ~public:(Jws.Pk.public pk) token)

let test_exp_skipped_without_now _ctx =
  let claims =
    Jwt.Claims.empty |> Jwt.Claims.sub "user" |> Jwt.Claims.exp 1000000000.
  in
  let token = Jwt.encode pk claims in
  let result = Jwt.decode ~public:(Jws.Pk.public pk) token in
  assert_bool "exp not checked without ~now" (Result.is_ok result)

(* nbf validation *)

let test_nbf_valid _ctx =
  let claims =
    Jwt.Claims.empty |> Jwt.Claims.sub "user" |> Jwt.Claims.nbf 1000000000.
  in
  let token = Jwt.encode pk claims in
  let result = Jwt.decode ~now:2000000000. ~public:(Jws.Pk.public pk) token in
  assert_bool "nbf passed" (Result.is_ok result)

let test_nbf_too_early _ctx =
  let claims =
    Jwt.Claims.empty |> Jwt.Claims.sub "user" |> Jwt.Claims.nbf 2000000000.
  in
  let token = Jwt.encode pk claims in
  assert_error_msg "Token not yet valid"
    (Jwt.decode ~now:1000000000. ~public:(Jws.Pk.public pk) token)

(* aud validation *)

let test_aud_single_match _ctx =
  let claims =
    Jwt.Claims.empty
    |> Jwt.Claims.sub "user"
    |> Jwt.Claims.aud [ "https://api.example.com" ]
  in
  let token = Jwt.encode pk claims in
  let result =
    Jwt.decode ~aud:"https://api.example.com" ~public:(Jws.Pk.public pk) token
  in
  assert_bool "aud matches" (Result.is_ok result)

let test_aud_single_mismatch _ctx =
  let claims =
    Jwt.Claims.empty
    |> Jwt.Claims.sub "user"
    |> Jwt.Claims.aud [ "https://other.example.com" ]
  in
  let token = Jwt.encode pk claims in
  assert_error_msg "Audience mismatch"
    (Jwt.decode ~aud:"https://api.example.com" ~public:(Jws.Pk.public pk) token)

let test_aud_many_match _ctx =
  let claims =
    Jwt.Claims.empty
    |> Jwt.Claims.sub "user"
    |> Jwt.Claims.aud [ "https://api.example.com"; "https://other.example.com" ]
  in
  let token = Jwt.encode pk claims in
  let result =
    Jwt.decode ~aud:"https://api.example.com" ~public:(Jws.Pk.public pk) token
  in
  assert_bool "aud in list" (Result.is_ok result)

let test_aud_missing _ctx =
  let claims = Jwt.Claims.empty |> Jwt.Claims.sub "user" in
  let token = Jwt.encode pk claims in
  assert_error_msg "Missing aud claim"
    (Jwt.decode ~aud:"https://api.example.com" ~public:(Jws.Pk.public pk) token)

let test_aud_skipped_without_param _ctx =
  let claims = Jwt.Claims.empty |> Jwt.Claims.sub "user" in
  let token = Jwt.encode pk claims in
  let result = Jwt.decode ~public:(Jws.Pk.public pk) token in
  assert_bool "aud not checked" (Result.is_ok result)

(* aud accessor *)

let test_aud_accessor_single _ctx =
  let claims =
    Jwt.Claims.empty |> Jwt.Claims.aud [ "https://api.example.com" ]
  in
  let token = Jwt.encode pk claims in
  let jwt = Jwt.decode ~public:(Jws.Pk.public pk) token |> msg_to_failure in
  assert_equal (Some [ "https://api.example.com" ]) (Jwt.aud jwt)

let test_aud_accessor_many _ctx =
  let claims = Jwt.Claims.empty |> Jwt.Claims.aud [ "a"; "b" ] in
  let token = Jwt.encode pk claims in
  let jwt = Jwt.decode ~public:(Jws.Pk.public pk) token |> msg_to_failure in
  assert_equal (Some [ "a"; "b" ]) (Jwt.aud jwt)

(* Wrong key *)

let test_wrong_key _ctx =
  let claims = Jwt.Claims.empty |> Jwt.Claims.sub "user" in
  let token = Jwt.encode pk claims in
  let wrong_key = `Oct (String.make 32 'x') in
  assert_error_msg "Invalid signature" (Jwt.decode ~public:wrong_key token)

(* Invalid payload *)

let test_invalid_claims _ctx =
  let token = Jws.Compact.encode pk "not json" in
  assert_error_msg "Invalid JWT claims"
    (Jwt.decode ~public:(Jws.Pk.public pk) token)

let test_non_object_claims _ctx =
  let token = Jws.Compact.encode pk "42" in
  assert_error_msg "Invalid JWT claims"
    (Jwt.decode ~public:(Jws.Pk.public pk) token)

(* All tests *)

let all_tests =
  [
    "roundtrip" >:: test_roundtrip; "custom_claim" >:: test_custom_claim
  ; "typ_header" >:: test_typ_header; "ec_roundtrip" >:: test_ec_roundtrip
  ; "exp_valid" >:: test_exp_valid; "exp_expired" >:: test_exp_expired
  ; "exp_skipped_without_now" >:: test_exp_skipped_without_now
  ; "nbf_valid" >:: test_nbf_valid; "nbf_too_early" >:: test_nbf_too_early
  ; "aud_single_match" >:: test_aud_single_match
  ; "aud_single_mismatch" >:: test_aud_single_mismatch
  ; "aud_many_match" >:: test_aud_many_match; "aud_missing" >:: test_aud_missing
  ; "aud_skipped_without_param" >:: test_aud_skipped_without_param
  ; "aud_accessor_single" >:: test_aud_accessor_single
  ; "aud_accessor_many" >:: test_aud_accessor_many
  ; "wrong_key" >:: test_wrong_key; "invalid_claims" >:: test_invalid_claims
  ; "non_object_claims" >:: test_non_object_claims
  ]
