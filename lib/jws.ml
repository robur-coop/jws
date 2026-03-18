let msg_to_failure = function Ok v -> v | Error (`Msg msg) -> failwith msg
let error_msgf fmt = Format.kasprintf (fun msg -> Error (`Msg msg)) fmt
let error_to_failure = function Ok v -> v | Error err -> failwith err
let ( let* ) = Result.bind

exception Jws_error of string

let jws_errorf fmt = Format.kasprintf (fun str -> raise (Jws_error str)) fmt

let msg_to_jws_error = function
  | Ok v -> v
  | Error (`Msg msg) -> raise (Jws_error msg)

let msg_to_base64_error = function
  | Ok v -> v
  | Error (`Msg msg) -> raise (Jwk.Base64_error msg)

let msg_to_invalid_arg = function
  | Ok v -> v
  | Error (`Msg msg) -> invalid_arg msg

let error_to_jws_error = function
  | Ok v -> v
  | Error msg -> raise (Jws_error msg)

module S = Map.Make (String)
module Base64u = Base64u
module Jwk = Jwk
module Jwa = Jwa

module Pk = struct
  type pk =
    [ `RSA of Mirage_crypto_pk.Rsa.priv
    | `P256 of Mirage_crypto_ec.P256.Dsa.priv
    | `P384 of Mirage_crypto_ec.P384.Dsa.priv
    | `P521 of Mirage_crypto_ec.P521.Dsa.priv
    | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]

  type t = [ pk | `Oct of string ]

  let algorithm : t -> Jwa.t = function
    | `RSA _ -> `RS256
    | `P256 _ -> `ES256
    | `P384 _ -> `ES384
    | `P521 _ -> `ES512
    | `ED25519 _ -> `EdDSA
    | `Oct _ -> `HS256

  let public : t -> Jwk.t = function
    | `RSA pk -> `RSA (Mirage_crypto_pk.Rsa.pub_of_priv pk)
    | `P256 pk -> `P256 (Mirage_crypto_ec.P256.Dsa.pub_of_priv pk)
    | `P384 pk -> `P384 (Mirage_crypto_ec.P384.Dsa.pub_of_priv pk)
    | `P521 pk -> `P521 (Mirage_crypto_ec.P521.Dsa.pub_of_priv pk)
    | `ED25519 pk -> `ED25519 (Mirage_crypto_ec.Ed25519.pub_of_priv pk)
    | `Oct k -> `Oct k

  type with_alg =
    | RSA of [ Jwa.alg_for_rsa0 | Jwa.alg_for_rsa1 ] * Mirage_crypto_pk.Rsa.priv
    | P256 of Jwa.alg_for_p256 * Mirage_crypto_ec.P256.Dsa.priv
    | P384 of Jwa.alg_for_p384 * Mirage_crypto_ec.P384.Dsa.priv
    | P521 of Jwa.alg_for_p521 * Mirage_crypto_ec.P521.Dsa.priv
    | Oct of Jwa.alg_for_oct * string
    | Ed25519 of Jwa.alg_for_ed25519 * Mirage_crypto_ec.Ed25519.priv

  let alg = function
    | RSA (alg, _) -> (alg :> Jwa.t)
    | P256 (alg, _) -> (alg :> Jwa.t)
    | P384 (alg, _) -> (alg :> Jwa.t)
    | P521 (alg, _) -> (alg :> Jwa.t)
    | Oct (alg, _) -> (alg :> Jwa.t)
    | Ed25519 (alg, _) -> (alg :> Jwa.t)

  let pk = function
    | RSA (_, pk) -> `RSA pk
    | P256 (_, pk) -> `P256 pk
    | P384 (_, pk) -> `P384 pk
    | P521 (_, pk) -> `P521 pk
    | Oct (_, pk) -> `Oct pk
    | Ed25519 (_, pk) -> `ED25519 pk

  (* NOTE(dinosaure): if you think that () is weird, it's to warn you that such
     function should not be exposed. *)
  let to_alg_and_pk pk ?(alg = algorithm pk) () =
    match (pk, alg) with
    | `RSA pk, ((#Jwa.alg_for_rsa0 | #Jwa.alg_for_rsa1) as alg) -> RSA (alg, pk)
    | `P256 pk, (#Jwa.alg_for_p256 as alg) -> P256 (alg, pk)
    | `P384 pk, (#Jwa.alg_for_p384 as alg) -> P384 (alg, pk)
    | `P521 pk, (#Jwa.alg_for_p521 as alg) -> P521 (alg, pk)
    | `Oct pk, (#Jwa.alg_for_oct as alg) -> Oct (alg, pk)
    | `ED25519 pk, (#Jwa.alg_for_ed25519 as alg) -> Ed25519 (alg, pk)
    | _ -> invalid_arg "Algorithm and private key mismatch"

  module P0 = Mirage_crypto_pk.Rsa.PSS (Digestif.SHA256)
  module P1 = Mirage_crypto_pk.Rsa.PSS (Digestif.SHA384)
  module P2 = Mirage_crypto_pk.Rsa.PSS (Digestif.SHA512)

  let tsign alg_and_pk data =
    match alg_and_pk with
    | RSA ((#Jwa.alg_for_rsa0 as alg), key) ->
        let hash = Jwk.hash_of_alg (alg :> Jwa.t) in
        let hash = (hash :> Digestif.hash') in
        let module Hash = (val Digestif.module_of_hash' hash) in
        let digest = Hash.to_raw_string (Hash.digest_string data) in
        Mirage_crypto_pk.Rsa.PKCS1.sign ~key ~hash (`Digest digest)
    | RSA (`PS256, key) -> P0.sign ~key (`Message data)
    | RSA (`PS384, key) -> P1.sign ~key (`Message data)
    | RSA (`PS512, key) -> P2.sign ~key (`Message data)
    | P256 (_, key) ->
        let digest = Digestif.SHA256.(to_raw_string (digest_string data)) in
        let r, s = Mirage_crypto_ec.P256.Dsa.sign ~key digest in
        r ^ s
    | P384 (_, key) ->
        let digest = Digestif.SHA384.(to_raw_string (digest_string data)) in
        let r, s = Mirage_crypto_ec.P384.Dsa.sign ~key digest in
        r ^ s
    | P521 (_, key) ->
        let digest = Digestif.SHA512.(to_raw_string (digest_string data)) in
        let r, s = Mirage_crypto_ec.P521.Dsa.sign ~key digest in
        r ^ s
    | Oct (alg, key) ->
        let hash = (Jwk.hash_of_alg (alg :> Jwa.t) :> Digestif.hash') in
        let module Hash = (val Digestif.module_of_hash' hash) in
        Hash.to_raw_string (Hash.hmac_string ~key data)
    | Ed25519 (_, key) -> Mirage_crypto_ec.Ed25519.sign ~key data

  let sign ?alg pk data =
    let alg = match alg with Some alg -> alg | None -> algorithm pk in
    let alg_and_pk = to_alg_and_pk ~alg pk () in
    tsign alg_and_pk data

  let of_private_key = function
    | #pk as pk -> Ok pk
    | _ -> error_msgf "Unsupported private key"

  let of_private_key_exn pk = of_private_key pk |> msg_to_invalid_arg
end

type t = { nonce: string option; p: Jsont.json S.t; v: string }

let alg : Jwa.t Jsont.t =
  let lst =
    [
      ("HS256", `HS256); ("HS384", `HS384); ("HS512", `HS512); ("RS256", `RS256)
    ; ("RS384", `RS384); ("RS512", `RS512); ("ES256", `ES256); ("ES384", `ES384)
    ; ("ES512", `ES512); ("PS256", `PS256); ("PS384", `PS384); ("PS512", `PS512)
    ; ("EdDSA", `EdDSA)
    ]
  in
  Jsont.enum lst

let protected =
  let open Jsont in
  let alg = Object.mem "alg" ~enc:(fun (alg, _, _) -> alg) alg in
  let nonce = Object.opt_mem "nonce" ~enc:(fun (_, nonce, _) -> nonce) string in
  let rest =
    let enc (_, _, p) = p in
    Object.keep_unknown ~enc (Object.Mems.string_map json)
  in
  Object.map (fun alg nonce p -> (alg, nonce, p))
  |> alg
  |> nonce
  |> rest
  |> Object.finish

let base64u =
  let enc = Base64u.encode in
  let dec = Base64u.decode in
  let dec s = msg_to_base64_error (dec s) in
  Jsont.map ~enc ~dec Jsont.string

let make_signing_input alg nonce p payload =
  let p0 = Jsont_bytesrw.encode_string protected (alg, nonce, p) in
  let p0 = error_to_failure p0 in
  Base64u.encode p0 ^ "." ^ Base64u.encode payload

let compute_signature alg_and_pk { nonce; p; v= p1 } =
  let alg = Pk.alg alg_and_pk in
  Pk.tsign alg_and_pk (make_signing_input alg nonce p p1)

let validate_crit ?(understood = []) props =
  match S.find_opt "crit" props with
  | None -> Ok ()
  | Some t -> (
      match Jsont.Json.decode (Jsont.list Jsont.string) t with
      | Error _ -> error_msgf "Invalid crit header parameter"
      | Ok [] -> error_msgf "The crit header parameter MUST NOT be empty"
      | Ok crits ->
          if List.mem "crit" crits then
            error_msgf "The crit header parameter MUST NOT list itself"
          else if List.for_all (fun c -> List.mem c understood) crits then Ok ()
          else error_msgf "Unrecognized critical header extension")

let t ?(understood = []) material =
  let open Jsont in
  let fprotected =
    let enc =
      match material with
      | Some (`Private_key alg_and_pk) ->
          let alg = Pk.alg alg_and_pk in
          Some (fun { nonce; p; _ } -> (alg, nonce, p))
      | Some (`Public_key p) ->
          let alg = Jwk.algorithm p in
          Some (fun { nonce; p; _ } -> (alg, nonce, p))
      | None -> None
    in
    let protected =
      let enc = Jsont_bytesrw.encode_string protected in
      let enc s = error_to_failure (enc s) in
      let dec = Jsont_bytesrw.decode_string protected in
      let dec s = error_to_jws_error (dec s) in
      Jsont.map ~enc ~dec base64u
    in
    Object.mem "protected" ?enc protected
  in
  let fpayload =
    let enc { v; _ } = v in
    Object.mem "payload" ~enc base64u
  in
  let fsignature =
    let enc =
      match material with
      | Some (`Private_key alg_and_pk) -> Some (compute_signature alg_and_pk)
      | _ -> None
    in
    Object.mem "signature" ?enc base64u
  in
  let fn (alg, nonce, pr) p1 signature =
    let jwk = S.find_opt "jwk" pr in
    let jwk = Option.map (Jsont.Json.decode Jwk.t) jwk in
    let jwk = Option.map Result.to_option jwk in
    let jwk = Option.join jwk in
    let p =
      match (jwk, material) with
      | _, Some (`Private_key alg_and_pk) ->
          let alg' = Pk.alg alg_and_pk in
          if alg <> alg' then jws_errorf "Algorithms mismatch";
          let pk = Pk.pk alg_and_pk in
          Pk.public pk
      | _, Some (`Public_key p) -> p
      | Some p, None -> p
      | _ -> jws_errorf "No public key provided"
    in
    validate_crit ~understood pr |> msg_to_jws_error;
    let m = make_signing_input alg nonce pr p1 in
    let alg_and_p =
      try Jwk.to_alg_and_p ~alg p ()
      with Invalid_argument msg -> raise (Jws_error msg)
    in
    if Jwk.tverify alg_and_p m signature then { nonce; p= pr; v= p1 }
    else jws_errorf "Invalid signature"
  in
  Object.map fn |> fprotected |> fpayload |> fsignature |> Object.finish

let str str = Jsont.String (str, Jsont.Meta.none)

let encode ?kid ?(extra = S.empty) alg_and_pk ?nonce data =
  let p =
    match kid with
    | None ->
        let pk = Pk.pk alg_and_pk in
        let t = Jsont.Json.encode Jwk.t (Pk.public pk) |> Result.get_ok in
        S.add "jwk" t extra
    | Some uri -> S.add "kid" (str uri) extra
  in
  let v = { nonce; p; v= data } in
  Jsont_bytesrw.encode_string (t (Some (`Private_key alg_and_pk))) v
  |> Result.get_ok

let encode_exn ?alg ?kid ?extra pk ?nonce data =
  let alg_and_pk =
    match alg with
    | Some alg -> Pk.to_alg_and_pk ~alg pk ()
    | None -> Pk.to_alg_and_pk pk ()
  in
  encode ?kid ?extra alg_and_pk ?nonce data

let encode ?kid ?extra pk ?nonce data =
  let alg_and_pk = Pk.to_alg_and_pk pk () in
  encode ?kid ?extra alg_and_pk ?nonce data

let decode ?(understood = []) ?public str =
  let p = Option.map (fun p -> `Public_key p) public in
  try
    match Jsont_bytesrw.decode_string (t ~understood p) str with
    | Ok _ as value -> value
    | Error _ -> error_msgf "Invalid JWS value"
  with
  | Jws_error msg -> error_msgf "%s" msg
  | Jwk.Base64_error msg -> error_msgf "%s" msg

let decode_exn ?understood ?public str =
  decode ?understood ?public str |> msg_to_failure

module Compact = struct
  let encode ?kid ?(extra = S.empty) alg_and_pk ?nonce data =
    let alg = Pk.alg alg_and_pk in
    let extra =
      match kid with
      | None ->
          let pk = Pk.pk alg_and_pk in
          let t = Jsont.Json.encode Jwk.t (Pk.public pk) |> Result.get_ok in
          S.add "jwk" t extra
      | Some uri -> S.add "kid" (str uri) extra
    in
    let h = Jsont_bytesrw.encode_string protected (alg, nonce, extra) in
    let h = error_to_failure h in
    let h64 = Base64u.encode h in
    let p64 = Base64u.encode data in
    let signing_input = h64 ^ "." ^ p64 in
    let signature = Pk.tsign alg_and_pk signing_input in
    signing_input ^ "." ^ Base64u.encode signature

  let encode_exn ?alg ?kid ?extra pk ?nonce data =
    let alg_and_pk =
      match alg with
      | Some alg -> Pk.to_alg_and_pk ~alg pk ()
      | None -> Pk.to_alg_and_pk pk ()
    in
    encode ?kid ?extra alg_and_pk ?nonce data

  let encode ?kid ?extra pk ?nonce data =
    let alg_and_pk = Pk.to_alg_and_pk pk () in
    encode ?kid ?extra alg_and_pk ?nonce data

  let decode ?(understood = []) ?public compact =
    match String.split_on_char '.' compact with
    | [ h64; p64; s64 ] ->
        let* h_raw = Base64u.decode h64 in
        let* alg, nonce, props =
          Jsont_bytesrw.decode_string protected h_raw
          |> Result.map_error (fun _e -> `Msg "Invalid protected header")
        in
        let* () = validate_crit ~understood props in
        let* signature = Base64u.decode s64 in
        let m = h64 ^ "." ^ p64 in
        let* p =
          match public with
          | Some p -> Ok p
          | None -> begin
              let jwk = S.find_opt "jwk" props in
              let jwk = Option.map (Jsont.Json.decode Jwk.t) jwk in
              let jwk = Option.map Result.to_option jwk in
              match Option.join jwk with
              | Some p -> Ok p
              | None -> error_msgf "No public key provided"
            end
        in
        let* alg_and_p =
          match Jwk.to_alg_and_p ~alg p () with
          | v -> Ok v
          | exception Invalid_argument msg -> error_msgf "%s" msg
        in
        if Jwk.tverify alg_and_p m signature then
          let* payload = Base64u.decode p64 in
          Ok { nonce; p= props; v= payload }
        else error_msgf "Invalid signature"
    | _ -> error_msgf "Invalid JWS Compact Serialization: expected 3 parts"

  module Unsecured = struct
    let encode payload =
      let h64 = Base64u.encode {json|{"alg":"none"}|json} in
      let p64 = Base64u.encode payload in
      h64 ^ "." ^ p64 ^ "."

    let unsecured_header =
      let open Jsont in
      let alg = Object.mem "alg" string in
      let nonce = Object.opt_mem "nonce" string in
      let rest = Object.keep_unknown (Object.Mems.string_map json) in
      Object.map (fun alg nonce p -> (alg, nonce, p))
      |> alg
      |> nonce
      |> rest
      |> Object.finish

    let decode ?(allow_none = false) compact =
      if not allow_none then
        error_msgf "Unsecured JWS not allowed (set ~allow_none:true to accept)"
      else
        match String.split_on_char '.' compact with
        | [ h64; p64; s ] when s = "" -> (
            let* h_raw = Base64u.decode h64 in
            match Jsont_bytesrw.decode_string unsecured_header h_raw with
            | Error _ -> error_msgf "Invalid unsecured JWS header"
            | Ok (alg_str, nonce, props) ->
                if alg_str <> "none" then
                  error_msgf "Unsecured JWS must have alg=none, got %s" alg_str
                else
                  let* payload = Base64u.decode p64 in
                  Ok { nonce; p= props; v= payload })
        | _ -> error_msgf "Invalid unsecured JWS: signature part must be empty"
  end
end

let nonce { nonce; _ } = nonce
let data { v; _ } = v

let value : type a. t -> key:string -> a Jsont.t -> a option =
 fun t ~key w ->
  match S.find_opt key t.p with
  | None -> None
  | Some v -> Jsont.Json.decode w v |> Result.to_option
