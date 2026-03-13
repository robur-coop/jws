let error_msgf fmt = Format.kasprintf (fun msg -> Error (`Msg msg)) fmt

let msg_to_invalid_arg = function
  | Ok v -> v
  | Error (`Msg msg) -> invalid_arg msg

exception Jwk_error of string

let jwk_errorf fmt = Format.kasprintf (fun str -> raise (Jwk_error str)) fmt

exception Base64_error of string

let msg_to_base64_error = function
  | Ok v -> v
  | Error (`Msg msg) -> raise (Base64_error msg)

let base64u =
  let enc = Base64u.encode in
  let dec = Base64u.decode in
  let dec = Fun.compose msg_to_base64_error dec in
  Jsont.map ~enc ~dec Jsont.string

let z =
  let enc = Base64u.Z.encode in
  let dec = Base64u.Z.decode in
  let dec = Fun.compose msg_to_base64_error dec in
  Jsont.map ~enc ~dec Jsont.string

type ec =
  [ `P256 of Mirage_crypto_ec.P256.Dsa.pub
  | `P384 of Mirage_crypto_ec.P384.Dsa.pub
  | `P521 of Mirage_crypto_ec.P521.Dsa.pub ]

type p =
  [ `RSA of Mirage_crypto_pk.Rsa.pub
  | `ED25519 of Mirage_crypto_ec.Ed25519.pub
  | ec ]

type t = [ p | `Oct of string ]

type with_alg =
  | RSA of [ Jwa.alg_for_rsa0 | Jwa.alg_for_rsa1 ] * Mirage_crypto_pk.Rsa.pub
  | P256 of Jwa.alg_for_p256 * Mirage_crypto_ec.P256.Dsa.pub
  | P384 of Jwa.alg_for_p384 * Mirage_crypto_ec.P384.Dsa.pub
  | P521 of Jwa.alg_for_p521 * Mirage_crypto_ec.P521.Dsa.pub
  | Oct of Jwa.alg_for_oct * string
  | Ed25519 of Jwa.alg_for_ed25519 * Mirage_crypto_ec.Ed25519.pub

let algorithm : t -> Jwa.t = function
  | `RSA _ -> `RS256
  | `P256 _ -> `ES256
  | `P384 _ -> `ES384
  | `P521 _ -> `ES512
  | `ED25519 _ -> `EdDSA
  | `Oct _ -> `HS256

(* NOTE(dinosaure): if you think that () is weird, it's to warn you that such
   function should not be exposed. *)
let to_alg_and_p p ?(alg = algorithm p) () =
  match (p, alg) with
  | `RSA p, ((#Jwa.alg_for_rsa0 | #Jwa.alg_for_rsa1) as alg) -> RSA (alg, p)
  | `P256 p, (#Jwa.alg_for_p256 as alg) -> P256 (alg, p)
  | `P384 p, (#Jwa.alg_for_p384 as alg) -> P384 (alg, p)
  | `P521 p, (#Jwa.alg_for_p521 as alg) -> P521 (alg, p)
  | `Oct p, (#Jwa.alg_for_oct as alg) -> Oct (alg, p)
  | `ED25519 p, (#Jwa.alg_for_ed25519 as alg) -> Ed25519 (alg, p)
  | _ -> invalid_arg "Algorithm and public key mismatch"

let of_public_key = function
  | #p as p -> Ok p
  | _ -> error_msgf "Unsupported public key"

let of_public_key_exn p = of_public_key p |> msg_to_invalid_arg

let hash_of_alg : Jwa.t -> [> `SHA256 | `SHA384 | `SHA512 ] = function
  | `HS256 | `RS256 | `ES256 | `PS256 -> `SHA256
  | `HS384 | `RS384 | `ES384 | `PS384 -> `SHA384
  | `HS512 | `RS512 | `ES512 | `PS512 -> `SHA512
  | `EdDSA -> `SHA512

let tverify alg_and_p data signature =
  match alg_and_p with
  | RSA ((#Jwa.alg_for_rsa0 as alg), key) ->
      let hash = hash_of_alg (alg :> Jwa.t) in
      let hash = (hash :> Digestif.hash') in
      let module Hash = (val Digestif.module_of_hash' hash) in
      let digest = Hash.to_raw_string (Hash.digest_string data) in
      let hashp h = h = hash in
      Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature (`Digest digest)
  | RSA (`PS256, key) ->
      let module P = Mirage_crypto_pk.Rsa.PSS (Digestif.SHA256) in
      P.verify ~key ~signature (`Message data)
  | RSA (`PS384, key) ->
      let module P = Mirage_crypto_pk.Rsa.PSS (Digestif.SHA384) in
      P.verify ~key ~signature (`Message data)
  | RSA (`PS512, key) ->
      let module P = Mirage_crypto_pk.Rsa.PSS (Digestif.SHA512) in
      P.verify ~key ~signature (`Message data)
  | P256 (_, key) when String.length signature = 64 ->
      let s = (String.sub signature 0 32, String.sub signature 32 32) in
      let digest = Digestif.SHA256.(to_raw_string (digest_string data)) in
      Mirage_crypto_ec.P256.Dsa.verify ~key s digest
  | P384 (_, key) when String.length signature = 96 ->
      let s = (String.sub signature 0 48, String.sub signature 48 48) in
      let digest = Digestif.SHA384.(to_raw_string (digest_string data)) in
      Mirage_crypto_ec.P384.Dsa.verify ~key s digest
  | P521 (_, key) when String.length signature = 132 ->
      let s = (String.sub signature 0 66, String.sub signature 66 66) in
      let digest = Digestif.SHA512.(to_raw_string (digest_string data)) in
      Mirage_crypto_ec.P521.Dsa.verify ~key s digest
  | Oct (alg, key) -> begin
      let hash = (hash_of_alg (alg :> Jwa.t) :> Digestif.hash') in
      let module Hash = (val Digestif.module_of_hash' hash) in
      let expected = Hash.hmac_string ~key data in
      try Hash.equal expected (Hash.of_raw_string signature) with _ -> false
    end
  | Ed25519 (_, key) -> Mirage_crypto_ec.Ed25519.verify ~key signature ~msg:data
  | _ -> false

let verify ?alg p data signature =
  let alg_and_p = to_alg_and_p ?alg p () in
  tverify alg_and_p data signature

let rsa =
  let open Jsont in
  let e =
    let enc ({ Mirage_crypto_pk.Rsa.e; _ } : Mirage_crypto_pk.Rsa.pub) = e in
    Object.mem "e" ~enc z
  in
  let n =
    let enc ({ Mirage_crypto_pk.Rsa.n; _ } : Mirage_crypto_pk.Rsa.pub) = n in
    Object.mem "n" ~enc z
  in
  let fn e n =
    match Mirage_crypto_pk.Rsa.pub ~e ~n with
    | Ok t -> t
    | Error _ -> jwk_errorf "Invalid public RSA key"
  in
  Object.map fn |> e |> n |> Object.finish

let ec ~x ~y ~pub_of_octets =
  let open Jsont in
  let x = Object.mem "x" ~enc:x base64u in
  let y = Object.mem "y" ~enc:y base64u in
  let fn x y =
    let str = String.concat "" [ "\004"; x; y ] in
    match pub_of_octets str with
    | Ok t -> t
    | Error _ -> jwk_errorf "Invalid elliptic curve key"
  in
  Object.map fn |> x |> y |> Object.finish

let ec =
  let open Jsont in
  let p256 =
    let pub_of_octets = Mirage_crypto_ec.P256.Dsa.pub_of_octets in
    let x key =
      let str = Mirage_crypto_ec.P256.Dsa.pub_to_octets key in
      String.sub str 1 32
    in
    let y key =
      let str = Mirage_crypto_ec.P256.Dsa.pub_to_octets key in
      String.sub str 33 32
    in
    let dec x = `P256 x in
    Object.Case.map "P-256" (ec ~x ~y ~pub_of_octets) ~dec
  in
  let p384 =
    let pub_of_octets = Mirage_crypto_ec.P384.Dsa.pub_of_octets in
    let x key =
      let str = Mirage_crypto_ec.P384.Dsa.pub_to_octets key in
      String.sub str 1 48
    in
    let y key =
      let str = Mirage_crypto_ec.P384.Dsa.pub_to_octets key in
      String.sub str 49 48
    in
    let dec x = `P384 x in
    Object.Case.map "P-384" (ec ~x ~y ~pub_of_octets) ~dec
  in
  let p521 =
    let pub_of_octets = Mirage_crypto_ec.P521.Dsa.pub_of_octets in
    let x key =
      let str = Mirage_crypto_ec.P521.Dsa.pub_to_octets key in
      String.sub str 1 66
    in
    let y key =
      let str = Mirage_crypto_ec.P521.Dsa.pub_to_octets key in
      String.sub str 67 66
    in
    let dec x = `P521 x in
    Object.Case.map "P-521" (ec ~x ~y ~pub_of_octets) ~dec
  in
  let enc_case = function
    | `P256 x -> Object.Case.value p256 x
    | `P384 x -> Object.Case.value p384 x
    | `P521 x -> Object.Case.value p521 x
  in
  let cases = Object.Case.[ make p256; make p384; make p521 ] in
  Object.map Fun.id
  |> Object.case_mem "crv" string ~enc:Fun.id ~enc_case cases
  |> Object.finish

let okp : Mirage_crypto_ec.Ed25519.pub Jsont.t =
  let open Jsont in
  let ed25519 =
    let pub_of_octets = Mirage_crypto_ec.Ed25519.pub_of_octets in
    let x key = Mirage_crypto_ec.Ed25519.pub_to_octets key in
    let x_mem = Object.mem "x" ~enc:x base64u in
    let fn x =
      match pub_of_octets x with
      | Ok t -> t
      | Error _ -> jwk_errorf "Invalid Ed25519 public key"
    in
    Object.Case.map "Ed25519"
      (Object.map fn |> x_mem |> Object.finish)
      ~dec:Fun.id
  in
  let enc_case key = Object.Case.value ed25519 key in
  let cases = Object.Case.[ make ed25519 ] in
  Object.map Fun.id
  |> Object.case_mem "crv" string ~enc:Fun.id ~enc_case cases
  |> Object.finish

let oct : string Jsont.t =
  let open Jsont in
  let k =
    let enc key = key in
    Object.mem "k" ~enc base64u
  in
  Object.map Fun.id |> k |> Object.finish

let t =
  let rsa = Jsont.Object.Case.map "RSA" rsa ~dec:(fun x -> `RSA x) in
  let ec_case = Jsont.Object.Case.map "EC" ec ~dec:(fun x -> (x :> t)) in
  let okp = Jsont.Object.Case.map "OKP" okp ~dec:(fun x -> `ED25519 x) in
  let oct_case = Jsont.Object.Case.map "oct" oct ~dec:(fun x -> `Oct x) in
  let enc_case = function
    | `RSA x -> Jsont.Object.Case.value rsa x
    | `ED25519 x -> Jsont.Object.Case.value okp x
    | `Oct x -> Jsont.Object.Case.value oct_case x
    | #ec as x -> Jsont.Object.Case.value ec_case x
  in
  let cases =
    Jsont.Object.Case.[ make rsa; make ec_case; make okp; make oct_case ]
  in
  Jsont.Object.map Fun.id
  |> Jsont.Object.case_mem "kty" Jsont.string ~enc:Fun.id ~enc_case cases
  |> Jsont.Object.finish

let encode v = Jsont_bytesrw.encode_string t v |> Result.get_ok

let decode str =
  try
    match Jsont_bytesrw.decode_string t str with
    | Ok _ as value -> value
    | Error _ -> error_msgf "Invalid JWK"
  with
  | Jwk_error msg -> error_msgf "%s" msg
  | Base64_error msg -> error_msgf "%s" msg

let signature t =
  let str = encode t in
  let hash = Digestif.SHA256.digest_string str in
  let hash = Digestif.SHA256.to_raw_string hash in
  Base64u.encode hash
