(** A fairly straightforward implementation of JWS in OCaml using
    [mirage-crypto] and [Jsont]. *)

module Base64u : sig
  val encode : string -> string
  val decode : string -> (string, [> `Msg of string ]) result

  module Z : sig
    val encode : Z.t -> string
    val decode : string -> (Z.t, [> `Msg of string ]) result
  end
end

module Jwa : sig
  type t =
    [ `HS256
    | `HS384
    | `HS512
    | `RS256
    | `RS384
    | `RS512
    | `ES256
    | `ES384
    | `ES512
    | `PS256
    | `PS384
    | `PS512
    | `EdDSA ]
end

module Jwk : sig
  type p =
    [ `RSA of Mirage_crypto_pk.Rsa.pub
    | `P256 of Mirage_crypto_ec.P256.Dsa.pub
    | `P384 of Mirage_crypto_ec.P384.Dsa.pub
    | `P521 of Mirage_crypto_ec.P521.Dsa.pub
    | `ED25519 of Mirage_crypto_ec.Ed25519.pub ]

  type t = [ p | `Oct of string ]

  val encode : t -> string
  val decode : string -> (t, [> `Msg of string ]) result
  val t : t Jsont.t
  val algorithm : t -> Jwa.t
  val verify : ?alg:Jwa.t -> t -> string -> string -> bool
  val of_public_key : [> p ] -> (t, [> `Msg of string ]) result
end

module S : Map.S with type key = string

module Pk : sig
  type pk =
    [ `RSA of Mirage_crypto_pk.Rsa.priv
    | `P256 of Mirage_crypto_ec.P256.Dsa.priv
    | `P384 of Mirage_crypto_ec.P384.Dsa.priv
    | `P521 of Mirage_crypto_ec.P521.Dsa.priv
    | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]

  type t = [ pk | `Oct of string ]

  val algorithm : t -> Jwa.t
  val public : t -> Jwk.t
  val sign : ?alg:Jwa.t -> t -> string -> string
  val of_private_key : [> pk ] -> (t, [> `Msg of string ]) result
end

type t

val nonce : t -> string option
val data : t -> string
val protected : t -> key:string -> 'a Jsont.t -> 'a option

val validate_crit :
     ?understood:string list
  -> Jsont.json S.t
  -> (unit, [> `Msg of string ]) result

val encode :
     ?alg:Jwa.t
  -> ?kid:string
  -> ?extra:Jsont.json S.t
  -> Pk.t
  -> ?nonce:string
  -> string
  -> string
(** [encode ?alg ?kid ?extra pk ?nonce data] is a JSON Web Signature which signs
    (or MACs) the given [data] with the given signature [pk] (a subset of
    {!type:Pk.t} follows [X509.Private_key.t]). *)

val decode :
     ?understood:string list
  -> ?public:Jwk.t
  -> string
  -> (t, [> `Msg of string ]) result

val decode_exn : ?understood:string list -> ?public:Jwk.t -> string -> t

module Compact : sig
  val encode :
       ?alg:Jwa.t
    -> ?extra:Jsont.json S.t
    -> Pk.t
    -> ?nonce:string
    -> string
    -> string

  val decode :
       ?understood:string list
    -> ?public:Jwk.t
    -> string
    -> (t, [> `Msg of string ]) result

  module Unsecured : sig
    val encode : string -> string
    val decode : ?allow_none:bool -> string -> (t, [> `Msg of string ]) result
  end
end
