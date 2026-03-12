(** {1 JWS - JSON Web Signature
    ({{:https://www.rfc-editor.org/rfc/rfc7515}RFC 7515})}

    A straightforward implementation of JWS in OCaml using
    {{:https://github.com/mirage/mirage-crypto}mirage-crypto} and
    {{:https://github.com/dbuenzli/jsont}Jsont}.

    This library uses polymorphic variants that are compatible with
    {!type:X509.Public_key.t} and {!type:X509.Private_key.t}. For instance,
    given a private key obtained from [x509]:
    {[
      let pk : X509.Private_key.t = ... in
      let jws = Jws.encode (Pk.of_private_key_exn pk) ~nonce "payload"
    ]}

    Protected header fields beyond [alg] and [nonce] can be read back via
    {!val:protected} using any {!type:Jsont.t} decoder:
    {[
      let url = Jws.protected jws ~key:"url" Jsont.string
    ]} *)

(** {2 Base64url} *)

module Base64u : sig
  val encode : string -> string
  (** [encode s] is the Base64url encoding of [s] without padding. *)

  val decode : string -> (string, [> `Msg of string ]) result
  (** [decode s] decodes [s] from Base64url (no padding). *)

  module Z : sig
    val encode : Z.t -> string
    (** [encode z] is the Base64url encoding of the big integer [z]. *)

    val decode : string -> (Z.t, [> `Msg of string ]) result
    (** [decode s] decodes a big integer from Base64url. *)
  end
end

(** {2 JWA - JSON Web Algorithms
    ({{:https://www.rfc-editor.org/rfc/rfc7518}RFC 7518})} *)

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
  (** The set of algorithms defined by
      {{:https://www.rfc-editor.org/rfc/rfc7518#section-3.1}RFC 7518, 3.1}. *)
end

(** {2 JWK - JSON Web Key ({{:https://www.rfc-editor.org/rfc/rfc7517}RFC 7517})}
*)

module Jwk : sig
  type p =
    [ `RSA of Mirage_crypto_pk.Rsa.pub
    | `P256 of Mirage_crypto_ec.P256.Dsa.pub
    | `P384 of Mirage_crypto_ec.P384.Dsa.pub
    | `P521 of Mirage_crypto_ec.P521.Dsa.pub
    | `ED25519 of Mirage_crypto_ec.Ed25519.pub ]
  (** Asymmetric public keys. This type is a subset of
      {!type:X509.Public_key.t}: any [X509.Public_key.t] value whose algorithm
      is supported can be injected via {!val:of_public_key}. *)

  type t = [ p | `Oct of string ]
  (** Public keys and symmetric (oct) keys. *)

  val encode : t -> string
  (** [encode key] is the JSON serialization of [key] as a JWK. *)

  val decode : string -> (t, [> `Msg of string ]) result
  (** [decode str] parses a JWK from its JSON serialization. Returns a
      descriptive error when the JSON is malformed, the key type is unknown, or
      the key parameters are invalid. *)

  val t : t Jsont.t
  (** A {!type:Jsont.t} codec for JWK values. Can be used with
      {!val:Jsont_bytesrw.decode_string} or composed into larger [Jsont]
      descriptions. *)

  val algorithm : t -> Jwa.t
  (** [algorithm key] is the default {!type:Jwa.t} algorithm for [key]. *)

  val verify : ?alg:Jwa.t -> t -> string -> string -> bool
  (** [verify ?alg p data signature] is [true] iff [signature] is a valid
      signature of [data] under [p] with algorithm [alg] (defaults to the
      default algorithm of the given [p] (see {!val:algorithm})).

      @raise Invalid_argument
        if the given [alg] does not match the given public key. *)

  val of_public_key : [> p ] -> (t, [> `Msg of string ]) result
  (** [of_public_key pk] converts an {!type:X509.Public_key.t} value to a
      {!type:t}. Fails if the key algorithm is not supported (e.g. DSA). *)
end

module S : Map.S with type key = string

(** {2 Private keys and signing} *)

module Pk : sig
  type pk =
    [ `RSA of Mirage_crypto_pk.Rsa.priv
    | `P256 of Mirage_crypto_ec.P256.Dsa.priv
    | `P384 of Mirage_crypto_ec.P384.Dsa.priv
    | `P521 of Mirage_crypto_ec.P521.Dsa.priv
    | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]
  (** Asymmetric private keys. This type is a subset of
      {!type:X509.Private_key.t}. *)

  type t = [ pk | `Oct of string ]
  (** Private keys and symmetric (oct) keys. *)

  val algorithm : t -> Jwa.t
  (** [algorithm pk] is the default {!type:Jwa.t} algorithm for the given [pk].
  *)

  val public : t -> Jwk.t
  (** [public pk] extracts the corresponding public key from the given [pk]. *)

  val sign : ?alg:Jwa.t -> t -> string -> string
  (** [sign ?alg pk data] signs [data] with [pk] ([alg] defaults to the default
      algorithm of the given [pk] (see {!val:algorithm})).

      @raise Invalid_argument
        if the given algorithm [alg] does not match the given private key [pk].
  *)

  val of_private_key : [> pk ] -> (t, [> `Msg of string ]) result
  (** [of_private_key pk] converts an {!type:X509.Private_key.t} value to a
      {!type:t}. Fails if the key algorithm is not supported. *)

  val of_private_key_exn : [> pk ] -> t
  (** [of_private_key_exn pk] is like {!val:of_private_key} but raises
      [Invalid_argument] on unsupported key types. *)
end

(** {2 JWS values} *)

type t
(** A decoded JWS value. *)

val nonce : t -> string option
(** [nonce jws] is the [nonce] protected header field, if present. *)

val data : t -> string
(** [data jws] is the payload carried by [jws]. *)

val protected : t -> key:string -> 'a Jsont.t -> 'a option
(** [protected jws ~key codec] decodes the protected header field [key] using
    the {!type:Jsont.t} [codec]. Returns [None] when the field is absent or
    cannot be decoded.

    For example, to read the ["url"] field added by ACME
    ({{:https://www.rfc-editor.org/rfc/rfc8555}RFC 8555}):
    {[
      Jws.protected jws ~key:"url" Jsont.string
    ]} *)

val validate_crit :
     ?understood:string list
  -> Jsont.json S.t
  -> (unit, [> `Msg of string ]) result
(** [validate_crit ?understood props] validates the ["crit"] header parameter
    according to
    {{:https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11}RFC 7515, 4.1.11}.
    [understood] is the list of extension header names the application
    recognizes. *)

(** {2 Flattened JSON Serialization
    ({{:https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2}RFC 7515, 7.2.2})}
*)

val encode :
     ?kid:string
  -> ?extra:Jsont.json S.t
  -> Pk.t
  -> ?nonce:string
  -> string
  -> string
(** [encode ?kid ?extra pk ?nonce data] produces a JWS Flattened JSON
    Serialization that signs (or MACs) [data] with [pk]. The algorithm is
    derived from [pk].

    When [kid] is provided, a ["kid"] header field is set and no JWK is
    embedded. Otherwise the public key is embedded as a ["jwk"] header field
    (this is the typical ACME workflow).

    [extra] carries additional protected header members as a {!type:Jsont.json}
    string map. For instance, to set the ["url"] field required by ACME:
    {[
      let extra = S.singleton "url" (Jsont.Json.string url) in
      Jws.encode ~extra pk ~nonce payload
    ]} *)

val encode_exn :
     ?alg:Jwa.t
  -> ?kid:string
  -> ?extra:Jsont.json S.t
  -> Pk.t
  -> ?nonce:string
  -> string
  -> string
(** [encode_exn ?alg ?kid ?extra pk ?nonce data] is like {!val:encode} but
    allows overriding the algorithm via [?alg].

    @raise Invalid_argument
      if the given algorithm [alg] does not match the given private key [pk]. *)

val decode :
     ?understood:string list
  -> ?public:Jwk.t
  -> string
  -> (t, [> `Msg of string ]) result
(** [decode ?understood ?public str] decodes and verifies a JWS Flattened JSON
    Serialization. The public key is taken from [public] if provided, otherwise
    from the embedded ["jwk"] header field. Returns a descriptive error when the
    JSON is malformed, no public key is available, the signature is invalid, or
    a critical header extension is not understood.

    [understood] lists the critical header extensions the application recognizes
    (see {!val:validate_crit}). *)

val decode_exn : ?understood:string list -> ?public:Jwk.t -> string -> t
(** [decode_exn] is like {!val:decode} but raises [Failure] on error. *)

(** {2 Compact Serialization
    ({{:https://www.rfc-editor.org/rfc/rfc7515#section-7.1}RFC 7515, 7.1})} *)

module Compact : sig
  val encode :
    ?extra:Jsont.json S.t -> Pk.t -> ?nonce:string -> string -> string
  (** [encode_exn ?alg ?extra pk ?nonce data] produces a JWS Compact
      Serialization ([header.payload.signature]). *)

  val encode_exn :
       ?alg:Jwa.t
    -> ?extra:Jsont.json S.t
    -> Pk.t
    -> ?nonce:string
    -> string
    -> string
  (** [encode_exn ?alg ?extra pk ?nonce data] is like {!val:encode} but allows
      overriding the algorithm via [?alg].

      @raise Invalid_argument if [alg] does not match [pk]. *)

  val decode :
       ?understood:string list
    -> ?public:Jwk.t
    -> string
    -> (t, [> `Msg of string ]) result
  (** [decode ?understood ?public compact] decodes and verifies a JWS Compact
      Serialization. See {!val:Jws.decode} for the semantics of [understood] and
      [public]. *)

  (** {3 Unsecured JWS
      ({{:https://www.rfc-editor.org/rfc/rfc7515#appendix-A.5}RFC 7515, A.5})}
  *)

  module Unsecured : sig
    val encode : string -> string
    (** [encode data] produces an unsecured JWS ([alg=none]) in Compact
        Serialization. The signature part is empty. *)

    val decode : ?allow_none:bool -> string -> (t, [> `Msg of string ]) result
    (** [decode ?allow_none compact] decodes an unsecured JWS. [allow_none]
        defaults to [false]: the caller must explicitly opt in to accept
        [alg=none], as recommended by
        {{:https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1}RFC 7515, 4.1.1}.
    *)
  end
end
