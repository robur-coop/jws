(** {1 JWT - JSON Web Token
    ({{:https://www.rfc-editor.org/rfc/rfc7519}RFC 7519})}

    A thin layer on top of {!module:Jws} Compact Serialization that interprets
    the payload as a JSON claims set.

    {2 Encoding a JWT}

    {[
      let claims =
        Jwt.Claims.empty
        |> Jwt.Claims.sub "1234567890"
        |> Jwt.Claims.iss "https://example.com"
        |> Jwt.Claims.iat 1516239022.
        |> Jwt.Claims.add "admin" Jsont.bool true
      in
      let token = Jwt.encode pk claims
    ]}

    {2 Decoding and validating a JWT}

    {[
      let now = Unix.gettimeofday () in
      match Jwt.decode ~now ~aud:"https://api.example.com" ~public token with
      | Ok jwt ->
          let sub = Jwt.sub jwt in
          let admin = Jwt.claim jwt ~key:"admin" Jsont.bool in
          ...
      | Error (`Msg e) -> ...
    ]} *)

(** {2 Claims}

    Claims are built as {!type:Jsont.json} string maps, the same representation
    used for protected header members in {!module:Jws}. The {!module:Claims}
    module provides helpers for the registered claim names defined by
    {{:https://www.rfc-editor.org/rfc/rfc7519#section-4.1}RFC 7519, 4.1}. *)

module Claims : sig
  type t = Jsont.json Jws.S.t

  val empty : t

  val iss : string -> t -> t
  (** Set the ["iss"] (issuer) claim. *)

  val sub : string -> t -> t
  (** Set the ["sub"] (subject) claim. *)

  val aud : string list -> t -> t
  (** Set the ["aud"] (audience) claim as a single string. *)

  val exp : float -> t -> t
  (** Set the ["exp"] (expiration time) claim as a epoch date (seconds since
      epoch) *)

  val nbf : float -> t -> t
  (** Set the ["nbf"] (not before) claim as a epoch date (seconds since epoch).
  *)

  val iat : float -> t -> t
  (** Set the ["iat"] (issued at) claim as a epoch date (seconds since epoch).
  *)

  val jti : string -> t -> t
  (** Set the ["jti"] (JWT ID) claim. *)

  val add : string -> 'a Jsont.t -> 'a -> t -> t
  (** [add key codec value claims] sets a custom claim using a {!type:Jsont.t}
      codec. For example:
      {[
        Claims.empty |> Claims.add "admin" Jsont.bool true
      ]} *)
end

(** {2 Decoded JWT values} *)

type t
(** A decoded and verified JWT. *)

val jws : t -> Jws.t
(** [header jwt] is the underlying JWS value. Use {!val:Jws.value} to read
    header fields such as ["kid"]. *)

val sub : t -> string option
(** [sub jwt] is the ["sub"] claim. *)

val iss : t -> string option
(** [iss jwt] is the ["iss"] claim. *)

val aud : t -> string list option
(** [aud jwt] is the ["aud"] claim, normalized to a list (a single-string
    audience is returned as a singleton list). *)

val exp : t -> float option
(** [exp jwt] is the ["exp"] claim. *)

val nbf : t -> float option
(** [nbf jwt] is the ["nbf"] claim. *)

val iat : t -> float option
(** [iat jwt] is the ["iat"] claim. *)

val jti : t -> string option
(** [jti jwt] is the ["jti"] claim. *)

val value : t -> key:string -> 'a Jsont.t -> 'a option
(** [value jwt ~key codec] reads a custom claim via a {!type:Jsont.t} codec.
    Returns [None] when the claim is absent or cannot be decoded. *)

(** {2 Encoding} *)

val encode :
  ?kid:string -> ?extra:Jsont.json Jws.S.t -> Jws.Pk.t -> Claims.t -> string
(** [encode pk claims] produces a signed JWT in Compact Serialization. The
    algorithm is derived from [pk] and a ["typ":"JWT"] header is added. *)

(** {2 Decoding} *)

val decode :
     ?now:float
  -> ?aud:string
  -> ?public:Jws.Jwk.t
  -> string
  -> (t, [> `Msg of string ]) result
(** [decode ?now ?aud ?public token] decodes and verifies a JWT.

    - If [now] is provided, the ["exp"] and ["nbf"] claims are validated against
      it. If [now] is omitted, time-based validation is skipped.
    - If [aud] is provided, the ["aud"] claim must be present and contain [aud].
    - [public] is the verification key (see {!val:Jws.Compact.decode}). *)
