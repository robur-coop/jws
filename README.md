# Jws, yet another implementation of JSON Web Signature/Token (RFC 7515)

There are many implementations of JSON Web tokens, but this one has two
characteristics:
- it works well with [mirage-crypto][mirage-crypto]
- It does not use GADTs and prefers (à la `mirage-crypto`) to use polymorphic
  variants
- It uses [jsont][jsont]
- It essentially offers what the user wants, namely to encode and decode JWTs

I simply wanted an encode/decode function. Not much else...

The improvement is minor but worthwhile. It is therefore a new implementation
of JSON Web Signatures according to [RFC 7515][RFC 7515]. It was not designed to
be particularly fancy, fast or intelligent... Just a library that's a bit of
pleasant to work with.

Here is an example that generates a token and reads it:
```ocaml
let () = Mirage_crypto_rng_unix.use_default ()
let ( let* ) = Result.bind
let pk = Jws.Pk.of_private_key_exn (X509.Private_key.generate ~seed:"foo=" `RSA)

let jwt =
  let v =
    let open Jwt.Claims in
    empty
    |> iss "http://robur.coop/"
    |> sub "My Super token"
    |> add "admin" Jsont.bool true in
  Jwt.encode pk v

let run () =
  let* t = Jwt.decode ~now:(Unix.gettimeofday ()) jwt in
  Fmt.pr ">>> token from: %a\n%!" Fmt.(Dump.option string) (Jwt.iss t);
  let is_admin = Jwt.value t ~key:"admin" Jsont.bool in
  let is_admin = Option.value ~default:false is_admin in
  Fmt.pr ">>> is admin? %b\n%!" is_admin;
  Ok ()

let () = match run () with
  | Ok () -> ()
  | Error (`Msg msg) -> prerr_endline msg
```

There are several other projects that can decode and encode JWTs:
- [ocaml-jose][ocaml-jose]
- [ocaml-jwt][ocaml-jwt]
- [jwto][jwto]
- An internal module of [ocaml-letsencrypt][ocaml-letsencrypt]

`jws` is the only one that supports all signature algorithms as stated in [RFC
7518, 3.1](https://datatracker.ietf.org/doc/html/rfc7518#section-3.1). Next,
`jws` offers compatibility with `X509.{Private_key,Public_key}` **without**
depending on it, using polymorphic variants. `jws` has fewer dependencies than
`jose` (the use of `astring` remains minor, and `ptime` is not really
required). `jws` is certainly less complete than `jose` (which also offers JWK
and JWE), but it is a little easier to use. It essentially only offers an
`encode` function and a `decode` function. Checks (expiry, date, audience,
public key, etc.) are integrated and do not require any additional action on the
part of the user.

[mirage-crypto]: https://github.com/mirage/mirage-crypto/
[jsont]: https://github.com/dbuenzli/jsont
[ocaml-jose]: https://github.com/ulrikstrid/ocaml-jose
[ocaml-jwt]: https://github.com/besport/ocaml-jwt
[jwto]: https://github.com/sporto/jwto
[ocaml-letsencrypt]: https://github.com/robur-coop/ocaml-letsencrypt
[RFC 7515]: https://datatracker.ietf.org/doc/html/rfc7515
