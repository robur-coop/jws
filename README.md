# Jws, yet another implementation of JSON Web Signature/Token (RFC7515)

There are many implementations of JSON Web tokens, but this one has two
characteristics:
- it works well with [mirage-crypto][mirage-crypto]
- It does not use GADTs and prefers (à la `mirage-crypto`) to use polymorphic variants
- It uses [jsont][jsont]

I simply wanted an encode/decode function. Not much else...

The improvement is minor but worthwhile. It is therefore a new implementation
of JSON Web Signatures according to [RFC7515][RFC7515]. It was not designed to
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

[mirage-crypto]: https://github.com/mirage/mirage-crypto/
[jsont]: https://github.com/dbuenzli/jsont
[RFC7515]: https://datatracker.ietf.org/doc/html/rfc7515
