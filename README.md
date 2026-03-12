# Jws, yet another implementation of JSON Web Signature (RFC7515)

There are many implementations of JSON Web tokens, but this one has two
characteristics:
- it works well with [mirage-crypto][mirage-crypto]
- It does not use GADTs and prefers (à la `mirage-crypto`) to use polymorphic variants
- It uses [jsont][jsont]

The improvement is minor but worthwhile. It is therefore a new implementation
of JSON Web Signatures according to [RFC7515][RFC7515]. It was not designed to
be particularly fancy, fast or intelligent... Just a library that's a bit of
pleasant to work with.

[mirage-crypto]: https://github.com/mirage/mirage-crypto/
[jsont]: https://github.com/dbuenzli/jsont
[RFC7515]: https://datatracker.ietf.org/doc/html/rfc7515
