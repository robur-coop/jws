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

type alg_for_rsa0 = [ `RS256 | `RS384 | `RS512 ]
type alg_for_rsa1 = [ `PS256 | `PS384 | `PS512 | alg_for_rsa0 ]
type alg_for_p256 = [ `ES256 ]
type alg_for_p384 = [ `ES384 ]
type alg_for_p521 = [ `ES512 ]
type alg_for_oct = [ `HS256 | `HS384 | `HS512 ]
type alg_for_ed25519 = [ `EdDSA ]
