let error_msgf fmt = Format.kasprintf (fun msg -> Error (`Msg msg)) fmt
let msgf fmt = Format.kasprintf (fun msg -> `Msg msg) fmt
let ( let* ) = Result.bind

let claims =
  let open Jsont in
  Object.as_string_map json

let str s = Jsont.Json.encode Jsont.string s |> Result.get_ok
let float n = Jsont.Json.encode Jsont.number n |> Result.get_ok
let strs ss = Jsont.Json.encode (Jsont.list Jsont.string) ss |> Result.get_ok

module Claims = struct
  type t = Jsont.json Jws.S.t

  let empty = Jws.S.empty
  let iss v t = Jws.S.add "iss" (str v) t
  let sub v t = Jws.S.add "sub" (str v) t
  let exp v t = Jws.S.add "exp" (float v) t
  let nbf v t = Jws.S.add "nbf" (float v) t
  let iat v t = Jws.S.add "iat" (float v) t
  let jti v t = Jws.S.add "jti" (str v) t

  let aud v t =
    match v with
    | [] -> t
    | [ v ] -> Jws.S.add "aud" (str v) t
    | vs -> Jws.S.add "aud" (strs vs) t

  let add key codec value t =
    let json = Jsont.Json.encode codec value |> Result.get_ok in
    Jws.S.add key json t
end

type t = { jws: Jws.t; claims: Claims.t }

let jws t = t.jws

let get_string key t =
  let v = Jws.S.find_opt key t.claims in
  let fn = Jsont.Json.decode Jsont.string in
  let v = Option.map fn v in
  let v = Option.map Result.to_option v in
  Option.join v

let get_number key t =
  let v = Jws.S.find_opt key t.claims in
  let fn = Jsont.Json.decode Jsont.number in
  let v = Option.map fn v in
  let v = Option.map Result.to_option v in
  Option.join v

let iss t = get_string "iss" t
let sub t = get_string "sub" t
let exp t = get_number "exp" t
let nbf t = get_number "nbf" t
let iat t = get_number "iat" t
let jti t = get_string "jti" t

let aud t =
  let v = Jws.S.find_opt "aud" t.claims in
  let fn v =
    let open Jsont in
    let a = Json.decode string v in
    let b = Json.decode (list string) v in
    match (a, b) with Ok v, _ -> Some [ v ] | _, Ok v -> Some v | _ -> None
  in
  let v = Option.map fn v in
  Option.join v

let value t ~key codec =
  let v = Jws.S.find_opt key t.claims in
  let fn = Jsont.Json.decode codec in
  let v = Option.map fn v in
  let v = Option.map Result.to_option v in
  Option.join v

let validate_exp ?now claims =
  let v = Jws.S.find_opt "exp" claims in
  let v = Option.map (Jsont.Json.decode Jsont.number) v in
  let v = Option.map Result.to_option v in
  match (now, v) with
  | None, _ -> Ok ()
  | Some _, None -> Ok ()
  | Some _, Some None -> error_msgf "Invalid exp claim"
  | Some now, Some (Some exp) when now < exp -> Ok ()
  | Some _, Some (Some _) -> error_msgf "Token expired"

let validate_nbf ?now claims =
  let v = Jws.S.find_opt "nbf" claims in
  let v = Option.map (Jsont.Json.decode Jsont.number) v in
  let v = Option.map Result.to_option v in
  match (now, v) with
  | None, _ -> Ok ()
  | Some _, None -> Ok ()
  | Some _, Some None -> error_msgf "Invalid nbf claim"
  | Some now, Some (Some nbf) when now >= nbf -> Ok ()
  | Some _, Some (Some _) -> error_msgf "Token not yet valid"

let validate_aud ?aud claims =
  let v = Jws.S.find_opt "aud" claims in
  let fn v =
    let open Jsont in
    let a = Json.decode string v in
    let b = Json.decode (list string) v in
    match (a, b) with Ok v, _ -> Some [ v ] | _, Ok v -> Some v | _ -> None
  in
  let v = Option.map fn v in
  match (aud, v) with
  | None, (None | Some _) -> Ok ()
  | Some _, None -> error_msgf "Missing aud claim"
  | Some _, Some None -> error_msgf "Invalid aud claim"
  | Some aud, Some (Some auds) when List.mem aud auds -> Ok ()
  | Some _, Some (Some _) -> error_msgf "Audience mismatch"

let encode ?kid ?(extra = Jws.S.empty) pk c =
  let payload = Jsont_bytesrw.encode_string claims c |> Result.get_ok in
  let extra = Jws.S.add "typ" (str "JWT") extra in
  Jws.Compact.encode ?kid ~extra pk payload

let guard ~err fn = if fn () then Ok () else Error err

let decode ?now ?aud ?public compact =
  let* jws = Jws.Compact.decode ?public compact in
  let* claims =
    Jsont_bytesrw.decode_string claims (Jws.data jws)
    |> Result.map_error (fun _e -> `Msg "Invalid JWT claims")
  in
  let err = msgf "Invalid JWS type" in
  let* () =
    guard ~err @@ fun () ->
    match Jws.value jws ~key:"typ" Jsont.string with
    | Some "JWT" -> true
    | _ -> false
  in
  let* () = validate_exp ?now claims in
  let* () = validate_nbf ?now claims in
  let* () = validate_aud ?aud claims in
  Ok { jws; claims }
