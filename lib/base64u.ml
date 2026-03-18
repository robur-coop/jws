let error_msgf fmt = Format.kasprintf (fun msg -> Error (`Msg msg)) fmt

let trim_leading_null = function
  | "" -> String.empty
  | str ->
      let idx = ref 0 in
      let len = String.length str in
      while !idx < len && str.[!idx] = '\000' do
        incr idx
      done;
      String.sub str !idx (len - !idx)

let rev str =
  let len = String.length str in
  String.init len (fun idx -> str.[len - succ idx])

let encode =
  let pad = false and alphabet = Base64.uri_safe_alphabet in
  Base64.encode_string ~pad ~alphabet

let decode str =
  let pad = false and alphabet = Base64.uri_safe_alphabet in
  Base64.decode ~pad ~alphabet str

let compose f g x = f (g x)
let ( $ ) = compose
let ( let* ) = Result.bind

module Z = struct
  let encode = encode $ trim_leading_null $ rev $ Z.to_bits

  let decode z64 =
    let* bits = decode z64 in
    let bits = rev bits in
    try Ok (Z.of_bits bits) with _ -> error_msgf "Invalid big number"
end
