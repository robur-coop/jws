open OUnit2

let () =
  let tests = Tjwk.all_tests @ Tjws.all_tests in
  let suite = "suite" >::: tests in
  Mirage_crypto_rng_unix.use_default ();
  run_test_tt_main suite
