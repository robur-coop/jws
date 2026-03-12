open OUnit2

let () =
  Mirage_crypto_rng_unix.use_default ();
  let tests = Tjwk.all_tests @ Tjws.all_tests @ Tjwt.all_tests in
  let suite = "suite" >::: tests in
  run_test_tt_main suite
