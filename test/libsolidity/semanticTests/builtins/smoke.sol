contract ClientReceipt {
}
// ====
// compileViaYul: also
// ----
// smoke_test0 ->
// smoke_test1: 1 -> 1
// smoke_test2: 2, 3 -> 2, 3
// smoke_test2: 2, 3, 4 -> FAILURE
// smoke_test0 ->
