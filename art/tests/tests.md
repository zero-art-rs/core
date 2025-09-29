# Tests

Unit tests can be run with the next command:
```shell
cargo test --release -p art
```

Fuzz test can be run with the next command, by enabling `fuzz_test` feature:
```shell
RUST_LOG=debug cargo test fuzz_test --release -p art --features fuzz_test
```