# E7 live recovery correction

The previous script could observe the old API during shutdown and incorrectly
call this a successful restart. Ciphertext comparison did not demonstrate that
the evidence remained decryptable.

`scripts/ipfs_recovery.py:run_recovery` now verifies the repository API config,
listening Kubo PID, executable, daemon arguments and IPFS_PATH. It requires ten
distinct recursively pinned encrypted objects, decrypts them and checks recorded
SHA-256 and Keccak digests before shutdown. It waits for the old process to exit
and observes API unavailability before launching the same binary with the same
repository and arguments. It checks that the new PID owns the listener, then
decrypts and verifies every object again. API readiness and full retrieval
readiness use a monotonic clock starting before shutdown.

The replacement process remains running. State records PID, creation time and
repository to guard against PID reuse. Keys and plaintext never enter recovery
output. Failures are explicit, and analytical thesis assumptions remain separate.

Timing tests do not mutate services. A fresh end-to-end run must call the function
after registration with at least ten retained items having `eid`, `cid`, `key`
bytes, `sha`, and `keccak` (or original `raw` bytes to derive Keccak). These code
changes alone do not constitute a measured restart.
