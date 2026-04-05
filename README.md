# secret-manager

[![Crates.io](https://img.shields.io/crates/v/secret-manager.svg)](https://crates.io/crates/secret-manager)
[![docs.rs](https://docs.rs/secret-manager/badge.svg)](https://docs.rs/secret-manager)
[![codecov](https://codecov.io/gh/dnp1/secret-rotation-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/dnp1/secret-rotation-rs)

Distributed secret-key rotation and in-process caching for Rust services.

## Overview

`secret-manager` manages a ring buffer of versioned encryption keys shared across a cluster. Keys are generated, encrypted, and persisted by a **rotator**; they are fetched, decrypted, and cached in memory by a **syncer**. The two roles are intentionally decoupled so you can deploy them in whatever topology fits your system.

## Features

- **Key rotation** — periodic key generation with optimistic-locking so multiple instances converge safely
- **In-process ring buffer** — O(1) lookup by version, lock-free reads via atomics
- **Pluggable backends** — bring your own storage; built-in PostgreSQL backends via Diesel or SQLx
- **Pluggable encryptors** — `NoOpEncryptor`, `LocalEncryptor` (AES-256-GCM-SIV), or `KmsEncryptor` (AWS KMS)
- **Graceful shutdown** — `CancellationToken`-based, with `SecretManagerHandle::wait()` to drain tasks cleanly

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
secret-manager = { version = "0.1", features = ["pg-sqlx"] }
```

Available features:

| Feature | Description |
|---------|-------------|
| `pg-sqlx` | PostgreSQL backend using SQLx |
| `pg-diesel-async` | PostgreSQL backend using Diesel (async) |
| `aws-kms` | AWS KMS encryptor |
| `arc-swap` | Use `arc-swap::ArcSwap` for the ring buffer — wait-free reads, best under read-heavy workloads |
| `parking-lot` | Use `parking_lot::RwLock` instead of `std::sync::RwLock` — faster lock, no poison handling; ignored when `arc-swap` is also enabled |

By default `InMemorySecretGroup` uses `std::sync::RwLock`. Enable `arc-swap` for the lowest read latency (reads never block), or `parking-lot` for a lighter-weight lock without the overhead of poison checking.

See the [crate documentation](https://docs.rs/secret-manager) for full usage examples covering `SecretManager`, `KeyRotator`, and `SecretSyncer`.

## License

Licensed under MIT or Apache-2.0, at your option.
