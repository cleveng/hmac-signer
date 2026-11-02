# HMAC SHA256 Signer

A lightweight HMAC-SHA256 signing and verification library written in Rust.

Supports both native Rust applications and WebAssembly (WASM), allowing the same implementation to be used in Rust, JavaScript, and TypeScript projects.

## Features

- HMAC-SHA256 signature generation.
- HMAC-SHA256 signature verification.
- Optional timestamp tolerance validation.
- Hexadecimal signature encoding.
- Constant-time signature verification.
- Native Rust library support.
- WebAssembly support.
- TypeScript type definitions through `wasm-bindgen`.

## Installation

### Rust

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
hmac-signer = "1.0.0"
```

### TypeScript / JavaScript

Install from npm:

```bash
pnpm add hmac-signer
```

Or:

```bash
npm install hmac-signer
```

## Usage

### Rust usage

Import the signer:

```rust
use hmac_signer::{HmacSha256Signer, HmacSha256SignerTrait};
```

#### Create a signer

```rust
let signer = HmacSha256Signer::new("your-secret-key");
```

#### Generate a signature

```rust
let timestamp = 1793352268_i64;
let body = br#"{"amount":100,"currency":"USD"}"#;

let signature = signer.sign(body, timestamp)?;

println!("Signature: {}", signature);
```

#### Verify a signature

```rust
let valid = signer.verify(
    body,
    timestamp,
    &signature,
    Some(300),
)?;

println!("Valid: {}", valid);
```

#### Disable timestamp validation

Pass `None` as the tolerance parameter:

```rust
let valid = signer.verify(
    body,
    timestamp,
    &signature,
    None,
)?;
```

### TypeScript / JavaScript usage

Import the signer:

```typescript
import { HmacSha256Signer } from 'hmac-signer';
```

#### Create a signer by typescript

```typescript
const signer = new HmacSha256Signer('your-secret-key');
```

#### Generate a signature by typescript

```typescript
const timestamp = BigInt(Math.floor(Date.now() / 1000));

const body = new TextEncoder().encode(
  JSON.stringify({
    amount: 100,
    currency: 'USD',
  })
);

const signature = signer.sign(body, timestamp);

console.log(signature);
```

#### Verify a signature by typescript

```typescript
const valid = signer.verify(body, timestamp, signature, 300n);

console.log(valid);
```

#### Disable timestamp validation by typescript

Pass `undefined`:

```typescript
const valid = signer.verify(body, timestamp, signature, undefined);
```

## Signature Format

The signature is generated using HMAC-SHA256.

The signed message format is:

```text
timestamp + "." + request_body
```

The signature generation algorithm:

```text
HMAC-SHA256(
    secret,
    timestamp + "." + request_body
)
```

The resulting digest is encoded as a lowercase hexadecimal string.

Example:

```text
timestamp = 1793352268
body      = {"amount":100}

message   = 1793352268.{"amount":100}

signature = HMAC-SHA256(secret, message)
```

## Timestamp Tolerance

The `verify` method accepts an optional `tolerance` parameter.

| Parameter   | Description                                       |
| ----------- | ------------------------------------------------- |
| `Some(300)` | Allow a timestamp difference of up to 300 seconds |
| `Some(60)`  | Allow a timestamp difference of up to 60 seconds  |
| `Some(0)`   | Require the timestamp to match the current second |
| `None`      | Disable timestamp validation                      |

If the timestamp is outside the allowed window, verification returns an error.

## API Reference

### HmacSha256Signer

Creates an HMAC-SHA256 signer.

```rust
HmacSha256Signer::new(secret: impl Into<String>) -> Self
```

### sign

Generates a signature.

```rust
fn sign(
    &self,
    body: &[u8],
    timestamp: Option<i64>,
) -> Result<(i64, String), anyhow::Error>
```

### verify

Verifies a signature.

```rust
fn verify(
    &self,
    body: &[u8],
    timestamp: i64,
    signature: &str,
    tolerance: Option<i64>,
) -> Result<bool, anyhow::Error>
```

## Building from Source

### Native Rust

```bash
cargo build --release -vvv
```

Run tests:

```bash
cargo test
```

### WebAssembly

Install the WASM target:

```bash
rustup target add wasm32-unknown-unknown
```

Install `wasm-pack`:

```bash
cargo install wasm-pack
```

Build the WASM package:

```bash
wasm-pack build --target bundler --release -- --features wasm

wasm-pack build \
  --target bundler \
  --release \
  --scope cakioe \
  --out-dir pkg \
  --out-name hmac_signer \
  -- --features wasm

cd pkg
npm stage publish --access public
```

The generated npm package will be available in the `pkg/` directory.

## Security Considerations

- Keep your secret key confidential.
- Always use HTTPS when transmitting signatures.
- Use timestamp validation to reduce replay attack risks.
- Verify the original raw request body instead of re-serialized JSON.
- Use sufficiently random secret keys.
- Implement replay protection when strict request uniqueness is required.

## License

MIT
