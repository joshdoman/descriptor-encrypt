# descriptor-encrypt

## Overview

A rust library and CLI tool that efficiently encrypts a Bitcoin wallet descriptor such that it can only be recovered by a set of keys that can spend the funds.

## Introduction

Bitcoin wallet descriptors encode the spending conditions for Bitcoin outputs, including keys, scripts, and other requirements. While descriptors are powerful tools for representing wallet structures, securely backing them up presents a challenge, especially for multi-signature and complex script setups.

This library encrypts any Bitcoin wallet descriptor in a way that directly mirrors the descriptor's spending conditions:

- If your wallet requires 2-of-3 keys to spend, it will require exactly 2-of-3 keys to decrypt
- If your wallet uses a complex miniscript policy like "Either 2 keys OR (a timelock AND another key)", the encryption follows this same logical structure, as if all timelocks and hashlocks are satisfied

## How It Works

The encryption mechanism works through several key innovations:

1. **Security Mirroring**: The descriptor's spending policy is analyzed and transformed into an equivalent encryption policy
2. **Recursive Secret Sharing**: Shamir Secret Sharing is applied recursively to split encryption keys following the script's threshold requirements
3. **Per-Key Encryption**: Each share is encrypted with the corresponding public key from the descriptor, ensuring only key holders can access them
4. **Compact Encoding**: Tag-based and LEB128 variable-length encoding is used to minimize the size of the encrypted data
5. **Payload Extraction**: Sensitive data, including the master fingerprints, public keys and xpubs, hashes, and timelocks, are extracted from the descriptor and encrypted
6. **Template Extraction**: The descriptor template and derivation paths remain visible in plaintext, allowing key holders to derive the necessary public keys to recover the full descriptor

## Usage

```rust
use std::str::FromStr;
use descriptor_encrypt::{encrypt, decrypt, get_template, get_origin_derivation_paths};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};

// Create a descriptor - a 2-of-3 multisig in this example
let desc_str = "wsh(multi(2,\
    03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,\
    036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,\
    02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29\
))";
let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();

// Encrypt the descriptor
let encrypted_data = encrypt(descriptor.clone()).unwrap();

// Encrypt the descriptor with full secrecy (best for privacy but slower when decrypting large descriptors)
let encrypted_data_with_full_secrecy = encrypt(descriptor.clone()).unwrap();

// Get a template descriptor with dummy keys, hashes, and timelocks
let template = get_template(&encrypted_data).unwrap();

// Extract only the derivation paths (useful for deriving xpubs)
let paths = get_origin_derivation_paths(&encrypted_data).unwrap();

// Later, decrypt with the keys (in this example, only the first two keys are provided,
// which is sufficient for a 2-of-3 multisig)
let pk0 = DescriptorPublicKey::from_str("03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7").unwrap();
let pk1 = DescriptorPublicKey::from_str("036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00").unwrap();
let first_two_keys = vec![pk0, pk1];

// Recover the original descriptor
let recovered_descriptor = decrypt(&encrypted_data, first_two_keys).unwrap();
assert_eq!(descriptor.to_string(), recovered_descriptor.to_string());
```

## Supported Descriptor Types

The library supports all standard Bitcoin descriptor types:

- Single-signature (`pkh`, `wpkh`, `tr` with internal key)
- Multi-signature (`sh(multi)`, `wsh(multi)`, `sh(wsh(multi))`, etc.)
- Taproot (`tr` with script trees)
- Full Miniscript expressions (all logical operations, timelocks, hashlocks, etc.)
- Nested combinations of the above

## Security Considerations

This library ensures:

- Only key holders can decrypt descriptors, following the descriptor's original threshold logic
- Encrypted data reveals nothing about the keys or spending conditions without decryption
- Template extraction is possible without exposing sensitive information
- The encryption is deterministic, producing the same output given the same descriptor

The security of the system relies on the security of ChaCha20(Poly1305) for encryption and Shamir Secret Sharing for threshold access control.

## Installation
To build the project, use the following command:
```bash
cargo build --release
```
The executable will be located at `target/release/descriptor-encrypt`.

## CLI Usage

`descriptor-encrypt` is a command-line tool for encrypting and decrypting Bitcoin descriptors.

### Commands

*   #### Encrypt a Descriptor
    Encrypts a Bitcoin descriptor and outputs the result as hex.
    ```bash
    ./target/release/descriptor-encrypt encrypt <DESCRIPTOR_STRING>
    ```
    **Arguments**:
    *   `<DESCRIPTOR_STRING>`: The Bitcoin descriptor string to encrypt.

    **Options**:
    *   `-w, --with-full-secrecy`: Enables full secrecy mode, which leaks no information about key inclusion without full decryption.

*   #### Decrypt a Descriptor
    Decrypts hex-encoded encrypted descriptor data using a set of public keys.
    ```bash
    ./target/release/descriptor-encrypt decrypt <DATA> -p <PKS>
    ```
    **Arguments**:
    *   `<DATA>`: hex-encoded encrypted data.
    *   `-p, --pks <PKS>`: Comma-separated list of public keys and xpubs (e.g., "pk1,pk2,pk3"). At least one public key must be provided.

*   #### Get Template Descriptor
    Retrieves a template descriptor (with dummy keys, hashes, and timelocks) from hex-encoded encrypted data.
    ```bash
    ./target/release/descriptor-encrypt get-template <DATA>
    ```
    **Arguments**:
    *   `<DATA>`: hex-encoded encrypted data.

*   #### Get Origin Derivation Paths
    Retrieves the origin derivation paths from hex-encoded encrypted data.
    ```bash
    ./target/release/descriptor-encrypt get-derivation-paths <DATA>
    ```
    **Arguments**:
    *   `<DATA>`: hex-encoded encrypted data.

## Library Usage

The core logic of `descriptor-encrypt` can also be used as a library in other Rust projects.

### Key Functions

**`encrypt(desc: Descriptor<DescriptorPublicKey>) -> Result<Vec<u8>>`**
    
* Encrypts a descriptor such that it can only be recovered by a set of keys with access to the funds.

**`encrypt_with_full_secrecy(desc: Descriptor<DescriptorPublicKey>) -> Result<Vec<u8>>`**

* Identical to `encrypt` except it leaks no information about key inclusion without full decryption.
* Provides maximum privacy but slower to decrypt, as we must try all possible combinations of shares and keys. This has a running time of $O((N+1)^K)$, where $N$ is the number of provided keys and $K$ is the number of shares.

**`decrypt(data: &[u8], pks: Vec<DescriptorPublicKey>) -> Result<Descriptor<DescriptorPublicKey>>`**

* Decrypts an encrypted descriptor using a set of public keys with access to the funds.

**`get_template(data: &[u8]) -> Result<Descriptor<DescriptorPublicKey>>`**

* Returns a template descriptor with dummy keys, hashes, and timelocks from the encrypted data.

**`get_origin_derivation_paths(data: &[u8]) -> Result<Vec<DerivationPath>>`**

* Returns the origin derivation paths found in the encrypted descriptor.

## Demo

<div align="center">
  <a href="https://www.youtube.com/watch?v=ankTi65Y-EA" target="_blank">
    <img src="https://img.youtube.com/vi/ankTi65Y-EA/maxresdefault.jpg" alt="descriptor-encrypt Demo" style="max-width: 100%; box-shadow: 0 0 10px rgba(0,0,0,0.4); border-radius: 5px;">
  </a>
</div>

## License
This project is licensed under the CC0-1.0 License.

## Author
Joshua Doman <joshsdoman@gmail.com>
