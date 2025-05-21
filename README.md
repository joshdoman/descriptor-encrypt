# descriptor-encrypt

## Overview
A rust library and CLI tool that efficiently encrypts a Bitcoin wallet descriptor such that it can only be recovered by a set of keys that can spend the funds.

## Features

`descriptor-encrypt` provides a robust mechanism for encrypting Bitcoin wallet descriptors with a security model that maps directly to the spending conditions of the descriptor itself. Here's what it does in detail:

### Threshold-Based Security Model
- **Threshold Authentication**: The descriptor's access control policy (e.g., m-of-n multisig) automatically determines the decryption threshold
- **Policy Mirroring**: Encryption security policy directly mirrors the descriptor's spending policy - if a wallet requires 2-of-3 keys to spend, it will also require 2-of-3 keys to decrypt

### Cryptographic Implementation
- **Deterministic Key Derivation**: Master encryption keys are derived deterministically from the descriptor's structure and content
- **Shamir Secret Sharing**: Implements recursive Shamir's Secret Sharing to split the master encryption key according to the descriptor's threshold requirements
- **Public Key-Based Access Control**: Each share is encrypted with the corresponding public key from the descriptor
- **ChaCha20-Poly1305 Encryption**: Uses modern, efficient encryption for both the payload (ChaCha20) and the key shares (ChaCha20Poly1305)

### Complex Descriptor Support
- **Full Descriptor Coverage**: Supports all Bitcoin descriptor types including:
  - Single-sig (wpkh, pkh)
  - Multi-sig (sorted, unsorted)
  - Complex scripts (Miniscript expressions)
  - Taproot descriptors with internal keys and script paths
- **Nested Threshold Handling**: Properly handles nested threshold conditions (e.g., an OR with AND conditions inside it)
- **Time and Hash Lock Support**: Maintains time locks and hash locks in the template while encrypting the specific values

### Template and Path Extraction
- **Origin Path Extraction**: Can extract derivation paths from encrypted descriptors without full decryption
- **Template Generation**: Can reveal the structure of an encrypted descriptor (with dummy values) without revealing the actual keys

### Compact Encoding
- **Tag-Based Encoding**: Uses tag-based encoding to minimize the size of the descriptor template
- **Variable-Length Encoding**: Uses LEB128 variable-length integers to minimize the size of the encrypted data

This ensures that a descriptor can only be decrypted by the same keys needed to spend from it, creating a direct correspondence between fund access and descriptor recovery.

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
    Encrypts a Bitcoin descriptor and outputs the result in Base64.
    ```bash
    ./target/release/descriptor-encrypt encrypt <DESCRIPTOR_STRING>
    ```
    **Arguments**:
    *   `<DESCRIPTOR_STRING>`: The Bitcoin descriptor string to encrypt.

*   #### Decrypt a Descriptor
    Decrypts Base64-encoded encrypted descriptor data using a set of public keys.
    ```bash
    ./target/release/descriptor-encrypt decrypt <BASE64_DATA> -p <PKS>
    ```
    **Arguments**:
    *   `<BASE64_DATA>`: Base64-encoded encrypted data.
    *   `-p, --pks <PKS>`: Comma-separated list of public keys and xpubs (e.g., "pk1,pk2,pk3"). At least one public key must be provided.

*   #### Get Template Descriptor
    Retrieves a template descriptor (with dummy keys, hashes, and timelocks) from Base64-encoded encrypted data.
    ```bash
    ./target/release/descriptor-encrypt get-template <BASE64_DATA>
    ```
    **Arguments**:
    *   `<BASE64_DATA>`: Base64-encoded encrypted data.

*   #### Get Origin Derivation Paths
    Retrieves the origin derivation paths from Base64-encoded encrypted data.
    ```bash
    ./target/release/descriptor-encrypt get-derivation-paths <BASE64_DATA>
    ```
    **Arguments**:
    *   `<BASE64_DATA>`: Base64-encoded encrypted data.

## Library Usage

The core logic of `descriptor-encrypt` can also be used as a library in other Rust projects.

### Key Functions

**`encrypt(desc: Descriptor<DescriptorPublicKey>) -> Result<Vec<u8>>`**
    
* Encrypts a descriptor such that it can only be recovered by a set of keys with access to the funds.

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