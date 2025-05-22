// Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// SPDX-License-Identifier: CC0-1.0

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::str::FromStr;

use descriptor_encrypt::bitcoin::bip32::DerivationPath;
use descriptor_encrypt::miniscript::{Descriptor, DescriptorPublicKey};

#[derive(Parser)]
#[clap(name = "descriptor-encrypt")]
#[clap(author = "Joshua Doman <joshsdoman@gmail.com>")]
#[clap(version = "0.1.0")]
#[clap(about = "CLI tool to encrypt and decrypt Bitcoin descriptors.", long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypts a Bitcoin descriptor, outputs hex (use -w or --with-full-secrecy for maximum privacy)
    Encrypt(EncryptArgs),
    /// Decrypts a hex-encoded encrypted descriptor
    Decrypt(DecryptArgs),
    /// Gets a template descriptor (dummy keys, fingerprints, hashes, and timelocks) from hex-encoded encrypted data
    GetTemplate(GetTemplateArgs),
    /// Gets origin derivation paths from hex-encoded encrypted data
    GetDerivationPaths(GetPathsArgs),
}

#[derive(Args)]
struct EncryptArgs {
    /// The Bitcoin descriptor string to encrypt
    descriptor: String,
    /// Enable full secrecy mode, which leaks no information about key inclusion without full decryption.
    #[clap(short, long)]
    with_full_secrecy: bool,
}

#[derive(Args)]
struct DecryptArgs {
    /// Hex-encoded encrypted data
    data: String,
    /// Comma-separated list of public keys and xpubs
    /// Example: "pk1,pk2,pk3"
    #[clap(short, long, value_delimiter = ',')]
    pks: Vec<String>,
}

#[derive(Args)]
struct GetTemplateArgs {
    /// Hex-encoded encrypted data
    data: String,
}

#[derive(Args)]
struct GetPathsArgs {
    /// Hex-encoded encrypted data
    data: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt(args) => handle_encrypt(args),
        Commands::Decrypt(args) => handle_decrypt(args),
        Commands::GetTemplate(args) => handle_get_template(args),
        Commands::GetDerivationPaths(args) => handle_get_derivation_paths(args),
    }
}

fn handle_encrypt(args: EncryptArgs) -> Result<()> {
    let desc = Descriptor::<DescriptorPublicKey>::from_str(&args.descriptor)
        .context("Failed to parse descriptor string")?;

    let encrypted_data = if args.with_full_secrecy {
        descriptor_encrypt::encrypt_with_full_secrecy(desc)
            .context("Encryption with full secrecy failed")?
    } else {
        descriptor_encrypt::encrypt(desc).context("Encryption failed")?
    };

    println!("{}", hex::encode(encrypted_data));

    Ok(())
}

fn handle_decrypt(args: DecryptArgs) -> Result<()> {
    let data_bytes =
        hex::decode(&args.data).context("Failed to decode hex data for encrypted payload")?;

    let mut pks = Vec::new();
    for pk_str in args.pks {
        let pk = DescriptorPublicKey::from_str(&pk_str)
            .with_context(|| format!("Failed to parse public key string: {}", pk_str))?;
        pks.push(pk);
    }

    let decrypted_desc =
        descriptor_encrypt::decrypt(&data_bytes, pks).context("Decryption failed")?;

    println!("{}", decrypted_desc);

    Ok(())
}

fn handle_get_template(args: GetTemplateArgs) -> Result<()> {
    let data_bytes = hex::decode(&args.data).context("Failed to decode hex data")?;

    let template_desc = descriptor_encrypt::get_template(&data_bytes)
        .context("Failed to get template descriptor")?;

    println!("{}", template_desc);

    Ok(())
}

fn handle_get_derivation_paths(args: GetPathsArgs) -> Result<()> {
    let data_bytes = hex::decode(&args.data).context("Failed to decode hex data")?;

    let paths: Vec<DerivationPath> = descriptor_encrypt::get_origin_derivation_paths(&data_bytes)
        .context("Failed to get origin derivation paths")?;

    if paths.is_empty() {
        println!("No origin derivation paths found in the descriptor.");
    } else {
        for path in paths {
            println!("{}", path);
        }
    }

    Ok(())
}
