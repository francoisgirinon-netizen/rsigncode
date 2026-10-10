use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Sign and verify files with Authenticode.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign a file
    Sign { input: PathBuf, output: PathBuf },
    /// Verify the signatures of a file
    Verify { input: PathBuf },
    /// Write the data to sign for detached signing
    ExtractData { input: PathBuf, output: PathBuf },
    /// Attach a detached signature to a file
    AttachSignature {
        signature: PathBuf,
        input: PathBuf,
        output: PathBuf,
    },
    /// Write the signature of a signed file
    ExtractSignature { input: PathBuf, output: PathBuf },
    /// Remove the signature of a file
    RemoveSignature { input: PathBuf, output: PathBuf },
    /// Add a timestamp or an unauthenticated blob to a signed file
    Add { input: PathBuf, output: PathBuf },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let name = match cli.command {
        Command::Sign { .. } => "sign",
        Command::Verify { .. } => "verify",
        Command::ExtractData { .. } => "extract-data",
        Command::AttachSignature { .. } => "attach-signature",
        Command::ExtractSignature { .. } => "extract-signature",
        Command::RemoveSignature { .. } => "remove-signature",
        Command::Add { .. } => "add",
    };
    eprintln!("rsigncode: `{name}` is not implemented yet");
    ExitCode::FAILURE
}
