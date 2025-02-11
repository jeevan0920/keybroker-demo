// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use keybroker_client::error::Error as KeybrokerError;
use keybroker_client::{CcaExampleToken, KeyBrokerClient, TsmAttestationReport};
use std::process;

/// Structure for parsing and storing the command-line arguments
#[derive(Clone, Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The address this client should connect to to request a key.
    #[arg(short, long, default_value = "http://127.0.0.1:8088")]
    endpoint: String,

    /// Use a CCA example token (instead of the TSM report)
    #[arg(short, long, default_value_t = false)]
    mock_evidence: bool,

    /// Use a pre-generated passport instead of live attestation
    #[arg(short, long)]
    passport: Option<String>,

    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Silence all output
    #[arg(short, long, default_value_t = false)]
    quiet: bool,

    /// The key name to use
    key_name: String,
}

fn main() {
    let args = Args::parse();

    stderrlog::new()
        .quiet(args.quiet)
        .verbosity(1 + usize::from(args.verbosity))
        .init()
        .unwrap();

    let client = KeyBrokerClient::new(&args.endpoint);

    let result = if let Some(passport) = args.passport {
        // Use passport-based verification if a passport is provided
        client.get_key_with_passport(&args.key_name, &passport)
    } else {
        // Otherwise use traditional challenge-response attestation
        if args.mock_evidence {
            client.get_key(&args.key_name, &CcaExampleToken {})
        } else {
            client.get_key(&args.key_name, &TsmAttestationReport {})
        }
    };

    // If the attestation was successful, print the key we got from the keybroker and exit with code 0.
    // If the attestation failed for genuine attestation related error, print the reason and exit with code 1.
    // For any other kind of error (crypto, network connectivity, ...), print an hopefully useful message to diagnose the issue and exit with code 2.
    let code = match result {
        Ok(key) => {
            let plainstring_key = String::from_utf8(key).unwrap();
            log::info!("Key retrieval success :-) ! The key returned from the keybroker is '{plainstring_key}'");
            0
        }

        Err(error) => {
            if let KeybrokerError::AttestationFailure(reason, details) = error {
                log::info!("Attestation/passport verification failure :-( ! {reason}: {details}");
                1
            } else {
                log::error!("The key request failed with: {error:?}");
                2
            }
        }
    };

    process::exit(code)
}
