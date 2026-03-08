pub mod gsm;

use std::num::NonZero;

use clap::Parser;
use futures::StreamExt;
use google_cloud_secretmanager_v1::client::SecretManagerService;

#[derive(clap::Parser)]
pub struct Program {
    /// Project ID to scan for secrets in. Can also be set via the `PROJECT_ID` environment variable.
    #[clap(long, env, global = true)]
    project_id: Option<String>,

    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Parser)]
pub enum Command {
    /// Scan for secrets containing a specific value
    Scan {
        #[clap(long, short = 's')]
        raw_secret: String,
        #[clap(long, short = 'E')]
        exact: bool,
    },

    /// Get a specific secret version
    Get {
        name: String,
        #[clap(long, short = 'V')]
        version: Option<NonZero<usize>>,
    },
}

#[tokio::main]
async fn main() {
    let cmd = Program::parse();

    let project_id = match cmd.project_id {
        Some(project_id) => project_id,
        None => {
            eprintln!(
                "Project ID must be provided via --project-id or PROJECT_ID environment variable"
            );
            std::process::exit(1);
        }
    };

    let client = SecretManagerService::builder()
        .build()
        .await
        .expect("Build GSM client");

    match cmd.command {
        Command::Scan { raw_secret, exact } => {
            handle_scan(&client, &project_id, &raw_secret, exact).await;
        }
        Command::Get { name, version } => {
            handle_get(&client, &project_id, &name, version).await;
        }
    }
}

async fn handle_scan(
    client: &SecretManagerService,
    project_id: &str,
    raw_secret: &str,
    exact: bool,
) {
    let mut stream = gsm::scan_stream(
        &client,
        gsm::ScanOptions {
            project_id: project_id.to_string(),
            raw_secret: raw_secret.as_bytes().to_vec(),
            scan_mode: if exact {
                gsm::ScanMode::Exact
            } else {
                gsm::ScanMode::Contains
            },
        },
    )
    .await
    .expect("Scaning secrets");

    let mut empty = true;

    while let Some(res) = stream.next().await {
        empty = false;
        let res = res.expect("Reading scan result");
        println!("Found secret: {}", res.name);
        println!("  Self link: {}", res.self_link);
        println!("  Version count: {}", res.version_count);
        println!("  Found in versions:");
        for version in res.found_in_versions {
            println!(
                "    - Version {} (latest: {})",
                version.number, version.latest
            );
        }
    }

    if empty {
        println!("No secrets found containing the specified value");
    }
}

async fn handle_get(
    client: &SecretManagerService,
    project_id: &str,
    name: &str,
    version: Option<NonZero<usize>>,
) {
    let get_result = gsm::access_secret(
        client,
        gsm::AccessSecretOptions {
            filter: if version.is_some() {
                gsm::AccessSecretFilter::Versions {
                    versions: vec![version.unwrap().get()],
                }
            } else {
                gsm::AccessSecretFilter::LatestOnly
            },
            name: name.to_string(),
            project_id: project_id.to_string(),
        },
    )
    .await;

    let secrets = match get_result {
        Ok(secrets) => secrets,
        Err(err) => {
            if gsm::is_notfound(&err) {
                eprintln!("Secret {name} not found");
            } else {
                eprintln!("Error accessing secret: {:?}", err);
            }
            return;
        }
    };

    if secrets.is_empty() {
        println!("No secret versions found for {}", name);
        return;
    }

    let secret = &secrets[0];
    println!("Secret: {}", secret.name);
    println!("  Self link: {}", secret.self_link);
    println!(
        "  Version: {} (latest: {})",
        secret.version.number, secret.version.latest
    );
    println!("  Data: {}", String::from_utf8_lossy(&secret.data));
}
