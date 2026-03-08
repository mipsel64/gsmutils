mod types;

pub use types::*;

use std::pin::Pin;

use eyre::Context;
use futures::StreamExt;
use google_cloud_gax::paginator::ItemPaginator as _;
use google_cloud_secretmanager_v1::{client::SecretManagerService, model::secret_version::State};


pub async fn scan_stream(
    client: &SecretManagerService,
    opts: ScanOptions,
) -> eyre::Result<Pin<Box<dyn futures::Stream<Item = eyre::Result<ScanResult>>>>> {
    if opts.raw_secret.is_empty() {
        eyre::bail!("Secret to scan for cannot be empty");
    }

    if opts.project_id.is_empty() {
        eyre::bail!("Project ID cannot be empty");
    }

    let ScanOptions {
        project_id,
        raw_secret,
        scan_mode,
    } = opts;

    let (tx, rx) = async_channel::unbounded();
    let mut list = client
        .list_secrets()
        .set_parent(format!("projects/{}", project_id))
        .by_item();

    while let Some(item) = list.next().await.transpose()? {
        let project_id = project_id.clone();
        let raw_secret = raw_secret.clone();
        let tx = tx.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let name = basename(&item.name);
            let result = access_secret(
                &client,
                AccessSecretOptions {
                    name: name.to_string(),
                    project_id,
                    filter: AccessSecretFilter::All,
                },
            )
            .await;

            let secrets = match result {
                Ok(secrets) => secrets,
                Err(err) => {
                    let _ = tx.send(Err(err).wrap_err_with(|| "Accessing secret")).await;
                    return;
                }
            };

            let mut found_in_versions = vec![];
            let version_count = secrets.len();
            for secret in secrets {
                let found = match scan_mode {
                    ScanMode::Exact => secret.data == raw_secret,
                    ScanMode::Contains => secret
                        .data
                        .windows(raw_secret.len())
                        .any(|window| window == raw_secret.as_slice()),
                };
                if found {
                    found_in_versions.push(secret.version);
                }
            }

            if !found_in_versions.is_empty() {
                let res = ScanResult {
                    name: name.to_string(),
                    data: raw_secret,
                    self_link: item.name.clone(),
                    version_count,
                    found_in_versions,
                };
                if tx.send(Ok(res)).await.is_err() {
                    // Receiver dropped, stop processing
                    return;
                }
            }
        });
    }

    Ok(Box::pin(rx))
}

pub async fn scan(
    client: &SecretManagerService,
    opts: ScanOptions,
) -> eyre::Result<Vec<ScanResult>> {
    let mut ret = vec![];
    let mut stream = scan_stream(client, opts).await?;
    while let Some(result) = stream.next().await {
        ret.push(result?);
    }
    Ok(ret)
}

pub async fn access_secret(
    client: &SecretManagerService,
    opts: AccessSecretOptions,
) -> eyre::Result<Vec<Secret>> {
    if opts.name.is_empty() {
        eyre::bail!("Secret name cannot be empty");
    }

    if opts.project_id.is_empty() {
        eyre::bail!("Project ID cannot be empty");
    }

    let parent = format!("projects/{}/secrets/{}", opts.project_id, opts.name);

    if matches!(opts.filter, AccessSecretFilter::LatestOnly) {
        let secret = access_secret_version(client, &opts.project_id, &opts.name, None).await?;
        return Ok(vec![secret]);
    }

    let latest_version = get_latest_version_number(client, &parent)
        .await
        .wrap_err_with(|| "Getting latest vesrion number")?;

    // List all availale versions
    let mut list = client.list_secret_versions().set_parent(parent).by_item();
    let mut ret = vec![];
    while let Some(metadata) = list.next().await.transpose()? {
        let number: usize = basename(&metadata.name)
            .parse()
            .wrap_err_with(|| "Parsing version number from secret version name")?;

        if metadata.state != State::Enabled {
            continue;
        }

        if matches!(opts.filter, AccessSecretFilter::Versions { ref versions } if !versions.contains(&number))
        {
            continue;
        }

        ret.push(Secret {
            data: get_secret_value(client, &metadata.name)
                .await
                .wrap_err_with(|| "Getting secret data")?,
            name: basename(&opts.name).to_string(),
            self_link: metadata.name.clone(),
            version: Version {
                number,
                latest: number == latest_version,
            },
        });
    }

    Ok(ret)
}

pub async fn access_secret_version(
    client: &SecretManagerService,
    project_id: &str,
    name: &str,
    version: Option<usize>,
) -> eyre::Result<Secret> {
    if name.is_empty() {
        eyre::bail!("Secret name cannot be empty");
    }

    if project_id.is_empty() {
        eyre::bail!("Project ID cannot be empty");
    }

    let parent = format!("projects/{}/secrets/{}", project_id, name);

    let version_name = format!(
        "projects/{}/secrets/{}/versions/{}",
        project_id,
        name,
        version.map_or("latest".to_string(), |v| v.to_string())
    );

    let metadata = client
        .get_secret_version()
        .set_name(&version_name)
        .send()
        .await
        .wrap_err_with(|| "Getting secret version metadata")?;

    let version_numer: usize = if let Some(v) = version {
        v
    } else {
        let number: usize = basename(&metadata.name)
            .parse()
            .wrap_err_with(|| "Parsing version number from secret version name")?;
        number
    };

    let latest_number = get_latest_version_number(client, &parent)
        .await
        .wrap_err_with(|| "Getting latest version number")?;

    Ok(Secret {
        name: basename(name).to_string(),
        self_link: metadata.name.clone(),
        data: get_secret_value(client, &version_name)
            .await
            .wrap_err_with(|| "Getting secret data")?,
        version: Version {
            number: version_numer,
            latest: version_numer == latest_number,
        },
    })
}

async fn get_secret_value(
    client: &SecretManagerService,
    version_name: &str,
) -> eyre::Result<Vec<u8>> {
    let resp = client
        .access_secret_version()
        .set_name(version_name.to_string())
        .send()
        .await
        .wrap_err_with(|| "Getting secret version")?;
    let Some(payload) = resp.payload else {
        eyre::bail!("Secret version has no payload");
    };
    Ok(payload.data.to_vec())
}

async fn get_latest_version_number(
    client: &SecretManagerService,
    resource_name: &str,
) -> eyre::Result<usize> {
    let resp = client
        .get_secret_version()
        .set_name(format!("{}/versions/latest", resource_name))
        .send()
        .await
        .wrap_err_with(|| "Getting secret version metadata")?;
    let number: usize = basename(&resp.name)
        .parse()
        .wrap_err_with(|| "Parsing version number from secret version name")?;
    Ok(number)
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn is_notfound(err: &eyre::Report) -> bool {
    err.chain().any(|cause| {
        if let Some(gax_err) = cause.downcast_ref::<google_cloud_gax::error::Error>() {
            matches!(gax_err.status(), Some(status) if status.code == google_cloud_gax::error::rpc::Code::NotFound) 
        } else {
            false
        }
    })
}
