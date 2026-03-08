# gsmutils

Small CLI utilities for Google Secret Manager.

## What it does

- Scan all enabled secret versions in a project for a value
- Fetch a specific secret (latest version by default)

## Requirements

- Rust (edition 2024 toolchain)
- Access to Google Secret Manager in your GCP project
- Application Default Credentials configured (for example, via `gcloud auth application-default login`)

## Build

```bash
cargo build --release
```

Binary output:

```text
target/release/gsmu
```

## Usage

Set your project ID once:

```bash
export PROJECT_ID="your-gcp-project-id"
```

Or pass it explicitly with `--project-id`.

### Scan for a value

Contains match (default behavior):

```bash
./target/release/gsmu scan --raw-secret "my-token-fragment"
```

Exact match:

```bash
./target/release/gsmu scan --raw-secret "full-secret-value" --exact
```

### Get a secret value

Latest version:

```bash
./target/release/gsmu get my-secret-name
```

Specific version:

```bash
./target/release/gsmu get my-secret-name --version 3
```

## Command help

```bash
./target/release/gsmu --help
./target/release/gsmu scan --help
./target/release/gsmu get --help
```
