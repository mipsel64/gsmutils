#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub project_id: String,
    pub input: ScanInput,
    pub mode: ScanMode,
}

#[derive(Debug, Clone)]
pub enum ScanInput {
    RawScret(Vec<u8>),
    Name(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Exact,
    Contains,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub name: String,
    pub self_link: String,
    pub version_count: usize,
    pub found_in_versions: Vec<Version>,
}

#[derive(Debug, Clone, Copy)]
pub struct Version {
    pub number: usize,
    pub latest: bool,
}

#[derive(Debug, Clone)]
pub struct AccessSecretOptions {
    pub name: String,
    pub project_id: String,
    pub filter: AccessSecretFilter,
}

#[derive(Debug, Clone)]
pub enum AccessSecretFilter {
    All,
    LatestOnly,
    Versions { versions: Vec<usize> },
}

#[derive(Debug, Clone)]
pub struct Secret {
    pub name: String,
    pub self_link: String,
    pub data: Vec<u8>,
    pub version: Version,
}
