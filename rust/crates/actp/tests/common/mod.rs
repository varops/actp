//! Helpers shared by the integration tests: the Go binaries they run against.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub struct Bins {
    pub go: PathBuf,
    pub agent: PathBuf,
    pub rust: PathBuf,
}

pub fn repo_root() -> PathBuf {
    canon(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.."))
}

/// `canonicalize` without Windows' `\\?\` prefix, which Go's path functions do not expect.
pub fn canon(p: &Path) -> PathBuf {
    let c = p.canonicalize().expect("canonicalize");
    let s = c.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC") => PathBuf::from(rest),
        _ => c,
    }
}

pub fn bins() -> &'static Bins {
    static BINS: OnceLock<Bins> = OnceLock::new();
    BINS.get_or_init(|| {
        let exe = if cfg!(windows) { ".exe" } else { "" };
        let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join("go-bin");
        std::fs::create_dir_all(&out).unwrap();
        let build = |env: &str, name: &str, pkg: &str| -> PathBuf {
            if let Some(p) = std::env::var_os(env).filter(|p| !p.is_empty()) {
                return PathBuf::from(p);
            }
            let target = out.join(format!("{name}{exe}"));
            let status = std::process::Command::new("go")
                .args(["build", "-o"])
                .arg(&target)
                .arg(pkg)
                .current_dir(repo_root())
                .env("CGO_ENABLED", "0")
                .status()
                .unwrap_or_else(|e| {
                    panic!("building {pkg} with go (set {env} to use a prebuilt binary): {e}")
                });
            assert!(status.success(), "go build {pkg} failed");
            target
        };
        Bins {
            go: build("ACTP_GO_BIN", "actp-go", "./cmd/actp"),
            agent: build(
                "ACTP_TESTAGENT_BIN",
                "actp-testagent",
                "./cmd/actp-testagent",
            ),
            rust: PathBuf::from(env!("CARGO_BIN_EXE_actp")),
        }
    })
}

pub fn hash(token: &str) -> String {
    use sha2::Digest;
    format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(token.as_bytes()))
    )
}

pub fn yaml_path(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "''"))
}
