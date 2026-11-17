//! `actp serve` has no papers verifier, so it refuses org mode.

use std::process::Command;

#[test]
fn actp_serve_refuses_org_mode() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("org-serve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("actp.yaml");
    let d = dir.to_string_lossy().replace('\\', "/");
    std::fs::write(
        &cfg,
        format!(
            "server:\n  log_dir: '{d}/logs'\n  state_dir: '{d}/state'\n  tokens_file: '{d}/tokens.yaml'\n  workspaces:\n    - name: it\n      path: '{d}'\n  agents:\n    - id: a\n      command: x\n  org:\n    machine: laptop-a\n    require_grant: machines.operate\n    access:\n      agents: [a]\n"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_actp"))
        .args(["serve", "--config"])
        .arg(&cfg)
        .env("HOME", &dir)
        .env("USERPROFILE", &dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("org mode needs a papers verifier"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
