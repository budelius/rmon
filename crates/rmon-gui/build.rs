//! Embeds the exe icon, and stamps the binary with what produced it.
//!
//! The About dialog exists to answer one question — "am I running the build I
//! just made?" — which a version number alone cannot answer during
//! development, where every build is 0.1.0. The commit and the build time can.

use std::path::Path;
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/rmon.ico")
            .compile()
            .expect("embed rmon.ico as exe resource");
    }

    stamp_build_info();
}

fn stamp_build_info() {
    // Naming a rerun trigger opts out of cargo's default "rerun when anything
    // in the package changed", so every input that should freshen the stamp
    // has to be named. Workspace source directories are watched recursively;
    // `target/` deliberately is not, or the build would never settle.
    for watched in [
        "build.rs",
        "src",
        "../rmon-core/src",
        "../rmon-agent/src",
        "../../Cargo.lock",
        "../../CHANGELOG.md",
    ] {
        println!("cargo::rerun-if-changed={watched}");
    }
    for git in [".git/HEAD", ".git/index"] {
        let path = Path::new("../..").join(git);
        if path.exists() {
            println!("cargo::rerun-if-changed=../../{git}");
        }
    }

    println!(
        "cargo::rustc-env=RMON_BUILD_TIME={}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    );
    println!(
        "cargo::rustc-env=RMON_GIT_SHA={}",
        git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into())
    );
    // A dirty tree means the commit does not describe what was built, which
    // is worth saying out loud rather than implying a clean provenance.
    let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.trim().is_empty());
    println!("cargo::rustc-env=RMON_GIT_DIRTY={dirty}");
}

/// Runs a git command in the workspace root, or `None` if git is unavailable
/// or this is not a checkout — a source tarball still has to build.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(["-C", "../.."])
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
