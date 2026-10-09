//! `install.sh` until a release pipeline exists (RFC-0180 phase 1): nothing writes the release's
//! address into the script or publishes a seed list beside it, so the documented `curl | sudo bash`
//! stops. It stops saying how to go on, naming both `TALLY_RELEASE` and `TALLY_SEEDS` and how to
//! pass them through `sudo`, before it asks for root and with nothing installed. Run with no
//! network: a `curl` that cannot download stands in for a release that publishes no seed list.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;

type Result<T = ()> = std::result::Result<T, String>;

fn installer() -> Result<PathBuf> {
    std::env::var_os("TALLY_INSTALLER")
        .map(PathBuf::from)
        .ok_or_else(|| "TALLY_INSTALLER names install.sh (set by the build)".to_owned())
}

/// The installer's refusal (its stderr) run with `env` and `path` first on its PATH; an error if
/// it did not stop.
fn refusal(env: &[(&str, &str)], path: Option<&std::path::Path>) -> Result<String> {
    let mut command = Command::new("bash");
    command
        .arg(installer()?)
        .env_remove("TALLY_RELEASE")
        .env_remove("TALLY_SEEDS");
    for (name, value) in env {
        command.env(name, value);
    }
    if let Some(path) = path {
        let inherited = std::env::var("PATH").unwrap_or_default();
        command.env("PATH", format!("{}:{inherited}", path.display()));
    }
    let output = command.output().map_err(|error| error.to_string())?;
    if output.status.success() {
        return Err("the installer ran to its end".to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

/// It says how to pass both, through sudo, and that nothing was installed: never that it needs
/// root first.
fn says_how_to_pass_them(refusal: &str) -> Result {
    for needed in [
        "sudo TALLY_RELEASE=",
        "TALLY_SEEDS=",
        "Nothing was installed",
    ] {
        if !refusal.contains(needed) {
            return Err(format!("the refusal does not say {needed:?}: {refusal}"));
        }
    }
    if refusal.contains("run as root") {
        return Err(format!(
            "it asked for root before saying what to pass: {refusal}"
        ));
    }
    Ok(())
}

#[test]
fn an_installer_naming_no_release_says_how_to_pass_one_and_the_seeds() -> Result {
    let refusal = refusal(&[], None)?;
    assert!(refusal.contains("names no release"), "{refusal}");
    says_how_to_pass_them(&refusal)
}

#[test]
fn a_release_publishing_no_seed_list_says_how_to_pass_one() -> Result {
    let stub = std::env::temp_dir().join(format!("tally-install-{}", std::process::id()));
    std::fs::create_dir_all(&stub).map_err(|error| error.to_string())?;
    let curl = stub.join("curl");
    // curl's exit for an HTTP error (404), as for a release with no `seeds`.
    std::fs::write(&curl, "#!/bin/sh\nexit 22\n").map_err(|error| error.to_string())?;
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| error.to_string())?;
    let refusal = refusal(
        &[("TALLY_RELEASE", "https://release.example/tally/v0.1.0")],
        Some(&stub),
    )?;
    assert!(
        refusal.contains("https://release.example/tally/v0.1.0/seeds"),
        "{refusal}"
    );
    says_how_to_pass_them(&refusal)
}
