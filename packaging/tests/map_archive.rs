//! The map image's archiver (`packaging/map/entrypoint.sh archive-pass`) packing a day's ACARS
//! lines: sorted by message time by the image's own `tally-acars-collect`, compressed into the
//! day's tar, and a day with gaps packed as partial, never before the collector's
//! [`PACKED_FROM`]. The script runs with its two fixed paths (the history volume and the image's
//! share directory) moved under a temporary directory.

use std::path::{Path, PathBuf};
use std::process::Command;

use tally_acars_collect::PACKED_FROM;

/// What the script runs beside the collector, from the host's PATH, as the image's Debian has it.
const TOOLS: &[&str] = &[
    "bash",
    "cut",
    "date",
    "du",
    "find",
    "gzip",
    "mkdir",
    "mv",
    "printf",
    "rm",
    "rmdir",
    "sha256sum",
    "sort",
    "sync",
    "tar",
];

type Result<T = ()> = std::result::Result<T, String>;

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| error.to_string())
}

fn runfile(variable: &str) -> Result<PathBuf> {
    let path = std::env::var_os(variable)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{variable} is set by the build"))?;
    io(std::fs::canonicalize(path))
}

fn write(path: &Path, contents: &str) -> Result {
    if let Some(dir) = path.parent() {
        io(std::fs::create_dir_all(dir))?;
    }
    io(std::fs::write(path, contents))
}

/// `name` from `archive`, decompressed when it is gzip.
fn member(archive: &Path, name: &str) -> Result<String> {
    let out = io(Command::new("tar")
        .arg("-xOf")
        .arg(archive)
        .arg(name)
        .output())?;
    if !out.status.success() {
        return Err(format!("{name} is not in {}", archive.display()));
    }
    if !name.ends_with(".gz") {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let mut gunzip = io(Command::new("gzip")
        .arg("-dc")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn())?;
    if let Some(mut stdin) = gunzip.stdin.take() {
        io(std::io::Write::write_all(&mut stdin, &out.stdout))?;
    }
    let out = io(gunzip.wait_with_output())?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Runs one pass of the archiver at `now`.
fn archive_pass(entrypoint: &Path, path: &str, now: u64) -> Result {
    let out = io(Command::new("bash")
        .arg(entrypoint)
        .args(["archive-pass", &now.to_string(), "0", "8"])
        .env("PATH", path)
        .output())?;
    if !out.status.success() {
        return Err(format!(
            "archive-pass failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[test]
fn a_days_acars_lines_are_packed_sorted_and_a_day_with_gaps_is_partial() -> Result {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned());
    for tool in TOOLS {
        if !std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()) {
            return Err(format!(
                "the archiver runs {tool}, which is not on PATH ({path})"
            ));
        }
    }
    let base = std::env::var_os("TEST_TMPDIR")
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join(format!("tally-map-archive-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let history = base.join("globe_history");
    let share = base.join("share");
    write(&share.join("ATTRIBUTION"), "attribution\n")?;
    write(&share.join("LICENSE-aircraft-database"), "license\n")?;

    let script = io(std::fs::read_to_string(runfile("TALLY_MAP_ENTRYPOINT")?))?;
    for fixed in [
        "GLOBE_HISTORY=/var/globe_history",
        "-C /usr/local/share/tally-map",
    ] {
        if !script.contains(fixed) {
            return Err(format!("entrypoint.sh no longer has `{fixed}`"));
        }
    }
    let script = script
        .replace(
            "GLOBE_HISTORY=/var/globe_history",
            &format!("GLOBE_HISTORY={}", history.display()),
        )
        .replace(
            "-C /usr/local/share/tally-map",
            &format!("-C {}", share.display()),
        );
    let entrypoint = base.join("tally-map");
    write(&entrypoint, &script)?;

    // 2026-10-20: whole, its lines as two receivers' batches arrived.
    let whole = history.join("2026/10/20");
    write(&whole.join("traces/ab/trace_full_abcdef.json"), "{}")?;
    let lines = [
        r#"{"kind":"acars","label":"H1","t":1792497600,"text":"b2"}"#,
        r#"{"kind":"acars","label":"H1","t":1792497700,"text":"b3"}"#,
        r#"{"icao":"A1B2C3","kind":"vdl2","label":"H1","t":1792497650}"#,
        r#"{"gs":"1","kind":"hfdl","label":"_d","t":1792497500}"#,
    ];
    // And a line cut short, which the sort drops.
    write(
        &whole.join("acars.jsonl"),
        &(lines.join("\n") + "\n" + r#"{"kind":"acars","label":"H1","t":17"# + "\n"),
    )?;
    // 2026-10-19: the collector missed some of it.
    let gapped = history.join("2026/10/19");
    write(&gapped.join("acars.jsonl"), &(lines[0].to_owned() + "\n"))?;
    write(&gapped.join("acars.gaps"), "1792454400 1792454460 down\n")?;
    // 2026-10-18: a pack cut short after its .gz was renamed and before its .jsonl was removed,
    // and one cut short while it wrote the .gz: the .jsonl is the day's, packed again.
    let twice = history.join("2026/10/18");
    write(&twice.join("acars.jsonl"), &(lines[0].to_owned() + "\n"))?;
    write(&twice.join("acars.jsonl.gz"), "a stale pack\n")?;
    write(&twice.join("acars.jsonl.gz.tmp"), "half a pack\n")?;
    // A sort a stopped container left.
    write(&history.join("archive/.sorting/run-1"), "left\n")?;

    // The collector, on PATH as the image installs it.
    let bin = base.join("bin");
    io(std::fs::create_dir_all(&bin))?;
    io(std::fs::copy(
        runfile("TALLY_ACARS_COLLECT")?,
        bin.join("tally-acars-collect"),
    ))?;
    let path = format!("{}:{path}", bin.display());
    let archive = history.join("archive");
    // 2026-10-21 00:00 UTC, the end of 10/20: a second before it is due, it is left as it is.
    let ended = 1_792_540_800;
    archive_pass(&entrypoint, &path, ended + PACKED_FROM - 1)?;
    assert!(archive.join("2026-10-19.partial.tar").exists());
    assert!(!archive.join("2026-10-20.tar").exists());
    assert!(whole.join("acars.jsonl").exists());
    archive_pass(&entrypoint, &path, ended + PACKED_FROM)?;

    let sorted = [lines[3], lines[0], lines[2], lines[1]];
    assert_eq!(
        member(&archive.join("2026-10-20.tar"), "./acars.jsonl.gz")?,
        sorted.join("\n") + "\n"
    );
    assert!(!archive.join("2026-10-20.partial.tar").exists());
    let partial = archive.join("2026-10-19.partial.tar");
    assert_eq!(
        member(&partial, "./acars.gaps")?,
        "1792454400 1792454460 down\n"
    );
    assert_eq!(
        member(&partial, "./acars.jsonl.gz")?,
        lines[0].to_owned() + "\n"
    );
    assert!(!archive.join("2026-10-19.tar").exists());
    let recovered = archive.join("2026-10-18.tar");
    assert_eq!(
        member(&recovered, "./acars.jsonl.gz")?,
        lines[0].to_owned() + "\n"
    );
    assert!(member(&recovered, "./acars.jsonl.gz.tmp").is_err());
    assert!(member(&recovered, "./acars.jsonl").is_err());
    assert!(!twice.join("acars.jsonl.gz.tmp").exists());
    // The sort's runs are gone, and were never beside the day.
    assert!(!archive.join(".sorting").exists());
    assert!(!whole.join("acars.jsonl").exists());
    let _ = std::fs::remove_dir_all(&base);
    Ok(())
}
