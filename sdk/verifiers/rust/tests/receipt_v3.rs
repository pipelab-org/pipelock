// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use pipelock_verifier_rs::v3::{claims_input, verify_paths, Options};
use serde_json::Value;

#[test]
fn shared_v3_corpus() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/testdata/v3");
    if !corpus.is_dir() {
        return; // The published crate is independent of the monorepo corpus.
    }
    let mut vectors: Vec<_> = fs::read_dir(corpus)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("request.json").is_file())
        .collect();
    vectors.sort();
    let (mut projected, mut legacy, mut reordered, mut identical) = (0, 0, 0, 0);
    let mut failures = Vec::new();
    for vector in vectors {
        let read = |name: &str| fs::read(vector.join(name)).unwrap();
        let request: Value = serde_json::from_slice(&read("request.json")).unwrap();
        let mut paths: Vec<_> = request["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| vector.join(name.as_str().unwrap()))
            .collect();
        if request["legacy"] == true {
            assert!(!claims_input(&paths[0]).unwrap(), "{vector:?}");
            legacy += 1;
            continue;
        }

        let explicit_v3 = request["format"] == "v3";
        let options = Options {
            explicit_v3,
            ..serde_json::from_value(request).unwrap()
        };
        let verify = |paths: &[PathBuf]| {
            let temporary;
            let directory;
            let inputs = if options.directory {
                // The vector directory also contains the control JSON files.
                temporary = TestDirectory::new();
                for path in paths {
                    let target = temporary.0.join(path.strip_prefix(&vector).unwrap());
                    fs::create_dir_all(target.parent().unwrap()).unwrap();
                    fs::copy(path, target).unwrap();
                }
                directory = [temporary.0.clone()];
                &directory
            } else {
                paths
            };
            verify_paths(inputs, &options)
                .unwrap_or_else(|err| panic!("{}: {err}", vector.display()))
        };
        let name = vector.file_name().unwrap().to_string_lossy();
        let result = verify(&paths);
        let actual = result.projection();
        let expected = read("projection.json");
        if actual == expected.strip_suffix(b"\n").unwrap_or(&expected) {
            projected += 1;
        } else {
            failures.push(format!(
                "{name}\nexpected {}\nactual   {}",
                String::from_utf8_lossy(&expected),
                String::from_utf8_lossy(actual)
            ));
        }

        let full = result.json();
        if name == "g04-absent-max-write-error-pin" {
            let document: Value = serde_json::from_slice(full).unwrap();
            let parent = &document["histories"][0]["streams"][0];
            assert_eq!(parent["end"], "closed");
            assert_eq!(parent["tip"], parent["last"]);
            assert!(parent.get("unconfirmed_from").is_none());
        }
        let expected = read("expect.json");
        identical += usize::from(full == expected.strip_suffix(b"\n").unwrap_or(&expected));
        if paths.len() > 1 {
            paths.reverse();
            assert_eq!(full, verify(&paths).json(), "{name}");
            reordered += 1;
        }
    }
    eprintln!(
        "{projected} projections matched, {legacy} legacy detector cases, \
         {reordered} reversed file orders, {identical} full documents identical"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!((projected, legacy), (394, 5));
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "pipelock-receipt-v3-rs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn v3_help_does_not_open_evidence() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
        .args(["v3", "missing-evidence", "--help"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--key",
        "--allow-prefix",
        "--format",
        "--output",
        "--claims",
    ] {
        assert!(help.contains(flag), "missing {flag}");
    }
}

#[test]
fn cli_status_and_usage_errors() {
    use std::process::Command;

    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
            .args(args)
            .output()
            .unwrap()
    };
    let dir = TestDirectory::new();
    let path = dir.0.join("evidence.jsonl");
    fs::write(&path, b"not JSON\n").unwrap();
    let path = path.to_str().unwrap();

    let claim = cli(&["v3", "--claims", path]);
    assert_eq!(claim.status.code(), Some(0));
    assert_eq!(claim.stdout, b"false\n");
    assert!(claim.stderr.is_empty());

    for (args, code, finding) in [
        (vec!["v3"], 3, "NO_EVIDENCE"),
        (vec!["v3", "--format", "v3", path], 1, "LINE_LAYOUT"),
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(code));
        assert!(output.stderr.is_empty());
        assert_eq!(output.stdout.last(), Some(&b'\n'));
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(document["exit_code"], code);
        assert_eq!(document["findings"][0]["code"], finding);
    }

    let missing_path = dir.0.join("missing");
    let missing = missing_path.to_str().unwrap();
    for args in [
        vec!["v3", "--claims"],
        vec!["v3", "--claims", missing],
        vec!["v3", "--claims", path, path],
        vec!["v3", missing],
        vec!["v3", "--key", "deadbeef", path],
        vec!["v3", "--format", "v3", path, path],
        vec!["v3", "--format", "v3", dir.0.to_str().unwrap()],
        vec!["v3", "--output", "invalid", path],
        vec!["v3", "--expect-head", "invalid", path],
        vec!["v3", "--expect-seq", "invalid", path],
        vec!["v3", "--expect-lineage", "invalid", path],
        vec!["v3", "--accept-discontinuity", "invalid", path],
        vec!["v3", "--allow-partial-history", "invalid", path],
        vec!["v3", "--format", "v2", path],
        vec!["v3", "--allow-prefix=true", path],
        vec!["v3", "--unknown", path],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().lines().count(),
            1,
            "{args:?}"
        );
    }

    fs::File::create(path).unwrap().set_len(8_388_609).unwrap();
    let output = cli(&["receipt", path]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        output.stderr,
        b"read receipt: input exceeds 8388608 bytes\n"
    );
}

#[test]
fn registry_matches_public_contract() {
    let shared = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../receipt-v3/registry.json");
    if !shared.is_file() {
        return;
    }
    let shared: Value = serde_json::from_slice(&fs::read(shared).unwrap()).unwrap();
    let vendored: Value = serde_json::from_str(include_str!("../src/v3/registry.json")).unwrap();
    for section in [
        "profile",
        "layout",
        "limits",
        "objects",
        "conditions",
        "enums",
        "kinds",
        "findings",
        "normalization_profiles",
    ] {
        assert_eq!(vendored[section], shared[section], "{section}");
    }
}

#[test]
fn cli_accepts_independent_endpoint_requirements() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/testdata/v3/g01-valid-line");
    if !corpus.is_dir() {
        return;
    }
    let read = |name: &str| -> Value {
        serde_json::from_slice(&fs::read(corpus.join(name)).unwrap()).unwrap()
    };
    let request = read("request.json");
    let document = read("expect.json");
    let history = &document["histories"][0];
    let stream = &history["streams"][0];
    let id = stream["stream"].as_str().unwrap();
    let head = stream["tip"]["record"].as_str().unwrap();
    let seq = stream["tip"]["seq"].as_u64().unwrap();
    let key = request["keys"][0].as_str().unwrap();
    let file = corpus.join(request["inputs"][0].as_str().unwrap());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
        .args([
            "v3",
            "--key",
            key,
            "--output=projection",
            "--expect-lineage",
            history["lineage"].as_str().unwrap(),
            "--expect-head",
            &format!("{id}:{seq}:{head}"),
            "--expect-seq",
            &format!("{id}:{seq}"),
            "--",
        ])
        .arg(file)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["verdict"], "VALID");
    assert_eq!(result["accepted"].as_array().unwrap().len(), 3);
    assert!(result.get("findings").is_none());
}

#[test]
fn mixed_directory_reads_bare_v2_session() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/testdata/v3");
    if !corpus.is_dir() {
        return;
    }
    let copy = |vector: &str| {
        let vector = corpus.join(vector);
        let request: Value =
            serde_json::from_slice(&fs::read(vector.join("request.json")).unwrap()).unwrap();
        (
            vector.join(request["inputs"][0].as_str().unwrap()),
            request["keys"][0].as_str().unwrap().to_string(),
        )
    };
    let (v3_file, v3_key) = copy("g01-valid-line");
    let (v2_file, v2_key) = copy("g10-valid-raw-unrewritable-intent");
    let directory = TestDirectory::new();
    fs::copy(&v3_file, directory.0.join(v3_file.file_name().unwrap())).unwrap();
    let receipt = fs::read_to_string(v2_file).unwrap();
    fs::write(
        directory
            .0
            .join(format!("evidence-example.run.{}-0.jsonl", "a".repeat(32))),
        format!(
            "{{\"type\":\"evidence_receipt\",\"detail\":{}}}\n",
            receipt.trim()
        ),
    )
    .unwrap();
    let result = verify_paths(
        std::slice::from_ref(&directory.0),
        &Options {
            keys: vec![v2_key, v3_key],
            directory: true,
            ..Options::default()
        },
    )
    .unwrap();
    let document: Value = serde_json::from_slice(result.json()).unwrap();
    assert_eq!(document["legacy"][0]["format"], "evidence_v2", "{document}");
    assert_eq!(
        document["legacy"][0]["verdict"], "VALID PREFIX, END UNPROVEN",
        "{document}"
    );
    assert_eq!(
        document["findings"],
        serde_json::json!([{
            "class": "invalid", "code": "LEGACY_CHAIN_UNLISTED"
        }]),
        "{document}"
    );
}

#[test]
fn legacy_presentations_require_directory_scope() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/testdata/v3");
    if !corpus.is_dir() {
        return;
    }
    let inputs = |vector: &str| {
        let vector = corpus.join(vector);
        let request: Value =
            serde_json::from_slice(&fs::read(vector.join("request.json")).unwrap()).unwrap();
        vector.join(request["inputs"][0].as_str().unwrap())
    };
    let v3 = inputs("g01-valid-line");
    let (action, evidence) = (
        inputs("g10-action-receipt-v1-chain"),
        inputs("g10-valid-raw-unrewritable-intent"),
    );
    for legacy in [action, evidence] {
        let error = verify_paths(&[v3.clone(), legacy.clone()], &Options::default())
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("require directory scope"),
            "{error}"
        );
        let error = verify_paths(&[legacy], &Options::default()).err().unwrap();
        assert!(
            error.to_string().contains("legacy-only evidence"),
            "{error}"
        );
    }

    let recorder_vector = corpus.join("g09-writer-switch-legacy");
    let recorder = fs::read_dir(recorder_vector)
        .unwrap()
        .map(|file| file.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("evidence-")
        })
        .unwrap();
    let error = verify_paths(&[v3, recorder], &Options::default())
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("require directory scope"),
        "{error}"
    );
}

#[test]
fn cli_fault_on_unavailable_scratch() {
    let dir = TestDirectory::new();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
        .arg("v3")
        .env("TMPDIR", dir.0.join("missing"))
        .env("TMP", dir.0.join("missing"))
        .env("TEMP", dir.0.join("missing"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("record scratch file"));
}

#[test]
fn cutover_reports_invalid_legacy_restart_and_group_inventory() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/testdata/v3/g09-writer-switch-rotated-legacy");
    if !corpus.is_dir() {
        return;
    }
    let request: Value =
        serde_json::from_slice(&fs::read(corpus.join("request.json")).unwrap()).unwrap();
    let options: Options = serde_json::from_value(request.clone()).unwrap();
    let dir = TestDirectory::new();
    for file in request["inputs"].as_array().unwrap() {
        let file = file.as_str().unwrap();
        if file.starts_with("chain-link-") {
            fs::write(dir.0.join(file), b"{}").unwrap();
        } else {
            fs::copy(corpus.join(file), dir.0.join(file)).unwrap();
        }
    }
    fs::create_dir(dir.0.join("ael")).unwrap();
    fs::write(dir.0.join("receipt-group-unknown.json"), b"{}").unwrap();
    let result = verify_paths(std::slice::from_ref(&dir.0), &options).unwrap();
    let doc: Value = serde_json::from_slice(result.json()).unwrap();
    let rows = doc["legacy"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|row| row["verdict"] == "RESTART CONTINUITY FAILED"),
        "{doc}"
    );
    assert!(
        rows.iter().any(|row| row["verdict"] == "GROUP_INVALID"),
        "{doc}"
    );
    assert_eq!(doc["verdict"], "INVALID", "{doc}");
    assert!(
        doc["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["code"] == "LEGACY_INVALID"),
        "{doc}"
    );
}

#[test]
fn closed_stream_checks_a_torn_final_write() {
    let vector = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/testdata/v3/g01-valid-line");
    if !vector.is_dir() {
        return;
    }
    let request: Value =
        serde_json::from_slice(&fs::read(vector.join("request.json")).unwrap()).unwrap();
    let options: Options = serde_json::from_value(request.clone()).unwrap();
    let filename = request["inputs"][0].as_str().unwrap();
    let directory = TestDirectory::new();
    let path = directory.0.join(filename);
    assert!(claims_input(&path).unwrap());
    let mut receipt = fs::read(vector.join(filename)).unwrap();
    receipt.extend(b"torn tail");
    fs::write(&path, receipt).unwrap();
    let result = verify_paths(&[path], &options).unwrap();
    let doc: Value = serde_json::from_slice(result.json()).unwrap();
    assert_eq!(doc["findings"][0]["code"], "DATA_AFTER_CLOSE", "{doc}");
}

#[test]
fn caller_and_directory_reject_invalid_scope() {
    use pipelock_verifier_rs::v3::{Head, Position, Sequence};

    let result = verify_paths(
        &[],
        &Options {
            directory: true,
            ..Options::default()
        },
    );
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("exactly one directory"));

    let bad = "not-a-stream".to_owned();
    let options = [
        Options {
            expect_heads: vec![Head {
                stream: bad.clone(),
                position: Position {
                    record: String::new(),
                    seq: 0,
                },
            }],
            ..Options::default()
        },
        Options {
            expect_sequences: vec![Sequence {
                stream: bad,
                seq: 0,
            }],
            ..Options::default()
        },
    ];
    for option in &options {
        let err = verify_paths(&[], option).err().unwrap();
        assert!(err.to_string().starts_with("expected"));
    }

    let directory = TestDirectory::new();
    fs::create_dir(directory.0.join("invalid.receipt-v3.jsonl")).unwrap();
    let result = verify_paths(
        std::slice::from_ref(&directory.0),
        &Options {
            directory: true,
            ..Options::default()
        },
    );
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("not a regular file"));
}

#[test]
fn earlier_shard_cannot_have_a_torn_tail() {
    let vector = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/testdata/v3/g01-valid-line");
    if !vector.is_dir() {
        return;
    }
    let request: Value =
        serde_json::from_slice(&fs::read(vector.join("request.json")).unwrap()).unwrap();
    let options: Options = serde_json::from_value(request.clone()).unwrap();
    let filename = request["inputs"][0].as_str().unwrap();
    let wire = fs::read(vector.join(filename)).unwrap();
    let cut = wire.iter().position(|&b| b == b'\n').unwrap() + 1;
    let directory = TestDirectory::new();
    let open = directory.0.join(filename);
    let close = directory
        .0
        .join(filename.replace("-0000000000000000.", "-0000000000000001."));
    let mut first = wire[..cut].to_vec();
    first.extend_from_slice(b"torn");
    fs::write(&open, first).unwrap();
    fs::write(&close, &wire[cut..]).unwrap();
    let result = verify_paths(&[close, open], &options).unwrap();
    let doc: Value = serde_json::from_slice(result.json()).unwrap();
    assert_eq!(doc["findings"][0]["code"], "FILE_LAYOUT", "{doc}");
    assert_eq!(doc["exit_code"], 1);
}

#[test]
fn operational_recorder_read_failure_is_a_legacy_finding() {
    let vector = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/testdata/v3/g07-operational-logs-only");
    if !vector.is_dir() {
        return;
    }
    let request: Value =
        serde_json::from_slice(&fs::read(vector.join("request.json")).unwrap()).unwrap();
    let options: Options = serde_json::from_value(request.clone()).unwrap();
    let filename = request["inputs"][0].as_str().unwrap();
    let recorder = fs::read_to_string(vector.join(filename)).unwrap();
    let mut lines = recorder.lines();
    let mut line: Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    line["hash"] = Value::String("0".repeat(64));
    let damaged = std::iter::once(line.to_string())
        .chain(lines.map(str::to_owned))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let dir = TestDirectory::new();
    let valid = vector.with_file_name("g01-valid-line");
    let valid_input: Value =
        serde_json::from_slice(&fs::read(valid.join("request.json")).unwrap()).unwrap();
    let v3_filename = valid_input["inputs"][0].as_str().unwrap();
    fs::copy(valid.join(v3_filename), dir.0.join(v3_filename)).unwrap();
    let recorder = dir.0.join(filename);
    for bytes in [damaged.as_bytes(), b"\xff\n"] {
        fs::write(&recorder, bytes).unwrap();
        let result = verify_paths(std::slice::from_ref(&dir.0), &options).unwrap();
        let doc: Value = serde_json::from_slice(result.json()).unwrap();
        assert!(
            doc["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["code"] == "LEGACY_INVALID"),
            "damaged recorder did not produce LEGACY_INVALID"
        );
    }
}

#[test]
fn filename_claimed_missing_or_directory_inputs_are_input_errors() {
    use std::process::Command;

    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
            .args(args)
            .output()
            .unwrap()
    };
    let dir = TestDirectory::new();
    let good = dir.0.join("good.jsonl");
    fs::write(&good, b"{}\n").unwrap();
    let absent_v3 = dir.0.join("absent.receipt-v3.jsonl");
    let absent_v4 = dir.0.join("absent.receipt-v4.jsonl");
    let dir_v3 = dir.0.join("dir.receipt-v3.jsonl");
    fs::create_dir(&dir_v3).unwrap();

    let good_s = good.to_str().unwrap();
    let av3 = absent_v3.to_str().unwrap();
    let av4 = absent_v4.to_str().unwrap();
    let dv3 = dir_v3.to_str().unwrap();

    for args in [
        vec!["v3", "--claims", av3],
        vec!["v3", "--claims", av4],
        vec!["v3", "--claims", dv3],
        vec!["v3", av3],
        vec!["v3", av4],
        vec!["v3", good_s, av3],
        vec!["v3", good_s, av4],
        vec!["v3", good_s, dv3],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().lines().count(),
            1,
            "{args:?}"
        );
    }
}

#[test]
fn claims_accepts_double_dash_separator() {
    use std::process::Command;

    let dir = TestDirectory::new();
    // Run inside the directory so the operand itself starts with a dash.
    let cli = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_pipelock-verifier-rs"))
            .args(args)
            .current_dir(&dir.0)
            .output()
            .unwrap()
    };
    let v3_s = "-dash.receipt-v3.jsonl";
    let plain_s = "plain.jsonl";
    fs::write(dir.0.join(v3_s), b"{}\n").unwrap();
    fs::write(dir.0.join(plain_s), b"{}\n").unwrap();

    for (args, want) in [
        (vec!["v3", "--claims", "--", v3_s], b"true\n".as_slice()),
        (vec!["v3", "--claims", "--", plain_s], b"false\n".as_slice()),
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        assert_eq!(output.stdout, want, "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}");
    }

    for args in [
        vec!["v3", "--claims", "--"],
        vec!["v3", "--claims", "--", v3_s, plain_s],
        vec!["v3", "--claims", "--claims", v3_s],
        vec!["v3", "--claims", "--allow-prefix", v3_s],
        vec!["v3", "--claims=true", v3_s],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_profile_names_keep_their_claim() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    for (suffix, code) in [
        (".receipt-v4.jsonl", "UNKNOWN_PROFILE"),
        (".receipt-v3.jsonl", "FILE_LAYOUT"),
    ] {
        let dir = TestDirectory::new();
        let mut name = vec![0xff];
        name.extend_from_slice(suffix.as_bytes());
        let path = dir.0.join(OsString::from_vec(name));
        fs::write(
            &path, b"{}
",
        )
        .unwrap();
        assert!(claims_input(&path).unwrap(), "{suffix}");
        let options: Options =
            serde_json::from_value(serde_json::json!({"directory": true})).unwrap();
        let result = verify_paths(std::slice::from_ref(&dir.0), &options).unwrap();
        let document: Value = serde_json::from_slice(result.json()).unwrap();
        assert!(
            document["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| finding["code"] == code),
            "{suffix}: {document}"
        );
        assert_eq!(document["ignored_files"], 0, "{suffix}");
    }
}

#[test]
fn profile_claims_need_the_exact_filename_suffix() {
    let dir = TestDirectory::new();
    let path = dir.0.join(
        "other.receipt-v3.jsonl
",
    );
    fs::write(
        &path, b"{}
",
    )
    .unwrap();
    assert!(!claims_input(&path).unwrap());
}
