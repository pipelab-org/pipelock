// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use crate::util::Result;

use super::{input_error, wire::Record};

#[derive(Clone, Copy)]
pub(super) struct Location {
    pub seq: u64,
    offset: u64,
    len: usize,
    body_code: Option<&'static str>,
    after_damage: bool,
}

pub(super) struct Store {
    file: RefCell<File>,
    // Named files can be unlinked immediately on Unix. On Windows the handle
    // uses delete-on-close, so it also vanishes when verification is interrupted.
    positions: BTreeMap<String, BTreeMap<(u64, String), Location>>,
}

impl Store {
    pub(super) fn new() -> Result<Self> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|e| input_error(format!("name scratch file: {e}")))?;
        let path = std::env::temp_dir().join(format!("pipelock-v3-{}", hex::encode(random)));
        let file = scratch_file(path)?;
        Ok(Self {
            file: RefCell::new(file),
            positions: BTreeMap::new(),
        })
    }

    pub(super) fn insert(&mut self, record: &Record) -> Result<()> {
        let entries = self.positions.entry(record.stream.clone()).or_default();
        let key = (record.seq, record.id.clone());
        if let Some(found) = entries.get_mut(&key) {
            found.after_damage &= record.after_damage;
            return Ok(());
        }
        let data = serde_json::to_vec(record)
            .map_err(|e| input_error(format!("encode staged record: {e}")))?;
        let file = self.file.get_mut();
        let offset = file.seek(SeekFrom::End(0)).map_err(scratch_error)?;
        file.write_all(&data).map_err(scratch_error)?;
        entries.insert(
            key,
            Location {
                seq: record.seq,
                offset,
                len: data.len(),
                body_code: record.body_code,
                after_damage: record.after_damage,
            },
        );
        Ok(())
    }

    pub(super) fn records(
        &self,
        stream: &str,
        limit: u64,
    ) -> impl Iterator<Item = Result<Record>> + '_ {
        self.positions
            .get(stream)
            .into_iter()
            .flat_map(|records| records.values())
            .take_while(move |location| location.seq <= limit)
            .map(|location| self.read(*location))
    }

    fn read(&self, location: Location) -> Result<Record> {
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(location.offset))
            .map_err(scratch_error)?;
        let mut bytes = vec![0; location.len];
        file.read_exact(&mut bytes).map_err(scratch_error)?;
        let mut record: Record = serde_json::from_slice(&bytes)
            .map_err(|e| input_error(format!("decode staged record: {e}")))?;
        record.body_code = location.body_code;
        record.after_damage = location.after_damage;
        Ok(record)
    }

    pub(super) fn at(&self, stream: &str, seq: u64) -> Result<Option<Record>> {
        self.positions
            .get(stream)
            .and_then(|records| records.range((seq, String::new())..).next())
            .map(|(_, location)| *location)
            .filter(|location| location.seq == seq)
            .map(|location| self.read(location))
            .transpose()
    }
}

fn scratch_file(path: PathBuf) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0400_0000); // FILE_FLAG_DELETE_ON_CLOSE
    }
    let file = options.open(&path).map_err(scratch_error)?;
    #[cfg(unix)]
    fs::remove_file(&path).map_err(scratch_error)?;
    Ok(file)
}

fn scratch_error(error: std::io::Error) -> crate::util::VerifierError {
    input_error(format!("record scratch file: {error}"))
}
