// SPDX-License-Identifier: Apache-2.0

//! Prepare numeric identity lookups from the workload image in a per-Pod volume.

use std::collections::HashSet;
use std::fs::{OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const MAX_FILE: u64 = 4 * 1024 * 1024;

pub fn prepare() -> io::Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    if uid == 0 || gid == 0 {
        return Err(io::Error::other(
            "pinned accounts require a non-root user and group",
        ));
    }
    let output = Path::new("/mnt/openshell-accounts");
    for (name, user) in [("passwd", true), ("group", false)] {
        let contents = read_accounts(Path::new("/"), name).map_err(|error| {
            io::Error::new(error.kind(), format!("read image /etc/{name}: {error}"))
        })?;
        let rendered = project(&contents, uid, gid, user)?;
        let mut file = tempfile::NamedTempFile::new_in(output)?;
        file.write_all(&rendered)?;
        file.as_file()
            .set_permissions(Permissions::from_mode(0o444))?;
        file.persist(output.join(name))?;
    }
    Ok(())
}

fn read_accounts(root: &Path, name: &str) -> io::Result<Vec<u8>> {
    let path = root.join("etc").join(name);
    match path.symlink_metadata() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    // Some images link /etc/passwd into /usr. Both trees are read-only in
    // this init. A link into a runtime mount or virtual filesystem is invalid.
    let source = path.canonicalize()?;
    if !(source.starts_with(root.join("etc")) || source.starts_with(root.join("usr"))) {
        return Err(io::Error::other(
            "account file points outside the image account trees",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(
            "image account database must be a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE || bytes.contains(&0) {
        return Err(io::Error::other("invalid image account database"));
    }
    Ok(bytes)
}

fn project(input: &[u8], uid: u32, gid: u32, user: bool) -> io::Result<Vec<u8>> {
    let id = if user { uid } else { gid };
    let mut names = HashSet::new();
    let mut exists = false;
    let mut output = Vec::with_capacity(input.len());
    for line in input.split_inclusive(|b| *b == b'\n') {
        let entry = line.strip_suffix(b"\n").unwrap_or(line);
        let fields: Vec<_> = entry.splitn(8, |b| *b == b':').collect();
        names.insert(fields[0]);
        let numeric = |value: &[u8]| std::str::from_utf8(value).ok()?.parse::<u32>().ok();
        if fields.get(2).and_then(|field| numeric(field)) == Some(id) {
            if fields.len() != if user { 7 } else { 4 } || fields[0].is_empty() {
                return Err(io::Error::other(
                    "invalid account entry for pinned identity",
                ));
            }
            exists = true;
            if user && numeric(fields[3]) != Some(gid) {
                let mut adjusted = fields;
                let primary = gid.to_string();
                adjusted[3] = primary.as_bytes();
                output.extend(adjusted.join(&b':'));
                if line.ends_with(b"\n") {
                    output.push(b'\n');
                }
                continue;
            }
        }
        output.extend_from_slice(line);
    }
    if exists {
        return Ok(output);
    }
    let mut name = String::from("agent");
    if names.contains(name.as_bytes()) {
        name = format!("agent-{id}");
        for suffix in 1.. {
            if !names.contains(name.as_bytes()) {
                break;
            }
            name = format!("agent-{id}-{suffix}");
        }
    }
    let entry = if user {
        format!("{name}:!:{uid}:{gid}::/sandbox:/bin/sh\n")
    } else {
        format!("{name}:!:{gid}:\n")
    };
    // A local synthetic identity precedes any image-supplied NSS compat entry.
    let mut rendered = entry.into_bytes();
    rendered.extend(output);
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_only_the_missing_ids_and_preserves_image_accounts() {
        let old = b"root:x:0:0::/root:/bin/sh\nsandbox:x:998:998::/sandbox:/bin/sh\n";
        let passwd = project(old, 1500, 1600, true).unwrap();
        assert_eq!(
            passwd,
            [b"agent:!:1500:1600::/sandbox:/bin/sh\n".as_slice(), old].concat()
        );
        assert_eq!(project(&passwd, 1500, 1600, true).unwrap(), passwd);
        assert_eq!(project(b"", 1500, 1600, false).unwrap(), b"agent:!:1600:\n");
    }

    #[test]
    fn keeps_existing_names_and_resolves_name_collisions() {
        let source = b"agent:x:998:998::/original:/bin/sh\nagent-1500:x:999:999::/:/bin/sh\n";
        assert!(
            project(source, 1500, 1500, true)
                .unwrap()
                .starts_with(b"agent-1500-1:!:1500:1500:")
        );
        let existing = b"user:x:1500:998:label:/home/user:/bin/sh";
        assert_eq!(
            project(existing, 1500, 1600, true).unwrap(),
            b"user:x:1500:1600:label:/home/user:/bin/sh"
        );
        assert_eq!(
            project(b"staff:x:1600:old", 1500, 1600, false).unwrap(),
            b"staff:x:1600:old"
        );
    }

    #[test]
    fn reads_image_symlinks_and_refuses_links_into_runtime_mounts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("etc")).unwrap();
        std::fs::create_dir(root.join("usr")).unwrap();
        assert!(read_accounts(&root, "passwd").unwrap().is_empty());
        std::fs::write(root.join("usr/passwd"), b"x").unwrap();
        std::os::unix::fs::symlink("../usr/passwd", root.join("etc/passwd")).unwrap();
        assert_eq!(read_accounts(&root, "passwd").unwrap(), b"x");
        std::fs::write(root.join("outside"), b"x").unwrap();
        std::os::unix::fs::symlink("../outside", root.join("etc/group")).unwrap();
        assert!(read_accounts(&root, "group").is_err());
    }
}
