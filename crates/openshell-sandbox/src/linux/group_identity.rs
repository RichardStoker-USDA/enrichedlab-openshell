// SPDX-License-Identifier: Apache-2.0

//! Answer identity-preserving setgroups requests without executing the syscall.

use std::fs;
use std::io;
use std::mem::size_of;

use super::seccomp_notify::{Notification, NotificationListener};
use super::task_memory;

/// Compare the notifying thread's supplementary groups to a private copy of
/// the requested list. The answer has no side effects on process credentials.
pub fn reapply_groups(listener: &NotificationListener, request: Notification) -> io::Result<()> {
    listener.validate_id(request.id)?;
    let denied = || io::Error::from_raw_os_error(libc::EPERM);
    let count = usize::try_from(request.args[0]).map_err(|_| denied())?;
    // Linux NGROUPS_MAX. Reject impossible counts before allocating or reading.
    if count > 65_536 {
        return Err(denied());
    }
    let status = fs::read(format!("/proc/{}/status", request.tid))?;
    let mut current = groups_from_status(&status)?;
    if current.len() != count {
        return Err(denied());
    }
    let mut copied = vec![0_u8; count * size_of::<libc::gid_t>()];
    let mut address = request.args[1];
    for chunk in copied.chunks_mut(task_memory::MAX_TASK_MEMORY_COPY) {
        listener.validate_id(request.id)?;
        task_memory::read_exact(request.tid, address, chunk)?;
        address = address
            .checked_add(u64::try_from(chunk.len()).map_err(|_| denied())?)
            .ok_or_else(denied)?;
    }
    let mut requested: Vec<_> = copied
        .chunks_exact(size_of::<libc::gid_t>())
        .map(|chunk| libc::gid_t::from_ne_bytes(chunk.try_into().expect("one gid_t")))
        .collect();
    current.sort_unstable();
    requested.sort_unstable();
    if requested != current {
        return Err(denied());
    }
    // respond_value revalidates the notification. Never continue setgroups:
    // the kernel must never consume the original caller-owned array.
    listener.respond_value(request.id, 0)
}

fn groups_from_status(status: &[u8]) -> io::Result<Vec<libc::gid_t>> {
    let invalid = || io::Error::from_raw_os_error(libc::EINVAL);
    let mut fields = status
        .split(|&b| b == b'\n')
        .filter_map(|line| line.strip_prefix(b"Groups:"));
    let groups = fields.next().ok_or_else(invalid)?;
    if fields.next().is_some() {
        return Err(invalid());
    }
    std::str::from_utf8(groups)
        .map_err(|_| invalid())?
        .split_ascii_whitespace()
        .map(|word| word.parse().map_err(|_| invalid()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_groups_are_parsed_independently_of_the_task_name() {
        assert_eq!(
            groups_from_status(b"Name:\t\xff\nGroups:\t19 4 4\n").unwrap(),
            [19, 4, 4]
        );
        assert!(groups_from_status(b"Groups:\t\n").unwrap().is_empty());
        for malformed in [
            &b"Name: test\n"[..],
            b"Groups: bad\n",
            b"Groups: 1\nGroups: 2\n",
        ] {
            assert!(groups_from_status(malformed).is_err());
        }
    }
}
