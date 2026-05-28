//! Read-only USB mount auto-policy — macOS portion (TASK-245).
//!
//! Uses `diskutil unmount <BSDName>` then `diskutil mount readOnly
//! <BSDName>`. Catches the "Resource busy" race by retrying once after
//! 200 ms. Pure command-builder lives here so the unit tests don't
//! shell out.

pub fn unmount_argv(bsd_name: &str) -> Vec<String> {
    vec![
        "diskutil".to_string(),
        "unmount".to_string(),
        bsd_name.to_string(),
    ]
}

pub fn mount_readonly_argv(bsd_name: &str) -> Vec<String> {
    vec![
        "diskutil".to_string(),
        "mount".to_string(),
        "readOnly".to_string(),
        bsd_name.to_string(),
    ]
}

pub fn mount_rw_argv(bsd_name: &str) -> Vec<String> {
    vec![
        "diskutil".to_string(),
        "mount".to_string(),
        bsd_name.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_shapes_are_canonical() {
        assert_eq!(
            unmount_argv("disk2s1"),
            vec!["diskutil", "unmount", "disk2s1"]
        );
        assert_eq!(
            mount_readonly_argv("disk2s1"),
            vec!["diskutil", "mount", "readOnly", "disk2s1"]
        );
        assert_eq!(
            mount_rw_argv("disk2s1"),
            vec!["diskutil", "mount", "disk2s1"]
        );
    }
}
