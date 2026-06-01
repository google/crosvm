// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;

/// Normalizes a path lexically by resolving `..` and `.` components.
/// Returns `Some(PathBuf)` containing an absolute path starting with `/`,
/// or `None` if the path is invalid (e.g., attempts to traverse above the root).
// TODO: Replace with `std::path::Path::normalize_lexically` once it is stabilized.
// Note the behavioral differences compared to `std::path::Path::normalize_lexically`:
// 1. The standard library's `normalize_lexically` returns a `Result` and errors on `..` components
//    that traverse above the root or starting point (e.g., `/../a` or `a/../../b`), which matches
//    this function's behavior of returning `None`.
// 2. This function always returns an absolute path starting with `/`, whereas the standard
//    library's `normalize_lexically` preserves relative paths.
fn normalize_lexically(path: &Path) -> Option<PathBuf> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {
                components.clear();
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                // Error if attempting to traverse above the root directory.
                components.pop()?;
            }
            std::path::Component::Normal(c) => {
                components.push(c);
            }
            _ => {}
        }
    }
    let mut normalized = PathBuf::from("/");
    for c in components {
        normalized.push(c);
    }
    Some(normalized)
}

/// Represents the access level for a path in the allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessLevel {
    /// No access allowed.
    None,
    /// Directory traversal (lookup) only access.
    /// Automatically granted to ancestor directories of allowed paths to act as a traversable
    /// pathway. This level is only granted automatically and cannot be configured manually.
    Traverse,
    /// Full read and write access.
    /// Granted to explicitly allowed paths and inherited by all their descendants.
    Full,
}

/// Represents a pre-calculated filter for directory entry validation.
#[derive(Debug, Clone)]
pub enum ReadDirFilter {
    /// Allows all directory entries (parent directory has Full access level).
    AllowAll,
    /// Allows only the specified entry names (parent directory has Traverse access level).
    AllowOnly(HashSet<OsString>),
    /// Denies all directory entries (parent directory is not accessible).
    DenyAll,
}

#[derive(Debug, Clone)]
struct TrieNode {
    access_level: AccessLevel,
    children: HashMap<OsString, TrieNode>,
    active_children_count: usize,
}

impl Default for TrieNode {
    fn default() -> Self {
        Self {
            access_level: AccessLevel::None,
            children: HashMap::new(),
            active_children_count: 0,
        }
    }
}

impl TrieNode {
    /// Returns true if this node is active (has an access level > None or has active children).
    fn is_active(&self) -> bool {
        self.access_level > AccessLevel::None || self.active_children_count > 0
    }

    /// Returns true if any descendant of this node has an active access level.
    #[allow(dead_code)]
    fn has_active_descendants(&self) -> bool {
        self.active_children_count > 0
    }
}

/// A hierarchical path allowlist that restricts file system access using a prefix tree (Trie).
///
/// The allowlist provides a high-performance, zero-overhead mechanism (when unused) to enforce
/// path-based access boundaries for FUSE/virtiofs devices.
///
/// # Public API Semantics
///
/// Access checks are divided into two distinct operations:
/// * **`is_accessible(path)`**: Checks if a path can be looked up or read (e.g., for `lookup`,
///   `readdir`, `open`).
///   - Returns `true` if the path is explicitly allowed, is a descendant of an allowed path, or is
///     an ancestor directory needed to reach an allowed path.
/// * **`is_writable(path)`**: Checks if a path can be modified (e.g., for `mkdir`, `create`,
///   `unlink`, `rename`).
///   - Returns `true` ONLY if the path is explicitly allowed or is a descendant of an allowed path.
///     **Ancestor directories are never writable.**
///
/// # Under the Hood: Access Levels & Inheritance
///
/// Internally, each path in the Trie is mapped to one of the following **`AccessLevel`**s:
/// * **`None` (Blocked)**: Complete restriction.
/// * **`Traverse` (Traversal Only - Non-inheritable)**: Granted to ancestor directories. It serves
///   strictly as a traversable pathway to reach allowed paths. Sibling paths under a `Traverse`
///   directory remain blocked.
/// * **`Full` (Full Access - Inheritable)**: Granted to explicitly allowed paths. This level is
///   automatically propagated to all descendant paths (e.g., allowing `/a/b` automatically grants
///   `Full` access to `/a/b/c/**`).
///
/// # Illustrative Scenarios
///
/// ## Scenario 1: When `/a/b` and `/a/b/c` are added to allowlist
///
/// Accessible:
///
/// - `/`, `/a`, `/a/b/**` (traversable down to `/a/b` and all its descendants)
///
/// Writable:
///
/// - `/a/b/**` (full write access inside `/a/b` and all its descendants)
///
/// ## Scenario 2: When access to `/a/b` is revoked (while keeping `/a/b/c` allowed)
///
/// To keep `/a/b/c` accessible, `/a/b` is automatically demoted to `Traverse` (Read-only traversal
/// pathway) rather than being blocked entirely:
///
/// Accessible:
///
/// - `/`, `/a`, `/a/b`, `/a/b/c/**` (traversal is allowed through `/a/b`, but sibling `/a/b/d` is
///   now blocked)
///
/// Writable:
///
/// - `/a/b/c/**` (write access is strictly restricted to the remaining allowed subtree)
#[derive(Debug, Clone, Default)]
pub struct PathAllowlist {
    root: TrieNode,
}

impl PathAllowlist {
    /// Creates a new `PathAllowlist`.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }

    /// Parses a normalized path into its components, ignoring non-normal components.
    fn parse_components(path: &Path) -> Vec<&OsStr> {
        path.components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// Adds a path to the allowed list. The path will be normalized before being added.
    /// Returns true if the path was valid and successfully added.
    /// Returns false if the path was invalid (e.g. traversed above root).
    #[allow(dead_code)]
    pub fn add_path<P: AsRef<Path>>(&mut self, path: P) -> bool {
        let normalized = match normalize_lexically(path.as_ref()) {
            Some(p) => p,
            None => return false,
        };
        let components = Self::parse_components(&normalized);

        // Adds a path component recursively.
        // Returns true if this node's active state changed from inactive to active.
        fn add_rec(node: &mut TrieNode, components: &[&OsStr]) -> bool {
            let was_active = node.is_active();

            if components.is_empty() {
                node.access_level = AccessLevel::Full;
                return !was_active && node.is_active();
            }

            let first = components[0];
            if node.access_level == AccessLevel::None {
                node.access_level = AccessLevel::Traverse;
            }

            let child = node.children.entry(first.to_os_string()).or_default();
            let child_active_changed = add_rec(child, &components[1..]);

            if child_active_changed {
                node.active_children_count += 1;
            }

            !was_active && node.is_active()
        }

        add_rec(&mut self.root, &components);
        true
    }

    /// Removes a path from the allowed list. The path will be normalized before removal.
    /// Returns true if the path was explicitly allowed and successfully removed (or demoted).
    /// Returns false if the path was not explicitly allowed.
    #[allow(dead_code)]
    pub fn remove_path<P: AsRef<Path>>(&mut self, path: P) -> bool {
        let normalized = match normalize_lexically(path.as_ref()) {
            Some(p) => p,
            None => return false,
        };
        let components = Self::parse_components(&normalized);

        // Removes a path component recursively.
        // Returns (removed, became_inactive):
        // - removed: true if the path was explicitly allowed and successfully removed/demoted.
        // - became_inactive: true if this node's active state changed from active to inactive.
        fn remove_rec(node: &mut TrieNode, components: &[&OsStr]) -> (bool, bool) {
            let was_active = node.is_active();

            if components.is_empty() {
                if node.access_level != AccessLevel::Full {
                    return (false, false);
                }

                if node.has_active_descendants() {
                    // If it has active descendants, demote it to Traverse to keep it as an
                    // ancestor.
                    node.access_level = AccessLevel::Traverse;
                } else {
                    node.access_level = AccessLevel::None;
                }
                let became_inactive = was_active && !node.is_active();
                return (true, became_inactive);
            }

            let first = components[0];
            let mut removed = false;

            if let Some(child) = node.children.get_mut(first) {
                let (child_removed, child_became_inactive) = remove_rec(child, &components[1..]);
                removed = child_removed;

                if child_became_inactive {
                    node.active_children_count -= 1;
                }

                // Clean up the child node if it is no longer active.
                if !child.is_active() {
                    node.children.remove(first);
                }
            }

            // Demote this ancestor node if it no longer has any active descendants.
            if node.access_level == AccessLevel::Traverse && !node.has_active_descendants() {
                node.access_level = AccessLevel::None;
            }

            let became_inactive = was_active && !node.is_active();
            (removed, became_inactive)
        }

        let (removed, _) = remove_rec(&mut self.root, &components);
        removed
    }

    /// Resolves the effective access level for a given path by traversing the Trie.
    fn get_access_level(&self, path: &Path) -> AccessLevel {
        let normalized = match normalize_lexically(path) {
            Some(p) => p,
            None => return AccessLevel::None,
        };
        let components = Self::parse_components(&normalized);

        let mut current = &self.root;
        if current.access_level == AccessLevel::Full {
            return AccessLevel::Full;
        }

        for comp in components {
            if let Some(next) = current.children.get(comp) {
                current = next;
                if current.access_level == AccessLevel::Full {
                    return AccessLevel::Full;
                }
            } else {
                return AccessLevel::None;
            }
        }

        current.access_level
    }

    /// Checks if a path is accessible (read/lookup).
    ///
    /// A path is accessible if it has at least `Traverse` access level.
    pub fn is_accessible<P: AsRef<Path>>(&self, path: P) -> bool {
        if !self.root.is_active() {
            return false;
        }
        self.get_access_level(path.as_ref()) >= AccessLevel::Traverse
    }

    /// Checks if a path is allowed to be written to.
    ///
    /// A path is writable only if it has `Full` access level.
    pub fn is_writable<P: AsRef<Path>>(&self, path: P) -> bool {
        if !self.root.is_active() {
            return false;
        }
        self.get_access_level(path.as_ref()) == AccessLevel::Full
    }

    /// Returns a `ReadDirFilter` for the given parent directory path.
    ///
    /// This pre-calculates the accessible entries within the directory, avoiding the need
    /// to perform full path resolution and Trie traversal for each individual entry during
    /// directory listing.
    pub fn get_read_dir_filter<P: AsRef<Path>>(&self, parent_path: P) -> ReadDirFilter {
        if !self.root.is_active() {
            return ReadDirFilter::DenyAll;
        }

        let normalized = match normalize_lexically(parent_path.as_ref()) {
            Some(p) => p,
            None => return ReadDirFilter::DenyAll,
        };
        let components = Self::parse_components(&normalized);

        let mut current = &self.root;
        if current.access_level == AccessLevel::Full {
            return ReadDirFilter::AllowAll;
        }

        for comp in components {
            if let Some(next) = current.children.get(comp) {
                current = next;
                if current.access_level == AccessLevel::Full {
                    return ReadDirFilter::AllowAll;
                }
            } else {
                return ReadDirFilter::DenyAll;
            }
        }

        match current.access_level {
            AccessLevel::Full => ReadDirFilter::AllowAll,
            AccessLevel::Traverse => {
                let allowed_entries = current
                    .children
                    .iter()
                    .filter(|(_, child)| child.is_active())
                    .map(|(name, _)| name.clone())
                    .collect::<HashSet<_>>();
                ReadDirFilter::AllowOnly(allowed_entries)
            }
            AccessLevel::None => ReadDirFilter::DenyAll,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_lexically() {
        assert_eq!(
            normalize_lexically(Path::new("/a/b/c")),
            Some(PathBuf::from("/a/b/c"))
        );
        assert_eq!(
            normalize_lexically(Path::new("/a/../b")),
            Some(PathBuf::from("/b"))
        );
        assert_eq!(
            normalize_lexically(Path::new("/a/./b")),
            Some(PathBuf::from("/a/b"))
        );
        assert_eq!(
            normalize_lexically(Path::new("/")),
            Some(PathBuf::from("/"))
        );
        assert_eq!(normalize_lexically(Path::new("")), Some(PathBuf::from("/")));
        assert_eq!(
            normalize_lexically(Path::new("a/b")),
            Some(PathBuf::from("/a/b"))
        );
        assert_eq!(
            normalize_lexically(Path::new("/a/b/../c/./d")),
            Some(PathBuf::from("/a/c/d"))
        );

        // Error cases (above root)
        assert_eq!(normalize_lexically(Path::new("..")), None);
        assert_eq!(normalize_lexically(Path::new("/..")), None);
        assert_eq!(normalize_lexically(Path::new("/a/../..")), None);
        assert_eq!(normalize_lexically(Path::new("/a/b/../../..")), None);
    }

    #[test]
    fn test_path_allowlist_empty() {
        let allowlist = PathAllowlist::new();
        // When empty, everything should be blocked
        assert!(!allowlist.is_accessible("/a/b"));
        assert!(!allowlist.is_writable("/a/b"));
    }

    #[test]
    fn test_path_allowlist_allowed_rules() {
        let mut allowlist = PathAllowlist::new();
        allowlist.add_path("/a/b");

        // Exact match
        assert!(allowlist.is_accessible("/a/b"));
        // Child path (inherited Full)
        assert!(allowlist.is_accessible("/a/b/c"));
        assert!(allowlist.is_accessible("/a/b/c/d"));
        // Ancestor path (explicit Traverse)
        assert!(allowlist.is_accessible("/a"));
        assert!(allowlist.is_accessible("/"));

        // Unrelated path
        assert!(!allowlist.is_accessible("/d"));
        assert!(!allowlist.is_accessible("/a/c"));
    }

    #[test]
    fn test_path_allowlist_writable_rules() {
        let mut allowlist = PathAllowlist::new();
        allowlist.add_path("/a/b");

        // Exact match
        assert!(allowlist.is_writable("/a/b"));
        // Child path
        assert!(allowlist.is_writable("/a/b/c"));

        // Ancestor path (NOT writable, only allowed for lookup)
        assert!(!allowlist.is_writable("/a"));
        assert!(!allowlist.is_writable("/"));

        // Unrelated path
        assert!(!allowlist.is_writable("/d"));
    }

    #[test]
    fn test_path_allowlist_multiple_paths() {
        let mut allowlist = PathAllowlist::new();
        allowlist.add_path("/a/b");
        allowlist.add_path("/c/d");

        assert!(allowlist.is_accessible("/a/b"));
        assert!(allowlist.is_accessible("/c/d"));
        assert!(allowlist.is_accessible("/a"));
        assert!(allowlist.is_accessible("/c"));

        assert!(!allowlist.is_accessible("/e"));
    }

    #[test]
    fn test_path_allowlist_remove_path() {
        let mut allowlist = PathAllowlist::new();
        allowlist.add_path("/a/b");
        assert!(allowlist.is_accessible("/a/b"));

        assert!(allowlist.remove_path("/a/b"));
        assert!(!allowlist.is_accessible("/a/b"));

        // Removing again should fail
        assert!(!allowlist.remove_path("/a/b"));
    }

    #[test]
    fn test_path_allowlist_remove_parent_keeps_child() {
        // Both parent and child are explicitly allowed. Removing the parent
        // should demote the parent to Traverse, but the child remains Full (accessible & writable).
        let mut allowlist = PathAllowlist::new();
        allowlist.add_path("/a/b");
        allowlist.add_path("/a/b/c");

        assert!(allowlist.is_accessible("/a/b"));
        assert!(allowlist.is_writable("/a/b"));
        assert!(allowlist.is_accessible("/a/b/c"));
        assert!(allowlist.is_writable("/a/b/c"));

        assert!(allowlist.remove_path("/a/b"));

        // Child remains fully accessible.
        assert!(allowlist.is_accessible("/a/b/c"));
        assert!(allowlist.is_writable("/a/b/c"));

        // Parent is demoted to Traverse (accessible but not writable).
        assert!(allowlist.is_accessible("/a/b"));
        assert!(!allowlist.is_writable("/a/b"));

        // Ancestors remain accessible.
        assert!(allowlist.is_accessible("/a"));
        assert!(allowlist.is_accessible("/"));

        // Removing the demoted parent again should fail as it is no longer explicitly allowed.
        assert!(!allowlist.remove_path("/a/b"));
    }

    #[test]
    fn test_path_allowlist_remove_child_inherited() {
        // Both parent and child are explicitly allowed. Removing the child
        // should not block the child because it still inherits Full access from the parent.
        let mut allowlist = PathAllowlist::new();
        allowlist.add_path("/a/b");
        allowlist.add_path("/a/b/c");

        assert!(allowlist.remove_path("/a/b/c"));

        // Parent remains fully accessible.
        assert!(allowlist.is_accessible("/a/b"));
        assert!(allowlist.is_writable("/a/b"));

        // Child remains accessible due to inheritance from the parent.
        assert!(allowlist.is_accessible("/a/b/c"));
        assert!(allowlist.is_writable("/a/b/c"));

        // Removing the child again should fail.
        assert!(!allowlist.remove_path("/a/b/c"));
    }

    #[test]
    fn test_path_allowlist_remove_one_of_multiple_children() {
        // Two sibling paths are allowed under a common ancestor. Removing one sibling
        // should block it, but the other sibling and the ancestor (Traverse) should remain.
        let mut allowlist = PathAllowlist::new();
        allowlist.add_path("/a/b/c");
        allowlist.add_path("/a/b/d");

        assert!(allowlist.is_accessible("/a/b/c"));
        assert!(allowlist.is_writable("/a/b/c"));
        assert!(allowlist.is_accessible("/a/b/d"));
        assert!(allowlist.is_writable("/a/b/d"));
        assert!(allowlist.is_accessible("/a/b"));
        assert!(!allowlist.is_writable("/a/b"));

        assert!(allowlist.remove_path("/a/b/c"));

        // Sibling remains fully accessible.
        assert!(allowlist.is_accessible("/a/b/d"));
        assert!(allowlist.is_writable("/a/b/d"));

        // Removed path is blocked.
        assert!(!allowlist.is_accessible("/a/b/c"));
        assert!(!allowlist.is_writable("/a/b/c"));

        // Common ancestor remains Traverse.
        assert!(allowlist.is_accessible("/a/b"));
        assert!(!allowlist.is_writable("/a/b"));

        // Removing the child again should fail.
        assert!(!allowlist.remove_path("/a/b/c"));
    }

    #[test]
    fn test_path_allowlist_remove_non_existent() {
        // Removing a non-existent path should not affect existing paths and should return false.
        let mut allowlist = PathAllowlist::new();
        allowlist.add_path("/a/b");

        assert!(!allowlist.remove_path("/a/c"));

        assert!(allowlist.is_accessible("/a/b"));
        assert!(allowlist.is_writable("/a/b"));
    }

    #[cfg(unix)]
    #[test]
    fn test_path_allowlist_non_utf8() {
        use std::os::unix::ffi::OsStrExt;

        let mut allowlist = PathAllowlist::new();
        // Create paths with invalid UTF-8 bytes (e.g., 0xff and 0xfe)
        let path_ff = OsStr::from_bytes(b"/a/b\xff");
        let path_fe = OsStr::from_bytes(b"/a/b\xfe");

        allowlist.add_path(Path::new(path_ff));

        // Exact match for allowed non-UTF8 path should succeed
        assert!(allowlist.is_accessible(Path::new(path_ff)));
        assert!(allowlist.is_writable(Path::new(path_ff)));

        // A different invalid UTF-8 path should be blocked (no false collision!)
        assert!(!allowlist.is_accessible(Path::new(path_fe)));
        assert!(!allowlist.is_writable(Path::new(path_fe)));
    }

    #[test]
    fn test_path_allowlist_invalid_paths() {
        let mut allowlist = PathAllowlist::new();

        // Adding invalid path should be ignored and return false
        assert!(!allowlist.add_path("/a/../.."));
        assert!(!allowlist.is_accessible("/"));

        // Removing invalid path should return false and not affect others
        assert!(allowlist.add_path("/a"));
        assert!(allowlist.is_accessible("/a"));
        assert!(!allowlist.remove_path("/a/../.."));
        assert!(allowlist.is_accessible("/a"));
    }

    #[test]
    fn test_path_allowlist_get_read_dir_filter() {
        let mut allowlist = PathAllowlist::new();

        // Empty allowlist should return DenyAll for any path
        assert!(matches!(
            allowlist.get_read_dir_filter("/"),
            ReadDirFilter::DenyAll
        ));
        assert!(matches!(
            allowlist.get_read_dir_filter("/a"),
            ReadDirFilter::DenyAll
        ));

        allowlist.add_path("/a/b");

        // Root directory is Traverse, should only allow "a"
        match allowlist.get_read_dir_filter("/") {
            ReadDirFilter::AllowOnly(set) => {
                assert_eq!(set.len(), 1);
                assert!(set.contains(OsStr::new("a")));
            }
            _ => panic!("expected AllowOnly"),
        }

        // /a is Traverse, should only allow "b"
        match allowlist.get_read_dir_filter("/a") {
            ReadDirFilter::AllowOnly(set) => {
                assert_eq!(set.len(), 1);
                assert!(set.contains(OsStr::new("b")));
            }
            _ => panic!("expected AllowOnly"),
        }

        // /a/b is Full, should return AllowAll
        assert!(matches!(
            allowlist.get_read_dir_filter("/a/b"),
            ReadDirFilter::AllowAll
        ));

        // Descendant of Full path should also return AllowAll
        assert!(matches!(
            allowlist.get_read_dir_filter("/a/b/c"),
            ReadDirFilter::AllowAll
        ));

        // Test redundant nodes under Full path
        let mut allowlist2 = PathAllowlist::new();
        allowlist2.add_path("/a/b/c");
        allowlist2.add_path("/a");
        // /a is Full, so /a/b should be AllowAll even if 'b' exists as Traverse in Trie
        assert!(matches!(
            allowlist2.get_read_dir_filter("/a/b"),
            ReadDirFilter::AllowAll
        ));

        // Unrelated path should return DenyAll
        assert!(matches!(
            allowlist.get_read_dir_filter("/d"),
            ReadDirFilter::DenyAll
        ));
    }
}
