// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements DT path handling.

use std::fmt;
use std::str::FromStr;

use crate::fdt::Error;
use crate::fdt::Result;

pub(crate) const PATH_SEP: &str = "/";

// Property name and offset containing a phandle value.
#[derive(Debug, PartialEq)]
pub(crate) struct PhandlePin(pub String, pub u32);

/// Device tree path.
#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct Path(String);

impl Path {
    // Verify path and strip unneeded characters.
    fn sanitize(path: &str) -> Result<String> {
        if path.is_empty() || !path.starts_with(PATH_SEP) {
            return Err(Error::InvalidPath(format!("{path} is not absolute")));
        } else if path == PATH_SEP {
            return Ok(path.into());
        }
        let path = path.trim_end_matches(PATH_SEP);
        if path.is_empty() || path.split(PATH_SEP).skip(1).any(|c| c.is_empty()) {
            Err(Error::InvalidPath("empty component in path".into()))
        } else {
            assert!(path.starts_with(PATH_SEP));
            Ok(path.into())
        }
    }

    // Create a new Path.
    pub(crate) fn new(path: &str) -> Result<Self> {
        Ok(Self(Self::sanitize(path)?))
    }

    // Push a new path segment, creating a new path.
    pub(crate) fn push(&self, subpath: &str) -> Result<Self> {
        let mut new_path = self.0.clone();
        if !new_path.ends_with(PATH_SEP) {
            new_path.push_str(PATH_SEP);
        }
        new_path.push_str(
            subpath
                .trim_start_matches(PATH_SEP)
                .trim_end_matches(PATH_SEP),
        );
        Ok(Self(Self::sanitize(&new_path)?))
    }

    // Iterate path segments.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &str> {
        self.0
            .split(PATH_SEP)
            .skip(if self.0 == PATH_SEP { 2 } else { 1 }) // Skip empty segments at start
    }

    // Return `true` if the path points to a child of `other`.
    pub(crate) fn is_child_of(&self, other: &Path) -> bool {
        let mut self_iter = self.iter();
        for elem in other.iter() {
            if self_iter.next() != Some(elem) {
                return false;
            }
        }
        true
    }
}

impl FromStr for Path {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Path::new(value)
    }
}

impl TryFrom<&str> for Path {
    type Error = Error;

    fn try_from(value: &str) -> Result<Path> {
        value.parse()
    }
}

impl TryFrom<String> for Path {
    type Error = Error;

    fn try_from(value: String) -> Result<Path> {
        value.parse()
    }
}

impl From<Path> for String {
    fn from(val: Path) -> Self {
        val.0 // Return path
    }
}

impl AsRef<str> for Path {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Parse a DT path string containing a node path and a property location (name and offset),
// eg '/path/to/node:prop1:4'.
pub(crate) fn parse_path_with_prop(value: &str) -> Result<(Path, PhandlePin)> {
    const PROP_SEP: char = ':';
    let mut elements = value.split(PROP_SEP);
    let path: Path = elements.next().unwrap().parse()?; // There will always be at least one.
    let prop = elements
        .next()
        .ok_or_else(|| Error::InvalidPath("missing property part".into()))?
        .to_owned();
    let off: u32 = elements
        .next()
        .ok_or_else(|| Error::InvalidPath("missing offset part".into()))?
        .parse()
        .map_err(|_| Error::InvalidPath("cannot parse offset as u32".into()))?;
    Ok((path, PhandlePin(prop, off)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdt_parse_path() {
        let l: Path = "/".parse().unwrap();
        assert!(l.iter().next().is_none());

        let l: Path = "/a/b/c".parse().unwrap();
        assert!(l.iter().eq(["a", "b", "c"]));

        let (path, prop) = parse_path_with_prop("/:a:0").unwrap();
        assert!(path.iter().next().is_none());
        assert_eq!(prop.0, "a");
        assert_eq!(prop.1, 0);

        let (path, prop) = parse_path_with_prop("/a/b/c:defg:1").unwrap();
        assert!(path.iter().eq(["a", "b", "c"]));
        assert_eq!(prop.0, "defg");
        assert_eq!(prop.1, 1);
    }

    #[test]
    fn fdt_path_parse_invalid() {
        assert!(Path::from_str("").is_err());
        assert!(Path::from_str("/a/b//c").is_err());
        assert!(Path::from_str("a/b").is_err());
        assert!(Path::from_str("a").is_err());
        parse_path_with_prop("a").expect_err("parse error");
        parse_path_with_prop("a::").expect_err("parse error");
        parse_path_with_prop("/a/b:c:").expect_err("parse error");
        parse_path_with_prop("/a/b:c:p:w").expect_err("parse error");
    }

    #[test]
    fn fdt_path_from_empty() {
        let mut path = Path::new("/").unwrap();
        assert!(path.iter().next().is_none());
        path = path.push("abc").unwrap();
        assert!(path.iter().eq(["abc",]));
        path = Path::new("/").unwrap();
        path = path.push("a/b/c").unwrap();
        assert!(path.iter().eq(["a", "b", "c"]));
    }

    #[test]
    fn fdt_path_create() {
        let mut path = Path::new("/a/b/c").unwrap();
        path = path.push("de").unwrap();
        assert!(path.iter().eq(["a", "b", "c", "de"]));
        path = path.push("f/g/h").unwrap();
        assert!(path.iter().eq(["a", "b", "c", "de", "f", "g", "h"]));
    }

    #[test]
    fn fdt_path_childof() {
        let path = Path::new("/aaa/bbb/ccc").unwrap();
        assert!(path.is_child_of(&Path::new("/aaa").unwrap()));
        assert!(path.is_child_of(&Path::new("/aaa/bbb").unwrap()));
        assert!(path.is_child_of(&Path::new("/aaa/bbb/ccc").unwrap()));
        assert!(!path.is_child_of(&Path::new("/aaa/bbb/ccc/ddd").unwrap()));
        assert!(!path.is_child_of(&Path::new("/aa").unwrap()));
        assert!(!path.is_child_of(&Path::new("/aaa/bb").unwrap()));
        assert!(!path.is_child_of(&Path::new("/d").unwrap()));
        assert!(!path.is_child_of(&Path::new("/d/e").unwrap()));
    }
}
