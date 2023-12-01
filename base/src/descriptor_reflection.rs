// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides infrastructure for de/serializing descriptors embedded in Rust data structures.
//!
//! # Example
//!
//! ```
//! use serde_json::to_string;
//! use base::{
//!     FileSerdeWrapper, FromRawDescriptor, SafeDescriptor, SerializeDescriptors,
//!     deserialize_with_descriptors,
//! };
//! use tempfile::tempfile;
//!
//! let tmp_f = tempfile().unwrap();
//!
//! // Uses a simple wrapper to serialize a File because we can't implement Serialize for File.
//! let data = FileSerdeWrapper(tmp_f);
//!
//! // Wraps Serialize types to collect side channel descriptors as Serialize is called.
//! let data_wrapper = SerializeDescriptors::new(&data);
//!
//! // Use the wrapper with any serializer to serialize data is normal, grabbing descriptors
//! // as the data structures are serialized by the serializer.
//! let out_json = serde_json::to_string(&data_wrapper).expect("failed to serialize");
//!
//! // If data_wrapper contains any side channel descriptor refs
//! // (it contains tmp_f in this case), we can retrieve the actual descriptors
//! // from the side channel using into_descriptors().
//! let out_descriptors = data_wrapper.into_descriptors();
//!
//! // When sending out_json over some transport, also send out_descriptors.
//!
//! // For this example, we aren't really transporting data across the process, but we do need to
//! // convert the descriptor type.
//! let mut safe_descriptors = out_descriptors
//!     .iter()
//!     .map(|&v| unsafe { SafeDescriptor::from_raw_descriptor(v) });
//! std::mem::forget(data); // Prevent double drop of tmp_f.
//!
//! // The deserialize_with_descriptors function is used give the descriptor deserializers access
//! // to side channel descriptors.
//! let res: FileSerdeWrapper =
//!     deserialize_with_descriptors(|| serde_json::from_str(&out_json), safe_descriptors)
//!        .expect("failed to deserialize");
//! ```

use std::cell::Cell;
use std::cell::RefCell;
use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::ops::Deref;
use std::ops::DerefMut;
use std::panic::catch_unwind;
use std::panic::resume_unwind;
use std::panic::AssertUnwindSafe;

use serde::de;
use serde::de::Error;
use serde::de::Visitor;
use serde::ser;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use super::RawDescriptor;
use crate::descriptor::SafeDescriptor;

thread_local! {
    static DESCRIPTOR_DST: RefCell<Option<Vec<RawDescriptor>>> = Default::default();
}

/// Initializes the thread local storage for descriptor serialization. Fails if it was already
/// initialized without an intervening `take_descriptor_dst` on this thread.
fn init_descriptor_dst() -> Result<(), &'static str> {
    DESCRIPTOR_DST.with(|d| {
        let mut descriptors = d.borrow_mut();
        if descriptors.is_some() {
            return Err(
                "attempt to initialize descriptor destination that was already initialized",
            );
        }
        *descriptors = Some(Default::default());
        Ok(())
    })
}

/// Takes the thread local storage for descriptor serialization. Fails if there wasn't a prior call
/// to `init_descriptor_dst` on this thread.
fn take_descriptor_dst() -> Result<Vec<RawDescriptor>, &'static str> {
    match DESCRIPTOR_DST.with(|d| d.replace(None)) {
        Some(d) => Ok(d),
        None => Err("attempt to take descriptor destination before it was initialized"),
    }
}

/// Pushes a descriptor on the thread local destination of descriptors, returning the index in which
/// the descriptor was pushed.
//
/// Returns Err if the thread local destination was not already initialized.
fn push_descriptor(rd: RawDescriptor) -> Result<usize, &'static str> {
    DESCRIPTOR_DST.with(|d| {
        d.borrow_mut()
            .as_mut()
            .ok_or("attempt to serialize descriptor without descriptor destination")
            .map(|descriptors| {
                let index = descriptors.len();
                descriptors.push(rd);
                index
            })
    })
}

/// Serializes a descriptor for later retrieval in a parent `SerializeDescriptors` struct.
///
/// If there is no parent `SerializeDescriptors` being serialized, this will return an error.
///
/// For convenience, it is recommended to use the `with_raw_descriptor` module in a `#[serde(with =
/// "...")]` attribute which will make use of this function.
pub fn serialize_descriptor<S: Serializer>(
    rd: &RawDescriptor,
    se: S,
) -> std::result::Result<S::Ok, S::Error> {
    let index = push_descriptor(*rd).map_err(ser::Error::custom)?;
    se.serialize_u32(
        index
            .try_into()
            .map_err(|_| ser::Error::custom("attempt to serialize too many descriptors at once"))?,
    )
}

/// Wrapper for a `Serialize` value which will capture any descriptors exported by the value when
/// given to an ordinary `Serializer`.
///
/// This is the corresponding type to use for serialization before using
/// `deserialize_with_descriptors`.
///
/// # Examples
///
/// ```
/// use serde_json::to_string;
/// use base::{FileSerdeWrapper, SerializeDescriptors};
/// use tempfile::tempfile;
///
/// let tmp_f = tempfile().unwrap();
/// let data = FileSerdeWrapper(tmp_f);
/// let data_wrapper = SerializeDescriptors::new(&data);
///
/// // Serializes `v` as normal...
/// let out_json = serde_json::to_string(&data_wrapper).expect("failed to serialize");
/// // If `serialize_descriptor` was called, we can capture the descriptors from here.
/// let out_descriptors = data_wrapper.into_descriptors();
/// ```
pub struct SerializeDescriptors<'a, T: Serialize>(&'a T, Cell<Vec<RawDescriptor>>);

impl<'a, T: Serialize> SerializeDescriptors<'a, T> {
    pub fn new(inner: &'a T) -> Self {
        Self(inner, Default::default())
    }

    pub fn into_descriptors(self) -> Vec<RawDescriptor> {
        self.1.into_inner()
    }
}

impl<'a, T: Serialize> Serialize for SerializeDescriptors<'a, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        init_descriptor_dst().map_err(ser::Error::custom)?;

        // catch_unwind is used to ensure that init_descriptor_dst is always balanced with a call to
        // take_descriptor_dst afterwards.
        let res = catch_unwind(AssertUnwindSafe(|| self.0.serialize(serializer)));
        self.1.set(take_descriptor_dst().unwrap());
        match res {
            Ok(r) => r,
            Err(e) => resume_unwind(e),
        }
    }
}

thread_local! {
    static DESCRIPTOR_SRC: RefCell<Option<Vec<Option<SafeDescriptor>>>> = Default::default();
}

/// Sets the thread local storage of descriptors for deserialization. Fails if this was already
/// called without a call to `take_descriptor_src` on this thread.
///
/// This is given as a collection of `Option` so that unused descriptors can be returned.
fn set_descriptor_src(descriptors: Vec<Option<SafeDescriptor>>) -> Result<(), &'static str> {
    DESCRIPTOR_SRC.with(|d| {
        let mut src = d.borrow_mut();
        if src.is_some() {
            return Err("attempt to set descriptor source that was already set");
        }
        *src = Some(descriptors);
        Ok(())
    })
}

/// Takes the thread local storage of descriptors for deserialization. Fails if the storage was
/// already taken or never set with `set_descriptor_src`.
///
/// If deserialization was done, the descriptors will mostly come back as `None` unless some of them
/// were unused.
fn take_descriptor_src() -> Result<Vec<Option<SafeDescriptor>>, &'static str> {
    DESCRIPTOR_SRC.with(|d| {
        d.replace(None)
            .ok_or("attempt to take descriptor source which was never set")
    })
}

/// Takes a descriptor at the given index from the thread local source of descriptors.
//
/// Returns None if the thread local source was not already initialized.
fn take_descriptor(index: usize) -> Result<SafeDescriptor, &'static str> {
    DESCRIPTOR_SRC.with(|d| {
        d.borrow_mut()
            .as_mut()
            .ok_or("attempt to deserialize descriptor without descriptor source")?
            .get_mut(index)
            .ok_or("attempt to deserialize out of bounds descriptor")?
            .take()
            .ok_or("attempt to deserialize descriptor that was already taken")
    })
}

/// Deserializes a descriptor provided via `deserialize_with_descriptors`.
///
/// If `deserialize_with_descriptors` is not in the call chain, this will return an error.
///
/// For convenience, it is recommended to use the `with_raw_descriptor` module in a `#[serde(with =
/// "...")]` attribute which will make use of this function.
pub fn deserialize_descriptor<'de, D>(de: D) -> std::result::Result<SafeDescriptor, D::Error>
where
    D: Deserializer<'de>,
{
    struct DescriptorVisitor;

    impl<'de> Visitor<'de> for DescriptorVisitor {
        type Value = u32;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an integer which fits into a u32")
        }

        fn visit_u8<E: de::Error>(self, value: u8) -> Result<Self::Value, E> {
            Ok(value as _)
        }

        fn visit_u16<E: de::Error>(self, value: u16) -> Result<Self::Value, E> {
            Ok(value as _)
        }

        fn visit_u32<E: de::Error>(self, value: u32) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
            value.try_into().map_err(E::custom)
        }

        fn visit_u128<E: de::Error>(self, value: u128) -> Result<Self::Value, E> {
            value.try_into().map_err(E::custom)
        }

        fn visit_i8<E: de::Error>(self, value: i8) -> Result<Self::Value, E> {
            value.try_into().map_err(E::custom)
        }

        fn visit_i16<E: de::Error>(self, value: i16) -> Result<Self::Value, E> {
            value.try_into().map_err(E::custom)
        }

        fn visit_i32<E: de::Error>(self, value: i32) -> Result<Self::Value, E> {
            value.try_into().map_err(E::custom)
        }

        fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
            value.try_into().map_err(E::custom)
        }

        fn visit_i128<E: de::Error>(self, value: i128) -> Result<Self::Value, E> {
            value.try_into().map_err(E::custom)
        }
    }

    let index = de.deserialize_u32(DescriptorVisitor)? as usize;
    take_descriptor(index).map_err(D::Error::custom)
}

/// Allows the use of any serde deserializer within a closure while providing access to the a set of
/// descriptors for use in `deserialize_descriptor`.
///
/// This is the corresponding call to use deserialize after using `SerializeDescriptors`.
///
/// If `deserialize_with_descriptors` is called anywhere within the given closure, it return an
/// error.
pub fn deserialize_with_descriptors<F, T, E>(
    f: F,
    descriptors: impl IntoIterator<Item = SafeDescriptor>,
) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
    E: de::Error,
{
    let descriptor_src = descriptors.into_iter().map(Option::Some).collect();
    set_descriptor_src(descriptor_src).map_err(E::custom)?;

    // catch_unwind is used to ensure that set_descriptor_src is always balanced with a call to
    // take_descriptor_src afterwards.
    let res = catch_unwind(AssertUnwindSafe(f));

    // unwrap is used because set_descriptor_src is always called before this, so it should never
    // panic.
    let empty_descriptors = take_descriptor_src().unwrap();

    // The deserializer should have consumed every descriptor.
    debug_assert!(empty_descriptors.into_iter().all(|d| d.is_none()));

    match res {
        Ok(r) => r,
        Err(e) => resume_unwind(e),
    }
}

/// Module that exports `serialize`/`deserialize` functions for use with `#[serde(with = "...")]`
/// attribute. It only works with fields with `RawDescriptor` type.
///
/// # Examples
///
/// ```
/// use serde::{Deserialize, Serialize};
/// use base::RawDescriptor;
///
/// #[derive(Serialize, Deserialize)]
/// struct RawContainer {
///     #[serde(with = "base::with_raw_descriptor")]
///     rd: RawDescriptor,
/// }
/// ```
pub mod with_raw_descriptor {
    use serde::Deserializer;

    use super::super::RawDescriptor;
    pub use super::serialize_descriptor as serialize;
    use crate::descriptor::IntoRawDescriptor;

    pub fn deserialize<'de, D>(de: D) -> std::result::Result<RawDescriptor, D::Error>
    where
        D: Deserializer<'de>,
    {
        super::deserialize_descriptor(de).map(IntoRawDescriptor::into_raw_descriptor)
    }
}

/// Module that exports `serialize`/`deserialize` functions for use with `#[serde(with = "...")]`
/// attribute.
///
/// # Examples
///
/// ```
/// use std::fs::File;
/// use serde::{Deserialize, Serialize};
/// use base::RawDescriptor;
///
/// #[derive(Serialize, Deserialize)]
/// struct FileContainer {
///     #[serde(with = "base::with_as_descriptor")]
///     file: File,
/// }
/// ```
pub mod with_as_descriptor {
    use serde::Deserializer;
    use serde::Serializer;

    use crate::descriptor::AsRawDescriptor;
    use crate::descriptor::FromRawDescriptor;
    use crate::descriptor::IntoRawDescriptor;

    pub fn serialize<S: Serializer>(
        rd: &dyn AsRawDescriptor,
        se: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        super::serialize_descriptor(&rd.as_raw_descriptor(), se)
    }

    pub fn deserialize<'de, D, T>(de: D) -> std::result::Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromRawDescriptor,
    {
        super::deserialize_descriptor(de)
            .map(IntoRawDescriptor::into_raw_descriptor)
            .map(|rd| unsafe { T::from_raw_descriptor(rd) })
    }
}

/// A simple wrapper around `File` that implements `Serialize`/`Deserialize`, which is useful when
/// the `#[serde(with = "with_as_descriptor")]` trait is infeasible, such as for a field with type
/// `Option<File>`.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct FileSerdeWrapper(#[serde(with = "with_as_descriptor")] pub File);

impl fmt::Debug for FileSerdeWrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<File> for FileSerdeWrapper {
    fn from(file: File) -> Self {
        FileSerdeWrapper(file)
    }
}

impl From<FileSerdeWrapper> for File {
    fn from(f: FileSerdeWrapper) -> File {
        f.0
    }
}

impl Deref for FileSerdeWrapper {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for FileSerdeWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;
    use std::mem::ManuallyDrop;

    use serde::de::DeserializeOwned;
    use serde::Deserialize;
    use serde::Serialize;
    use tempfile::tempfile;

    use super::super::deserialize_with_descriptors;
    use super::super::with_as_descriptor;
    use super::super::with_raw_descriptor;
    use super::super::AsRawDescriptor;
    use super::super::FileSerdeWrapper;
    use super::super::FromRawDescriptor;
    use super::super::RawDescriptor;
    use super::super::SafeDescriptor;
    use super::super::SerializeDescriptors;

    fn deserialize<T: DeserializeOwned>(json: &str, descriptors: &[RawDescriptor]) -> T {
        let safe_descriptors = descriptors
            .iter()
            .map(|&v| unsafe { SafeDescriptor::from_raw_descriptor(v) });

        deserialize_with_descriptors(|| serde_json::from_str(json), safe_descriptors).unwrap()
    }

    #[test]
    fn raw() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct RawContainer {
            #[serde(with = "with_raw_descriptor")]
            rd: RawDescriptor,
        }
        // Specifically chosen to not overlap a real descriptor to avoid having to allocate any
        // descriptors for this test.
        let fake_rd = 5_123_457_i32;
        let v = RawContainer {
            rd: fake_rd as RawDescriptor,
        };
        let v_serialize = SerializeDescriptors::new(&v);
        let json = serde_json::to_string(&v_serialize).unwrap();
        let descriptors = v_serialize.into_descriptors();
        let res = deserialize(&json, &descriptors);
        assert_eq!(v, res);
    }

    #[test]
    fn file() {
        #[derive(Serialize, Deserialize)]
        struct FileContainer {
            #[serde(with = "with_as_descriptor")]
            file: File,
        }

        let v = FileContainer {
            file: tempfile().unwrap(),
        };
        let v_serialize = SerializeDescriptors::new(&v);
        let json = serde_json::to_string(&v_serialize).unwrap();
        let descriptors = v_serialize.into_descriptors();
        let v = ManuallyDrop::new(v);
        let res: FileContainer = deserialize(&json, &descriptors);
        assert_eq!(v.file.as_raw_descriptor(), res.file.as_raw_descriptor());
    }

    #[test]
    fn option() {
        #[derive(Serialize, Deserialize)]
        struct TestOption {
            a: Option<FileSerdeWrapper>,
            b: Option<FileSerdeWrapper>,
        }

        let v = TestOption {
            a: None,
            b: Some(tempfile().unwrap().into()),
        };
        let v_serialize = SerializeDescriptors::new(&v);
        let json = serde_json::to_string(&v_serialize).unwrap();
        let descriptors = v_serialize.into_descriptors();
        let v = ManuallyDrop::new(v);
        let res: TestOption = deserialize(&json, &descriptors);
        assert!(res.a.is_none());
        assert!(res.b.is_some());
        assert_eq!(
            v.b.as_ref().unwrap().as_raw_descriptor(),
            res.b.unwrap().as_raw_descriptor()
        );
    }

    #[test]
    fn map() {
        let mut v: HashMap<String, FileSerdeWrapper> = HashMap::new();
        v.insert("a".into(), tempfile().unwrap().into());
        v.insert("b".into(), tempfile().unwrap().into());
        v.insert("c".into(), tempfile().unwrap().into());
        let v_serialize = SerializeDescriptors::new(&v);
        let json = serde_json::to_string(&v_serialize).unwrap();
        let descriptors = v_serialize.into_descriptors();
        // Prevent the files in `v` from dropping while allowing the HashMap itself to drop. It is
        // done this way to prevent a double close of the files (which should reside in `res`)
        // without triggering the leak sanitizer on `v`'s HashMap heap memory.
        let v: HashMap<_, _> = v
            .into_iter()
            .map(|(k, v)| (k, ManuallyDrop::new(v)))
            .collect();
        let res: HashMap<String, FileSerdeWrapper> = deserialize(&json, &descriptors);

        assert_eq!(v.len(), res.len());
        for (k, v) in v.iter() {
            assert_eq!(
                res.get(k).unwrap().as_raw_descriptor(),
                v.as_raw_descriptor()
            );
        }
    }
}
