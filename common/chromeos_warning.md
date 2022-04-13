# Warning

These crates are shared with ChromeOS and used by other ChromeOS Rust projects. However since crosvm
is refactoring this part of the code heavily, ChromeOS has pinned the version of some of these
crates:

- cros_async
- data_model
- io_uring
- sync
- sys_util
- sys_util_core

Modifications made here will not be available for other ChromeOS projects.

If you are looking for a place to add new ChromeOS-specific utilities, please consider
[libchromeos-rs](https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/libchromeos-rs).

If modifications to these crates cannot be avoided, consider manually updating the revision in the
corresponding ebuild file, which may come with a significant need for refactoring.

Alternatively, for small changes consider adding a patch file into the corresponding ebuild file
instead.

See [b/229016539](http://b/229016539) for details.
