// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::{gid_t, pid_t, uid_t};
use std::os::raw::{c_char, c_int, c_ulong};

/// Struct minijail is an opaque type inside libminijail.
/// See the minijail man page for a description of functions.
#[derive(Debug, Copy, Clone)]
pub enum minijail {}

#[link(name = "minijail")]
extern "C" {
    pub fn minijail_new() -> *mut minijail;
    pub fn minijail_change_uid(j: *mut minijail, uid: uid_t);
    pub fn minijail_change_gid(j: *mut minijail, gid: gid_t);
    pub fn minijail_set_supplementary_gids(j: *mut minijail, size: usize, list: *const gid_t);
    pub fn minijail_keep_supplementary_gids(j: *mut minijail);
    pub fn minijail_change_user(j: *mut minijail, user: *const c_char) -> c_int;
    pub fn minijail_change_group(j: *mut minijail, group: *const c_char) -> c_int;
    pub fn minijail_use_seccomp(j: *mut minijail);
    pub fn minijail_no_new_privs(j: *mut minijail);
    pub fn minijail_use_seccomp_filter(j: *mut minijail);
    pub fn minijail_set_seccomp_filter_tsync(j: *mut minijail);
    pub fn minijail_parse_seccomp_filters(j: *mut minijail, path: *const c_char);
    pub fn minijail_parse_seccomp_filters_from_fd(j: *mut minijail, fd: c_int);
    pub fn minijail_log_seccomp_filter_failures(j: *mut minijail);
    pub fn minijail_use_caps(j: *mut minijail, capmask: u64);
    pub fn minijail_capbset_drop(j: *mut minijail, capmask: u64);
    pub fn minijail_set_ambient_caps(j: *mut minijail);
    pub fn minijail_reset_signal_mask(j: *mut minijail);
    pub fn minijail_namespace_vfs(j: *mut minijail);
    pub fn minijail_namespace_enter_vfs(j: *mut minijail, ns_path: *const c_char);
    pub fn minijail_new_session_keyring(j: *mut minijail);
    pub fn minijail_skip_remount_private(j: *mut minijail);
    pub fn minijail_namespace_ipc(j: *mut minijail);
    pub fn minijail_namespace_net(j: *mut minijail);
    pub fn minijail_namespace_enter_net(j: *mut minijail, ns_path: *const c_char);
    pub fn minijail_namespace_cgroups(j: *mut minijail);
    pub fn minijail_close_open_fds(j: *mut minijail);
    pub fn minijail_namespace_pids(j: *mut minijail);
    pub fn minijail_namespace_user(j: *mut minijail);
    pub fn minijail_namespace_user_disable_setgroups(j: *mut minijail);
    pub fn minijail_uidmap(j: *mut minijail, uidmap: *const c_char) -> c_int;
    pub fn minijail_gidmap(j: *mut minijail, gidmap: *const c_char) -> c_int;
    pub fn minijail_remount_proc_readonly(j: *mut minijail);
    pub fn minijail_run_as_init(j: *mut minijail);
    pub fn minijail_write_pid_file(j: *mut minijail, path: *const c_char) -> c_int;
    pub fn minijail_inherit_usergroups(j: *mut minijail);
    pub fn minijail_use_alt_syscall(j: *mut minijail, table: *const c_char) -> c_int;
    pub fn minijail_add_to_cgroup(j: *mut minijail, path: *const c_char) -> c_int;
    pub fn minijail_enter_chroot(j: *mut minijail, dir: *const c_char) -> c_int;
    pub fn minijail_enter_pivot_root(j: *mut minijail, dir: *const c_char) -> c_int;
    pub fn minijail_fork(j: *mut minijail) -> pid_t;
    pub fn minijail_get_original_path(j: *mut minijail, chroot_path: *const c_char) -> *mut c_char;
    pub fn minijail_mount_dev(j: *mut minijail);
    pub fn minijail_mount_tmp(j: *mut minijail);
    pub fn minijail_mount_tmp_size(j: *mut minijail, size: usize);
    pub fn minijail_mount_with_data(
        j: *mut minijail,
        src: *const c_char,
        dest: *const c_char,
        type_: *const c_char,
        flags: c_ulong,
        data: *const c_char,
    ) -> c_int;
    pub fn minijail_mount(
        j: *mut minijail,
        src: *const c_char,
        dest: *const c_char,
        type_: *const c_char,
        flags: c_ulong,
    ) -> c_int;
    pub fn minijail_bind(
        j: *mut minijail,
        src: *const c_char,
        dest: *const c_char,
        writeable: c_int,
    ) -> c_int;
    pub fn minijail_preserve_fd(j: *mut minijail, parent_fd: c_int, child_fd: c_int) -> c_int;
    pub fn minijail_enter(j: *const minijail);
    pub fn minijail_run(
        j: *mut minijail,
        filename: *const c_char,
        argv: *const *const c_char,
    ) -> c_int;
    pub fn minijail_run_no_preload(
        j: *mut minijail,
        filename: *const c_char,
        argv: *const *const c_char,
    ) -> c_int;
    pub fn minijail_run_pid(
        j: *mut minijail,
        filename: *const c_char,
        argv: *const *const c_char,
        pchild_pid: *mut pid_t,
    ) -> c_int;
    pub fn minijail_run_pipe(
        j: *mut minijail,
        filename: *const c_char,
        argv: *const *const c_char,
        pstdin_fd: *mut c_int,
    ) -> c_int;
    pub fn minijail_run_pid_pipes(
        j: *mut minijail,
        filename: *const c_char,
        argv: *const *const c_char,
        pchild_pid: *mut pid_t,
        pstdin_fd: *mut c_int,
        pstdout_fd: *mut c_int,
        pstderr_fd: *mut c_int,
    ) -> c_int;
    pub fn minijail_run_pid_pipes_no_preload(
        j: *mut minijail,
        filename: *const c_char,
        argv: *const *const c_char,
        pchild_pid: *mut pid_t,
        pstdin_fd: *mut c_int,
        pstdout_fd: *mut c_int,
        pstderr_fd: *mut c_int,
    ) -> c_int;
    pub fn minijail_kill(j: *mut minijail) -> c_int;
    pub fn minijail_wait(j: *mut minijail) -> c_int;
    pub fn minijail_destroy(j: *mut minijail);
} // extern "C"
