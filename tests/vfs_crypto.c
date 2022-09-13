// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

extern char* program_invocation_short_name;

int main(int argc, char** argv) {
  if (argc != 2) {
    printf("Usage: %s <path_to_directory>\n", program_invocation_short_name);
    return 1;
  }

  int dir = open(argv[1], O_DIRECTORY | O_CLOEXEC);
  if (dir < 0) {
    perror("Failed to open directory");
    return 1;
  }

  struct fscrypt_policy policy;
  int ret = ioctl(dir, FS_IOC_GET_ENCRYPTION_POLICY, &policy);
  if (ret < 0) {
    perror("FS_IOC_GET_ENCRYPTION_POLICY failed");
    return 1;
  }

  printf("File system encryption policy:\n");
  printf("\tversion = %#x\n", policy.version);
  printf("\tcontents_encryption_mode = %#x\n", policy.contents_encryption_mode);
  printf("\tfilenames_encryption_mode = %#x\n",
         policy.filenames_encryption_mode);
  printf("\tflags = %#x\n", policy.flags);
  printf("\tmaster_key_descriptor = 0x");
  for (int i = 0; i < FS_KEY_DESCRIPTOR_SIZE; ++i) {
    printf("%x", policy.master_key_descriptor[i]);
  }
  printf("\n");

  ret = ioctl(dir, FS_IOC_SET_ENCRYPTION_POLICY, &policy);
  if (ret < 0) {
    perror("FS_IOC_SET_ENCRYPTION_POLICY failed");
    return 1;
  }

  return 0;
}
