/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "internal.h"

#include <assert.h>
#include <string.h>
#include <errno.h>

#include <paths.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h> /* sysconf */
#include <fcntl.h>

#ifndef CPUSTATES
# define CPUSTATES 5U
#endif
#ifndef CP_USER
# define CP_USER 0
# define CP_NICE 1
# define CP_SYS 2
# define CP_IDLE 3
# define CP_INTR 4
#endif


int uv__platform_loop_init(uv_loop_t* loop) {
  // TODO(jgruber): Implement.
  // Based on epoll_create1 on linux. The epoll API allows monitoring fd's
  // for possible IO.
  return UV__ERR(EINVAL);
}

void uv__platform_loop_delete(uv_loop_t* loop) {
  // TODO(jgruber): Implement.
}

void uv__set_process_title(const char* title) {
  // TODO(jgruber): Implement.
  // Sets the thread / process name. Based on prctl(PR_SET_NAME, ...) on linux.
}

int uv_exepath(char* buffer, size_t* size) {
  // TODO(jgruber): Implement.
  // Based on readlink. The full path of the current executable.

  if (buffer == NULL || size == NULL || *size == 0)
    return UV_EINVAL;

  const char* fake_path = "TODO";
  const int fake_path_length = strlen(fake_path);

  if (*size < fake_path_length + 1) return UV_EINVAL;

  *size = fake_path_length;
  memcpy(buffer, fake_path, *size);
  buffer[*size] = '\0';

  return 0;
}

uint64_t uv_get_free_memory(void) {
  // TODO(jgruber): Implement.
  // Based on sysinfo, fetches RAM usage information.
  return UV__ERR(EINVAL);
}


uint64_t uv_get_total_memory(void) {
  // TODO(jgruber): Implement.
  // Based on sysinfo, fetches RAM usage information.
  return UV__ERR(EINVAL);
}


void uv_loadavg(double avg[3]) {
  // TODO(jgruber): Implement.
  // Based on sysinfo.
}


int uv_resident_set_memory(size_t* rss) {
  // TODO(jgruber): Implement.
  // Reads from /proc/ on linux.
  return UV__ERR(EINVAL);
}

uint64_t uv__hrtime(uv_clocktype_t type) {
  // TODO(jgruber): Implement.
  // Calls clock_gettime on linux.
  return 0;
}

int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  // TODO(jgruber): Implement.
  // Conditionally implemented (HAVE_IFADDRS_H). Based on getifaddrs.
  *count = 0;
  *addresses = NULL;
  return UV_ENOSYS;
}

void uv_free_interface_addresses(uv_interface_address_t* addresses,
  int count) {
  int i;

  for (i = 0; i < count; i++) {
    uv__free(addresses[i].name);
  }

  uv__free(addresses);
}

void uv__io_poll(uv_loop_t* loop, int timeout) {
  // TODO(jgruber): Implement.
  // See also: uv__platform_loop_init.
}

void uv__platform_invalidate_fd(uv_loop_t* loop, int fd) {
  // TODO(jgruber): Implement.
  // See also: uv__platform_loop_init.
}

int uv_uptime(double* uptime) {
  int r;
  struct timespec sp;
  r = clock_gettime(CLOCK_MONOTONIC, &sp);
  if (r)
    return UV__ERR(errno);

  *uptime = sp.tv_sec;
  return 0;
}

int uv__io_fork(uv_loop_t* loop) {
  // TODO(jgruber): Implement.
  // See also: uv__platform_loop_init.
  return UV__ERR(EINVAL);
}

int uv__io_check_fd(uv_loop_t* loop, int fd) {
  // TODO(jgruber): Implement.
  // See also: uv__platform_loop_init.
  return UV__ERR(EINVAL);
}

int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
  // TODO(jgruber): Implement.
  // Reads /proc/stat.
  return UV__ERR(EINVAL);
}

void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count) {
  int i;

  for (i = 0; i < count; i++) {
    uv__free(cpu_infos[i].model);
  }

  uv__free(cpu_infos);
}

// TODO(jgruber): Implement the following functions.
//
// --- core.c ------------------------------------------------------------------

int uv_getrusage(uv_rusage_t* rusage) {
  // TODO(jgruber): Implement.
  return 0;
}

int uv_os_getpriority(uv_pid_t pid, int* priority) {
  // TODO(jgruber): There are no process priorities in Fuchsia.
  *priority = 0;
  return 0;
}

int uv_os_setpriority(uv_pid_t pid, int priority) {
  // TODO(jgruber): There are no process priorities in Fuchsia.
  return 0;
}

// TODO(jgruber): Implement the following functions.
//
// --- thread.c ----------------------------------------------------------------

size_t thread_stack_size(void) {
  // TODO(jgruber): Implement.
  return 0;
}
