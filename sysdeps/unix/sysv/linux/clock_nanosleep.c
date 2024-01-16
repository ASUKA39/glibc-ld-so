/* Copyright (C) 2003-2022 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <time.h>
#include <kernel-features.h>
#include <errno.h>

#include <sysdep-cancel.h>
#include "kernel-posix-cpu-timers.h"

#include <shlib-compat.h>


static int valid_nanosleep_ts (const struct __timespec64 *ts) {
  return (ts->tv_nsec >= 0 && ts->tv_nsec < 1000000000L && ts->tv_sec >= 0);
}

/* Use CLOCK_MONOTONIC and convert request with TIMER_ABSTIME to use relative time */
#define MONOTONIC_FALLBACK do {                                         \
    if (__glibc_unlikely (flags & TIMER_ABSTIME))                       \
    {                                                                   \
      struct __timespec64 current_realtime, actual_req;                 \
      actual_req = *req;                                                \
      if(__clock_gettime64(CLOCK_REALTIME, &current_realtime))          \
        return EINVAL;                                                  \
      actual_req.tv_nsec -= current_realtime.tv_nsec;                   \
      actual_req.tv_sec -= current_realtime.tv_sec;                     \
      if (actual_req.tv_nsec < 0)                                       \
      {                                                                 \
        --actual_req.tv_sec;                                            \
        actual_req.tv_nsec = 1000000000L + actual_req.tv_nsec;          \
      }                                                                 \
      r = INTERNAL_SYSCALL_CANCEL (clock_nanosleep_time64,              \
                                   CLOCK_MONOTONIC,                     \
                                   flags & ~TIMER_ABSTIME,              \
                                   &actual_req, rem);                   \
    } else                                                              \
      r = INTERNAL_SYSCALL_CANCEL (clock_nanosleep_time64,              \
                                   CLOCK_MONOTONIC, flags,              \
                                   req, rem);                           \
  } while (0)

/* We can simply use the syscall.  The CPU clocks are not supported
   with this function.  */
int
__clock_nanosleep_time64 (clockid_t clock_id, int flags,
			  const struct __timespec64 *req,
			  struct __timespec64 *rem)
{
  if (clock_id == CLOCK_THREAD_CPUTIME_ID)
    return EINVAL;
  if (clock_id == CLOCK_PROCESS_CPUTIME_ID)
    clock_id = MAKE_PROCESS_CPUCLOCK (0, CPUCLOCK_SCHED);

  /* If the call is interrupted by a signal handler or encounters an error,
     it returns a positive value similar to errno.  */

#ifndef __NR_clock_nanosleep_time64
# define __NR_clock_nanosleep_time64 __NR_clock_nanosleep
#endif

  int r;
#ifdef __ASSUME_TIME64_SYSCALLS
  r = INTERNAL_SYSCALL_CANCEL (clock_nanosleep_time64, clock_id, flags, req,
			       rem);
  if (__glibc_unlikely (INTERNAL_SYSCALL_ERRNO (r) == EINVAL
			&& clock_id == CLOCK_REALTIME
			&& valid_nanosleep_ts(req)))
    MONOTONIC_FALLBACK;
#else
  if (!in_time_t_range (req->tv_sec))
    {
      r = INTERNAL_SYSCALL_CANCEL (clock_nanosleep_time64, clock_id, flags,
				   req, rem);
      if (__glibc_unlikely (INTERNAL_SYSCALL_ERRNO (r) == EINVAL
			    && clock_id == CLOCK_REALTIME
			    && valid_nanosleep_ts(req)))
	MONOTONIC_FALLBACK;
      if (r == -ENOSYS)
	r = -EOVERFLOW;
    }
  else
    {
      struct timespec tr32;
      struct timespec ts32 = valid_timespec64_to_timespec (*req);
      r = INTERNAL_SYSCALL_CANCEL (clock_nanosleep, clock_id, flags, &ts32,
				   &tr32);
      if (__glibc_unlikely (INTERNAL_SYSCALL_ERRNO (r) == EINVAL
			    && clock_id == CLOCK_REALTIME
			    && valid_nanosleep_ts(req)))
	MONOTONIC_FALLBACK;
      if (INTERNAL_SYSCALL_ERROR_P (r))
	{
	  if (r == -EINTR && rem != NULL && (flags & TIMER_ABSTIME) == 0)
	    *rem = valid_timespec_to_timespec64 (tr32);
	}
    }
#endif
  return -r;
}

#if __TIMESIZE != 64
libc_hidden_def (__clock_nanosleep_time64)

int
__clock_nanosleep (clockid_t clock_id, int flags, const struct timespec *req,
                   struct timespec *rem)
{
  int r;
  struct __timespec64 treq64, trem64;

  treq64 = valid_timespec_to_timespec64 (*req);
  r = __clock_nanosleep_time64 (clock_id, flags, &treq64,
                                rem != NULL ? &trem64 : NULL);

  if (r == EINTR && rem != NULL && (flags & TIMER_ABSTIME) == 0)
    *rem = valid_timespec64_to_timespec (trem64);

  return r;
}
#endif
libc_hidden_def (__clock_nanosleep)
versioned_symbol (libc, __clock_nanosleep, clock_nanosleep, GLIBC_2_17);
/* clock_nanosleep moved to libc in version 2.17;
   old binaries may expect the symbol version it had in librt.  */
#if SHLIB_COMPAT (libc, GLIBC_2_2, GLIBC_2_17)
strong_alias (__clock_nanosleep, __clock_nanosleep_2);
compat_symbol (libc, __clock_nanosleep_2, clock_nanosleep, GLIBC_2_2);
#endif
