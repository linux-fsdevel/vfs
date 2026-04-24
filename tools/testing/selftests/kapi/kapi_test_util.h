/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Compatibility helpers for KAPI selftests.
 *
 * __NR_open is not defined on aarch64 and riscv64 (only __NR_openat exists).
 * Provide a wrapper that uses __NR_openat with AT_FDCWD to achieve the same
 * behavior as __NR_open on architectures that lack it.
 */
#ifndef KAPI_TEST_UTIL_H
#define KAPI_TEST_UTIL_H

#include <fcntl.h>
#include <sys/syscall.h>

#ifndef __NR_open
/*
 * On architectures without __NR_open (e.g., aarch64, riscv64),
 * use openat(AT_FDCWD, ...) which is equivalent.
 */
static inline long kapi_sys_open(const char *pathname, int flags, int mode)
{
	return syscall(__NR_openat, AT_FDCWD, pathname, flags, mode);
}
#else
static inline long kapi_sys_open(const char *pathname, int flags, int mode)
{
	return syscall(__NR_open, pathname, flags, mode);
}
#endif

#endif /* KAPI_TEST_UTIL_H */
