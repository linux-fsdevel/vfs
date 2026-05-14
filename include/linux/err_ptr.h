/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERR_PTR_H
#define _LINUX_ERR_PTR_H

#include <linux/err.h>
#include <linux/bug.h>

/**
 * ERR_PTR_SAFE - Create an error pointer, with validation.
 * @error: An error code to encode as an error pointer.
 *
 * Like ERR_PTR(), but validates @error:
 * - For constant @error: fails the build if the value is not a valid errno
 *   (zero is allowed, producing NULL).
 * - For variable @error: warns and clamps to -MAX_ERRNO if out of range.
 *
 * Subsystems may opt in for all ERR_PTR() call sites by adding after includes:
 *   #undef ERR_PTR
 *   #define ERR_PTR(err) ERR_PTR_SAFE(err)
 */
#define ERR_PTR_SAFE(error) ({						\
	long __e = (error);						\
	if (__builtin_constant_p(__e))					\
		BUILD_BUG_ON(__e && !IS_ERR_VALUE(__e));		\
	__builtin_constant_p(__e) ? (void *)__e :			\
		(void *)(WARN_ON(__e && !IS_ERR_VALUE(__e)) ? -MAX_ERRNO : __e);\
})

#endif /* _LINUX_ERR_PTR_H */
