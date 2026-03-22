/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * syscall_api_spec.h - System Call API Specification Integration
 *
 * This header extends the SYSCALL_DEFINEX macros to support inline API specifications,
 * allowing syscall documentation to be written alongside the implementation in a
 * human-readable and machine-parseable format.
 */

#ifndef _LINUX_SYSCALL_API_SPEC_H
#define _LINUX_SYSCALL_API_SPEC_H

#include <linux/kernel_api_spec.h>

/* Automatic syscall validation infrastructure */
/*
 * The validation is now integrated directly into the SYSCALL_DEFINEx macros
 * in syscalls.h when CONFIG_KAPI_RUNTIME_CHECKS is enabled.
 *
 * The validation happens in the __do_kapi_sys##name wrapper function which:
 * 1. Validates all parameters before calling the actual syscall
 * 2. Calls the real syscall implementation
 * 3. Validates the return value
 * 4. Returns the result
 */


/*
 * Helper macros for common syscall patterns
 */

/* For syscalls that can sleep */
#define KAPI_SYSCALL_SLEEPABLE \
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

/* For syscalls that must be atomic */
#define KAPI_SYSCALL_ATOMIC \
	KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_ATOMIC)

/* Common parameter specifications */
#define KAPI_PARAM_FD(idx, desc) \
	KAPI_PARAM(idx, "fd", "int", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN) \
		.type = KAPI_TYPE_FD, \
		.constraint_type = KAPI_CONSTRAINT_NONE, \
	KAPI_PARAM_END

#define KAPI_PARAM_USER_BUF(idx, name, desc) \
	KAPI_PARAM(idx, name, "void __user *", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_USER | KAPI_PARAM_IN) \
	KAPI_PARAM_END

/**
 * KAPI_PARAM_USER_STRUCT - Define a userspace struct pointer parameter
 * @idx: Parameter index (0-based)
 * @name: Parameter name
 * @struct_type: The struct type (e.g., struct iocb)
 * @desc: Parameter description
 *
 * This macro defines a parameter that is a userspace pointer to a struct.
 * The pointer will be validated to ensure:
 * - The pointer is accessible in userspace
 * - The memory region of sizeof(struct_type) bytes is accessible
 */
#define KAPI_PARAM_USER_STRUCT(idx, name, struct_type, desc) \
	KAPI_PARAM(idx, name, #struct_type " __user *", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_USER | KAPI_PARAM_IN) \
		.type = KAPI_TYPE_USER_PTR, \
		.size = sizeof(struct_type), \
		.constraint_type = KAPI_CONSTRAINT_USER_PTR, \
	KAPI_PARAM_END

/**
 * KAPI_PARAM_USER_PTR_SIZED - Define a userspace pointer with explicit size
 * @idx: Parameter index (0-based)
 * @name: Parameter name
 * @ptr_size: Size in bytes of the memory region
 * @desc: Parameter description
 *
 * This macro defines a parameter that is a userspace pointer to a memory
 * region of a specific size. The pointer will be validated to ensure:
 * - The pointer is accessible in userspace
 * - The memory region of ptr_size bytes is accessible
 */
#define KAPI_PARAM_USER_PTR_SIZED(idx, name, ptr_size, desc) \
	KAPI_PARAM(idx, name, "void __user *", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_USER | KAPI_PARAM_IN) \
		.type = KAPI_TYPE_USER_PTR, \
		.size = ptr_size, \
		.constraint_type = KAPI_CONSTRAINT_USER_PTR, \
	KAPI_PARAM_END

/**
 * KAPI_PARAM_USER_STRING - Define a userspace null-terminated string parameter
 * @idx: Parameter index (0-based)
 * @name: Parameter name
 * @min_len: Minimum string length (excluding null terminator)
 * @max_len: Maximum string length (excluding null terminator)
 * @desc: Parameter description
 *
 * This macro defines a parameter that is a userspace pointer to a
 * null-terminated string. The string will be validated to ensure:
 * - The pointer is accessible in userspace
 * - The string length (excluding null terminator) is within [min_len, max_len]
 */
#define KAPI_PARAM_USER_STRING(idx, name, min_len, max_len, desc) \
	KAPI_PARAM(idx, name, "const char __user *", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_USER | KAPI_PARAM_IN) \
		.type = KAPI_TYPE_USER_PTR, \
		.constraint_type = KAPI_CONSTRAINT_USER_STRING, \
		.min_value = min_len, \
		.max_value = max_len, \
	KAPI_PARAM_END

/**
 * KAPI_PARAM_USER_PATH - Define a userspace pathname parameter
 * @idx: Parameter index (0-based)
 * @name: Parameter name
 * @desc: Parameter description
 *
 * This macro defines a parameter that is a userspace pointer to a
 * null-terminated pathname string. The path will be validated to ensure:
 * - The pointer is accessible in userspace
 * - The path is a valid null-terminated string
 * - The path length does not exceed PATH_MAX (4096 bytes)
 */
#define KAPI_PARAM_USER_PATH(idx, name, desc) \
	KAPI_PARAM(idx, name, "const char __user *", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_USER | KAPI_PARAM_IN) \
		.type = KAPI_TYPE_PATH, \
		.constraint_type = KAPI_CONSTRAINT_USER_PATH, \
	KAPI_PARAM_END

#define KAPI_PARAM_SIZE_T(idx, name, desc) \
	KAPI_PARAM(idx, name, "size_t", desc) \
		KAPI_PARAM_FLAGS(KAPI_PARAM_IN) \
		KAPI_PARAM_RANGE(0, S64_MAX) \
	KAPI_PARAM_END

/* Common error specifications */
#define KAPI_ERROR_EBADF(idx) \
	KAPI_ERROR(idx, -EBADF, "EBADF", "Invalid file descriptor", \
		   "The file descriptor is not valid or has been closed")

#define KAPI_ERROR_EINVAL(idx, condition) \
	KAPI_ERROR(idx, -EINVAL, "EINVAL", condition, \
		   "Invalid argument provided")

#define KAPI_ERROR_ENOMEM(idx) \
	KAPI_ERROR(idx, -ENOMEM, "ENOMEM", "Insufficient memory", \
		   "Cannot allocate memory for the operation")

#define KAPI_ERROR_EPERM(idx) \
	KAPI_ERROR(idx, -EPERM, "EPERM", "Operation not permitted", \
		   "The calling process does not have the required permissions")

#define KAPI_ERROR_EFAULT(idx) \
	KAPI_ERROR(idx, -EFAULT, "EFAULT", "Bad address", \
		   "Invalid user space address provided")

/* Standard return value specifications */
#define KAPI_RETURN_SUCCESS_ZERO \
	KAPI_RETURN("long", "0 on success, negative error code on failure") \
		KAPI_RETURN_SUCCESS(0, "== 0") \
	KAPI_RETURN_END

#define KAPI_RETURN_FD_SPEC \
	KAPI_RETURN("long", "File descriptor on success, negative error code on failure") \
		.check_type = KAPI_RETURN_FD, \
	KAPI_RETURN_END

#define KAPI_RETURN_COUNT \
	KAPI_RETURN("long", "Number of bytes processed on success, negative error code on failure") \
		KAPI_RETURN_SUCCESS(0, ">= 0") \
	KAPI_RETURN_END

/**
 * KAPI_SIGNAL_MASK_COUNT - Set the signal mask count
 * @count: Number of signal masks defined
 */
#define KAPI_SIGNAL_MASK_COUNT(count) \
	.signal_mask_count = count,

#endif /* _LINUX_SYSCALL_API_SPEC_H */