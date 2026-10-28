// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/capability.h>
#include <linux/sched.h>

#include "../clone3/clone3_selftests.h"
#include "../kselftest_harness.h"

#define SYSCTL_PATH "/proc/sys/kernel/unprivileged_userns_caps_allowed"

static const uint64_t cap_full_set = ~0ULL;

struct cap_state {
	bool bset;
	bool permitted;
	bool effective;
};

static int get_cap_state(int cap, struct cap_state *state)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2];
	uint32_t mask;
	int idx;

	if (cap < 0 || cap >= 64)
		return -EINVAL;

	if (syscall(SYS_capget, &hdr, data) != 0)
		return -errno;

	idx = (cap >= 32) ? 1 : 0;
	mask = 1U << (cap % 32);

	state->bset = (prctl(PR_CAPBSET_READ, cap, 0, 0, 0) == 1);
	state->permitted = (data[idx].permitted & mask) != 0;
	state->effective = (data[idx].effective & mask) != 0;

	return 0;
}

static bool cap_raised(int cap)
{
	struct cap_state t;

	if (get_cap_state(cap, &t) != 0)
		return false;

	return t.bset && t.permitted && t.effective;
}

static bool cap_dropped(int cap)
{
	struct cap_state t;

	if (get_cap_state(cap, &t) != 0)
		return false;

	return !t.bset && !t.permitted && !t.effective;
}

static int set_effective_cap(int cap)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct data[2] = {};

	if (cap >= 0) {
		int idx = (cap >= 32) ? 1 : 0;
		uint32_t mask = 1U << (cap % 32);

		data[idx].effective = mask;
		data[idx].permitted = mask;
	}

	return syscall(SYS_capset, &hdr, data);
}

static int drop_privileges(void)
{
	return set_effective_cap(-1);
}

static int write_file(const char *path, const char *str)
{
	ssize_t len = strlen(str);
	ssize_t ret;
	int fd;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ret = write(fd, str, len);
	close(fd);

	return (ret == len) ? 0 : -1;
}

static int read_sysctl_caps(uint64_t *caps_out)
{
	char buf[64] = {};
	ssize_t ret;
	int fd;

	fd = open(SYSCTL_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ret = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (ret <= 0)
		return -1;

	*caps_out = strtoull(buf, NULL, 16);
	return 0;
}

static int write_sysctl_caps(uint64_t val)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%016llx\n", (unsigned long long)val);
	return write_file(SYSCTL_PATH, buf);
}

/*
 * Attempts setns(CLONE_NEWUSER) into an unprivileged child user namespace
 * from the owning parent process (which has no effective capabilities in
 * its own namespace and relies on the parent-owner rule in
 * cap_capable_helper()).
 */
static int run_parent_owner_setns(uint64_t sysctl_mask)
{
	pid_t owner_pid;
	int status;

	if (write_sysctl_caps(sysctl_mask) != 0)
		return -1;

	owner_pid = fork();
	if (owner_pid < 0)
		return -1;

	if (owner_pid == 0) {
		struct __clone_args args = {
			.flags = CLONE_FILES | CLONE_NEWUSER,
			.exit_signal = SIGCHLD,
		};
		pid_t child_pid;
		int userns_fd;
		int err;

		if (drop_privileges() != 0)
			_exit(255);

		child_pid = sys_clone3(&args, sizeof(args));
		if (child_pid < 0)
			_exit(255);

		if (child_pid == 0) {
			int fd = open("/proc/self/ns/user", O_RDONLY);

			if (fd < 0)
				_exit(255);
			_exit(fd);
		}

		if (waitpid(child_pid, &status, 0) != child_pid ||
		    !WIFEXITED(status) || WEXITSTATUS(status) == 255)
			_exit(255);

		userns_fd = WEXITSTATUS(status);
		err = (setns(userns_fd, CLONE_NEWUSER) == 0) ? 0 : errno;
		close(userns_fd);
		_exit(err);
	}

	if (waitpid(owner_pid, &status, 0) != owner_pid || !WIFEXITED(status))
		return -1;

	return WEXITSTATUS(status);
}

FIXTURE(userns_bset) {
	uint64_t orig_caps;
	bool have_orig_caps;
};

FIXTURE_SETUP(userns_bset)
{
	self->orig_caps = 0;
	self->have_orig_caps = false;

	if (geteuid() != 0)
		SKIP(return, "Requires root privileges");
	if (access(SYSCTL_PATH, F_OK) != 0)
		SKIP(return, "Sysctl %s not present", SYSCTL_PATH);

	ASSERT_EQ(0, read_sysctl_caps(&self->orig_caps));
	self->have_orig_caps = true;
}

FIXTURE_TEARDOWN(userns_bset)
{
	if (self->have_orig_caps)
		write_sysctl_caps(self->orig_caps);
}

/*
 * An unprivileged userns creator with the full mask should receive
 * CAP_NET_ADMIN and CAP_SYS_ADMIN.
 */
TEST_F(userns_bset, default_full_capabilities)
{
	pid_t pid;
	int status;

	ASSERT_EQ(0, write_sysctl_caps(cap_full_set));

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		if (drop_privileges() != 0)
			_exit(1);
		if (unshare(CLONE_NEWUSER) != 0)
			_exit(2);
		if (!cap_raised(CAP_SYS_ADMIN))
			_exit(3);
		if (!cap_raised(CAP_NET_ADMIN))
			_exit(4);
		_exit(0);
	}

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

/*
 * Dropping CAP_NET_ADMIN from the sysctl prevents unprivileged userns
 * from obtaining CAP_NET_ADMIN while retaining other capabilities.
 */
TEST_F(userns_bset, unprivileged_restriction)
{
	uint64_t restricted_mask = cap_full_set & ~(1ULL << CAP_NET_ADMIN);
	pid_t pid;
	int status;

	ASSERT_EQ(0, write_sysctl_caps(restricted_mask));

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		if (drop_privileges() != 0)
			_exit(1);
		if (unshare(CLONE_NEWUSER) != 0)
			_exit(2);
		if (!cap_raised(CAP_SYS_ADMIN))
			_exit(3);
		if (!cap_dropped(CAP_NET_ADMIN))
			_exit(4);
		_exit(0);
	}

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

/*
 * Unprivileged userns should retain effective capabilities from the creator
 * (CAP_NET_ADMIN) while still having unheld capabilities (CAP_NET_RAW) trimmed.
 */
TEST_F(userns_bset, creator_retains_effective_cap)
{
	uint64_t restricted_mask = cap_full_set &
		~((1ULL << CAP_NET_ADMIN) | (1ULL << CAP_NET_RAW));
	pid_t pid;
	int status;

	ASSERT_EQ(0, write_sysctl_caps(restricted_mask));

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		if (set_effective_cap(CAP_NET_ADMIN) != 0)
			_exit(1);

		if (unshare(CLONE_NEWUSER) != 0)
			_exit(2);

		if (!cap_raised(CAP_NET_ADMIN))
			_exit(3);
		if (!cap_dropped(CAP_NET_RAW))
			_exit(4);
		if (!cap_raised(CAP_SYS_ADMIN))
			_exit(5);

		_exit(0);
	}

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

/*
 * Privileged processes (with CAP_SYS_ADMIN in parent ns) retain full
 * capabilities regardless of the unprivileged sysctl mask.
 */
TEST_F(userns_bset, privileged_bypass)
{
	uint64_t restricted_mask = cap_full_set & ~(1ULL << CAP_NET_ADMIN);
	pid_t pid;
	int status;

	ASSERT_EQ(0, write_sysctl_caps(restricted_mask));

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		if (unshare(CLONE_NEWUSER) != 0)
			_exit(1);
		if (!cap_raised(CAP_NET_ADMIN))
			_exit(2);
		_exit(0);
	}

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

/*
 * Verify that once a capability is dropped in a user namespace
 * a privileged creator (holding CAP_SYS_ADMIN) in that namespace
 * cannot regain the dropped capability by creating a nested child
 * namespace.
 */
TEST_F(userns_bset, nested_monotonic_restriction)
{
	uint64_t restricted_mask = cap_full_set & ~(1ULL << CAP_NET_ADMIN);
	pid_t pid;
	int status;

	ASSERT_EQ(0, write_sysctl_caps(restricted_mask));

	pid = fork();
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		if (set_effective_cap(CAP_SETFCAP) != 0)
			_exit(1);
		if (unshare(CLONE_NEWUSER) != 0)
			_exit(2);
		if (!cap_dropped(CAP_NET_ADMIN))
			_exit(3);

		/* Map our UID/GID so creating a nested userns is permitted */
		if (write_file("/proc/self/setgroups", "deny\n") != 0 ||
		    write_file("/proc/self/uid_map", "0 0 1\n") != 0 ||
		    write_file("/proc/self/gid_map", "0 0 1\n") != 0)
			_exit(4);

		if (unshare(CLONE_NEWUSER) != 0)
			_exit(5);
		if (!cap_dropped(CAP_NET_ADMIN))
			_exit(6);
		if (!cap_raised(CAP_SYS_ADMIN))
			_exit(7);
		_exit(0);
	}

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

/*
 * Verify that an unprivileged parent owning a child namespace retains
 * implicit capabilities over it when permitted by the child's cap_bset.
 */
TEST_F(userns_bset, parent_owner_cap_permitted)
{
	EXPECT_EQ(0, run_parent_owner_setns(cap_full_set));
}

/*
 * Verify that an unprivileged parent's implicit capabilities over its
 * owned child namespace are restricted by the child's cap_bset.
 */
TEST_F(userns_bset, parent_owner_cap_restricted)
{
	uint64_t restricted_mask = cap_full_set & ~(1ULL << CAP_SYS_ADMIN);

	EXPECT_EQ(EPERM, run_parent_owner_setns(restricted_mask));
}

TEST_HARNESS_MAIN
