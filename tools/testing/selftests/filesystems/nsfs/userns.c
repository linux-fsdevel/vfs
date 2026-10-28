// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/nsfs.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "../../clone3/clone3_selftests.h"
#include "../../kselftest_harness.h"

TEST(user_get_info_self)
{
	struct user_ns_info info = {};
	int fd;

	fd = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0) {
		TH_LOG("Failed to open /proc/self/ns/user: %m");
	}

	ASSERT_EQ(0, ioctl(fd, NS_USER_GET_INFO, &info)) {
		TH_LOG("ioctl(NS_USER_GET_INFO) failed on self: %m");
	}
	close(fd);

	EXPECT_EQ(USER_NS_INFO_SIZE_VER0, info.size);
	EXPECT_EQ(0, info.spare);
	EXPECT_NE(0ULL, info.cap_bset);
}

TEST(user_get_info_restricted_bset)
{
	struct __clone_args args = {
		.flags = CLONE_NEWUSER | CLONE_NEWUSER_BSET,
		.exit_signal = SIGCHLD,
		.cap_bset = 0,
	};
	int status;
	pid_t pid;

	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		struct user_ns_info info = {};
		int fd;

		fd = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			_exit(1);

		if (ioctl(fd, NS_USER_GET_INFO, &info) != 0) {
			close(fd);
			_exit(2);
		}
		close(fd);

		if (info.cap_bset != 0)
			_exit(3);

		_exit(0);
	}

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST(user_get_info_invalid_ns_type)
{
	struct user_ns_info info = {};
	int mntns_fd;

	mntns_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(mntns_fd, 0) {
		TH_LOG("Failed to open /proc/self/ns/mnt: %m");
	}

	EXPECT_EQ(-1, ioctl(mntns_fd, NS_USER_GET_INFO, &info));
	EXPECT_EQ(EINVAL, errno);

	close(mntns_fd);
}

TEST(user_get_info_buffer_too_small)
{
	__u32 small_buf = 0;
	int fd;

	fd = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);

	/* Encode a buffer size smaller than USER_NS_INFO_SIZE_VER0 (4B vs 16B) */
	EXPECT_EQ(-1, ioctl(fd, _IOR(NSIO, 14, __u32), &small_buf));

	close(fd);
}

TEST(user_get_info_null_arg)
{
	int fd;

	fd = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(fd, 0);

	EXPECT_EQ(-1, ioctl(fd, NS_USER_GET_INFO, NULL));
	EXPECT_EQ(EINVAL, errno);

	close(fd);
}

TEST_HARNESS_MAIN
