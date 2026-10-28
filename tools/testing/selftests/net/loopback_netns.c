// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/sched.h>
#include <linux/types.h>
#include <net/if.h>

#include "../clone3/clone3_selftests.h"
#include "../kselftest_harness.h"

static int get_lo_flags(void)
{
	struct ifreq ifr;
	int fd, ret;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	close(fd);

	if (ret < 0)
		return -errno;

	return ifr.ifr_flags;
}

TEST(baseline_lo_down)
{
	int flags;

	ASSERT_EQ(0, unshare(CLONE_NEWUSER | CLONE_NEWNET));

	flags = get_lo_flags();
	ASSERT_GE(flags, 0);
	EXPECT_EQ(0, flags & IFF_UP);
}

TEST(unshare_loopback)
{
	struct stat st_before, st_after;
	int flags;

	ASSERT_EQ(0, stat("/proc/self/ns/net", &st_before));
	ASSERT_EQ(0, unshare(CLONE_NEWUSER | UNSHARE_NEWNET_LOOPBACK));
	ASSERT_EQ(0, stat("/proc/self/ns/net", &st_after));
	EXPECT_NE(st_before.st_ino, st_after.st_ino);

	flags = get_lo_flags();
	ASSERT_GE(flags, 0);
	EXPECT_NE(0, flags & IFF_UP);
	EXPECT_NE(0, flags & IFF_RUNNING);
}

TEST(clone3_loopback)
{
	struct __clone_args args = {
		.flags = CLONE_NEWUSER | CLONE_NEWNET_LOOPBACK,
		.exit_signal = SIGCHLD,
	};
	struct stat st_parent, st_child;
	int status;
	pid_t pid;

	ASSERT_EQ(0, stat("/proc/self/ns/net", &st_parent));

	pid = sys_clone3(&args, sizeof(args));
	ASSERT_GE(pid, 0);

	if (pid == 0) {
		int flags;

		if (stat("/proc/self/ns/net", &st_child) != 0 ||
		    st_parent.st_ino == st_child.st_ino)
			_exit(1);

		flags = get_lo_flags();
		if (flags < 0 || !(flags & IFF_UP) || !(flags & IFF_RUNNING))
			_exit(2);

		_exit(0);
	}

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status));
}

TEST_HARNESS_MAIN
