// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#define __SANE_USERSPACE_TYPES__ // Use ll64

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "kselftest.h"

#define NR_TESTS	14

static const char * const dev_files[] = {
	"/dev/zero", "/dev/null", "/dev/urandom",
	"/proc/version", "/proc"
};

static const struct {
	bool lower;
	bool nested;
	const char *desc;
} ovl_tests[] = {
	{ false, false, "an overlayfs file" },
	{ false, true, "a nested overlayfs file" },
	{ true, false, "an overlayfs lower file" },
	{ true, true, "a nested overlayfs lower file" },
};

void print_cachestat(struct cachestat *cs)
{
	ksft_print_msg(
	"Using cachestat: Cached: %llu, Dirty: %llu, Writeback: %llu, Evicted: %llu, Recently Evicted: %llu\n",
	cs->nr_cache, cs->nr_dirty, cs->nr_writeback,
	cs->nr_evicted, cs->nr_recently_evicted);
}

enum file_type {
	FILE_MMAP,
	FILE_SHMEM
};

bool write_exactly(int fd, size_t filesize)
{
	int random_fd = open("/dev/urandom", O_RDONLY);
	char *cursor, *data;
	int remained;
	bool ret;

	if (random_fd < 0) {
		ksft_print_msg("Unable to access urandom.\n");
		ret = false;
		goto out;
	}

	data = malloc(filesize);
	if (!data) {
		ksft_print_msg("Unable to allocate data.\n");
		ret = false;
		goto close_random_fd;
	}

	remained = filesize;
	cursor = data;

	while (remained) {
		ssize_t read_len = read(random_fd, cursor, remained);

		if (read_len <= 0) {
			ksft_print_msg("Unable to read from urandom.\n");
			ret = false;
			goto out_free_data;
		}

		remained -= read_len;
		cursor += read_len;
	}

	/* write random data to fd */
	remained = filesize;
	cursor = data;
	while (remained) {
		ssize_t write_len = write(fd, cursor, remained);

		if (write_len <= 0) {
			ksft_print_msg("Unable write random data to file.\n");
			ret = false;
			goto out_free_data;
		}

		remained -= write_len;
		cursor += write_len;
	}

	ret = true;
out_free_data:
	free(data);
close_random_fd:
	close(random_fd);
out:
	return ret;
}

/*
 * fsync() is implemented via noop_fsync() on tmpfs. This makes the fsync()
 * test fail below, so we need to check for test file living on a tmpfs.
 */
static bool is_on_tmpfs(int fd)
{
	struct statfs statfs_buf;

	if (fstatfs(fd, &statfs_buf))
		return false;

	return statfs_buf.f_type == TMPFS_MAGIC;
}

/*
 * Open/create the file at filename, (optionally) write random data to it
 * (exactly num_pages), then test the cachestat syscall on this file.
 *
 * If write_random == true or check_cached == true, check that all num_pages
 * pages of the file are cached or evicted.
 *
 * If test_fsync == true, fsync the file, then check the number of dirty
 * pages.
 */
static int test_cachestat(const char *filename, bool write_random,
			  bool check_cached, bool create,
			  bool test_fsync, unsigned long num_pages,
			  int open_flags, mode_t open_mode)
{
	size_t PS = sysconf(_SC_PAGESIZE);
	int filesize = num_pages * PS;
	int ret = KSFT_PASS;
	long syscall_ret;
	struct cachestat cs;
	struct cachestat_range cs_range = { 0, filesize };

	int fd = open(filename, open_flags, open_mode);

	if (fd == -1) {
		ksft_print_msg("Unable to create/open file.\n");
		ret = KSFT_FAIL;
		goto out;
	} else {
		ksft_print_msg("Create/open %s\n", filename);
	}

	if (write_random) {
		if (!write_exactly(fd, filesize)) {
			ksft_print_msg("Unable to access urandom.\n");
			ret = KSFT_FAIL;
			goto out1;
		}
	}

	syscall_ret = syscall(__NR_cachestat, fd, &cs_range, &cs, 0);

	ksft_print_msg("Cachestat call returned %ld\n", syscall_ret);

	if (syscall_ret) {
		ksft_print_msg("Cachestat returned non-zero.\n");
		ret = KSFT_FAIL;
		goto out1;

	} else {
		print_cachestat(&cs);

		if (write_random || check_cached) {
			if (cs.nr_cache + cs.nr_evicted != num_pages) {
				ksft_print_msg(
					"Total number of cached and evicted pages is off.\n");
				ret = KSFT_FAIL;
			}
		}
	}

	if (test_fsync) {
		if (is_on_tmpfs(fd)) {
			ret = KSFT_SKIP;
		} else if (fsync(fd)) {
			ksft_print_msg("fsync fails.\n");
			ret = KSFT_FAIL;
		} else {
			syscall_ret = syscall(__NR_cachestat, fd, &cs_range, &cs, 0);

			ksft_print_msg("Cachestat call (after fsync) returned %ld\n",
				syscall_ret);

			if (!syscall_ret) {
				print_cachestat(&cs);

				if (cs.nr_dirty) {
					ret = KSFT_FAIL;
					ksft_print_msg(
						"Number of dirty should be zero after fsync.\n");
				}
			} else {
				ksft_print_msg("Cachestat (after fsync) returned non-zero.\n");
				ret = KSFT_FAIL;
				goto out1;
			}
		}
	}

out1:
	close(fd);

	if (create)
		remove(filename);
out:
	return ret;
}
const char *file_type_str(enum file_type type)
{
	switch (type) {
	case FILE_SHMEM:
		return "shmem";
	case FILE_MMAP:
		return "mmap";
	default:
		return "unknown";
	}
}


bool run_cachestat_test(enum file_type type)
{
	size_t PS = sysconf(_SC_PAGESIZE);
	size_t filesize = PS * 512 * 2; /* 2 2MB huge pages */
	int syscall_ret;
	size_t compute_len = PS * 512;
	struct cachestat_range cs_range = { PS, compute_len };
	char *filename = "tmpshmcstat", *map;
	struct cachestat cs;
	bool ret = true;
	int fd;
	unsigned long num_pages = compute_len / PS;
	if (type == FILE_SHMEM)
		fd = shm_open(filename, O_CREAT | O_RDWR, 0600);
	else
		fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0666);

	if (fd < 0) {
		ksft_print_msg("Unable to create %s file.\n",
				file_type_str(type));
		ret = false;
		goto out;
	}

	if (ftruncate(fd, filesize)) {
		ksft_print_msg("Unable to truncate %s file.\n",file_type_str(type));
		ret = false;
		goto close_fd;
	}
	switch (type) {
	case FILE_SHMEM:
		if (!write_exactly(fd, filesize)) {
			ksft_print_msg("Unable to write to file.\n");
			ret = false;
			goto close_fd;
		}
		break;
	case FILE_MMAP:
		map = mmap(NULL, filesize, PROT_READ | PROT_WRITE,
				 MAP_SHARED, fd, 0);

		if (map == MAP_FAILED) {
			ksft_print_msg("mmap failed.\n");
			ret = false;
			goto close_fd;
		}
		for (int i = 0; i < filesize; i++)
			map[i] = 'A';
		break;
	default:
		ksft_print_msg("Unsupported file type.\n");
		ret = false;
		goto close_fd;
	}
	syscall_ret = syscall(__NR_cachestat, fd, &cs_range, &cs, 0);

	if (syscall_ret) {
		ksft_print_msg("Cachestat returned non-zero.\n");
		ret = false;
		goto close_fd;
	} else {
		print_cachestat(&cs);
		if (cs.nr_cache + cs.nr_evicted != num_pages) {
			ksft_print_msg(
				"Total number of cached and evicted pages is off.\n");
			ret = false;
		}
	}

close_fd:
	shm_unlink(filename);
out:
	return ret;
}

static int mount_overlayfs(const char *lowerdir, const char *upperdir,
			   const char *workdir, const char *merged)
{
	char opts[4 * PATH_MAX];

	snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s",
		 lowerdir, upperdir, workdir);
	if (mount("overlay", merged, "overlay", 0, opts)) {
		ksft_print_msg("Unable to mount overlayfs (need root?): %s\n",
			       strerror(errno));
		return KSFT_SKIP;
	}

	return KSFT_PASS;
}

/*
 * Write a file to an overlayfs, either directly to its lower dir (if lower)
 * or through the overlayfs mount, so that its page cache is in the lower or
 * upper dir. Then open the file read-only, so it is not copied up, through the
 * overlayfs mount or, if nested, through a second overlayfs mount on top of it
 * (using the first one's merged dir as its lower dir), and run cachestat on
 * it. Overlayfs does not cache file data in its own inodes, so cachestat sees
 * the pages only if it is forwarded one (or two, if nested) stacking levels
 * down, to the page cache belonging to the real file.
 */
static int run_cachestat_overlayfs_test(bool lower, bool nested)
{
	char tmpl[] = "/tmp/cachestat_ovl.XXXXXX";
	char lowerdir[PATH_MAX];
	char upper1[PATH_MAX], work1[PATH_MAX], merged1[PATH_MAX];
	char upper2[PATH_MAX], work2[PATH_MAX], merged2[PATH_MAX];
	char cmd[PATH_MAX + 16], file[PATH_MAX + 16];
	const char *write_path, *read_path;
	char *base;
	int ret;

	base = mkdtemp(tmpl);
	if (!base) {
		ksft_print_msg("Unable to create overlayfs base dir: %s\n",
			       strerror(errno));
		return KSFT_FAIL;
	}

	snprintf(lowerdir, sizeof(lowerdir), "%s/lower", base);
	snprintf(upper1, sizeof(upper1), "%s/upper1", base);
	snprintf(work1, sizeof(work1), "%s/work1", base);
	snprintf(merged1, sizeof(merged1), "%s/merged1", base);
	snprintf(upper2, sizeof(upper2), "%s/upper2", base);
	snprintf(work2, sizeof(work2), "%s/work2", base);
	snprintf(merged2, sizeof(merged2), "%s/merged2", base);

	if (mkdir(lowerdir, 0755) || mkdir(upper1, 0755) ||
	    mkdir(work1, 0755) || mkdir(merged1, 0755) ||
	    mkdir(upper2, 0755) || mkdir(work2, 0755) ||
	    mkdir(merged2, 0755)) {
		ksft_print_msg("Unable to create overlayfs dirs: %s\n",
			       strerror(errno));
		ret = KSFT_FAIL;
		goto cleanup;
	}

	if (lower)
		write_path = lowerdir;
	else
		write_path = merged1;

	if (nested)
		read_path = merged2;
	else
		read_path = merged1;

	snprintf(file, sizeof(file), "%s/cachestat", write_path);

	/* Write the lower file before mounting overlayfs over it */
	if (lower) {
		ret = test_cachestat(file, true, false, false, false, 4,
				     O_CREAT | O_RDWR, 0600);
		if (ret != KSFT_PASS)
			goto cleanup;
	}

	ret = mount_overlayfs(lowerdir, upper1, work1, merged1);
	if (ret != KSFT_PASS)
		goto cleanup;

	if (!lower) {
		ret = test_cachestat(file, true, false, false, false, 4,
				     O_CREAT | O_RDWR, 0600);
		if (ret != KSFT_PASS)
			goto umount;
	}

	if (nested) {
		ret = mount_overlayfs(merged1, upper2, work2, merged2);
		if (ret != KSFT_PASS)
			goto umount;
	}

	snprintf(file, sizeof(file), "%s/cachestat", read_path);
	/* Look at that page cache through the overlayfs layer(s) */
	ret = test_cachestat(file, false, true, false, false, 4,
			     O_RDONLY, 0);

	if (nested)
		umount(merged2);
umount:
	umount(merged1);
cleanup:
	/* Best-effort recursive cleanup of the temporary tree. */
	snprintf(cmd, sizeof(cmd), "rm -rf %s", base);
	if (system(cmd))
		ksft_print_msg("Unable to clean up %s\n", base);
	return ret;
}

int main(void)
{
	int ret;

	ksft_print_header();

	ret = syscall(__NR_cachestat, -1, NULL, NULL, 0);
	if (ret == -1 && errno == ENOSYS)
		ksft_exit_skip("cachestat syscall not available\n");

	ksft_set_plan(NR_TESTS);

	if (ret == -1 && errno == EBADF) {
		ksft_test_result_pass("bad file descriptor recognized\n");
		ret = 0;
	} else {
		ksft_test_result_fail("bad file descriptor ignored\n");
		ret = 1;
	}

	for (int i = 0; i < 5; i++) {
		const char *dev_filename = dev_files[i];

		if (test_cachestat(dev_filename, false, false, false, false,
				   4, O_RDONLY, 0400) == KSFT_PASS)
			ksft_test_result_pass("cachestat works with %s\n", dev_filename);
		else {
			ksft_test_result_fail("cachestat fails with %s\n", dev_filename);
			ret = 1;
		}
	}

	if (test_cachestat("tmpfilecachestat", true, false, true,
			   false, 4, O_CREAT | O_RDWR, 0600) == KSFT_PASS)
		ksft_test_result_pass("cachestat works with a normal file\n");
	else {
		ksft_test_result_fail("cachestat fails with normal file\n");
		ret = 1;
	}

	switch (test_cachestat("tmpfilecachestat", true, false, true,
			       true, 4, O_CREAT | O_RDWR, 0600)) {
	case KSFT_FAIL:
		ksft_test_result_fail("cachestat fsync fails with normal file\n");
		ret = KSFT_FAIL;
		break;
	case KSFT_PASS:
		ksft_test_result_pass("cachestat fsync works with a normal file\n");
		break;
	case KSFT_SKIP:
		ksft_test_result_skip("tmpfilecachestat is on tmpfs\n");
		break;
	}

	if (run_cachestat_test(FILE_SHMEM))
		ksft_test_result_pass("cachestat works with a shmem file\n");
	else {
		ksft_test_result_fail("cachestat fails with a shmem file\n");
		ret = 1;
	}

	if (run_cachestat_test(FILE_MMAP))
		ksft_test_result_pass("cachestat works with a mmap file\n");
	else {
		ksft_test_result_fail("cachestat fails with a mmap file\n");
		ret = 1;
	}

	for (int i = 0; i < ARRAY_SIZE(ovl_tests); i++) {
		const char *desc = ovl_tests[i].desc;

		switch (run_cachestat_overlayfs_test(ovl_tests[i].lower,
						     ovl_tests[i].nested)) {
		case KSFT_FAIL:
			ksft_test_result_fail("cachestat fails with %s\n", desc);
			ret = 1;
			break;
		case KSFT_PASS:
			ksft_test_result_pass("cachestat works with %s\n", desc);
			break;
		case KSFT_SKIP:
			ksft_test_result_skip("overlayfs not available for %s\n",
					      desc);
			break;
		}
	}
	return ret;
}
