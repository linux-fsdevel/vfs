// SPDX-License-Identifier: LGPL-2.1
/*
 * The concurrency ID a thread reports after a failed execve(2).
 *
 * sched_mm_cid_fork() makes a task a user of the CIDs of its mm. In per
 * CPU mode a new user gets no CID there. It takes the CID of its CPU when
 * it is scheduled in. A failed execve(2) rejoins its mm while the task is
 * running and the other threads are still users. The task returns to user
 * space before any schedule in, so the join has to give it a CID.
 *
 * Per CPU mode needs more threads than the mm has CIDs. The number of CIDs
 * follows the union of the allowed CPUs of the threads, which only grows.
 * The affinity is therefore narrowed before the fork(2) that creates the
 * process under test. A few threads are then enough on any machine.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rseq.h"
#include "kselftest.h"

#define NARROW_CPUS	2
#define THREADS		4
#define ROUNDS		100

/* Exit status of the process under test. */
#define CHILD_PASS	0
#define CHILD_FAIL	1
#define CHILD_SKIP	2
#define CHILD_ERROR	3

static int stop;

/*
 * Stay alive as a user of the CIDs of the mm while the execve(2) below
 * leaves the mm and rejoins it. A thread needs no rseq area for that.
 */
static void *waiter(void *arg)
{
	while (!RSEQ_READ_ONCE(stop))
		(void)sched_yield();
	return NULL;
}

/* Join @t. Return 0, or the error number after reporting it. */
static int join_thread(pthread_t t)
{
	int err = pthread_join(t, NULL);

	if (err)
		fprintf(stderr, "pthread_join: %s\n", strerror(err));
	return err;
}

/* Remove @path. Return 0, or -1 after reporting the error. */
static int remove_file(const char *path)
{
	if (unlink(path)) {
		fprintf(stderr, "unlink %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

/* The directory of the test's executable, "." when it cannot be read. */
static const char *test_dir(char *buf, size_t len)
{
	ssize_t n = readlink("/proc/self/exe", buf, len - 1);
	char *slash;

	if (n <= 0)
		return ".";
	buf[n] = '\0';
	slash = strrchr(buf, '/');
	if (!slash)
		return ".";
	*slash = '\0';
	return slash == buf ? "/" : buf;
}

/*
 * Create a file that no binfmt handler recognises and leave its path in
 * @path. execve(2) on it reaches sched_mm_cid_before_execve(). It then
 * fails with ENOEXEC before begin_new_exec() kills the other threads. A
 * path that does not exist would fail before bprm_execve().
 *
 * The directory must allow execution. Try the directory of the test first,
 * then /tmp. Return 0 on success. One execve(2) is done as a check.
 */
static int make_unknown_format_file(char *path, size_t len)
{
	char self[PATH_MAX];
	const char *const dirs[] = { test_dir(self, sizeof(self)), "/tmp" };
	static const char junk[] = "not a binary of any known format\n";
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		char *const av[] = { path, NULL };
		bool written;
		int fd;

		snprintf(path, len, "%s/mm_cid_execve_test.XXXXXX", dirs[i]);
		fd = mkstemp(path);
		if (fd < 0)
			continue;
		written = write(fd, junk, sizeof(junk) - 1) == (ssize_t)sizeof(junk) - 1 &&
			  !fchmod(fd, 0755);
		/* An open file would make execve(2) fail with ETXTBSY. */
		if (close(fd) || !written) {
			remove_file(path);
			continue;
		}
		if (execve(path, av, NULL) == -1 && errno == ENOEXEC)
			return 0;
		remove_file(path);
	}
	return -1;
}

/*
 * The process under test. Start THREADS threads on a narrow set of CPUs.
 * Then fail execve(2) in a loop and read the mm_cid after each call.
 * Return a CHILD_* status.
 */
static int run_child(void)
{
	pthread_t thread[THREADS];
	char path[PATH_MAX];
	unsigned int nr_cids, worst = 0;
	cpu_set_t mask;
	int i, err = 0, started = 0, ret = CHILD_PASS;

	/* The mm has no more IDs than CPUs its threads may run on. */
	if (sched_getaffinity(0, sizeof(mask), &mask)) {
		fprintf(stderr, "sched_getaffinity: %s\n", strerror(errno));
		return CHILD_ERROR;
	}
	nr_cids = CPU_COUNT(&mask);

	if (make_unknown_format_file(path, sizeof(path))) {
		fprintf(stderr, "no directory to run an unknown format file from: %s\n",
			strerror(errno));
		return CHILD_SKIP;
	}

	for (i = 0; i < THREADS; i++) {
		err = pthread_create(&thread[i], NULL, waiter, NULL);
		if (err)
			break;
		started++;
	}
	if (started < THREADS) {
		fprintf(stderr, "pthread_create: %s\n", strerror(err));
		ret = CHILD_ERROR;
		goto out;
	}

	for (i = 0; i < ROUNDS; i++) {
		char *const av[] = { path, NULL };
		unsigned int cid;

		if (!execve(path, av, NULL)) {
			fprintf(stderr, "execve(%s) succeeded, expected ENOEXEC\n", path);
			ret = CHILD_ERROR;
			goto out;
		}
		if (errno != ENOEXEC) {
			fprintf(stderr, "execve(%s): %s, expected ENOEXEC\n",
				path, strerror(errno));
			ret = CHILD_ERROR;
			goto out;
		}
		cid = rseq_current_mm_cid();
		if (cid > worst)
			worst = cid;
		if (cid >= nr_cids) {
			fprintf(stderr, "mm_cid %u (0x%x) after a failed execve, round %d of %d\n",
				cid, cid, i, ROUNDS);
			ret = CHILD_FAIL;
			goto out;
		}
	}
	fprintf(stderr, "%d threads, %d failed execve, largest mm_cid %u, below %u\n",
		started + 1, ROUNDS, worst, nr_cids);
out:
	RSEQ_WRITE_ONCE(stop, 1);
	for (i = 0; i < started; i++) {
		if (join_thread(thread[i]) && ret == CHILD_PASS)
			ret = CHILD_ERROR;
	}
	if (remove_file(path) && ret == CHILD_PASS)
		ret = CHILD_ERROR;
	return ret;
}

/* Keep the first @nr CPUs of @src in @dst. */
static int narrow_cpus(cpu_set_t *dst, const cpu_set_t *src, int nr)
{
	int cpu, taken = 0;

	CPU_ZERO(dst);
	for (cpu = 0; cpu < CPU_SETSIZE && taken < nr; cpu++) {
		if (!CPU_ISSET(cpu, src))
			continue;
		CPU_SET(cpu, dst);
		taken++;
	}
	return taken;
}

int main(void)
{
	cpu_set_t allowed, narrow;
	int status = 0;
	pid_t child;

	ksft_print_header();
	ksft_set_plan(1);

	if (!rseq_available())
		ksft_exit_skip("rseq is unavailable\n");
	/* glibc before 2.35 registers no rseq area. */
	if (rseq_register_current_thread())
		ksft_exit_fail_msg("rseq_register_current_thread: %s\n", strerror(errno));
	if (!rseq_mm_cid_available())
		ksft_exit_skip("the rseq mm_cid field is unavailable\n");
	if (sched_getaffinity(0, sizeof(allowed), &allowed))
		ksft_exit_fail_msg("sched_getaffinity: %s\n", strerror(errno));
	if (!narrow_cpus(&narrow, &allowed, NARROW_CPUS))
		ksft_exit_skip("no CPU to run on\n");

	/*
	 * Narrow before the fork(2). The mm of the child starts with these
	 * allowed CPUs, and a later narrowing does not shrink them.
	 */
	if (sched_setaffinity(0, sizeof(narrow), &narrow))
		ksft_exit_skip("sched_setaffinity: %s\n", strerror(errno));
	child = fork();
	if (!child)
		_exit(run_child());
	if (child < 0)
		ksft_exit_fail_msg("fork: %s\n", strerror(errno));
	if (sched_setaffinity(0, sizeof(allowed), &allowed))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	if (waitpid(child, &status, 0) != child)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (!WIFEXITED(status))
		ksft_exit_fail_msg("the process under test was killed by signal %d\n",
				   WTERMSIG(status));

	switch (WEXITSTATUS(status)) {
	case CHILD_PASS:
		ksft_test_result_pass("mm_cid after a failed execve\n");
		break;
	case CHILD_SKIP:
		ksft_test_result_skip("mm_cid after a failed execve\n");
		break;
	case CHILD_FAIL:
		ksft_test_result_fail("mm_cid after a failed execve\n");
		break;
	default:
		ksft_exit_fail_msg("the process under test failed to run\n");
	}
	ksft_finished();
}
