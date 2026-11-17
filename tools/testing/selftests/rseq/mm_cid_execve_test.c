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
 * A second case covers the last user. A process that is back to a single
 * thread fails execve(2) while another process moves it to another CPU.
 * It leaves its mm as the last user on one CPU and rejoins it as the first
 * user on the other. A single thread must read 0 afterwards. That case
 * needs per CPU mode to last down to one thread. With the two allowed CPUs
 * of the test, the kernel only does that with at most three possible
 * CPUs. The case is skipped when a single thread reads 0 on both CPUs
 * before the execve(2).
 *
 * A third case covers the last user on a machine of any size. The kernel
 * also keeps per CPU mode down to one thread when the mm counts one
 * allowed CPU. The case makes such a thread run on a second CPU. The
 * diagram above run_child_widened() has the sequence.
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
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "rseq.h"
#include "kselftest.h"

#define NARROW_CPUS	2
#define THREADS		4
#define ROUNDS		100
#define ATTEMPTS	50
#define MOVE_EXECS	300

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

/* Run on @cpu and return the mm_cid read there. */
static unsigned int cid_on_cpu(int cpu)
{
	cpu_set_t one;

	CPU_ZERO(&one);
	CPU_SET(cpu, &one);
	if (sched_setaffinity(0, sizeof(one), &one))
		return UINT_MAX;
	return rseq_current_mm_cid();
}

/*
 * The second process under test. Its threads make the mm switch to per
 * CPU mode and exit. The last thread then fails execve(2) in a loop on the
 * CPU @from. A helper process moves it to the CPU @to, @delay_us after the
 * start of the loop. The thread then visits both CPUs and must read 0 on
 * each.
 * Return a CHILD_* status.
 */
static int run_child_moved(int delay_us)
{
	pthread_t thread[THREADS];
	char path[PATH_MAX];
	int cpus[NARROW_CPUS], nr = 0, cpu, i, started = 0, ret = CHILD_PASS;
	int from, to, go[2], status;
	unsigned int cid0, cid1;
	cpu_set_t mask, one;
	pid_t helper, self = getpid();
	char c = 0;

	if (sched_getaffinity(0, sizeof(mask), &mask))
		return CHILD_ERROR;
	for (cpu = 0; cpu < CPU_SETSIZE && nr < NARROW_CPUS; cpu++) {
		if (CPU_ISSET(cpu, &mask))
			cpus[nr++] = cpu;
	}
	if (nr < NARROW_CPUS) {
		fprintf(stderr, "fewer than %d allowed CPUs\n", NARROW_CPUS);
		return CHILD_SKIP;
	}
	if (make_unknown_format_file(path, sizeof(path))) {
		fprintf(stderr, "no directory to run an unknown format file from\n");
		return CHILD_SKIP;
	}

	for (i = 0; i < THREADS; i++) {
		if (pthread_create(&thread[i], NULL, waiter, NULL))
			break;
		started++;
	}
	/* Run on both CPUs while the threads exist: each CPU takes a CID. */
	for (i = 0; i < 2 * NARROW_CPUS; i++)
		cid_on_cpu(cpus[i % NARROW_CPUS]);
	RSEQ_WRITE_ONCE(stop, 1);
	for (i = 0; i < started; i++) {
		if (join_thread(thread[i]))
			ret = CHILD_ERROR;
	}
	if (ret != CHILD_PASS || started < THREADS) {
		ret = CHILD_ERROR;
		goto out;
	}

	cid0 = cid_on_cpu(cpus[0]);
	cid1 = cid_on_cpu(cpus[1]);
	if (cid0 == UINT_MAX || cid1 == UINT_MAX) {
		ret = CHILD_ERROR;
		goto out;
	}
	/* The CPUs own the CIDs only if one of them reads above 0. */
	if (!cid0 && !cid1) {
		fprintf(stderr, "the mm is not in per CPU mode with a single thread\n");
		ret = CHILD_SKIP;
		goto out;
	}
	/* Leave from the CPU that does not hold CID 0, rejoin on the other. */
	from = cid0 ? cpus[0] : cpus[1];
	to = from == cpus[0] ? cpus[1] : cpus[0];
	cid_on_cpu(from);

	if (pipe(go)) {
		ret = CHILD_ERROR;
		goto out;
	}
	helper = fork();
	if (helper < 0) {
		close(go[0]);
		close(go[1]);
		ret = CHILD_ERROR;
		goto out;
	}
	if (!helper) {
		/* Run beside the process under test, not on its CPU. */
		CPU_ZERO(&one);
		CPU_SET(to, &one);
		if (sched_setaffinity(0, sizeof(one), &one) || read(go[0], &c, 1) != 1)
			_exit(1);
		usleep(delay_us);
		_exit(!!sched_setaffinity(self, sizeof(one), &one));
	}
	if (write(go[1], &c, 1) != 1) {
		/* The helper waits for that byte. */
		kill(helper, SIGKILL);
		ret = CHILD_ERROR;
	}
	for (i = 0; i < MOVE_EXECS; i++) {
		char *const av[] = { path, NULL };

		if (execve(path, av, NULL) == -1 && errno != ENOEXEC) {
			fprintf(stderr, "execve(%s): %s, expected ENOEXEC\n",
				path, strerror(errno));
			ret = CHILD_ERROR;
			break;
		}
	}
	if (waitpid(helper, &status, 0) != helper || !WIFEXITED(status) ||
	    WEXITSTATUS(status))
		ret = CHILD_ERROR;
	close(go[0]);
	close(go[1]);

	/* The first visit lets the kernel settle, the second one is judged. */
	for (i = 0; i < 2 * NARROW_CPUS && ret == CHILD_PASS; i++) {
		unsigned int cid = cid_on_cpu(cpus[i % NARROW_CPUS]);

		if (cid == UINT_MAX) {
			ret = CHILD_ERROR;
		} else if (i >= NARROW_CPUS && cid) {
			fprintf(stderr,
				"single thread, mm_cid %u on CPU %d after a failed execve moved from CPU %d to CPU %d\n",
				cid, cpus[i % NARROW_CPUS], from, to);
			ret = CHILD_FAIL;
		}
	}
out:
	if (remove_file(path) && ret == CHILD_PASS)
		ret = CHILD_ERROR;
	return ret;
}

/* What the process under test and its helper share in run_child_widened(). */
struct widen_shared {
	int phase;
	int widened;
};

static int widen_cpu[NARROW_CPUS];

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Spin until @sh->phase reaches @phase. Return false after two seconds. */
static bool widen_wait(struct widen_shared *sh, int phase)
{
	uint64_t end = now_ms() + 2000;

	while (RSEQ_READ_ONCE(sh->phase) < phase) {
		if (now_ms() > end)
			return false;
	}
	return true;
}

/*
 * The helper of run_child_widened(). @pid is the process under test, which
 * starts on the CPU @a.
 * - Phase 1: widen the affinity of @pid to @a and @b, @delay_us after the
 *   start of its first execve(2) loop.
 * - Phase 2: keep the CPU @a busy, so that the scheduler moves @pid to @b.
 * - Phase 3: move @pid back to @a, @delay_us after the start of its second
 *   execve(2) loop.
 * Return the exit status of the helper.
 */
static int widen_helper(struct widen_shared *sh, pid_t pid, int a, int b, int delay_us)
{
	cpu_set_t set;

	/* Run beside the process under test, not on its CPU. */
	CPU_ZERO(&set);
	CPU_SET(b, &set);
	if (sched_setaffinity(0, sizeof(set), &set) || !widen_wait(sh, 1))
		return 1;
	usleep(delay_us);
	CPU_SET(a, &set);
	if (sched_setaffinity(pid, sizeof(set), &set))
		return 1;
	RSEQ_WRITE_ONCE(sh->widened, 1);

	if (!widen_wait(sh, 2))
		return 1;
	CPU_ZERO(&set);
	CPU_SET(a, &set);
	if (sched_setaffinity(0, sizeof(set), &set) || !widen_wait(sh, 3))
		return 1;
	usleep(delay_us);
	return !!sched_setaffinity(pid, sizeof(set), &set);
}

/*
 * Fail execve(2) on @path MOVE_EXECS times. Return 0, or -1 after reporting
 * an error other than ENOEXEC.
 */
static int fail_execs(char *path)
{
	int i;

	for (i = 0; i < MOVE_EXECS; i++) {
		char *const av[] = { path, NULL };

		if (execve(path, av, NULL) == -1 && errno != ENOEXEC) {
			fprintf(stderr, "execve(%s): %s, expected ENOEXEC\n",
				path, strerror(errno));
			return -1;
		}
	}
	return 0;
}

/*
 * The third process under test, P. A and B are two CPUs. P starts with A
 * as its only allowed CPU. H is a helper process. It makes the affinity
 * changes: a change made by P itself would reach the mm.
 *
 *   P                                     H
 *
 *   execve() fails, in a loop
 *     leaves the mm: no user left
 *                                         sched_setaffinity(P, {A, B})
 *                                           the mm has no user: its count
 *                                           of allowed CPUs stays 1
 *     rejoins the mm
 *   creates a thread
 *     the mm switches to per CPU mode
 *   joins the thread
 *     one user left, still per CPU mode
 *                                         keeps A busy
 *   is moved to B by the scheduler
 *     A and B each own a CID
 *   execve() fails, in a loop
 *     leaves the mm on B: no user left
 *                                         sched_setaffinity(P, {A})
 *     rejoins the mm on A
 *   visits A and B
 *
 * P must read 0 on both CPUs at the end. Each change of H has to land
 * while P is inside an execve(), so the case runs many times with a
 * different delay.
 * Return a CHILD_* status.
 */
static int run_child_widened(int delay_us)
{
	int a = widen_cpu[0], b = widen_cpu[1], i, status, ret = CHILD_PASS;
	struct widen_shared *sh;
	pid_t helper, self = getpid();
	char path[PATH_MAX];
	pthread_t thread;
	uint64_t end;

	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED)
		return CHILD_ERROR;
	if (make_unknown_format_file(path, sizeof(path))) {
		fprintf(stderr, "no directory to run an unknown format file from\n");
		return CHILD_SKIP;
	}
	helper = fork();
	if (helper < 0) {
		remove_file(path);
		return CHILD_ERROR;
	}
	if (!helper)
		_exit(widen_helper(sh, self, a, b, delay_us));

	RSEQ_WRITE_ONCE(sh->phase, 1);
	if (fail_execs(path)) {
		ret = CHILD_ERROR;
		goto out;
	}
	end = now_ms() + 2000;
	while (!RSEQ_READ_ONCE(sh->widened) && now_ms() < end)
		;
	if (!RSEQ_READ_ONCE(sh->widened)) {
		ret = CHILD_ERROR;
		goto out;
	}

	if (pthread_create(&thread, NULL, waiter, NULL)) {
		ret = CHILD_ERROR;
		goto out;
	}
	RSEQ_WRITE_ONCE(stop, 1);
	if (join_thread(thread)) {
		ret = CHILD_ERROR;
		goto out;
	}

	/* No affinity change by this process: it would reach the mm. */
	RSEQ_WRITE_ONCE(sh->phase, 2);
	end = now_ms() + 2000;
	while (sched_getcpu() != b && now_ms() < end)
		;
	if (sched_getcpu() != b) {
		fprintf(stderr, "the scheduler did not move the process to CPU %d\n", b);
		ret = CHILD_SKIP;
		goto out;
	}

	RSEQ_WRITE_ONCE(sh->phase, 3);
	if (fail_execs(path)) {
		ret = CHILD_ERROR;
		goto out;
	}
out:
	if (ret != CHILD_PASS)
		kill(helper, SIGKILL);
	if (waitpid(helper, &status, 0) != helper ||
	    (ret == CHILD_PASS && (!WIFEXITED(status) || WEXITSTATUS(status))))
		ret = CHILD_ERROR;
	if (remove_file(path) && ret == CHILD_PASS)
		ret = CHILD_ERROR;

	/* The first visit lets the kernel settle, the second one is judged. */
	for (i = 0; i < 2 * NARROW_CPUS && ret == CHILD_PASS; i++) {
		unsigned int cid = cid_on_cpu(widen_cpu[i % NARROW_CPUS]);

		if (cid == UINT_MAX) {
			ret = CHILD_ERROR;
		} else if (i >= NARROW_CPUS && cid) {
			fprintf(stderr,
				"single thread, mm_cid %u on CPU %d after a move from CPU %d to CPU %d\n",
				cid, widen_cpu[i % NARROW_CPUS], b, a);
			ret = CHILD_FAIL;
		}
	}
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

/*
 * Run @fn(@arg) in a new process and return its exit status. The affinity
 * is @narrow when its mm is created. The union of allowed CPUs of an mm
 * starts there and only grows.
 */
static int run_under_test(int (*fn)(int), int arg, const cpu_set_t *narrow,
			  const cpu_set_t *allowed)
{
	int status = 0;
	pid_t child;

	if (sched_setaffinity(0, sizeof(*narrow), narrow))
		ksft_exit_skip("sched_setaffinity: %s\n", strerror(errno));
	child = fork();
	if (!child)
		_exit(fn(arg));
	if (child < 0)
		ksft_exit_fail_msg("fork: %s\n", strerror(errno));
	if (sched_setaffinity(0, sizeof(*allowed), allowed))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	if (waitpid(child, &status, 0) != child)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (!WIFEXITED(status))
		ksft_exit_fail_msg("the process under test was killed by signal %d\n",
				   WTERMSIG(status));
	return WEXITSTATUS(status);
}

static void report(int status, const char *name)
{
	switch (status) {
	case CHILD_PASS:
		ksft_test_result_pass("%s\n", name);
		break;
	case CHILD_SKIP:
		ksft_test_result_skip("%s\n", name);
		break;
	case CHILD_FAIL:
		ksft_test_result_fail("%s\n", name);
		break;
	default:
		ksft_exit_fail_msg("the process under test failed to run\n");
	}
}

static int run_child_threads(int unused)
{
	return run_child();
}

int main(void)
{
	static const char widened[] =
		"mm_cid of a single thread after its affinity was widened during execve";
	cpu_set_t allowed, narrow, one;
	int status, i, cpu, nr = 0;

	ksft_print_header();
	ksft_set_plan(3);

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

	status = run_under_test(run_child_threads, 0, &narrow, &allowed);
	report(status, "mm_cid after a failed execve");

	/* The helper's move has to land inside an execve: spread its delay. */
	for (i = 0; i < ATTEMPTS; i++) {
		status = run_under_test(run_child_moved, (i * 37) % 1000, &narrow, &allowed);
		if (status != CHILD_PASS)
			break;
	}
	report(status, "mm_cid of a single thread after a failed execve on another CPU");

	for (cpu = 0; cpu < CPU_SETSIZE && nr < NARROW_CPUS; cpu++) {
		if (CPU_ISSET(cpu, &narrow))
			widen_cpu[nr++] = cpu;
	}
	if (nr < NARROW_CPUS) {
		ksft_test_result_skip("%s: fewer than %d CPUs\n", widened, NARROW_CPUS);
		ksft_finished();
	}
	narrow_cpus(&one, &allowed, 1);
	/* Both changes of the helper have to land inside an execve. */
	for (i = 0; i < 2 * ATTEMPTS; i++) {
		status = run_under_test(run_child_widened, (i * 37) % 1000, &one, &allowed);
		if (status != CHILD_PASS)
			break;
	}
	report(status, widened);
	ksft_finished();
}
