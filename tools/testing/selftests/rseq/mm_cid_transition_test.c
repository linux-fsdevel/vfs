// SPDX-License-Identifier: LGPL-2.1
/*
 * The concurrency IDs while the kernel switches their ownership mode.
 *
 * The kernel lets the tasks own the IDs of an mm while there are few
 * threads. The CPUs own them once there are more threads than IDs. The
 * kernel switches mode when the thread count crosses a threshold. It also
 * does when an affinity change widens the allowed CPUs.
 *
 * Each round creates a few threads and joins them, so the thread count
 * crosses both thresholds. A round has three kinds of threads:
 * - Most threads count in an array indexed by their mm_cid, with an rseq
 *   critical section and no lock. Two threads that run with the same
 *   mm_cid at the same time lose counts.
 * - One thread fails execve(2) in a loop. It leaves the mm and rejoins
 *   it.
 * - One thread calls vfork(2) in a loop. The child is a user of the mm
 *   until it exits. It can join while the thread above is out.
 *
 * A second case starts on two CPUs and widens the affinity of a thread
 * while the others count.
 *
 * A third case leaves the affinity changes to another process. It narrows
 * and widens every thread in a loop, while the threads count, call
 * vfork(2) and then exit with their process.
 *
 * The test fails when counts are lost, or when an mm_cid is not below the
 * number of possible CPUs. A kernel that loops looking for a free ID
 * shows as a timeout.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rseq.h"
#include "kselftest.h"

#define MAX_CIDS	CPU_SETSIZE
#define MAX_WORKERS	16
#define ROUNDS		200
#define WIDEN_RUNS	100
#define ROUND_US	500
#define MAX_TRIES	1000000

#define CHILD_PASS	0
#define CHILD_FAIL	1
#define CHILD_ERROR	2

struct worker {
	pthread_t	thread;
	intptr_t	counted;
	unsigned int	bad_cid;
	bool		execs;
	bool		vforks;
};

static intptr_t counts[MAX_CIDS];
static struct worker workers[MAX_WORKERS];
static int stop;
static int nr_possible;
static cpu_set_t all_cpus;
static char exec_path[PATH_MAX];

/* Add one to the count of the current mm_cid. */
static void count_one(struct worker *w)
{
	for (;;) {
		unsigned int cid = rseq_current_mm_cid();

		if (cid >= (unsigned int)nr_possible || cid >= MAX_CIDS) {
			w->bad_cid = cid;
			return;
		}
		if (!rseq_addv(RSEQ_MO_RELAXED, RSEQ_PERCPU_MM_CID, &counts[cid], 1, cid)) {
			w->counted++;
			return;
		}
	}
}

static int join_failed;

/* Join @t. Report an error and set join_failed if that fails. */
static void join_thread(pthread_t t)
{
	int err = pthread_join(t, NULL);

	if (err) {
		fprintf(stderr, "pthread_join: %s\n", strerror(err));
		RSEQ_WRITE_ONCE(join_failed, 1);
	}
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

static void *worker_fn(void *arg)
{
	struct worker *w = arg;
	char *const av[] = { exec_path, NULL };
	int i;

	if (rseq_register_current_thread())
		abort();
	while (!RSEQ_READ_ONCE(stop) && w->bad_cid == UINT_MAX) {
		for (i = 0; i < 100; i++)
			count_one(w);
		if (w->execs && execve(exec_path, av, NULL) == -1 && errno != ENOEXEC) {
			fprintf(stderr, "execve: %s, expected ENOEXEC\n", strerror(errno));
			abort();
		}
		if (w->vforks) {
			pid_t pid = vfork();

			if (!pid)
				_exit(0);
			if (pid < 0 || waitpid(pid, NULL, 0) != pid) {
				fprintf(stderr, "vfork: %s\n", strerror(errno));
				abort();
			}
		}
	}
	rseq_unregister_current_thread();
	return NULL;
}

/* Run @nr workers for a while, one of them failing execve(2). */
static int run_round(int nr, int widen_us)
{
	int i, started = 0, widened = 1;

	RSEQ_WRITE_ONCE(stop, 0);
	for (i = 0; i < nr; i++) {
		int err, tries = 0;

		workers[i].execs = i == 0 && exec_path[0];
		workers[i].vforks = i == 1;
		/* clone(CLONE_FS) fails with EAGAIN while a thread is in execve. */
		do {
			err = pthread_create(&workers[i].thread, NULL, worker_fn, &workers[i]);
			if (err == EAGAIN)
				sched_yield();
		} while (err == EAGAIN && ++tries < MAX_TRIES);
		if (err)
			break;
		started++;
	}
	if (widen_us >= 0) {
		usleep(widen_us);
		/* The union of allowed CPUs of the mm grows. */
		if (sched_setaffinity(0, sizeof(all_cpus), &all_cpus)) {
			fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
			widened = 0;
		}
	}
	usleep(ROUND_US);
	RSEQ_WRITE_ONCE(stop, 1);
	for (i = 0; i < started; i++)
		join_thread(workers[i].thread);
	return started == nr && widened && !RSEQ_READ_ONCE(join_failed) ? 0 : -1;
}

/* Compare the counts of the array with the counts of the workers. */
static int check_counts(const char *what)
{
	intptr_t counted = 0, total = 0;
	int i, ret = CHILD_PASS;

	for (i = 0; i < MAX_WORKERS; i++) {
		counted += workers[i].counted;
		if (workers[i].bad_cid != UINT_MAX) {
			fprintf(stderr, "%s: mm_cid %u (0x%x), %d possible CPUs\n",
				what, workers[i].bad_cid, workers[i].bad_cid, nr_possible);
			ret = CHILD_FAIL;
		}
	}
	for (i = 0; i < MAX_CIDS; i++)
		total += counts[i];
	if (total != counted) {
		fprintf(stderr, "%s: %ld counts lost out of %ld: two threads ran with one mm_cid\n",
			what, (long)(counted - total), (long)counted);
		ret = CHILD_FAIL;
	}
	return ret;
}

static void init_workers(void)
{
	int i;

	for (i = 0; i < MAX_WORKERS; i++)
		workers[i].bad_cid = UINT_MAX;
}

/*
 * A file no binfmt handler recognises, in @dir. execve(2) on it fails with
 * ENOEXEC after sched_mm_cid_before_execve() and before the other threads
 * are killed.
 */
static int make_unknown_format_file(const char *dir)
{
	static const char junk[] = "not a binary of any known format\n";
	char *const av[] = { exec_path, NULL };
	bool written;
	int fd;

	snprintf(exec_path, sizeof(exec_path), "%s/mm_cid_transition_test.XXXXXX", dir);
	fd = mkstemp(exec_path);
	if (fd < 0)
		goto fail;
	written = write(fd, junk, sizeof(junk) - 1) == (ssize_t)sizeof(junk) - 1 &&
		  !fchmod(fd, 0755);
	if (close(fd) || !written)
		goto unlink;
	if (execve(exec_path, av, NULL) == -1 && errno == ENOEXEC)
		return 0;
unlink:
	remove_file(exec_path);
fail:
	exec_path[0] = '\0';
	return -1;
}

/* Rounds of 1 to MAX_WORKERS threads: the count crosses both thresholds. */
static int run_child_rounds(int unused)
{
	int round, ret;

	init_workers();
	/* Without the file the rounds run with no execve. */
	if (make_unknown_format_file("/tmp") && make_unknown_format_file("."))
		fprintf(stderr, "no unknown format file: the rounds run without execve\n");
	for (round = 0; round < ROUNDS; round++) {
		if (run_round(1 + (round * 7) % MAX_WORKERS, -1)) {
			ret = CHILD_ERROR;
			goto out;
		}
	}
	ret = check_counts("thread count changes");
out:
	if (exec_path[0] && remove_file(exec_path) && ret == CHILD_PASS)
		ret = CHILD_ERROR;
	return ret;
}

/* Run one round that widens the allowed CPUs @delay_us after its start. */
static int run_child_widen(int delay_us)
{
	init_workers();
	if (run_round(3, delay_us))
		return CHILD_ERROR;
	return check_counts("affinity change");
}

/*
 * Narrow and widen the affinity of every thread of @pid in a loop, from
 * another process. Start after @delay_us and run until @pid exits.
 */
static void remote_setter(pid_t pid, int delay_us, const cpu_set_t *narrow)
{
	bool widen = true;
	char path[64];

	/* Die with the process under test, not before its exit. */
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	usleep(delay_us);
	while (getppid() == pid) {
		DIR *dir = opendir(path);
		struct dirent *de;

		if (!dir)
			break;
		while ((de = readdir(dir))) {
			pid_t tid = atoi(de->d_name);

			/* A thread can exit first: ESRCH is expected. */
			if (tid > 0)
				sched_setaffinity(tid, sizeof(all_cpus),
						  widen ? &all_cpus : narrow);
		}
		closedir(dir);
		widen = !widen;
	}
	_exit(0);
}

/* Run one round while another process changes the affinity of the threads. */
static int run_child_remote(int delay_us)
{
	pid_t self = getpid(), setter;
	cpu_set_t narrow;

	if (sched_getaffinity(0, sizeof(narrow), &narrow))
		return CHILD_ERROR;
	init_workers();
	setter = fork();
	if (setter < 0)
		return CHILD_ERROR;
	if (!setter)
		remote_setter(self, delay_us, &narrow);
	if (run_round(3, -1))
		return CHILD_ERROR;
	/* The setter keeps running while this process exits. */
	return check_counts("affinity change by another process");
}

static int read_nr_possible(void)
{
	int first, last, total = 0;
	char sep;
	FILE *f;

	f = fopen("/sys/devices/system/cpu/possible", "r");
	if (!f)
		return -1;
	/* A list of ranges: "0-63" or "0,2-5". */
	while (fscanf(f, "%d", &first) == 1) {
		last = first;
		sep = '\n';
		if (fscanf(f, "%c", &sep) == 1 && sep == '-') {
			if (fscanf(f, "%d", &last) != 1)
				break;
			if (fscanf(f, "%c", &sep) != 1)
				sep = '\n';
		}
		total += last - first + 1;
		if (sep != ',')
			break;
	}
	fclose(f);
	return total;
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
static int run_under_test(int (*fn)(int), int arg, const cpu_set_t *narrow)
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
	if (sched_setaffinity(0, sizeof(all_cpus), &all_cpus))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	if (waitpid(child, &status, 0) != child)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (!WIFEXITED(status))
		ksft_exit_fail_msg("the process under test was killed by signal %d\n",
				   WTERMSIG(status));
	if (WEXITSTATUS(status) > CHILD_FAIL)
		ksft_exit_fail_msg("the process under test failed to run\n");
	return WEXITSTATUS(status);
}

int main(void)
{
	cpu_set_t narrow;
	int status, i;

	ksft_print_header();
	ksft_set_plan(4);

	if (!rseq_available())
		ksft_exit_skip("rseq is unavailable\n");
	if (rseq_register_current_thread())
		ksft_exit_fail_msg("rseq_register_current_thread: %s\n", strerror(errno));
	if (!rseq_mm_cid_available())
		ksft_exit_skip("the rseq mm_cid field is unavailable\n");
	if (sched_getaffinity(0, sizeof(all_cpus), &all_cpus))
		ksft_exit_fail_msg("sched_getaffinity: %s\n", strerror(errno));
	nr_possible = read_nr_possible();
	if (nr_possible <= 0)
		ksft_exit_skip("cannot read the possible CPUs\n");

	narrow_cpus(&narrow, &all_cpus, 4);
	status = run_under_test(run_child_rounds, 0, &narrow);
	ksft_test_result(status == CHILD_PASS, "thread count changes on at most 4 CPUs\n");

	status = run_under_test(run_child_rounds, 0, &all_cpus);
	ksft_test_result(status == CHILD_PASS, "thread count changes on all CPUs\n");

	narrow_cpus(&narrow, &all_cpus, 2);
	for (i = 0; i < WIDEN_RUNS; i++) {
		status = run_under_test(run_child_widen, (i * 13) % ROUND_US, &narrow);
		if (status != CHILD_PASS)
			break;
	}
	ksft_test_result(status == CHILD_PASS, "affinity change widens the allowed CPUs\n");

	for (i = 0; i < WIDEN_RUNS; i++) {
		status = run_under_test(run_child_remote, (i * 13) % ROUND_US, &narrow);
		if (status != CHILD_PASS)
			break;
	}
	ksft_test_result(status == CHILD_PASS, "affinity changed by another process\n");
	ksft_finished();
}
