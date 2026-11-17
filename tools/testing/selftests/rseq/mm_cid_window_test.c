// SPDX-License-Identifier: LGPL-2.1
/*
 * Two race windows of the concurrency ID mode switches.
 *
 * Each case drives its threads through one sequence that a fix closed.
 * The window is a few instructions wide in the kernel, so the sequence
 * rarely lands in it. The cases vary their timing on each attempt, and
 * pass when the sequence misses the window.
 *
 * A kernel that can make a chosen task sleep inside the window hits it on
 * every attempt. The comments that start with "Delay injection" mark where
 * a thread would ask for that. The commit that adds this test names the
 * matching places in the kernel.
 *
 * Case 1: a failed execve(2) makes the mm switch to per CPU mode. A and B
 * are the two threads of a process on two CPUs. C is the vfork(2) child
 * of B.
 *
 *   CPU 0                                CPU 1
 *
 *   A: execve(2)
 *      leaves the mm
 *                                        B: vfork(2), and waits for C
 *                                        C: joins the mm, takes the last ID
 *                                        C: spins, and never schedules
 *   A: execve(2) fails
 *      rejoins the mm as its third user
 *      the mm switches to per CPU mode
 *   A: is scheduled out, and in again
 *   A: hands the IDs over
 *
 * A must not need an ID when it is scheduled in. B and C hold both, and
 * only A can free one.
 *
 * Case 2: a thread migrates while the mm switches to per CPU mode. M is
 * the main thread. One thread spins on each other CPU, so every ID is
 * taken. T1 and T2 are two of these threads.
 *
 *   CPU 0                         CPU 1                    CPU 2
 *
 *                                 T1: spins                T2: spins, and never
 *                                                              schedules
 *   M: creates one more thread
 *      the mm switches to per
 *      CPU mode
 *                                 T1: sleeps, and is
 *                                     scheduled in again
 *                                 T1: moves to CPU 2
 *                                                          T1: is scheduled in,
 *                                                              beside T2
 *   M: hands the IDs over
 *
 * T1 needs an ID on CPU 2 before M has handed them over. CPU 2 owns none
 * yet, since T2 still holds its own. T1 must find a free one.
 *
 * A kernel that loops looking for a free ID shows as a timeout.
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
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "rseq.h"
#include "kselftest.h"

#define ATTEMPTS	40
#define MAX_DELAY_US	400
#define SPIN_MS		300
#define SLOW_MS		100
#define MAX_SPINNERS	256
#define MOVE_WAIT_MS	2000

#define CHILD_PASS	0
#define CHILD_FAIL	1
#define CHILD_SKIP	2
#define CHILD_ERROR	3

static int go, done, moved, ready, stop;
static int pin_failed;
static int delay_us;
static int cpus[MAX_SPINNERS], nr_cpus;
static char exec_path[PATH_MAX];

static long long now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static void busy_wait_us(int us)
{
	long long end = now_us() + us;

	while (now_us() < end)
		;
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

static int pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/* Fill @cpus with the allowed CPUs. Return their number. */
static int read_allowed_cpus(void)
{
	cpu_set_t set;
	int cpu;

	if (sched_getaffinity(0, sizeof(set), &set))
		return -1;
	nr_cpus = 0;
	for (cpu = 0; cpu < CPU_SETSIZE && nr_cpus < MAX_SPINNERS; cpu++) {
		if (CPU_ISSET(cpu, &set))
			cpus[nr_cpus++] = cpu;
	}
	return CPU_COUNT(&set);
}

/*
 * Create a script that names itself as its interpreter. execve(2) on it
 * leaves the mm, follows the interpreter a few times and fails with ELOOP.
 * That keeps the task out of its mm longer than a file of unknown format.
 */
static int make_loop_script(void)
{
	char *const av[] = { exec_path, NULL };
	FILE *f;

	snprintf(exec_path, sizeof(exec_path), "/tmp/mm_cid_window_test.%d", getpid());
	f = fopen(exec_path, "w");
	if (!f)
		return -1;
	fprintf(f, "#!%s\n", exec_path);
	if (fclose(f) || chmod(exec_path, 0755))
		goto unlink;
	if (execve(exec_path, av, NULL) == -1 && errno == ELOOP)
		return 0;
unlink:
	remove_file(exec_path);
	return -1;
}

/* Run thread B of case 1: call vfork(2) after a delay and wait for C. */
static void *vfork_thread(void *arg)
{
	pid_t pid;

	if (pin(cpus[1])) {
		RSEQ_WRITE_ONCE(pin_failed, 1);
		return NULL;
	}
	while (!RSEQ_READ_ONCE(go))
		;
	busy_wait_us(delay_us);
	pid = vfork();
	if (!pid) {
		long long end = now_us() + SPIN_MS * 1000;

		/* Hold an ID on this CPU without scheduling. */
		while (!RSEQ_READ_ONCE(done) && now_us() < end)
			;
		_exit(0);
	}
	if (pid < 0 || waitpid(pid, NULL, 0) != pid) {
		fprintf(stderr, "vfork: %s\n", strerror(errno));
		abort();
	}
	return NULL;
}

/*
 * Run one attempt of case 1 in a new mm on two CPUs. Return a CHILD_*
 * status.
 */
static int run_child_join(int us)
{
	char *const av[] = { exec_path, NULL };
	long long start, end;
	unsigned int cid;
	pthread_t b;
	int err, exec_errno;

	delay_us = us;
	if (read_allowed_cpus() != 2 || pin(cpus[0]))
		return CHILD_ERROR;
	if (make_loop_script()) {
		fprintf(stderr, "cannot run a script from /tmp\n");
		return CHILD_SKIP;
	}
	if (pthread_create(&b, NULL, vfork_thread, NULL)) {
		remove_file(exec_path);
		return CHILD_ERROR;
	}
	/*
	 * Delay injection: this thread would ask here for two sleeps. One
	 * in execve(2), between leaving the mm and rejoining it. One when
	 * it has changed the mode, before it hands the IDs over. B is
	 * created above, so that it does not inherit the request.
	 */
	usleep(200);
	start = now_us();
	RSEQ_WRITE_ONCE(go, 1);
	execve(exec_path, av, NULL);
	exec_errno = errno;
	end = now_us();
	cid = rseq_current_mm_cid();
	RSEQ_WRITE_ONCE(done, 1);
	err = join_thread(b);
	if (remove_file(exec_path) || err)
		return CHILD_ERROR;
	if (exec_errno != ELOOP) {
		fprintf(stderr, "execve(%s): %s, expected ELOOP\n",
			exec_path, strerror(exec_errno));
		return CHILD_ERROR;
	}

	/* B did not run its part if it could not pin itself. */
	if (pin_failed) {
		fprintf(stderr, "a thread could not pin itself\n");
		return CHILD_ERROR;
	}
	if (cid >= 2) {
		fprintf(stderr, "mm_cid %u after a failed execve, 2 CPUs allowed\n", cid);
		return CHILD_FAIL;
	}
	if (end - start > SLOW_MS * 1000) {
		fprintf(stderr, "the failed execve took %lld ms\n", (end - start) / 1000);
		return CHILD_FAIL;
	}
	return CHILD_PASS;
}

/* Spin on the CPU cpus[@arg], as a thread of case 2. Thread 1 also moves. */
static void *spinner(void *arg)
{
	int nr = (long)arg;

	if (pin(cpus[nr])) {
		RSEQ_WRITE_ONCE(pin_failed, 1);
		return NULL;
	}
	__atomic_add_fetch(&ready, 1, __ATOMIC_RELAXED);
	while (!RSEQ_READ_ONCE(stop)) {
		if (nr != 1 || !RSEQ_READ_ONCE(go) || RSEQ_READ_ONCE(moved))
			continue;
		busy_wait_us(delay_us);
		/* Schedule out and in on this CPU, with the new mode set. */
		usleep(1000);
		/* Move to the CPU of thread 2. It has not scheduled since. */
		if (pin(cpus[2]))
			RSEQ_WRITE_ONCE(pin_failed, 1);
		RSEQ_WRITE_ONCE(moved, 1);
	}
	return NULL;
}

static void *idler(void *arg)
{
	while (!RSEQ_READ_ONCE(stop))
		usleep(1000);
	return NULL;
}

/*
 * Run one attempt of case 2 in a new mm on all CPUs. Return a CHILD_*
 * status.
 */
static int run_child_migrate(int us)
{
	static pthread_t threads[MAX_SPINNERS];
	int i, started = 0, waited = 0, ret = CHILD_PASS;
	pthread_t extra;

	delay_us = us;
	if (read_allowed_cpus() < 3 || pin(cpus[0]))
		return CHILD_ERROR;
	for (i = 1; i < nr_cpus; i++) {
		if (pthread_create(&threads[i], NULL, spinner, (void *)(long)i))
			break;
		started++;
	}
	if (started < nr_cpus - 1) {
		ret = CHILD_ERROR;
		goto out;
	}
	/*
	 * Wait until every thread runs on its CPU and holds an ID. A thread
	 * whose pin failed sets pin_failed and never gets ready.
	 */
	while (RSEQ_READ_ONCE(ready) < started && !RSEQ_READ_ONCE(pin_failed))
		usleep(100);
	if (RSEQ_READ_ONCE(pin_failed))
		goto out;
	usleep(1000);
	/*
	 * Delay injection: this thread would ask here for a sleep when it
	 * has changed the mode to per CPU, before it hands the IDs over.
	 */
	RSEQ_WRITE_ONCE(go, 1);
	if (pthread_create(&extra, NULL, idler, NULL)) {
		ret = CHILD_ERROR;
		goto out;
	}
	while (!RSEQ_READ_ONCE(moved) && waited++ < MOVE_WAIT_MS)
		usleep(1000);
	if (!RSEQ_READ_ONCE(moved)) {
		fprintf(stderr, "the moving thread did not move\n");
		ret = CHILD_FAIL;
	}
	RSEQ_WRITE_ONCE(stop, 1);
	if (join_thread(extra) && ret == CHILD_PASS)
		ret = CHILD_ERROR;
out:
	RSEQ_WRITE_ONCE(stop, 1);
	for (i = 1; i <= started; i++) {
		if (join_thread(threads[i]) && ret == CHILD_PASS)
			ret = CHILD_ERROR;
	}
	/* The sequence did not run as written if a thread could not pin itself. */
	if (pin_failed) {
		fprintf(stderr, "a thread could not pin itself\n");
		ret = CHILD_ERROR;
	}
	return ret;
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

/*
 * Run @fn(@arg) in a new process that starts on the CPUs in @start, and
 * return its exit status. The new process dies with this one.
 */
static int run_under_test(int (*fn)(int), int arg, const cpu_set_t *start,
			  const cpu_set_t *all)
{
	int status = 0;
	pid_t child;

	if (sched_setaffinity(0, sizeof(*start), start))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	child = fork();
	if (!child) {
		if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
			fprintf(stderr, "prctl(PR_SET_PDEATHSIG): %s\n", strerror(errno));
			_exit(CHILD_ERROR);
		}
		_exit(fn(arg));
	}
	if (child < 0)
		ksft_exit_fail_msg("fork: %s\n", strerror(errno));
	if (sched_setaffinity(0, sizeof(*all), all))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	if (waitpid(child, &status, 0) != child)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (!WIFEXITED(status))
		ksft_exit_fail_msg("the process under test was killed by signal %d\n",
				   WTERMSIG(status));
	if (WEXITSTATUS(status) == CHILD_ERROR)
		ksft_exit_fail_msg("the process under test failed to run\n");
	return WEXITSTATUS(status);
}

static void report(int status, const char *name)
{
	if (status == CHILD_SKIP)
		ksft_test_result_skip("%s\n", name);
	else
		ksft_test_result(status == CHILD_PASS, "%s\n", name);
}

int main(void)
{
	const char *join = "failed execve switches to per CPU mode";
	const char *migrate = "thread migrates during the switch to per CPU mode";
	cpu_set_t all, two;
	int status, i, cpu, nr_all;

	ksft_print_header();
	ksft_set_plan(2);

	if (!rseq_available())
		ksft_exit_skip("rseq is unavailable\n");
	if (rseq_register_current_thread())
		ksft_exit_fail_msg("rseq_register_current_thread: %s\n", strerror(errno));
	if (!rseq_mm_cid_available())
		ksft_exit_skip("the rseq mm_cid field is unavailable\n");
	if (sched_getaffinity(0, sizeof(all), &all))
		ksft_exit_fail_msg("sched_getaffinity: %s\n", strerror(errno));
	nr_all = CPU_COUNT(&all);

	if (nr_all < 2) {
		ksft_test_result_skip("%s: fewer than 2 CPUs\n", join);
	} else {
		CPU_ZERO(&two);
		for (cpu = 0; cpu < CPU_SETSIZE && CPU_COUNT(&two) < 2; cpu++) {
			if (CPU_ISSET(cpu, &all))
				CPU_SET(cpu, &two);
		}
		for (i = 0; i < ATTEMPTS; i++) {
			status = run_under_test(run_child_join, (i * 37) % MAX_DELAY_US,
						&two, &all);
			if (status != CHILD_PASS)
				break;
		}
		report(status, join);
	}

	/* Every ID is taken only when one thread spins on each possible CPU. */
	if (nr_all < 3 || nr_all > MAX_SPINNERS || nr_all != read_nr_possible()) {
		ksft_test_result_skip("%s: needs 3 to %d CPUs, all of them allowed\n",
				      migrate, MAX_SPINNERS);
	} else {
		for (i = 0; i < ATTEMPTS; i++) {
			status = run_under_test(run_child_migrate, (i * 37) % MAX_DELAY_US,
						&all, &all);
			if (status != CHILD_PASS)
				break;
		}
		report(status, migrate);
	}
	ksft_finished();
}
