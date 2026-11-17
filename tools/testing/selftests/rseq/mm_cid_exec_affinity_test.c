// SPDX-License-Identifier: LGPL-2.1
/*
 * The concurrency IDs after another process widens the affinity of a task
 * during its execve(2).
 *
 * The kernel sizes the IDs of an mm from the CPUs its threads are allowed
 * on. execve(2) copies the allowed CPUs of the task when it switches to
 * its new mm. The task becomes a user of the IDs of that mm later. An
 * affinity change in between comes from another task. The new mm has to
 * see it.
 *
 * A process starts on one CPU and calls execve(2) on this test. The parent
 * widens its affinity to all CPUs after a delay. The delay differs on each
 * attempt, so that some changes land inside the execve(2).
 *
 * The new program waits until it is allowed on all CPUs. It starts one
 * spinning thread per CPU, lets them spread, then stops all but one. With
 * two threads left, both must read an mm_cid below 2. A first case runs
 * the same program with all CPUs allowed from the start.
 *
 * The new program does not change its own affinity. Such a change would
 * update the allowed CPUs of its mm.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "rseq.h"
#include "kselftest.h"

#define MIN_CPUS	4
#define MAX_SPINNERS	64
#define ATTEMPTS	60
#define MAX_DELAY_US	1500
#define SPREAD_US	50000
#define SETTLE_US	50000
#define WIDE_WAIT_US	5000000

#define CHILD_PASS	0
#define CHILD_FAIL	1
#define CHILD_ERROR	2

struct spinner {
	pthread_t	thread;
	unsigned int	cid;
	int		stop;
};

static struct spinner spinners[MAX_SPINNERS];
static int nap;

static void *spinner_fn(void *arg)
{
	struct spinner *s = arg;

	if (rseq_register_current_thread())
		abort();
	while (!RSEQ_READ_ONCE(s->stop)) {
		RSEQ_WRITE_ONCE(s->cid, rseq_current_mm_cid());
		/* Sleep, so that the next read follows a schedule in. */
		if (RSEQ_READ_ONCE(nap))
			usleep(1000);
	}
	rseq_unregister_current_thread();
	return NULL;
}

/* Stop @s and join it. Return 0, or -1 after reporting a join error. */
static int stop_spinner(struct spinner *s)
{
	int err;

	RSEQ_WRITE_ONCE(s->stop, 1);
	err = pthread_join(s->thread, NULL);
	if (err) {
		fprintf(stderr, "pthread_join: %s\n", strerror(err));
		return -1;
	}
	return 0;
}

/*
 * The program under test, after the execve(2). Wait for @want allowed
 * CPUs, then check the IDs of two threads. Return a CHILD_* status.
 */
static int check_main(int want)
{
	unsigned int spread_cid = 0, cid, own;
	int nr = want < MAX_SPINNERS ? want : MAX_SPINNERS;
	int i, err, started = 0, keep = 0, waited = 0, failed = 0;
	cpu_set_t mask;

	for (;;) {
		if (sched_getaffinity(0, sizeof(mask), &mask))
			return CHILD_ERROR;
		if (CPU_COUNT(&mask) == want)
			break;
		if (waited >= WIDE_WAIT_US) {
			fprintf(stderr, "allowed on %d CPUs, expected %d\n",
				CPU_COUNT(&mask), want);
			return CHILD_ERROR;
		}
		usleep(100);
		waited += 100;
	}
	if (rseq_register_current_thread())
		return CHILD_ERROR;

	/* One thread per CPU, this one included. */
	for (i = 0; i < nr - 1; i++) {
		err = pthread_create(&spinners[i].thread, NULL, spinner_fn, &spinners[i]);
		if (err) {
			fprintf(stderr, "pthread_create: %s\n", strerror(err));
			break;
		}
		started++;
	}
	if (started)
		usleep(SPREAD_US);

	/* Keep the thread with the largest mm_cid. */
	for (i = 0; i < started; i++) {
		cid = RSEQ_READ_ONCE(spinners[i].cid);
		if (cid >= spread_cid) {
			spread_cid = cid;
			keep = i;
		}
	}
	for (i = 0; i < started; i++) {
		if (i != keep && stop_spinner(&spinners[i]))
			failed = 1;
	}
	if (failed || started < nr - 1) {
		if (started)
			stop_spinner(&spinners[keep]);
		return CHILD_ERROR;
	}

	RSEQ_WRITE_ONCE(nap, 1);
	usleep(SETTLE_US);
	cid = RSEQ_READ_ONCE(spinners[keep].cid);
	own = rseq_current_mm_cid();
	if (stop_spinner(&spinners[keep]))
		return CHILD_ERROR;

	if (cid >= 2 || own >= 2) {
		fprintf(stderr,
			"mm_cid %u and %u with 2 threads, largest mm_cid %u with %d threads\n",
			own, cid, spread_cid, nr);
		return CHILD_FAIL;
	}
	return CHILD_PASS;
}

static void busy_wait_us(int us)
{
	struct timespec start, now;

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while ((now.tv_sec - start.tv_sec) * 1000000L +
		 (now.tv_nsec - start.tv_nsec) / 1000 < us);
}

/*
 * Run the program under test in a new process that starts on the CPUs in
 * @start. Widen its affinity to @all after @delay_us, unless @delay_us is
 * negative. Run on the CPUs in @beside meanwhile. Return a CHILD_* status.
 */
static int run_attempt(const cpu_set_t *start, const cpu_set_t *beside,
		       const cpu_set_t *all, int delay_us)
{
	char want[16], arg0[] = "mm_cid_exec_affinity_test", arg1[] = "check";
	char *const av[] = { arg0, arg1, want, NULL };
	int go[2], status = 0;
	pid_t child;
	char c = 0;

	snprintf(want, sizeof(want), "%d", CPU_COUNT(all));
	if (pipe2(go, O_CLOEXEC))
		ksft_exit_fail_msg("pipe2: %s\n", strerror(errno));
	if (sched_setaffinity(0, sizeof(*start), start))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	child = fork();
	if (!child) {
		if (write(go[1], &c, 1) != 1)
			_exit(CHILD_ERROR);
		execv("/proc/self/exe", av);
		_exit(CHILD_ERROR);
	}
	if (child < 0)
		ksft_exit_fail_msg("fork: %s\n", strerror(errno));
	/* On the CPU of the child, the change would wait for its execve(2). */
	if (sched_setaffinity(0, sizeof(*beside), beside))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	close(go[1]);
	if (read(go[0], &c, 1) == 1 && delay_us >= 0) {
		busy_wait_us(delay_us);
		/* The child is in execve(2), or about to enter or leave it. */
		if (sched_setaffinity(child, sizeof(*all), all))
			ksft_print_msg("sched_setaffinity on the child: %s\n", strerror(errno));
	}
	close(go[0]);
	if (sched_setaffinity(0, sizeof(*all), all))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	if (waitpid(child, &status, 0) != child)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (!WIFEXITED(status))
		ksft_exit_fail_msg("the process under test was killed by signal %d\n",
				   WTERMSIG(status));
	return WEXITSTATUS(status);
}

int main(int argc, char **argv)
{
	cpu_set_t all, one, beside;
	int status, i, cpu;

	if (argc == 3 && !strcmp(argv[1], "check"))
		return check_main(atoi(argv[2]));

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
	if (CPU_COUNT(&all) < MIN_CPUS) {
		ksft_test_result_skip("all CPUs allowed before execve: fewer than %d CPUs\n",
				      MIN_CPUS);
		ksft_test_result_skip("affinity widened during execve: fewer than %d CPUs\n",
				      MIN_CPUS);
		ksft_finished();
	}

	/* The child starts on the first CPU, the parent runs on the second. */
	CPU_ZERO(&one);
	CPU_ZERO(&beside);
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &all))
			continue;
		if (!CPU_COUNT(&one)) {
			CPU_SET(cpu, &one);
		} else {
			CPU_SET(cpu, &beside);
			break;
		}
	}

	status = run_attempt(&all, &all, &all, -1);
	if (status == CHILD_ERROR)
		ksft_exit_fail_msg("the process under test failed to run\n");
	ksft_test_result(status == CHILD_PASS, "all CPUs allowed before execve\n");

	for (i = 0; i < ATTEMPTS; i++) {
		status = run_attempt(&one, &beside, &all, (i * 37) % MAX_DELAY_US);
		if (status == CHILD_ERROR)
			ksft_exit_fail_msg("the process under test failed to run\n");
		if (status != CHILD_PASS) {
			ksft_print_msg("attempt %d, affinity widened %d us after the fork\n",
				       i, (i * 37) % MAX_DELAY_US);
			break;
		}
	}
	ksft_test_result(status == CHILD_PASS,
			 "affinity widened by another process during execve\n");
	ksft_finished();
}
