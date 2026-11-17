// SPDX-License-Identifier: LGPL-2.1
/*
 * The upper bound of the concurrency IDs while the thread count changes.
 *
 * A process grows to more threads than it has CPUs, then shrinks back to
 * one thread. After each step every thread visits every allowed CPU and
 * reads its mm_cid there. The largest value must stay below the number of
 * possible CPUs. That is the upper bound of an mm_cid, and it sizes the
 * per-CID data of user space.
 *
 * The kernel also aims at compact IDs. Its target is max_cids:
 *
 *     opt_cids = min(threads, allowed CPUs)
 *     max_cids = min(opt_cids + opt_cids / 4, possible CPUs)
 *
 * The slack above opt_cids gives the switch between the two ownership
 * modes some hysteresis. Threads that come and go near the limit then do
 * not cause a costly mode switch each time.
 *
 * The test prints the steps where the largest mm_cid is above max_cids,
 * or above min(threads, allowed CPUs). They do not make it fail.
 *
 * The steps cross both ownership modes of the kernel. The tasks own the
 * IDs at first. The CPUs own them once there are more threads than
 * max_cids. The tasks own them again once the thread count drops below a
 * threshold.
 *
 * The number of IDs follows the union of the allowed CPUs of the threads,
 * which only grows. The affinity is therefore narrowed before the fork(2)
 * that creates the process under test.
 *
 * A last case widens the affinity. Three threads start on two CPUs, so the
 * CPUs own the IDs. The threads are then allowed on all CPUs. The kernel
 * aims at giving the IDs back to the tasks, so that three threads read an
 * mm_cid below 3. That is a target too: the case prints when it is missed.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rseq.h"
#include "kselftest.h"

#define MAX_THREADS	1024
#define MAX_STEPS	64
#define WIDEN_THREADS	3
#define WIDEN_MIN_CPUS	8
#define WIDEN_SETTLE_US	20000

/*
 * Exit status of the process under test: a mask of the bound and of the
 * targets exceeded.
 */
#define OVER_POSSIBLE	1
#define OVER_MAX_CIDS	2
#define OVER_STRICT	4
#define CHILD_ERROR	64

struct worker {
	pthread_t	thread;
	int		stop;
	unsigned int	ack;
	unsigned int	max_cid;
	int		max_cpu;
};

static struct worker workers[MAX_THREADS];
static unsigned int epoch;
static cpu_set_t allowed;
static cpu_set_t all_cpus;
static int nr_allowed;
static int nr_possible;

/* Visit each allowed CPU and record the largest mm_cid read there. */
static void tour(struct worker *w)
{
	cpu_set_t one;
	int cpu;

	w->max_cid = 0;
	w->max_cpu = -1;
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		unsigned int cid;

		if (!CPU_ISSET(cpu, &allowed))
			continue;
		CPU_ZERO(&one);
		CPU_SET(cpu, &one);
		if (sched_setaffinity(0, sizeof(one), &one))
			continue;
		cid = rseq_current_mm_cid();
		if (cid >= w->max_cid) {
			w->max_cid = cid;
			w->max_cpu = cpu;
		}
	}
	if (sched_setaffinity(0, sizeof(allowed), &allowed)) {
		fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
		abort();
	}
}

static void *worker_fn(void *arg)
{
	struct worker *w = arg;
	unsigned int seen = RSEQ_READ_ONCE(w->ack);

	if (rseq_register_current_thread())
		abort();
	while (!RSEQ_READ_ONCE(w->stop)) {
		unsigned int e = RSEQ_READ_ONCE(epoch);

		if (e == seen) {
			usleep(200);
			continue;
		}
		tour(w);
		seen = e;
		/* Publish max_cid and max_cpu to measure(). */
		rseq_smp_store_release(&w->ack, e);
	}
	rseq_unregister_current_thread();
	return NULL;
}

/* Run one tour on every thread. Return the largest mm_cid, and its CPU. */
static unsigned int measure(int nr_workers, int *cpu)
{
	unsigned int e = RSEQ_READ_ONCE(epoch) + 1;
	unsigned int max_cid;
	struct worker self;
	int i;

	RSEQ_WRITE_ONCE(epoch, e);
	tour(&self);
	max_cid = self.max_cid;
	*cpu = self.max_cpu;
	for (i = 0; i < nr_workers; i++) {
		while (rseq_smp_load_acquire(&workers[i].ack) != e)
			usleep(200);
		if (workers[i].max_cid > max_cid) {
			max_cid = workers[i].max_cid;
			*cpu = workers[i].max_cpu;
		}
	}
	return max_cid;
}

/*
 * Create or join threads to reach @target. Return 0, or the error number
 * after reporting it.
 */
static int set_workers(int *nr_workers, int target)
{
	int err;

	while (*nr_workers < target) {
		struct worker *w = &workers[*nr_workers];

		w->stop = 0;
		w->ack = RSEQ_READ_ONCE(epoch);
		err = pthread_create(&w->thread, NULL, worker_fn, w);
		if (err) {
			fprintf(stderr, "pthread_create: %s\n", strerror(err));
			return err;
		}
		(*nr_workers)++;
	}
	while (*nr_workers > target) {
		struct worker *w = &workers[*nr_workers - 1];

		RSEQ_WRITE_ONCE(w->stop, 1);
		err = pthread_join(w->thread, NULL);
		if (err) {
			fprintf(stderr, "pthread_join: %s\n", strerror(err));
			return err;
		}
		(*nr_workers)--;
	}
	return 0;
}

static unsigned int min_u(unsigned int a, unsigned int b)
{
	return a < b ? a : b;
}

/* The process under test. Return a mask of the OVER_* values. */
static int run_child(const int *steps, int nr_steps)
{
	int nr_workers = 0, ret = 0, i;

	if (sched_getaffinity(0, sizeof(allowed), &allowed))
		return CHILD_ERROR;
	nr_allowed = CPU_COUNT(&allowed);

	for (i = 0; i < nr_steps; i++) {
		unsigned int threads = steps[i], opt, max_cids, strict, cid;
		int cpu, over = 0, err;

		err = set_workers(&nr_workers, threads - 1);
		if (err) {
			ret |= CHILD_ERROR;
			break;
		}
		/* The first tour lets every thread schedule on every CPU. */
		measure(nr_workers, &cpu);
		cid = measure(nr_workers, &cpu);

		opt = min_u(threads, nr_allowed);
		strict = opt;
		max_cids = min_u(opt + opt / 4, nr_possible);
		if (cid >= (unsigned int)nr_possible)
			over |= OVER_POSSIBLE;
		if (cid >= max_cids)
			over |= OVER_MAX_CIDS;
		if (cid >= strict)
			over |= OVER_STRICT;
		ksft_print_msg(
			"%4u threads on %d CPUs: largest mm_cid %u on CPU %d, max_cids %u, min(threads, CPUs) %u%s%s%s\n",
			       threads, nr_allowed, cid, cpu, max_cids, strict,
			       over & OVER_STRICT ? ", above the min(threads, CPUs) target" : "",
			       over & OVER_MAX_CIDS ? ", above the max_cids target" : "",
			       over & OVER_POSSIBLE ? ", at or above the possible CPUs" : "");
		ret |= over;
	}
	if (set_workers(&nr_workers, 0))
		ret |= CHILD_ERROR;
	return ret;
}

/*
 * The process under test of the widening case. It starts on two CPUs.
 * Return a mask of the OVER_* values.
 */
static int run_child_widen(void)
{
	int nr_workers = 0, ret = 0, cpu, err;
	unsigned int cid;

	if (sched_getaffinity(0, sizeof(allowed), &allowed))
		return CHILD_ERROR;
	nr_allowed = CPU_COUNT(&allowed);

	err = set_workers(&nr_workers, WIDEN_THREADS - 1);
	if (err)
		return CHILD_ERROR;
	measure(nr_workers, &cpu);
	cid = measure(nr_workers, &cpu);
	ksft_print_msg("%4d threads on %d CPUs: largest mm_cid %u on CPU %d\n",
		       WIDEN_THREADS, nr_allowed, cid, cpu);

	/* Each thread widens its own affinity at the end of its next tour. */
	allowed = all_cpus;
	nr_allowed = CPU_COUNT(&allowed);
	if (sched_setaffinity(0, sizeof(allowed), &allowed))
		ret |= CHILD_ERROR;
	measure(nr_workers, &cpu);
	/* The kernel changes the owners of the IDs from a work item. */
	usleep(WIDEN_SETTLE_US);
	measure(nr_workers, &cpu);
	cid = measure(nr_workers, &cpu);
	if (cid >= (unsigned int)nr_possible)
		ret |= OVER_POSSIBLE;
	if (cid >= WIDEN_THREADS)
		ret |= OVER_STRICT;
	ksft_print_msg("%4d threads widened to %d CPUs: largest mm_cid %u on CPU %d%s\n",
		       WIDEN_THREADS, nr_allowed, cid, cpu,
		       ret & OVER_STRICT ? ", above the thread count target" : "");
	if (set_workers(&nr_workers, 0))
		ret |= CHILD_ERROR;
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

/* Thread counts from 1 up to twice the CPUs plus two, and back to 1. */
static int make_steps(int *steps, int cpus)
{
	int top = 2 * cpus + 2, stride = 1, n = 0, t;

	if (top > MAX_THREADS)
		top = MAX_THREADS;
	/* Every count on a small set of CPUs, a fraction on a large one. */
	while (2 * (top / stride) + 1 > MAX_STEPS)
		stride++;
	for (t = 1; t < top; t += stride)
		steps[n++] = t;
	steps[n++] = top;
	for (t = top - stride; t > 1; t -= stride)
		steps[n++] = t;
	steps[n++] = 1;
	return n;
}

static void test_ramp(const cpu_set_t *all, int cpus, const char *name)
{
	int steps[MAX_STEPS + 2], nr_steps, status = 0;
	cpu_set_t narrow;
	pid_t child;

	if (narrow_cpus(&narrow, all, cpus) < cpus) {
		ksft_test_result_skip("%s: below the possible CPUs\n", name);
		return;
	}
	nr_steps = make_steps(steps, cpus);

	/* Narrowed before the fork(2): the union of allowed CPUs only grows. */
	if (sched_setaffinity(0, sizeof(narrow), &narrow))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	child = fork();
	if (!child)
		_exit(run_child(steps, nr_steps));
	if (child < 0)
		ksft_exit_fail_msg("fork: %s\n", strerror(errno));
	if (sched_setaffinity(0, sizeof(*all), all))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	if (waitpid(child, &status, 0) != child)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (!WIFEXITED(status) || (WEXITSTATUS(status) & CHILD_ERROR))
		ksft_exit_fail_msg("the process under test failed to run\n");

	status = WEXITSTATUS(status);
	/* The targets are reported. Only the bound decides the result. */
	if (status & OVER_MAX_CIDS)
		ksft_print_msg("%s: some steps are above the max_cids target\n", name);
	if (status & OVER_STRICT)
		ksft_print_msg("%s: some steps are above min(threads, CPUs)\n", name);
	ksft_test_result(!(status & OVER_POSSIBLE),
			 "%s: below the possible CPUs\n", name);
}

static void test_widen(const cpu_set_t *all)
{
	const char *name = "widened from 2 CPUs: below the possible CPUs";
	cpu_set_t narrow;
	int status = 0;
	pid_t child;

	/* With fewer CPUs the kernel keeps the CPUs as owners of the IDs. */
	if (CPU_COUNT(all) < WIDEN_MIN_CPUS || nr_possible < WIDEN_MIN_CPUS) {
		ksft_test_result_skip("%s: fewer than %d CPUs\n", name, WIDEN_MIN_CPUS);
		return;
	}
	narrow_cpus(&narrow, all, 2);
	all_cpus = *all;
	if (sched_setaffinity(0, sizeof(narrow), &narrow))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	child = fork();
	if (!child)
		_exit(run_child_widen());
	if (child < 0)
		ksft_exit_fail_msg("fork: %s\n", strerror(errno));
	if (sched_setaffinity(0, sizeof(*all), all))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	if (waitpid(child, &status, 0) != child)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (!WIFEXITED(status) || (WEXITSTATUS(status) & CHILD_ERROR))
		ksft_exit_fail_msg("the process under test failed to run\n");
	/* The thread count is a target. Only the bound decides the result. */
	if (WEXITSTATUS(status) & OVER_STRICT)
		ksft_print_msg("widened from 2 CPUs: above the thread count target\n");
	ksft_test_result(!(WEXITSTATUS(status) & OVER_POSSIBLE), "%s\n", name);
}

int main(void)
{
	cpu_set_t all;
	int nr_all;

	ksft_print_header();
	ksft_set_plan(4);

	if (!rseq_available())
		ksft_exit_skip("rseq is unavailable\n");
	if (rseq_register_current_thread())
		ksft_exit_fail_msg("rseq_register_current_thread: %s\n", strerror(errno));
	if (!rseq_mm_cid_available())
		ksft_exit_skip("the rseq mm_cid field is unavailable\n");
	if (sched_getaffinity(0, sizeof(all), &all))
		ksft_exit_fail_msg("sched_getaffinity: %s\n", strerror(errno));
	nr_possible = read_nr_possible();
	if (nr_possible <= 0)
		ksft_exit_skip("cannot read the possible CPUs\n");
	nr_all = CPU_COUNT(&all);
	ksft_print_msg("%d possible CPUs, %d allowed\n", nr_possible, nr_all);

	test_ramp(&all, 2, "2 CPUs");
	test_ramp(&all, 4, "4 CPUs");
	test_ramp(&all, nr_all, "all CPUs");
	test_widen(&all);
	ksft_finished();
}
