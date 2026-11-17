// SPDX-License-Identifier: LGPL-2.1
/*
 * Affinity changes from another task while a task replaces or drops its mm.
 *
 * sched_setaffinity(2) on another task updates the allowed CPUs of the mm
 * of that task. It reads that mm under the pi_lock of the target. The
 * target can replace its mm in execve(2), or drop it when it exits, on
 * another CPU at the same time. The old mm is freed right after.
 *
 * Case 1: one process calls execve(2) on this test in a loop. Processes on
 * the other CPUs change its affinity as fast as they can.
 *
 * Case 2: short lived processes exit while another process changes their
 * affinity.
 *
 * A read of a freed mm stays invisible to user space. Both cases check
 * that both sides keep making progress, and that the kernel stays alive.
 * Under KASAN the kernel reports the read.
 *
 * The test uses no thread, so that it also runs on a kernel built without
 * CONFIG_FUTEX.
 *
 * Each case runs for one second. The first argument sets another number of
 * seconds.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "rseq.h"
#include "kselftest.h"

#define MAX_CPUS		256
#define MAX_SETTERS		4
#define RUNTIME_S		1
#define FIRST_EXEC_MS		5000
#define EXIT_DELAY_STEP_US	7
#define MAX_EXIT_DELAY_US	200

#define CHILD_PASS		0
#define CHILD_ERROR		2

/* Shared with the processes that change the affinity. */
struct shared {
	unsigned long long	changes[MAX_SETTERS];
	pid_t			target;		/* the process that exits */
};

static const char *exec_case = "affinity changes while a task replaces its mm";
static const char *exit_case = "affinity changes while a task drops its mm";

static int cpus[MAX_CPUS], nr_cpus;

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

static int pin(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

/* Set @one to the CPU @a, and @two to the CPUs @a and @b. */
static void init_masks(cpu_set_t *one, cpu_set_t *two, int a, int b)
{
	CPU_ZERO(one);
	CPU_SET(a, one);
	CPU_ZERO(two);
	CPU_SET(a, two);
	CPU_SET(b, two);
}

/*
 * Change the affinity of @pid, or of the process that exits when @pid is
 * zero, until @deadline. The two masks alternate, so that every change
 * reaches the mm of the target. Count the changes and exit.
 */
static void setter_main(struct shared *sh, int index, pid_t pid, int cpu,
			int a, int b, long long deadline)
{
	unsigned long long changes = 0;
	cpu_set_t one, two;
	int i = 0;

	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
		fprintf(stderr, "prctl(PR_SET_PDEATHSIG): %s\n", strerror(errno));
		_exit(CHILD_ERROR);
	}
	init_masks(&one, &two, a, b);
	if (pin(cpu)) {
		fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
		_exit(CHILD_ERROR);
	}
	while (now_us() < deadline) {
		const cpu_set_t *mask = (i++ & 1) ? &one : &two;
		pid_t target = pid ? pid : RSEQ_READ_ONCE(sh->target);

		if (!target)
			continue;
		if (!sched_setaffinity(target, sizeof(*mask), mask)) {
			changes++;
			continue;
		}
		/* The target can exit first: ESRCH is expected. */
		if (errno != ESRCH) {
			fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
			_exit(CHILD_ERROR);
		}
	}
	sh->changes[index] = changes;
	_exit(CHILD_PASS);
}

/* Count this instance of the process under test. Then call execve(2) again. */
static int exec_loop_main(char **argv)
{
	long long end = atoll(argv[3]);
	uint64_t one = 1;
	int fd = atoi(argv[2]);

	if (write(fd, &one, sizeof(one)) != sizeof(one))
		return CHILD_ERROR;
	if (now_us() >= end)
		return CHILD_PASS;
	execv("/proc/self/exe", argv);
	fprintf(stderr, "execv: %s\n", strerror(errno));
	return CHILD_ERROR;
}

/* Add the counts pending on @fd to @total. */
static int drain(int fd, unsigned long long *total)
{
	for (;;) {
		uint64_t value;
		ssize_t ret = read(fd, &value, sizeof(value));

		if (ret == sizeof(value)) {
			*total += value;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 && errno == EAGAIN)
			return 0;
		return -1;
	}
}

/*
 * Wait for the first instance of the process under test. Return -1 if it
 * does not come.
 */
static int wait_first_exec(int fd, unsigned long long *execs)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int ret;

	do {
		ret = poll(&pfd, 1, FIRST_EXEC_MS);
	} while (ret < 0 && errno == EINTR);
	if (ret != 1)
		return -1;
	if (drain(fd, execs) || !*execs)
		return -1;
	return 0;
}

/*
 * Start the process under test on the CPU @cpu. It counts its instances
 * through @fd and leaves its loop at @end. Return its pid.
 */
static pid_t start_exec_loop(char *name, int cpu, int fd, long long end)
{
	char mode[] = "exec-loop", fd_arg[16], end_arg[32];
	char *const av[] = { name, mode, fd_arg, end_arg, NULL };
	pid_t pid;

	snprintf(fd_arg, sizeof(fd_arg), "%d", fd);
	snprintf(end_arg, sizeof(end_arg), "%lld", end);
	pid = fork();
	if (pid)
		return pid;
	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0)) {
		fprintf(stderr, "prctl(PR_SET_PDEATHSIG): %s\n", strerror(errno));
		_exit(CHILD_ERROR);
	}
	if (pin(cpu)) {
		fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
		_exit(CHILD_ERROR);
	}
	execv("/proc/self/exe", av);
	fprintf(stderr, "execv: %s\n", strerror(errno));
	_exit(CHILD_ERROR);
}

/* Wait for the process @pid. Return its exit status, or -1. */
static int wait_status(pid_t pid)
{
	int status;
	pid_t ret;

	do {
		ret = waitpid(pid, &status, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret != pid || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/* Case 1. Change the affinity of a process that calls execve(2) in a loop. */
static void run_exec_case(char *name, int runtime_s, struct shared *sh)
{
	unsigned long long execs = 0, changes = 0;
	int a = cpus[nr_cpus - 2], b = cpus[nr_cpus - 1];
	pid_t victim, setters[MAX_SETTERS];
	int fd, i, nset, status = 0;
	long long deadline;
	pid_t ret;

	nset = nr_cpus - 2 < MAX_SETTERS ? nr_cpus - 2 : MAX_SETTERS;
	fd = eventfd(0, EFD_NONBLOCK);
	if (fd < 0)
		ksft_exit_fail_msg("eventfd: %s\n", strerror(errno));
	/* The process under test outlives those that change its affinity. */
	victim = start_exec_loop(name, a, fd,
				 now_us() + (runtime_s + 1) * 1000000LL);
	if (victim < 0)
		ksft_exit_fail_msg("fork: %s\n", strerror(errno));
	if (wait_first_exec(fd, &execs))
		ksft_exit_fail_msg("the process under test did not call execve\n");

	deadline = now_us() + runtime_s * 1000000LL;
	for (i = 0; i < nset; i++) {
		setters[i] = fork();
		if (!setters[i])
			setter_main(sh, i, victim, cpus[i], a, b, deadline);
		if (setters[i] < 0)
			ksft_exit_fail_msg("fork: %s\n", strerror(errno));
	}
	for (i = 0; i < nset; i++) {
		if (wait_status(setters[i]))
			ksft_exit_fail_msg("a process that changes the affinity failed\n");
		changes += sh->changes[i];
	}
	if (drain(fd, &execs))
		ksft_exit_fail_msg("read the count of the execve calls: %s\n",
				   strerror(errno));

	/* The process under test must still be in its loop. */
	ret = waitpid(victim, &status, WNOHANG);
	if (ret < 0)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (ret) {
		ksft_print_msg("the process under test left its loop: 0x%x\n",
			       status);
		ksft_test_result_fail("%s\n", exec_case);
		if (close(fd))
			ksft_exit_fail_msg("close: %s\n", strerror(errno));
		return;
	}
	if (kill(victim, SIGKILL))
		ksft_exit_fail_msg("kill: %s\n", strerror(errno));
	if (waitpid(victim, &status, 0) != victim)
		ksft_exit_fail_msg("waitpid: %s\n", strerror(errno));
	if (close(fd))
		ksft_exit_fail_msg("close: %s\n", strerror(errno));

	ksft_print_msg("%llu execve calls, %llu affinity changes\n",
		       execs, changes);
	ksft_test_result(execs && changes, "%s\n", exec_case);
}

/* Case 2. Change the affinity of processes while they exit. */
static void run_exit_case(int runtime_s, const cpu_set_t *all,
			  struct shared *sh)
{
	unsigned long long children = 0;
	int a = cpus[0], b = cpus[1];
	int delay = 0, bad = 0;
	long long deadline;
	pid_t setter, pid;

	deadline = now_us() + runtime_s * 1000000LL;
	if (pin(a))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));
	setter = fork();
	if (!setter)
		setter_main(sh, 0, 0, b, a, b, deadline);
	if (setter < 0)
		ksft_exit_fail_msg("fork: %s\n", strerror(errno));

	while (now_us() < deadline) {
		pid = fork();
		if (!pid) {
			/* Exit while the affinity of this process changes. */
			busy_wait_us(delay);
			_exit(CHILD_PASS);
		}
		if (pid < 0)
			ksft_exit_fail_msg("fork: %s\n", strerror(errno));
		RSEQ_WRITE_ONCE(sh->target, pid);
		if (wait_status(pid))
			bad++;
		RSEQ_WRITE_ONCE(sh->target, 0);
		children++;
		/* The next process exits later, relative to the changes. */
		delay = (delay + EXIT_DELAY_STEP_US) % MAX_EXIT_DELAY_US;
	}
	if (wait_status(setter))
		ksft_exit_fail_msg("the process that changes the affinity failed\n");
	if (sched_setaffinity(0, sizeof(*all), all))
		ksft_exit_fail_msg("sched_setaffinity: %s\n", strerror(errno));

	if (bad)
		ksft_print_msg("%d processes out of %llu did not exit cleanly\n",
			       bad, children);
	ksft_print_msg("%llu processes exited, %llu affinity changes\n",
		       children, sh->changes[0]);
	ksft_test_result(!bad && children && sh->changes[0], "%s\n", exit_case);
}

int main(int argc, char **argv)
{
	int runtime_s = RUNTIME_S;
	struct shared *sh;
	cpu_set_t all;
	int cpu;

	if (argc == 4 && !strcmp(argv[1], "exec-loop"))
		return exec_loop_main(argv);
	if (argc > 1 && atoi(argv[1]) > 0)
		runtime_s = atoi(argv[1]);

	ksft_print_header();
	ksft_set_plan(2);

	if (!rseq_available())
		ksft_exit_skip("rseq is unavailable\n");
	if (rseq_register_current_thread())
		ksft_exit_fail_msg("rseq_register_current_thread: %s\n",
				   strerror(errno));
	if (!rseq_mm_cid_available())
		ksft_exit_skip("the rseq mm_cid field is unavailable\n");
	if (sched_getaffinity(0, sizeof(all), &all))
		ksft_exit_fail_msg("sched_getaffinity: %s\n", strerror(errno));
	for (cpu = 0; cpu < CPU_SETSIZE && nr_cpus < MAX_CPUS; cpu++) {
		if (CPU_ISSET(cpu, &all))
			cpus[nr_cpus++] = cpu;
	}
	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE,
		  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (sh == MAP_FAILED)
		ksft_exit_fail_msg("mmap: %s\n", strerror(errno));

	/* One CPU for the tested process, one to move it to, one to run on. */
	if (nr_cpus < 3)
		ksft_test_result_skip("%s: fewer than 3 CPUs\n", exec_case);
	else
		run_exec_case(argv[0], runtime_s, sh);

	if (nr_cpus < 2)
		ksft_test_result_skip("%s: fewer than 2 CPUs\n", exit_case);
	else
		run_exit_case(runtime_s, &all, sh);

	ksft_finished();
}
