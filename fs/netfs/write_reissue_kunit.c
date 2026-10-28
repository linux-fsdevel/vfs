// SPDX-License-Identifier: GPL-2.0-only
/*
 * netfs_reissue_write must not clear prepare_write() errno.
 */
#include <kunit/test.h>
#include <kunit/static_stub.h>
#include <linux/uio.h>
#include "internal.h"

struct term_capture {
	ssize_t transferred_or_error;
	bool called;
};

static void capture_terminated(void *_op, ssize_t transferred_or_error)
{
	struct netfs_io_subrequest *subreq = _op;
	struct term_capture *cap = kunit_get_current_test()->priv;

	cap->called = true;
	cap->transferred_or_error = transferred_or_error;
	/* Mirror production: leave subreq->error as prepare_write set it. */
	(void)subreq;
}

/*
 * prepare_write_failed() sets FAILED + errno, then write_retry still calls
 * reissue_write().  Before the fix, reissue wiped error to 0 so terminated
 * reported success and mapping_set_error(0) was a no-op.
 */
static void reissue_preserves_prep_error(struct kunit *test)
{
	struct term_capture cap = {};
	struct netfs_io_request wreq = {};
	struct netfs_io_stream stream = {
		.source = NETFS_UPLOAD_TO_SERVER,
	};
	struct netfs_io_subrequest subreq = {
		.rreq = &wreq,
		.len = 1,
		.transferred = 0,
		.error = -EIO,
		.source = NETFS_UPLOAD_TO_SERVER,
	};
	char buf[1] = { 0 };
	struct kvec kvec = { .iov_base = buf, .iov_len = 1 };
	struct iov_iter source;

	__set_bit(NETFS_SREQ_FAILED, &subreq.flags);
	iov_iter_kvec(&source, ITER_SOURCE, &kvec, 1, 1);

	test->priv = &cap;
	kunit_activate_static_stub(test, netfs_write_subrequest_terminated,
				   capture_terminated);

	netfs_reissue_write(&stream, &subreq, &source);

	KUNIT_EXPECT_TRUE(test, cap.called);
	KUNIT_EXPECT_EQ(test, cap.transferred_or_error, -EIO);
	KUNIT_EXPECT_EQ(test, subreq.error, -EIO);
}

static struct kunit_case netfs_reissue_test_cases[] = {
	KUNIT_CASE(reissue_preserves_prep_error),
	{}
};

static struct kunit_suite netfs_reissue_test_suite = {
	.name = "netfs_reissue_write",
	.test_cases = netfs_reissue_test_cases,
};

kunit_test_suite(netfs_reissue_test_suite);
