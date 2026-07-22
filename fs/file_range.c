// SPDX-License-Identifier: GPL-2.0

#include <linux/compat.h>
#include <linux/backing-file.h>
#include <linux/cred.h>
#include <linux/export.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/sched/xacct.h>
#include <linux/splice.h>

#include <kunit/static_stub.h>
#include <kunit/visibility.h>

#include "internal.h"

#define FILE_RANGE_MAX_CHAIN_FILES	(FILESYSTEM_MAX_STACK_DEPTH + 1)

struct file_range_chain {
	struct file *files[FILE_RANGE_MAX_CHAIN_FILES];
	unsigned int nr_files;
};

struct file_range_context {
	struct file_range_chain source;
	struct file_range_chain destination;
	enum file_range_operation operation;
	loff_t pos_in;
	loff_t pos_out;
	unsigned int operation_flags;
	bool use_splice;
	bool splice_attempted;
};

static void file_range_chain_reset(struct file_range_chain *chain)
{
	while (chain->nr_files > 1)
		fput(chain->files[--chain->nr_files]);
}

static void file_range_context_init(struct file_range_context *ctx,
				    enum file_range_operation operation,
				    struct file *file_in, loff_t pos_in,
				    struct file *file_out, loff_t pos_out,
				    unsigned int flags)
{
	ctx->operation = operation;
	ctx->source.files[0] = file_in;
	ctx->source.nr_files = 1;
	ctx->destination.files[0] = file_out;
	ctx->destination.nr_files = 1;
	ctx->pos_in = pos_in;
	ctx->pos_out = pos_out;
	ctx->operation_flags = flags;
	ctx->use_splice = operation == FILE_RANGE_OPERATION_COPY &&
			  flags & COPY_FILE_SPLICE;
}

static void file_range_context_cleanup(struct file_range_context *ctx)
{
	file_range_chain_reset(&ctx->source);
	file_range_chain_reset(&ctx->destination);
}

DEFINE_FREE(file_range_context, struct file_range_context,
	    file_range_context_cleanup(&_T))

VISIBLE_IF_KUNIT
int copy_file_range_verify_backing_area(int read_write, struct file *file,
					const loff_t *ppos, size_t count)
{
	KUNIT_STATIC_STUB_REDIRECT(copy_file_range_verify_backing_area, read_write,
				   file, ppos, count);

	return rw_verify_area(read_write, file, ppos, count);
}

static struct file *
file_range_resolve_one(const struct file_range_layer_operations *ops,
		       struct file *file,
		       enum file_range_operation operation,
		       enum file_range_role role,
		       enum file_range_resolve_mode mode, bool nested)
{
	struct file *next;

	if (nested) {
		scoped_with_creds(file->f_cred)
			next = ops->resolve(file, operation, role, mode);
	} else {
		next = ops->resolve(file, operation, role, mode);
	}
	return next;
}

static int
file_range_resolve_next(struct file_range_chain *chain,
			enum file_range_operation operation,
			enum file_range_role role,
			enum file_range_resolve_mode mode)
{
	struct file *file = chain->files[chain->nr_files - 1];
	const struct file_range_layer_operations *ops;

	ops = file->f_op->file_range_layer_ops;
	if (!ops)
		return 0;
	if (!(ops->supported_operations & BIT(operation)))
		return 0;
	if (chain->nr_files == FILE_RANGE_MAX_CHAIN_FILES)
		return -ELOOP;
	if (WARN_ON_ONCE(!ops->resolve))
		return -EIO;
	if (role == FILE_RANGE_DESTINATION &&
	    WARN_ON_ONCE(!ops->prepare_write || !ops->finish_write))
		return -EIO;

	struct file *next __free(fput) =
		file_range_resolve_one(ops, file, operation, role, mode,
				       chain->nr_files > 1);

	if (IS_ERR(next))
		return PTR_ERR(next);
	if (WARN_ON_ONCE(!next))
		return -EIO;
	if (!(next->f_mode & FMODE_BACKING))
		return -EXDEV;
	if (!S_ISREG(file_inode(next)->i_mode))
		return -EINVAL;
	if (role == FILE_RANGE_SOURCE) {
		if (!(next->f_mode & FMODE_READ))
			return -EBADF;
	} else if (!(next->f_mode & FMODE_WRITE)) {
		return -EBADF;
	}
	/* Stack depth must decrease, which also prevents cycles. */
	if (file_inode(file)->i_sb->s_stack_depth <=
	    file_inode(next)->i_sb->s_stack_depth)
		return -EXDEV;

	chain->files[chain->nr_files] = no_free_ptr(next);
	chain->nr_files++;
	return 1;
}

static struct file *
file_range_chain_terminal(const struct file_range_chain *chain)
{
	return chain->files[chain->nr_files - 1];
}

static bool file_range_has_terminal_method(const struct file_range_context *ctx)
{
	struct file *file_in = file_range_chain_terminal(&ctx->source);
	struct file *file_out = file_range_chain_terminal(&ctx->destination);

	return file_out->f_op->copy_file_range &&
	       file_in->f_op->copy_file_range == file_out->f_op->copy_file_range;
}

static bool file_range_paired_layers(enum file_range_operation operation,
				     struct file *file_in,
				     struct file *file_out)
{
	const struct file_range_layer_operations *ops;

	ops = file_in->f_op->file_range_layer_ops;
	if (!ops || ops != file_out->f_op->file_range_layer_ops ||
	    !(ops->supported_operations & BIT(operation)))
		return false;

	return !file_in->f_op->copy_file_range &&
	       !file_out->f_op->copy_file_range;
}

/*
 * Do not resolve below an authoritative method reached through paired layers.
 */
static int
file_range_resolve_paired_prefix(struct file_range_context *ctx,
				 enum file_range_resolve_mode mode)
{
	for (;;) {
		struct file *file_in = file_range_chain_terminal(&ctx->source);
		struct file *file_out = file_range_chain_terminal(&ctx->destination);
		int ret;

		if (file_range_has_terminal_method(ctx))
			return 1;
		if (!file_range_paired_layers(ctx->operation, file_in, file_out))
			return 0;

		ret = file_range_resolve_next(&ctx->source, ctx->operation,
					      FILE_RANGE_SOURCE, mode);
		if (ret <= 0)
			return ret ?: -EIO;
		ret = file_range_resolve_next(&ctx->destination, ctx->operation,
					      FILE_RANGE_DESTINATION, mode);
		if (ret <= 0)
			return ret ?: -EIO;
	}
}

static int file_range_resolve(struct file_range_context *ctx,
			      enum file_range_resolve_mode mode)
{
	int ret;

	file_range_chain_reset(&ctx->source);
	file_range_chain_reset(&ctx->destination);

	ret = file_range_resolve_paired_prefix(ctx, mode);
	if (ret < 0)
		goto err;
	return 0;
err:
	file_range_chain_reset(&ctx->source);
	file_range_chain_reset(&ctx->destination);
	return ret;
}

static bool file_range_has_backing_files(const struct file_range_context *ctx)
{
	return ctx->source.nr_files > 1 || ctx->destination.nr_files > 1;
}

static bool
file_range_terminal_route_compatible(enum file_range_operation operation,
				     struct file *file_in,
				     struct file *file_out)
{
	if (file_out->f_op->copy_file_range)
		return file_in->f_op->copy_file_range ==
		       file_out->f_op->copy_file_range;
	return file_inode(file_in)->i_sb == file_inode(file_out)->i_sb;
}

static bool
file_range_logical_route_compatible(const struct file_range_context *ctx,
				    bool paired_layers)
{
	struct file *file_in = ctx->source.files[0];
	struct file *file_out = ctx->destination.files[0];

	return ctx->use_splice || paired_layers ||
	       file_range_terminal_route_compatible(ctx->operation, file_in,
						    file_out);
}

static int file_range_check_aliases(const struct file_range_context *ctx)
{
	const struct file_range_chain *source = &ctx->source;
	const struct file_range_chain *destination = &ctx->destination;
	unsigned int i, j;

	if (file_inode(source->files[0]) == file_inode(destination->files[0])) {
		if (source->nr_files != destination->nr_files)
			return -EXDEV;
		for (i = 0; i < source->nr_files; i++)
			if (file_inode(source->files[i]) !=
			    file_inode(destination->files[i]))
				return -EXDEV;
		return 0;
	}

	for (i = 0; i < source->nr_files; i++)
		for (j = 0; j < destination->nr_files; j++)
			if (file_inode(source->files[i]) ==
			    file_inode(destination->files[j]))
				return -EXDEV;

	return 0;
}

static int file_range_check_terminal_route(struct file_range_context *ctx)
{
	struct file *file_in = file_range_chain_terminal(&ctx->source);
	struct file *file_out = file_range_chain_terminal(&ctx->destination);

	if (ctx->use_splice)
		return 0;
	if (!file_range_terminal_route_compatible(ctx->operation, file_in,
						  file_out))
		return -EXDEV;

	return 0;
}

static int
file_range_resolve_route(struct file_range_context *ctx,
			 enum file_range_resolve_mode mode)
{
	int ret;

	ret = file_range_resolve(ctx, mode);
	if (!ret)
		ret = file_range_check_terminal_route(ctx);
	if (!ret)
		ret = file_range_check_aliases(ctx);
	return ret;
}

static int copy_file_range_checks(struct file *file_in, loff_t pos_in,
				  struct file *file_out, loff_t pos_out,
				  size_t *req_count)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	u64 count = *req_count;
	loff_t size_in;
	int ret;

	if (IS_IMMUTABLE(inode_out))
		return -EPERM;
	if (IS_SWAPFILE(inode_in) || IS_SWAPFILE(inode_out))
		return -ETXTBSY;
	if (pos_in + count < pos_in || pos_out + count < pos_out)
		return -EOVERFLOW;

	size_in = i_size_read(inode_in);
	if (pos_in >= size_in)
		count = 0;
	else
		count = min(count, size_in - (u64)pos_in);

	ret = generic_write_check_limits(file_out, pos_out, &count);
	if (ret)
		return ret;

	if (inode_in == inode_out && pos_out + count > pos_in &&
	    pos_out < pos_in + count)
		return -EINVAL;

	*req_count = count;
	return 0;
}

static int file_range_backing_checks(struct file_range_context *ctx,
				     loff_t len)
{
	struct file_range_chain *source = &ctx->source;
	struct file_range_chain *destination = &ctx->destination;
	unsigned int i, nr_files;
	int ret;

	if (destination->files[0]->f_flags & O_APPEND)
		return -EBADF;

	nr_files = max(source->nr_files, destination->nr_files);
	for (i = 1; i < nr_files; i++) {
		struct file *file_in = i < source->nr_files ?
				       source->files[i] : NULL;
		struct file *file_out = i < destination->nr_files ?
					destination->files[i] : NULL;

		if (file_out && IS_IMMUTABLE(file_inode(file_out)))
			return -EPERM;
		if ((file_in && IS_SWAPFILE(file_inode(file_in))) ||
		    (file_out && IS_SWAPFILE(file_inode(file_out))))
			return -ETXTBSY;
		if (file_in && len) {
			loff_t size_in = i_size_read(file_inode(file_in));

			if (ctx->pos_in >= size_in ||
			    len > size_in - (u64)ctx->pos_in)
				return -EXDEV;
		}
		if (file_out) {
			loff_t count = len;

			if (file_out->f_flags & O_APPEND)
				return -EBADF;
			if (!len)
				continue;
			ret = generic_write_check_limits(file_out, ctx->pos_out,
							 &count);
			if (ret)
				return ret;
			if (count != len)
				return -EXDEV;
		}
	}

	return 0;
}

static int file_range_verify_backing_area(enum file_range_role role,
					  struct file *file,
					  loff_t *pos, loff_t len)
{
	return copy_file_range_verify_backing_area(role == FILE_RANGE_SOURCE ?
						   READ : WRITE,
						   file, pos, len);
}

static int file_range_verify_backing_areas(struct file_range_context *ctx,
					   loff_t len)
{
	struct file_range_chain *source = &ctx->source;
	struct file_range_chain *destination = &ctx->destination;
	loff_t pos_in = ctx->pos_in;
	loff_t pos_out = ctx->pos_out;
	unsigned int i, nr_files;
	int ret;

	nr_files = max(source->nr_files, destination->nr_files);
	for (i = 1; i < nr_files; i++) {
		if (i < source->nr_files) {
			struct file *file = source->files[i];

			scoped_with_creds(file->f_cred)
				ret = file_range_verify_backing_area(FILE_RANGE_SOURCE,
								     file, &pos_in, len);
			if (ret)
				return ret;
		}
		if (i < destination->nr_files) {
			struct file *file = destination->files[i];

			scoped_with_creds(file->f_cred)
				ret = file_range_verify_backing_area(FILE_RANGE_DESTINATION,
								     file, &pos_out, len);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int
file_range_revalidate_chain(const struct file_range_chain *chain,
			    enum file_range_operation operation,
			    enum file_range_role role)
{
	unsigned int i;

	for (i = 0; i + 1 < chain->nr_files; i++) {
		const struct file_range_layer_operations *ops;

		ops = chain->files[i]->f_op->file_range_layer_ops;
		if (!ops)
			return -EXDEV;

		struct file *next __free(fput) =
			file_range_resolve_one(ops, chain->files[i], operation, role,
					       FILE_RANGE_RESOLVE_CACHED,
					       i > 0);

		if (IS_ERR(next))
			return PTR_ERR(next) == -EAGAIN ? -EXDEV : PTR_ERR(next);
		if (WARN_ON_ONCE(!next))
			return -EIO;
		if (next != chain->files[i + 1])
			return -EXDEV;
	}

	return 0;
}

static int
file_range_revalidate_destination(const struct file_range_context *ctx)
{
	return file_range_revalidate_chain(&ctx->destination,
					  ctx->operation,
					  FILE_RANGE_DESTINATION);
}

static ssize_t copy_file_range_splice(struct file_range_context *ctx,
				      struct file *file_in,
				      struct file *file_out, size_t len)
{
	loff_t pos_in = ctx->pos_in;
	loff_t pos_out = ctx->pos_out;

	/* Never hold the terminal freeze while splice reads the source. */
	ctx->splice_attempted = true;
	return do_splice_direct(file_in, &pos_in, file_out, &pos_out, len, 0);
}

/*
 * Each nonterminal frame freezes and prepares one destination layer, recurses
 * under the next edge's credentials, then finishes and thaws in reverse order.
 * Keeping that recursion here prevents a source wrapper from re-entering a
 * public file range operation and acquiring the terminal destination freeze
 * twice.
 */
static s64 copy_file_range_execute_terminal(struct file_range_context *ctx,
					    loff_t len)
{
	struct file *file_in = file_range_chain_terminal(&ctx->source);
	struct file *file_out = file_range_chain_terminal(&ctx->destination);
	ssize_t ret;

	if (ctx->use_splice ||
	    (!file_out->f_op->copy_file_range &&
	     !file_in->f_op->remap_file_range))
		return copy_file_range_splice(ctx, file_in, file_out, len);

	scoped_guard(super_write, file_inode(file_out)->i_sb) {
		if (file_out->f_op->copy_file_range) {
			ret = file_out->f_op->copy_file_range(file_in, ctx->pos_in,
					file_out, ctx->pos_out, len, 0);
		} else {
			ret = file_in->f_op->remap_file_range(file_in, ctx->pos_in,
					file_out, ctx->pos_out, len,
					REMAP_FILE_CAN_SHORTEN);
			if (ret <= 0)
				ctx->use_splice = true;
		}
	}
	if (ctx->use_splice)
		return copy_file_range_splice(ctx, file_in, file_out, len);
	return ret;
}

typedef s64 (*file_range_execute_terminal_t)(struct file_range_context *ctx,
					     loff_t len);

static s64 file_range_execute(struct file_range_context *ctx,
			      unsigned int layer, loff_t len,
			      file_range_execute_terminal_t execute_terminal)
{
	struct file_range_chain *chain = &ctx->destination;
	const struct file_range_layer_operations *ops;
	struct file *file;
	s64 ret;

	if (layer + 1 == chain->nr_files)
		return execute_terminal(ctx, len);

	file = chain->files[layer];
	ops = file->f_op->file_range_layer_ops;
	scoped_guard(super_write, file_inode(file)->i_sb) {
		ret = ops->prepare_write(file, chain->files[layer + 1],
					 ctx->operation);
		if (!ret) {
			scoped_with_creds(chain->files[layer + 1]->f_cred)
				ret = file_range_execute(ctx, layer + 1, len,
							 execute_terminal);
			ops->finish_write(file, chain->files[layer + 1],
					  ctx->operation, ctx->pos_out, ret);
		}
	}
	return ret;
}

static void copy_file_range_sync_source_access(const struct file_range_context *ctx)
{
	unsigned int i = ctx->source.nr_files - 1;

	while (i--) {
		struct file *file = ctx->source.files[i];
		const struct file_range_layer_operations *ops;

		ops = file->f_op->file_range_layer_ops;
		if (ops->sync_source_access)
			ops->sync_source_access(file);
	}
}

static void file_range_notify_backing(const struct file_range_context *ctx)
{
	unsigned int depth, nr_files;

	nr_files = max(ctx->source.nr_files, ctx->destination.nr_files);
	for (depth = 1; depth < nr_files; depth++) {
		if (depth < ctx->source.nr_files) {
			unsigned int i = ctx->source.nr_files - depth;

			fsnotify_access(ctx->source.files[i]);
		}
		if (depth < ctx->destination.nr_files) {
			unsigned int i = ctx->destination.nr_files - depth;

			fsnotify_modify(ctx->destination.files[i]);
		}
	}
}

static ssize_t copy_file_range_complete(const struct file_range_context *ctx,
					struct file *file_in,
					struct file *file_out, ssize_t ret)
{
	if (ctx->splice_attempted)
		copy_file_range_sync_source_access(ctx);
	if (ret > 0) {
		file_range_notify_backing(ctx);
		fsnotify_access(file_in);
		add_rchar(current, ret);
		fsnotify_modify(file_out);
		add_wchar(current, ret);
	}
	inc_syscr(current);
	inc_syscw(current);
	return ret;
}

ssize_t vfs_copy_file_range(struct file *file_in, loff_t pos_in,
			    struct file *file_out, loff_t pos_out,
			    size_t len, unsigned int flags)
{
	struct file_range_context ctx __free(file_range_context) = {};
	bool logical_route_compatible;
	bool paired_logical_layers;
	ssize_t ret;

	if (flags & ~COPY_FILE_SPLICE)
		return -EINVAL;

	file_range_context_init(&ctx, FILE_RANGE_OPERATION_COPY, file_in, pos_in,
				file_out, pos_out, flags);
	ret = generic_file_rw_checks(file_in, file_out);
	if (ret)
		return ret;

	paired_logical_layers = file_range_paired_layers(FILE_RANGE_OPERATION_COPY,
							 file_in, file_out);
	logical_route_compatible =
		file_range_logical_route_compatible(&ctx, paired_logical_layers);
	if (!logical_route_compatible)
		return -EXDEV;

	ret = copy_file_range_checks(file_in, pos_in, file_out, pos_out, &len);
	if (ret)
		return ret;
	ret = rw_verify_area(READ, file_in, &pos_in, len);
	if (ret)
		return ret;
	ret = rw_verify_area(WRITE, file_out, &pos_out, len);
	if (ret)
		return ret;
	if (!len)
		return 0;

	if (!ctx.use_splice && paired_logical_layers) {
		ret = file_range_resolve_route(&ctx,
					       FILE_RANGE_RESOLVE_MAY_OPEN);
		if (ret)
			return copy_file_range_complete(&ctx, file_in, file_out, ret);
	}

	if (ctx.use_splice ||
	    !file_range_chain_terminal(&ctx.destination)->f_op->copy_file_range ||
	    in_compat_syscall())
		len = min_t(size_t, MAX_RW_COUNT, len);

	/*
	 * Permission events may change a stacked destination.  Run all of them
	 * before the first write freeze, then revalidate before execution.
	 */
	if (file_range_has_backing_files(&ctx)) {
		ret = file_range_backing_checks(&ctx, len);
		if (ret)
			return copy_file_range_complete(&ctx, file_in, file_out, ret);
		ret = file_range_verify_backing_areas(&ctx, len);
		if (ret)
			return copy_file_range_complete(&ctx, file_in, file_out, ret);
		ret = file_range_revalidate_destination(&ctx);
		if (ret)
			return copy_file_range_complete(&ctx, file_in, file_out, ret);
		ret = file_range_backing_checks(&ctx, len);
		if (ret)
			return copy_file_range_complete(&ctx, file_in, file_out, ret);
	}

	ret = file_range_execute(&ctx, 0, len,
				 copy_file_range_execute_terminal);
	return copy_file_range_complete(&ctx, file_in, file_out, ret);
}
EXPORT_SYMBOL(vfs_copy_file_range);
