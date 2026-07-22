// SPDX-License-Identifier: GPL-2.0

#include <kunit/test.h>
#include <kunit/static_stub.h>
#include <linux/backing-file.h>
#include <linux/cpu.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs/super.h>
#include <linux/mount.h>
#include <linux/percpu.h>
#include <linux/pseudo_fs.h>
#include <linux/splice.h>

#include "../internal.h"

#define FILE_RANGE_TEST_MAGIC	0x63667274
#define FILE_RANGE_TEST_SIZE	4096
#define FILE_RANGE_TEST_MAX_EVENTS	8

static void file_range_test_put_inode(struct inode *inode)
{
	if (inode)
		iput(inode);
}

DEFINE_FREE(file_range_test_iput, struct inode *,
	    file_range_test_put_inode(_T))

enum file_range_test_event {
	FILE_RANGE_TEST_PREPARE_0,
	FILE_RANGE_TEST_PREPARE_1,
	FILE_RANGE_TEST_FINISH_0,
	FILE_RANGE_TEST_FINISH_1,
};

struct file_range_test_ctx {
	unsigned int resolve_calls[2][2][2];
	unsigned int prepare_calls;
	unsigned int finish_calls;
	unsigned int copy_calls;
	unsigned int verify_calls[2][3];
	unsigned int verify_write_readers[2][3];
	unsigned int prepare_file_write_readers[2];
	unsigned int prepare_next_write_readers[2];
	unsigned int finish_file_write_readers[2];
	unsigned int finish_next_write_readers[2];
	unsigned int copy_write_readers;
	unsigned int remap_calls;
	unsigned int remap_flags;
	unsigned int remap_write_readers;
	unsigned int splice_calls;
	unsigned int splice_write_readers;
	unsigned int sync_source_access_calls;
	unsigned int deeper_resolve_calls;
	unsigned int nr_events;
	unsigned int events[FILE_RANGE_TEST_MAX_EVENTS];
	s64 finish_ret[2];
	const struct file *verify_files[2][3];
	const struct cred *verify_creds[2][3];
	const struct cred *resolve_creds[2][2][2];
	const struct cred *prepare_creds[2];
	const struct cred *finish_creds[2];
	const struct cred *copy_cred;
	const struct cred *remap_cred;
	struct super_block *splice_destination_sb;
	loff_t remap_ret;
	enum file_range_operation resolve_operation;
	enum file_range_operation prepare_operation;
	enum file_range_operation finish_operation;
	unsigned int revalidate_file_write_readers[2];
	unsigned int revalidate_next_write_readers[2];
	bool record_revalidate_write_readers;
};

struct file_range_test_file {
	struct file_range_test_ctx *ctx;
	struct file *next;
	struct file *revalidate_next;
	int resolve_error;
	enum file_range_role resolve_error_role;
	enum file_range_resolve_mode resolve_error_mode;
	int prepare_error;
	unsigned int layer;
};

static unsigned int
file_range_test_write_readers(struct super_block *sb);

static unsigned int
file_range_test_resolve_count(const struct file_range_test_ctx *ctx)
{
	unsigned int layer, role, mode, count = 0;

	for (layer = 0; layer < ARRAY_SIZE(ctx->resolve_calls); layer++)
		for (role = 0; role < ARRAY_SIZE(ctx->resolve_calls[layer]); role++)
			for (mode = 0;
			     mode < ARRAY_SIZE(ctx->resolve_calls[layer][role]);
			     mode++)
				count += ctx->resolve_calls[layer][role][mode];
	return count;
}

static int
file_range_test_verify_backing_area(int read_write, struct file *file,
				    const loff_t *ppos, size_t count)
{
	struct file_range_test_file *test_file = file->private_data;
	struct file_range_test_ctx *ctx = test_file->ctx;
	enum file_range_role role;

	if (read_write == READ)
		role = FILE_RANGE_SOURCE;
	else if (read_write == WRITE)
		role = FILE_RANGE_DESTINATION;
	else
		return -EINVAL;
	if (WARN_ON_ONCE(test_file->layer >= ARRAY_SIZE(ctx->verify_calls[role])))
		return -EIO;

	ctx->verify_calls[role][test_file->layer]++;
	ctx->verify_write_readers[role][test_file->layer] =
		file_range_test_write_readers(file_inode(file)->i_sb);
	ctx->verify_files[role][test_file->layer] = file;
	ctx->verify_creds[role][test_file->layer] = current_cred();
	return rw_verify_area(read_write, file, ppos, count);
}

static struct file *
file_range_test_resolve(struct file *file,
			enum file_range_operation operation,
			enum file_range_role role,
			enum file_range_resolve_mode mode)
{
	struct file_range_test_file *test_file = file->private_data;
	struct file *next = test_file->next;

	test_file->ctx->resolve_operation = operation;
	test_file->ctx->resolve_calls[test_file->layer][role][mode]++;
	test_file->ctx->resolve_creds[test_file->layer][role][mode] =
		current_cred();
	if (test_file->resolve_error && role == test_file->resolve_error_role &&
	    mode == test_file->resolve_error_mode)
		return ERR_PTR(test_file->resolve_error);
	if (role == FILE_RANGE_DESTINATION &&
	    mode == FILE_RANGE_RESOLVE_CACHED &&
	    test_file->revalidate_next)
		next = test_file->revalidate_next;
	if (test_file->ctx->record_revalidate_write_readers &&
	    role == FILE_RANGE_DESTINATION &&
	    mode == FILE_RANGE_RESOLVE_CACHED) {
		test_file->ctx->revalidate_file_write_readers[test_file->layer] =
			file_range_test_write_readers(file_inode(file)->i_sb);
		test_file->ctx->revalidate_next_write_readers[test_file->layer] =
			file_range_test_write_readers(file_inode(next)->i_sb);
	}
	return get_file(next);
}

static int file_range_test_prepare(struct file *file, struct file *next,
				   enum file_range_operation operation)
{
	struct file_range_test_file *test_file = file->private_data;
	struct file_range_test_ctx *ctx = test_file->ctx;

	ctx->prepare_operation = operation;
	ctx->prepare_calls++;
	ctx->prepare_file_write_readers[test_file->layer] =
		file_range_test_write_readers(file_inode(file)->i_sb);
	ctx->prepare_next_write_readers[test_file->layer] =
		file_range_test_write_readers(file_inode(next)->i_sb);
	ctx->prepare_creds[test_file->layer] = current_cred();
	if (ctx->nr_events < ARRAY_SIZE(ctx->events))
		ctx->events[ctx->nr_events++] =
			FILE_RANGE_TEST_PREPARE_0 + test_file->layer;
	return test_file->prepare_error;
}

static void file_range_test_finish(struct file *file, struct file *next,
				   enum file_range_operation operation,
				   loff_t pos_out, s64 ret)
{
	struct file_range_test_file *test_file = file->private_data;
	struct file_range_test_ctx *ctx = test_file->ctx;

	ctx->finish_operation = operation;
	ctx->finish_calls++;
	ctx->finish_file_write_readers[test_file->layer] =
		file_range_test_write_readers(file_inode(file)->i_sb);
	ctx->finish_next_write_readers[test_file->layer] =
		file_range_test_write_readers(file_inode(next)->i_sb);
	ctx->finish_ret[test_file->layer] = ret;
	ctx->finish_creds[test_file->layer] = current_cred();
	if (ctx->nr_events < ARRAY_SIZE(ctx->events))
		ctx->events[ctx->nr_events++] =
			FILE_RANGE_TEST_FINISH_0 + test_file->layer;
}

static struct file *
file_range_test_fail_resolve(struct file *file,
			     enum file_range_operation operation,
			     enum file_range_role role,
			     enum file_range_resolve_mode mode)
{
	struct file_range_test_file *test_file = file->private_data;

	test_file->ctx->deeper_resolve_calls++;
	return ERR_PTR(-EUCLEAN);
}

static ssize_t file_range_test_copy(struct file *file_in, loff_t pos_in,
				    struct file *file_out, loff_t pos_out,
				    size_t len, unsigned int flags)
{
	struct file_range_test_file *test_file = file_out->private_data;

	test_file->ctx->copy_calls++;
	test_file->ctx->copy_write_readers =
		file_range_test_write_readers(file_inode(file_out)->i_sb);
	test_file->ctx->copy_cred = current_cred();
	return len;
}

static ssize_t
file_range_test_other_copy(struct file *file_in, loff_t pos_in,
			   struct file *file_out, loff_t pos_out,
			   size_t len, unsigned int flags)
{
	return -EOPNOTSUPP;
}

static loff_t
file_range_test_remap(struct file *file_in, loff_t pos_in,
		      struct file *file_out, loff_t pos_out, loff_t len,
		      unsigned int remap_flags)
{
	struct file_range_test_file *test_file = file_in->private_data;
	struct file_range_test_ctx *ctx = test_file->ctx;

	ctx->remap_calls++;
	ctx->remap_flags = remap_flags;
	ctx->remap_cred = current_cred();
	ctx->remap_write_readers =
		file_range_test_write_readers(file_inode(file_out)->i_sb);
	return ctx->remap_ret;
}

static ssize_t
file_range_test_splice_read(struct file *file, loff_t *ppos,
			    struct pipe_inode_info *pipe, size_t len,
			    unsigned int flags)
{
	struct file_range_test_file *test_file = file->private_data;
	struct file_range_test_ctx *ctx = test_file->ctx;

	ctx->splice_calls++;
	ctx->splice_write_readers =
		file_range_test_write_readers(ctx->splice_destination_sb);
	return -ENODATA;
}

static ssize_t
file_range_test_splice_write(struct pipe_inode_info *pipe, struct file *file,
			     loff_t *ppos, size_t len, unsigned int flags)
{
	return -EIO;
}

static unsigned int
file_range_test_write_readers(struct super_block *sb)
{
	struct percpu_rw_semaphore *sem;
	unsigned int readers = 0;
	int cpu;

	sem = &sb->s_writers.rw_sem[SB_FREEZE_WRITE - 1];
	for_each_possible_cpu(cpu)
		readers += *per_cpu_ptr(sem->read_count, cpu);
	return readers;
}

static void file_range_test_sync_source_access(struct file *file)
{
	struct file_range_test_file *test_file = file->private_data;

	test_file->ctx->sync_source_access_calls++;
}

static const struct file_range_layer_operations file_range_test_layer_ops = {
	.supported_operations = BIT(FILE_RANGE_OPERATION_COPY),
	.resolve = file_range_test_resolve,
	.prepare_write = file_range_test_prepare,
	.finish_write = file_range_test_finish,
	.sync_source_access = file_range_test_sync_source_access,
};

static const struct file_range_layer_operations
file_range_test_fail_layer_ops[] = {
	{
		.supported_operations = BIT(FILE_RANGE_OPERATION_COPY),
		.resolve = file_range_test_fail_resolve,
		.prepare_write = file_range_test_prepare,
		.finish_write = file_range_test_finish,
	},
	{
		.supported_operations = BIT(FILE_RANGE_OPERATION_COPY),
		.resolve = file_range_test_fail_resolve,
		.prepare_write = file_range_test_prepare,
		.finish_write = file_range_test_finish,
	},
};

static const struct file_operations file_range_test_wrapper_fops = {
	.file_range_layer_ops = &file_range_test_layer_ops,
};

static const struct file_operations file_range_test_method_wrapper_fops[] = {
	{
		.copy_file_range = file_range_test_copy,
		.file_range_layer_ops = &file_range_test_layer_ops,
	},
	{
		.copy_file_range = file_range_test_other_copy,
		.file_range_layer_ops = &file_range_test_layer_ops,
	},
	{
		.file_range_layer_ops = &file_range_test_layer_ops,
	},
};

static const struct file_operations file_range_test_exact_method_fops = {
	.copy_file_range = file_range_test_copy,
	.file_range_layer_ops = &file_range_test_fail_layer_ops[0],
};

static const struct file_operations file_range_test_terminal_fops[] = {
	{
		.copy_file_range = file_range_test_copy,
		.file_range_layer_ops = &file_range_test_fail_layer_ops[0],
	},
	{
		.copy_file_range = file_range_test_copy,
		.file_range_layer_ops = &file_range_test_fail_layer_ops[1],
	},
};

static const struct file_operations file_range_test_unflagged_fops = {
};

static const struct file_operations file_range_test_paired_remap_fops = {
	.remap_file_range = file_range_test_remap,
};

static const struct file_operations file_range_test_paired_splice_read_fops = {
	.llseek = noop_llseek,
	.splice_read = file_range_test_splice_read,
};

static const struct file_operations file_range_test_paired_splice_write_fops = {
	.splice_write = file_range_test_splice_write,
};

static int file_range_test_init_fs_context(struct fs_context *fc)
{
	return init_pseudo(fc, FILE_RANGE_TEST_MAGIC) ? 0 : -ENOMEM;
}

static struct file_system_type file_range_test_fs_types[] = {
	{
		.name = "file_range_test_0",
		.init_fs_context = file_range_test_init_fs_context,
		.kill_sb = kill_anon_super,
	},
	{
		.name = "file_range_test_1",
		.init_fs_context = file_range_test_init_fs_context,
		.kill_sb = kill_anon_super,
	},
	{
		.name = "file_range_test_2",
		.init_fs_context = file_range_test_init_fs_context,
		.kill_sb = kill_anon_super,
	},
};

static void file_range_test_unregister_fs(void *data)
{
	unregister_filesystem(data);
}

static void file_range_test_unmount(void *data)
{
	kern_unmount(data);
}

static void file_range_test_fput(void *data)
{
	__fput_sync(data);
}

static struct file *
file_range_test_manage_file(struct kunit *test, struct file *file,
			    struct file_range_test_file *test_file)
{
	int ret;

	file->private_data = test_file;
	ret = kunit_add_action_or_reset(test, file_range_test_fput, file);
	return ret ? ERR_PTR(ret) : file;
}

static struct vfsmount *
file_range_test_mount(struct kunit *test, struct file_system_type *fs_type,
		      unsigned int stack_depth)
{
	struct vfsmount *mnt;
	int ret;

	mnt = kern_mount(fs_type);
	if (IS_ERR(mnt))
		return mnt;
	mnt->mnt_sb->s_stack_depth = stack_depth;
	ret = kunit_add_action_or_reset(test, file_range_test_unmount, mnt);
	if (ret)
		return ERR_PTR(ret);
	return mnt;
}

static struct file *
alloc_test_file(struct kunit *test, struct vfsmount *mnt,
		const struct file_operations *fops,
		struct file_range_test_file *test_file,
		struct file *user_file)
{
	struct inode *inode __free(file_range_test_iput) =
		new_inode_pseudo(mnt->mnt_sb);
	struct file *file;

	if (!inode)
		return ERR_PTR(-ENOMEM);
	inode->i_ino = get_next_ino();
	inode->i_mode = S_IFREG | 0600;
	i_size_write(inode, FILE_RANGE_TEST_SIZE);
	simple_inode_init_ts(inode);
	inode->i_fop = fops;

	struct file *path_file __free(fput) =
		alloc_file_pseudo(inode, mnt, "copy", O_RDWR, fops);

	if (IS_ERR(path_file))
		return path_file;
	retain_and_null_ptr(inode);

	if (user_file) {
		file = backing_file_open(user_file, O_RDWR,
					 &path_file->f_path, current_cred());
		if (IS_ERR(file))
			return file;
	} else {
		file = no_free_ptr(path_file);
	}
	return file_range_test_manage_file(test, file, test_file);
}

static struct file *
alloc_backing_alias(struct kunit *test, struct file *user_file,
		    struct file *backing,
		    struct file_range_test_file *test_file)
{
	struct file *file;

	file = backing_file_open(user_file, O_RDWR, &backing->f_path,
				 current_cred());
	if (IS_ERR(file))
		return file;
	return file_range_test_manage_file(test, file, test_file);
}

static void
file_range_test_init_mounts(struct kunit *test,
			    struct vfsmount *mounts[3])
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(file_range_test_fs_types); i++) {
		struct file_system_type *fs_type =
			&file_range_test_fs_types[i];

		ret = register_filesystem(fs_type);
		KUNIT_ASSERT_EQ(test, ret, 0);
		ret = kunit_add_action_or_reset(test,
						file_range_test_unregister_fs,
						fs_type);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	for (i = 0; i < ARRAY_SIZE(file_range_test_fs_types); i++) {
		struct file_system_type *fs_type =
			&file_range_test_fs_types[i];
		unsigned int stack_depth =
			ARRAY_SIZE(file_range_test_fs_types) - i - 1;

		mounts[i] = file_range_test_mount(test, fs_type, stack_depth);
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, mounts[i]);
	}
	for (i = 1; i < ARRAY_SIZE(file_range_test_fs_types); i++)
		KUNIT_ASSERT_PTR_NE(test, mounts[i - 1]->mnt_sb,
				    mounts[i]->mnt_sb);
}

struct file_range_test_route {
	struct file_range_test_ctx ctx;
	struct file_range_test_file test_files[2][3];
	struct vfsmount *mounts[3];
	struct file *files[2][3];
};

static struct file_range_test_route *
alloc_cred_route(struct kunit *test, const struct cred *source_cred,
		 const struct cred *source_terminal_cred,
		 const struct cred *destination_cred,
		 const struct cred *destination_terminal_cred)
{
	const struct cred *creds[] = { source_cred, destination_cred };
	struct file_range_test_route *route;
	unsigned int side, layer;

	route = kunit_kzalloc(test, sizeof(*route), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, route);
	file_range_test_init_mounts(test, route->mounts);

	for (side = 0; side < ARRAY_SIZE(route->files); side++) {
		for (layer = 0; layer < ARRAY_SIZE(route->files[side]); layer++) {
			struct file_range_test_file *test_file =
				&route->test_files[side][layer];
			const struct cred *cred = creds[side];
			const struct file_operations *fops;
			struct file *user_file;

			test_file->ctx = &route->ctx;
			test_file->layer = layer;
			fops = layer + 1 == ARRAY_SIZE(route->files[side]) ?
			       &file_range_test_terminal_fops[side] :
			       &file_range_test_wrapper_fops;
			user_file = layer ? route->files[side][0] : NULL;
			if (layer + 1 == ARRAY_SIZE(route->files[side]))
				cred = side == FILE_RANGE_SOURCE ?
				       source_terminal_cred :
				       destination_terminal_cred;
			scoped_with_creds(cred)
				route->files[side][layer] =
					alloc_test_file(test, route->mounts[layer],
							fops, test_file, user_file);
			KUNIT_ASSERT_NOT_ERR_OR_NULL(test,
						     route->files[side][layer]);
			if (layer)
				route->test_files[side][layer - 1].next =
					route->files[side][layer];
		}
	}

	return route;
}

static struct file_range_test_route *
file_range_test_alloc_paired_route(struct kunit *test)
{
	return alloc_cred_route(test, current_cred(), current_cred(),
				current_cred(), current_cred());
}

static void
file_range_test_get_refs(const struct file_range_test_route *route,
			 unsigned long refs[2][2])
{
	unsigned int side, layer;

	for (side = 0; side < ARRAY_SIZE(route->files); side++)
		for (layer = 1; layer < ARRAY_SIZE(route->files[side]); layer++)
			refs[side][layer - 1] =
				file_count(route->files[side][layer]);
}

static void
file_range_test_expect_refs(struct kunit *test,
			    const struct file_range_test_route *route,
			    const unsigned long refs[2][2])
{
	unsigned int side, layer;

	for (side = 0; side < ARRAY_SIZE(route->files); side++)
		for (layer = 1; layer < ARRAY_SIZE(route->files[side]); layer++)
			KUNIT_EXPECT_EQ(test,
					file_count(route->files[side][layer]),
					refs[side][layer - 1]);
}

struct file_range_test_layered_file {
	struct file_range_test_file wrapper_private;
	struct file_range_test_file backing_private;
	struct file *wrapper;
	struct file *backing;
};

static struct file_range_test_layered_file *
alloc_layered_file(struct kunit *test, struct file_range_test_ctx *ctx,
		   struct vfsmount *wrapper_mnt,
		   struct vfsmount *backing_mnt,
		   const struct file_operations *wrapper_fops,
		   const struct file_operations *backing_fops)
{
	struct file_range_test_layered_file *file;

	file = kunit_kzalloc(test, sizeof(*file), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, file);
	file->wrapper_private.ctx = ctx;
	file->wrapper = alloc_test_file(test, wrapper_mnt, wrapper_fops,
					&file->wrapper_private, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file->wrapper);
	file->backing_private.ctx = ctx;
	file->backing_private.layer = 1;
	file->backing = alloc_test_file(test, backing_mnt, backing_fops,
					&file->backing_private, file->wrapper);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, file->backing);
	file->wrapper_private.next = file->backing;
	return file;
}

static void file_range_test_paired_dispatch(struct kunit *test)
{
	struct file_range_test_route *route;
	unsigned long refs[2][2];
	ssize_t ret;
	unsigned int layer;

	route = file_range_test_alloc_paired_route(test);
	file_range_test_get_refs(route, refs);
	route->ctx.record_revalidate_write_readers = true;
	memset(route->ctx.revalidate_file_write_readers, 0xff,
	       sizeof(route->ctx.revalidate_file_write_readers));
	memset(route->ctx.revalidate_next_write_readers, 0xff,
	       sizeof(route->ctx.revalidate_next_write_readers));

	ret = vfs_copy_file_range(route->files[FILE_RANGE_SOURCE][0], 0,
				  route->files[FILE_RANGE_DESTINATION][0],
				  0, 512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)512);
	for (layer = 0; layer < 2; layer++) {
		unsigned int (*calls)[2] = route->ctx.resolve_calls[layer];

		KUNIT_EXPECT_EQ(test, calls[FILE_RANGE_SOURCE]
					 [FILE_RANGE_RESOLVE_MAY_OPEN], 1U);
		KUNIT_EXPECT_EQ(test, calls[FILE_RANGE_DESTINATION]
					 [FILE_RANGE_RESOLVE_MAY_OPEN], 1U);
		KUNIT_EXPECT_EQ(test, calls[FILE_RANGE_SOURCE]
					 [FILE_RANGE_RESOLVE_CACHED], 0U);
		KUNIT_EXPECT_EQ(test, calls[FILE_RANGE_DESTINATION]
					 [FILE_RANGE_RESOLVE_CACHED], 1U);
		KUNIT_EXPECT_EQ(test,
				route->ctx.revalidate_file_write_readers[layer], 0U);
		KUNIT_EXPECT_EQ(test,
				route->ctx.revalidate_next_write_readers[layer], 0U);
	}
	KUNIT_EXPECT_EQ(test, route->ctx.prepare_calls, 2U);
	KUNIT_EXPECT_EQ(test, route->ctx.finish_calls, 2U);
	KUNIT_EXPECT_EQ(test, route->ctx.copy_calls, 1U);
	KUNIT_EXPECT_EQ(test, route->ctx.deeper_resolve_calls, 0U);
	for (layer = 0; layer < 2; layer++) {
		KUNIT_EXPECT_EQ(test,
				route->ctx.prepare_file_write_readers[layer], 1U);
		KUNIT_EXPECT_EQ(test,
				route->ctx.prepare_next_write_readers[layer], 0U);
		KUNIT_EXPECT_EQ(test,
				route->ctx.finish_file_write_readers[layer], 1U);
		KUNIT_EXPECT_EQ(test,
				route->ctx.finish_next_write_readers[layer], 0U);
	}
	KUNIT_EXPECT_EQ(test, route->ctx.copy_write_readers, 1U);
	file_range_test_expect_refs(test, route, refs);
}

static void file_range_test_credential_domains(struct kunit *test)
{
	CLASS(prepare_creds, source_cred)();
	CLASS(prepare_creds, source_terminal_cred)();
	CLASS(prepare_creds, destination_cred)();
	CLASS(prepare_creds, destination_terminal_cred)();
	const struct cred *caller_cred = current_cred();
	const struct cred *creds[] = {
		caller_cred,
		source_cred,
		source_terminal_cred,
		destination_cred,
		destination_terminal_cred,
	};
	const struct cred *expected_verify_creds[2][3] = {
		[FILE_RANGE_SOURCE] = {
			NULL, source_cred, source_terminal_cred,
		},
		[FILE_RANGE_DESTINATION] = {
			NULL, destination_cred, destination_terminal_cred,
		},
	};
	const struct cred *observed;
	struct file_range_test_route *route;
	unsigned int i, j, side, layer;
	ssize_t ret;

	for (i = 0; i < ARRAY_SIZE(creds); i++) {
		KUNIT_ASSERT_NOT_NULL(test, creds[i]);
		for (j = 0; j < i; j++)
			KUNIT_ASSERT_PTR_NE(test, creds[i], creds[j]);
	}

	route = alloc_cred_route(test, source_cred, source_terminal_cred,
				 destination_cred,
				 destination_terminal_cred);
	kunit_activate_static_stub(test, copy_file_range_verify_backing_area,
				   file_range_test_verify_backing_area);
	ret = vfs_copy_file_range(route->files[FILE_RANGE_SOURCE][0], 0,
				  route->files[FILE_RANGE_DESTINATION][0],
				  0, 512, 0);
	KUNIT_ASSERT_EQ(test, ret, (ssize_t)512);
	for (side = 0; side < ARRAY_SIZE(route->files); side++) {
		for (layer = 1; layer < ARRAY_SIZE(route->files[side]); layer++) {
			const struct file *verified_file =
				route->ctx.verify_files[side][layer];
			const struct cred *verified_cred =
				route->ctx.verify_creds[side][layer];

			KUNIT_EXPECT_EQ(test,
					route->ctx.verify_calls[side][layer], 1U);
			KUNIT_EXPECT_EQ(test,
					route->ctx.verify_write_readers[side][layer],
					0U);
			KUNIT_EXPECT_PTR_EQ(test, verified_file,
					    route->files[side][layer]);
			KUNIT_EXPECT_PTR_EQ(test, verified_cred,
					    expected_verify_creds[side][layer]);
		}
	}

	/* The first resolver on either endpoint uses the caller's credentials. */
	observed = route->ctx.resolve_creds[0][FILE_RANGE_SOURCE]
					  [FILE_RANGE_RESOLVE_MAY_OPEN];
	KUNIT_EXPECT_PTR_EQ(test, observed, caller_cred);
	observed = route->ctx.resolve_creds[0][FILE_RANGE_DESTINATION]
					  [FILE_RANGE_RESOLVE_MAY_OPEN];
	KUNIT_EXPECT_PTR_EQ(test, observed, caller_cred);
	observed = route->ctx.resolve_creds[0][FILE_RANGE_DESTINATION]
					  [FILE_RANGE_RESOLVE_CACHED];
	KUNIT_EXPECT_PTR_EQ(test, observed, caller_cred);

	/* Nested resolution uses the current backing file's pinned credentials. */
	observed = route->ctx.resolve_creds[1][FILE_RANGE_SOURCE]
					  [FILE_RANGE_RESOLVE_MAY_OPEN];
	KUNIT_EXPECT_PTR_EQ(test, observed, source_cred);
	observed = route->ctx.resolve_creds[1][FILE_RANGE_DESTINATION]
					  [FILE_RANGE_RESOLVE_MAY_OPEN];
	KUNIT_EXPECT_PTR_EQ(test, observed, destination_cred);
	observed = route->ctx.resolve_creds[1][FILE_RANGE_DESTINATION]
					  [FILE_RANGE_RESOLVE_CACHED];
	KUNIT_EXPECT_PTR_EQ(test, observed, destination_cred);

	/* Destination execution changes domains at each destination edge. */
	KUNIT_EXPECT_PTR_EQ(test, route->ctx.prepare_creds[0], caller_cred);
	KUNIT_EXPECT_PTR_EQ(test, route->ctx.prepare_creds[1], destination_cred);
	KUNIT_EXPECT_PTR_EQ(test, route->ctx.copy_cred,
			    destination_terminal_cred);
	KUNIT_EXPECT_PTR_EQ(test, route->ctx.finish_creds[1], destination_cred);
	KUNIT_EXPECT_PTR_EQ(test, route->ctx.finish_creds[0], caller_cred);
	KUNIT_EXPECT_PTR_EQ(test, current_cred(), caller_cred);
}

static void file_range_test_complete_chain_alias(struct kunit *test)
{
	struct file_range_test_file *alias_private;
	struct file_range_test_route *route;
	struct file *alias, *source, *destination, *shared;
	unsigned long refs[2][2], alias_refs;
	ssize_t ret;

	route = file_range_test_alloc_paired_route(test);
	source = route->files[FILE_RANGE_SOURCE][0];
	destination = route->files[FILE_RANGE_DESTINATION][0];
	shared = route->files[FILE_RANGE_DESTINATION][1];
	alias_private = kunit_kzalloc(test, sizeof(*alias_private), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, alias_private);
	alias_private->ctx = &route->ctx;
	alias_private->layer = 1;
	alias_private->next = route->files[FILE_RANGE_SOURCE][2];
	alias = alloc_backing_alias(test, source, shared, alias_private);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, alias);
	KUNIT_ASSERT_PTR_NE(test, alias, shared);
	KUNIT_ASSERT_PTR_EQ(test, file_inode(alias), file_inode(shared));
	KUNIT_ASSERT_PTR_NE(test,
			    file_inode(route->files[FILE_RANGE_SOURCE][2]),
			    file_inode(route->files[FILE_RANGE_DESTINATION][2]));

	route->test_files[FILE_RANGE_SOURCE][0].next = alias;
	file_range_test_get_refs(route, refs);
	alias_refs = file_count(alias);
	ret = vfs_copy_file_range(source, 0, destination, 1024, 512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)-EXDEV);
	KUNIT_EXPECT_EQ(test, route->ctx.prepare_calls, 0U);
	KUNIT_EXPECT_EQ(test, route->ctx.finish_calls, 0U);
	KUNIT_EXPECT_EQ(test, route->ctx.copy_calls, 0U);
	file_range_test_expect_refs(test, route, refs);
	KUNIT_EXPECT_EQ(test, file_count(alias), alias_refs);
}

static void file_range_test_layer_method_selection(struct kunit *test)
{
	struct file_range_test_layered_file *copy_method;
	struct file_range_test_layered_file *other_method;
	struct file_range_test_layered_file *no_method;
	struct file_range_test_ctx *ctx;
	struct vfsmount *mounts[3];
	unsigned int count;
	ssize_t ret;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	file_range_test_init_mounts(test, mounts);

	copy_method =
		alloc_layered_file(test, ctx, mounts[1], mounts[2],
				   &file_range_test_method_wrapper_fops[0],
				   &file_range_test_unflagged_fops);
	other_method =
		alloc_layered_file(test, ctx, mounts[1], mounts[2],
				   &file_range_test_method_wrapper_fops[1],
				   &file_range_test_unflagged_fops);
	no_method =
		alloc_layered_file(test, ctx, mounts[1], mounts[2],
				   &file_range_test_method_wrapper_fops[2],
				   &file_range_test_unflagged_fops);
	/* Matching tables do not pair files with different copy methods. */
	ret = vfs_copy_file_range(copy_method->wrapper, 0,
				  other_method->wrapper, 0, 512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)-EXDEV);
	/* A one-sided method keeps the ordinary same-sb route. */
	count = file_range_test_resolve_count(ctx);
	ret = vfs_copy_file_range(copy_method->wrapper, 0,
				  no_method->wrapper, 0, 512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)-EINVAL);
	KUNIT_EXPECT_EQ(test, file_range_test_resolve_count(ctx), count);
}

static void file_range_test_paired_splice_route(struct kunit *test)
{
	struct file_range_test_layered_file *source;
	struct file_range_test_layered_file *destination;
	struct file_range_test_ctx *ctx;
	struct vfsmount *mounts[3];
	unsigned int count;
	ssize_t ret;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	file_range_test_init_mounts(test, mounts);

	source = alloc_layered_file(test, ctx, mounts[0], mounts[2],
				    &file_range_test_wrapper_fops,
				    &file_range_test_paired_splice_read_fops);
	destination = alloc_layered_file(test, ctx, mounts[1], mounts[2],
					 &file_range_test_wrapper_fops,
					 &file_range_test_paired_splice_write_fops);
	ctx->splice_destination_sb = file_inode(destination->backing)->i_sb;

	/* A cross-sb paired zero-length request does not resolve either side. */
	count = file_range_test_resolve_count(ctx);
	ret = vfs_copy_file_range(source->wrapper, 0, destination->wrapper, 0,
				  0, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)0);
	KUNIT_EXPECT_EQ(test, file_range_test_resolve_count(ctx), count);
	/* Paired layers retain the ordinary unflagged terminal splice route. */
	ret = vfs_copy_file_range(source->wrapper, 0, destination->wrapper, 0,
				  512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)-ENODATA);
	KUNIT_EXPECT_EQ(test, ctx->splice_calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx->splice_write_readers, 0U);
	KUNIT_EXPECT_EQ(test, ctx->sync_source_access_calls, 1U);
}

static void file_range_test_paired_remap_route(struct kunit *test)
{
	struct file_range_test_layered_file *source;
	struct file_range_test_layered_file *destination;
	struct file_range_test_ctx *ctx;
	struct vfsmount *mounts[3];
	ssize_t ret;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	file_range_test_init_mounts(test, mounts);

	source = alloc_layered_file(test, ctx, mounts[1], mounts[2],
				    &file_range_test_wrapper_fops,
				    &file_range_test_paired_remap_fops);
	destination = alloc_layered_file(test, ctx, mounts[1], mounts[2],
					 &file_range_test_wrapper_fops,
					 &file_range_test_unflagged_fops);
	ctx->remap_ret = 512;

	ret = vfs_copy_file_range(source->wrapper, 0, destination->wrapper, 0,
				  512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)512);
	KUNIT_EXPECT_EQ(test, ctx->remap_calls, 1U);
	KUNIT_EXPECT_EQ(test, ctx->remap_flags,
			(unsigned int)REMAP_FILE_CAN_SHORTEN);
	KUNIT_EXPECT_EQ(test, ctx->remap_write_readers, 1U);
	KUNIT_EXPECT_PTR_EQ(test, ctx->remap_cred,
			    destination->backing->f_cred);
}

static void file_range_test_exact_method_precedence(struct kunit *test)
{
	struct file_range_test_file *source_private;
	struct file_range_test_file *destination_private;
	struct file_range_test_ctx *ctx;
	struct vfsmount *mounts[3];
	struct file *source, *destination;
	ssize_t ret;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	source_private = kunit_kzalloc(test, sizeof(*source_private), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, source_private);
	destination_private = kunit_kzalloc(test, sizeof(*destination_private),
					    GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, destination_private);
	file_range_test_init_mounts(test, mounts);
	source_private->ctx = ctx;
	source = alloc_test_file(test, mounts[0],
				 &file_range_test_exact_method_fops,
				 source_private, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, source);
	destination_private->ctx = ctx;
	destination = alloc_test_file(test, mounts[1],
				      &file_range_test_exact_method_fops,
				      destination_private, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, destination);

	/* An exact method wins even when both files share the same layer table. */
	ret = vfs_copy_file_range(source, 0, destination, 0, 512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)512);
	KUNIT_EXPECT_EQ(test, ctx->deeper_resolve_calls, 0U);
	KUNIT_EXPECT_EQ(test, ctx->copy_calls, 1U);
}

static void file_range_test_resolution_failure(struct kunit *test)
{
	struct file_range_test_route *route;
	struct file_range_test_file *fail_file;
	unsigned long refs[2][2];
	ssize_t ret;

	route = file_range_test_alloc_paired_route(test);
	file_range_test_get_refs(route, refs);

	fail_file = &route->test_files[FILE_RANGE_DESTINATION][1];
	fail_file->resolve_error = -EUCLEAN;
	fail_file->resolve_error_role = FILE_RANGE_DESTINATION;
	fail_file->resolve_error_mode = FILE_RANGE_RESOLVE_MAY_OPEN;

	ret = vfs_copy_file_range(route->files[FILE_RANGE_SOURCE][0], 0,
				  route->files[FILE_RANGE_DESTINATION][0],
				  0, 512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)-EUCLEAN);
	KUNIT_EXPECT_EQ(test, route->ctx.prepare_calls, 0U);
	KUNIT_EXPECT_EQ(test, route->ctx.finish_calls, 0U);
	KUNIT_EXPECT_EQ(test, route->ctx.copy_calls, 0U);
	file_range_test_expect_refs(test, route, refs);
}

static void file_range_test_revalidation_failure(struct kunit *test)
{
	struct file_range_test_route *route;
	struct file_range_test_file *alternate_file;
	const struct file_operations *alternate_fops;
	struct file *alternate;
	unsigned long refs[2][2], alternate_refs;
	unsigned int cached_calls;
	ssize_t ret;

	route = file_range_test_alloc_paired_route(test);
	alternate_file = kunit_kzalloc(test, sizeof(*alternate_file), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, alternate_file);
	alternate_file->ctx = &route->ctx;
	alternate_file->layer = 2;
	alternate_fops =
		&file_range_test_terminal_fops[FILE_RANGE_DESTINATION];
	alternate = alloc_test_file(test, route->mounts[2], alternate_fops,
				    alternate_file,
				    route->files[FILE_RANGE_DESTINATION][0]);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, alternate);

	route->test_files[FILE_RANGE_DESTINATION][1].revalidate_next =
		alternate;
	file_range_test_get_refs(route, refs);
	alternate_refs = file_count(alternate);

	ret = vfs_copy_file_range(route->files[FILE_RANGE_SOURCE][0], 0,
				  route->files[FILE_RANGE_DESTINATION][0],
				  0, 512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)-EXDEV);
	KUNIT_EXPECT_EQ(test, route->ctx.prepare_calls, 0U);
	KUNIT_EXPECT_EQ(test, route->ctx.finish_calls, 0U);
	KUNIT_EXPECT_EQ(test, route->ctx.copy_calls, 0U);
	cached_calls = route->ctx.resolve_calls[1][FILE_RANGE_DESTINATION]
					     [FILE_RANGE_RESOLVE_CACHED];
	KUNIT_EXPECT_EQ(test, cached_calls, 1U);
	file_range_test_expect_refs(test, route, refs);
	KUNIT_EXPECT_EQ(test, file_count(alternate), alternate_refs);
}

static void file_range_test_nested_prepare_failure(struct kunit *test)
{
	static const unsigned int expected_events[] = {
		FILE_RANGE_TEST_PREPARE_0,
		FILE_RANGE_TEST_PREPARE_1,
		FILE_RANGE_TEST_FINISH_0,
	};
	struct file_range_test_route *route;
	unsigned long refs[2][2];
	ssize_t ret;
	unsigned int i;

	route = file_range_test_alloc_paired_route(test);
	route->test_files[FILE_RANGE_DESTINATION][1].prepare_error =
		-EUCLEAN;
	file_range_test_get_refs(route, refs);

	ret = vfs_copy_file_range(route->files[FILE_RANGE_SOURCE][0], 0,
				  route->files[FILE_RANGE_DESTINATION][0],
				  0, 512, 0);
	KUNIT_EXPECT_EQ(test, ret, (ssize_t)-EUCLEAN);
	KUNIT_EXPECT_EQ(test, route->ctx.prepare_calls, 2U);
	KUNIT_EXPECT_EQ(test, route->ctx.finish_calls, 1U);
	KUNIT_EXPECT_EQ(test, route->ctx.copy_calls, 0U);
	KUNIT_EXPECT_EQ(test, route->ctx.finish_ret[0], (ssize_t)-EUCLEAN);
	KUNIT_ASSERT_EQ(test, route->ctx.nr_events,
			(unsigned int)ARRAY_SIZE(expected_events));
	for (i = 0; i < ARRAY_SIZE(expected_events); i++)
		KUNIT_EXPECT_EQ(test, route->ctx.events[i], expected_events[i]);
	file_range_test_expect_refs(test, route, refs);
}

static struct kunit_case file_range_test_cases[] = {
	KUNIT_CASE(file_range_test_paired_dispatch),
	KUNIT_CASE(file_range_test_credential_domains),
	KUNIT_CASE(file_range_test_complete_chain_alias),
	KUNIT_CASE(file_range_test_layer_method_selection),
	KUNIT_CASE(file_range_test_paired_splice_route),
	KUNIT_CASE(file_range_test_paired_remap_route),
	KUNIT_CASE(file_range_test_exact_method_precedence),
	KUNIT_CASE(file_range_test_resolution_failure),
	KUNIT_CASE(file_range_test_revalidation_failure),
	KUNIT_CASE(file_range_test_nested_prepare_failure),
	{},
};

static struct kunit_suite file_range_test_suite = {
	.name = "file_range",
	.test_cases = file_range_test_cases,
};

kunit_test_suite(file_range_test_suite);

MODULE_DESCRIPTION("KUnit tests for file range routing");
MODULE_LICENSE("GPL");
