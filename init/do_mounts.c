// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/fd.h>
#include <linux/tty.h>
#include <linux/suspend.h>
#include <linux/root_dev.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/async.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>
#include <linux/ramfs.h>
#include <linux/shmem_fs.h>
#include <linux/ktime.h>

#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/nfs_mount.h>
#include <linux/raid/detect.h>
#include <linux/fsverity.h>
#include <linux/hex.h>
#include <crypto/hash_info.h>
#include <uapi/linux/mount.h>

#include "do_mounts.h"

int root_mountflags = MS_RDONLY | MS_SILENT;
static char __initdata saved_root_name[64];
static int root_wait;

dev_t ROOT_DEV;

static int __init readonly(char *str)
{
	if (*str)
		return 0;
	root_mountflags |= MS_RDONLY;
	return 1;
}

static int __init readwrite(char *str)
{
	if (*str)
		return 0;
	root_mountflags &= ~MS_RDONLY;
	return 1;
}

__setup("ro", readonly);
__setup("rw", readwrite);

static int __init root_dev_setup(char *line)
{
	strscpy(saved_root_name, line, sizeof(saved_root_name));
	return 1;
}

__setup("root=", root_dev_setup);

static int __init rootwait_setup(char *str)
{
	if (*str)
		return 0;
	root_wait = -1;
	return 1;
}

__setup("rootwait", rootwait_setup);

static int __init rootwait_timeout_setup(char *str)
{
	int sec;

	if (kstrtoint(str, 0, &sec) || sec < 0) {
		pr_warn("ignoring invalid rootwait value\n");
		goto ignore;
	}

	if (check_mul_overflow(sec, MSEC_PER_SEC, &root_wait)) {
		pr_warn("ignoring excessive rootwait value\n");
		goto ignore;
	}

	return 1;

ignore:
	/* Fallback to indefinite wait */
	root_wait = -1;

	return 1;
}

__setup("rootwait=", rootwait_timeout_setup);

static char * __initdata root_mount_data;
static int __init root_data_setup(char *str)
{
	root_mount_data = str;
	return 1;
}

static char * __initdata root_fs_names;
static int __init fs_names_setup(char *str)
{
	root_fs_names = str;
	return 1;
}

static unsigned int __initdata root_delay;
static int __init root_delay_setup(char *str)
{
	if (kstrtouint(str, 0, &root_delay))
		return 0;
	return 1;
}

__setup("rootflags=", root_data_setup);
__setup("rootfstype=", fs_names_setup);
__setup("rootdelay=", root_delay_setup);

/*
 * rootimage= mounts the actual root filesystem from an image file located
 * on the filesystem specified by root= instead of using that filesystem
 * as the root directly.
 */
static char * __initdata root_image;
static int __init root_image_setup(char *str)
{
	root_image = str;
	return 1;
}

static char * __initdata root_image_fs_names;
static int __init root_image_fs_names_setup(char *str)
{
	root_image_fs_names = str;
	return 1;
}

static char * __initdata root_image_mount_data;
static int __init root_image_data_setup(char *str)
{
	root_image_mount_data = str;
	return 1;
}

static char * __initdata root_image_srcdir;
static int __init root_image_srcdir_setup(char *str)
{
	root_image_srcdir = str;
	return 1;
}

static char * __initdata root_image_verity;
static int __init root_image_verity_setup(char *str)
{
	root_image_verity = str;
	return 1;
}

__setup("rootimage=", root_image_setup);
__setup("rootimagefstype=", root_image_fs_names_setup);
__setup("rootimageflags=", root_image_data_setup);
__setup("rootimagesrcdir=", root_image_srcdir_setup);
__setup("rootimageverity=", root_image_verity_setup);

/* This can return zero length strings. Caller should check */
static int __init split_fs_names(char *page, size_t size, char *names)
{
	int count = 1;
	char *p = page;

	strscpy(p, names, size);
	while (*p++) {
		if (p[-1] == ',') {
			p[-1] = '\0';
			count++;
		}
	}

	return count;
}

static int __init do_mount_root(const char *name, const char *dir,
				 const char *fs, const int flags,
				 const void *data)
{
	struct super_block *s;
	char *data_page = NULL;
	int ret;

	if (data) {
		/* init_mount() requires a full page as fifth argument */
		data_page = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!data_page)
			return -ENOMEM;
		strscpy_pad(data_page, data, PAGE_SIZE);
	}

	ret = init_mount(name, dir, fs, flags, data_page);
	if (ret)
		goto out;

	init_chdir(dir);
	s = current->fs->pwd.dentry->d_sb;
	ROOT_DEV = s->s_dev;
	printk(KERN_INFO
	       "VFS: Mounted root (%s filesystem)%s on device %u:%u.\n",
	       s->s_type->name,
	       sb_rdonly(s) ? " readonly" : "",
	       MAJOR(ROOT_DEV), MINOR(ROOT_DEV));

out:
	kfree(data_page);
	return ret;
}

void __init mount_root_generic(char *name, char *pretty_name, int flags)
{
	char *fs_names = kmalloc(PAGE_SIZE, GFP_KERNEL);
	char *p;
	char b[BDEVNAME_SIZE];
	int num_fs, i;

	if (!fs_names)
		panic("VFS: Unable to mount root fs: not enough memory");

	scnprintf(b, BDEVNAME_SIZE, "unknown-block(%u,%u)",
		  MAJOR(ROOT_DEV), MINOR(ROOT_DEV));
	if (root_fs_names)
		num_fs = split_fs_names(fs_names, PAGE_SIZE, root_fs_names);
	else
		num_fs = list_bdev_fs_names(fs_names, PAGE_SIZE);
retry:
	for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p)+1) {
		int err;

		if (!*p)
			continue;
		err = do_mount_root(name, "/root", p, flags, root_mount_data);
		switch (err) {
			case 0:
				goto out;
			case -EACCES:
			case -EINVAL:
#ifdef CONFIG_BLOCK
				init_flush_fput();
#endif
				continue;
		}
	        /*
		 * Allow the user to distinguish between failed sys_open
		 * and bad superblock on root device.
		 * and give them a list of the available devices
		 */
		printk("VFS: Cannot open root device \"%s\" or %s: error %d\n",
				pretty_name, b, err);
		printk("Please append a correct \"root=\" boot option; here are the available partitions:\n");
		printk_all_partitions();

		if (root_fs_names)
			num_fs = list_bdev_fs_names(fs_names, PAGE_SIZE);
		if (!num_fs)
			pr_err("Can't find any bdev filesystem to be used for mount!\n");
		else {
			pr_err("List of all bdev filesystems:\n");
			for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p)+1)
				pr_err(" %s", p);
			pr_err("\n");
		}

		panic("VFS: Unable to mount root fs on %s", b);
	}
	if (!(flags & SB_RDONLY)) {
		flags |= SB_RDONLY;
		goto retry;
	}

	printk("List of all partitions:\n");
	printk_all_partitions();
	printk("No filesystem could mount root, tried: ");
	for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p)+1)
		printk(" %s", p);
	printk("\n");
	panic("VFS: Unable to mount root fs on \"%s\" or %s", pretty_name, b);
out:
	kfree(fs_names);
}
 
#ifdef CONFIG_ROOT_NFS

#define NFSROOT_TIMEOUT_MIN	5
#define NFSROOT_TIMEOUT_MAX	30
#define NFSROOT_RETRY_MAX	5

static void __init mount_nfs_root(void)
{
	char *root_dev, *root_data;
	unsigned int timeout;
	int try;

	if (nfs_root_data(&root_dev, &root_data))
		goto fail;

	/*
	 * The server or network may not be ready, so try several
	 * times.  Stop after a few tries in case the client wants
	 * to fall back to other boot methods.
	 */
	timeout = NFSROOT_TIMEOUT_MIN;
	for (try = 1; ; try++) {
		if (!do_mount_root(root_dev, "/root", "nfs", root_mountflags,
				   root_data))
			return;
		if (try > NFSROOT_RETRY_MAX)
			break;

		/* Wait, in case the server refused us immediately */
		ssleep(timeout);
		timeout <<= 1;
		if (timeout > NFSROOT_TIMEOUT_MAX)
			timeout = NFSROOT_TIMEOUT_MAX;
	}
fail:
	pr_err("VFS: Unable to mount root fs via NFS.\n");
}
#else
static inline void mount_nfs_root(void)
{
}
#endif /* CONFIG_ROOT_NFS */

#ifdef CONFIG_CIFS_ROOT

#define CIFSROOT_TIMEOUT_MIN	5
#define CIFSROOT_TIMEOUT_MAX	30
#define CIFSROOT_RETRY_MAX	5

static void __init mount_cifs_root(void)
{
	char *root_dev, *root_data;
	unsigned int timeout;
	int try;

	if (cifs_root_data(&root_dev, &root_data))
		goto fail;

	timeout = CIFSROOT_TIMEOUT_MIN;
	for (try = 1; ; try++) {
		if (!do_mount_root(root_dev, "/root", "cifs", root_mountflags,
				   root_data))
			return;
		if (try > CIFSROOT_RETRY_MAX)
			break;

		ssleep(timeout);
		timeout <<= 1;
		if (timeout > CIFSROOT_TIMEOUT_MAX)
			timeout = CIFSROOT_TIMEOUT_MAX;
	}
fail:
	pr_err("VFS: Unable to mount root fs via SMB.\n");
}
#else
static inline void mount_cifs_root(void)
{
}
#endif /* CONFIG_CIFS_ROOT */

static bool __init fs_is_nodev(char *fstype)
{
	struct file_system_type *fs = get_fs_type(fstype);
	bool ret = false;

	if (fs) {
		ret = !(fs->fs_flags & FS_REQUIRES_DEV);
		put_filesystem(fs);
	}

	return ret;
}

static int __init mount_nodev_root(char *root_device_name)
{
	char *fs_names, *fstype;
	int err = -EINVAL;
	int num_fs, i;

	fs_names = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!fs_names)
		return -EINVAL;
	num_fs = split_fs_names(fs_names, PAGE_SIZE, root_fs_names);

	for (i = 0, fstype = fs_names; i < num_fs;
	     i++, fstype += strlen(fstype) + 1) {
		if (!*fstype)
			continue;
		if (!fs_is_nodev(fstype))
			continue;
		err = do_mount_root(root_device_name, "/root", fstype,
				    root_mountflags, root_mount_data);
		if (!err)
			break;
	}

	kfree(fs_names);
	return err;
}

#ifdef CONFIG_BLOCK
static void __init mount_block_root(char *root_device_name)
{
	int err = create_dev("/dev/root", ROOT_DEV);

	if (err < 0)
		pr_emerg("Failed to create /dev/root: %d\n", err);
	mount_root_generic("/dev/root", root_device_name, root_mountflags);
}
#else
static inline void mount_block_root(char *root_device_name)
{
}
#endif /* CONFIG_BLOCK */

void __init mount_root(char *root_device_name)
{
	switch (ROOT_DEV) {
	case Root_NFS:
		mount_nfs_root();
		break;
	case Root_CIFS:
		mount_cifs_root();
		break;
	case Root_Generic:
		mount_root_generic(root_device_name, root_device_name,
				   root_mountflags);
		break;
	case 0:
		if (root_device_name && root_fs_names &&
		    mount_nodev_root(root_device_name) == 0)
			break;
		fallthrough;
	default:
		mount_block_root(root_device_name);
		break;
	}
}

#ifdef CONFIG_FS_VERITY
/*
 * Require the root image to carry the fsverity file digest given by
 * rootimageverity=<hash algorithm>:<hex digest>.  @file must have been
 * opened so that its fsverity information is loaded.  Any deviation
 * fails the boot: with a trusted command line this pins the complete
 * image contents, which fsverity keeps verifying against the image's
 * Merkle tree as they are read.
 */
static void __init verify_root_image(struct file *file)
{
	u8 want[FS_VERITY_MAX_DIGEST_SIZE], got[FS_VERITY_MAX_DIGEST_SIZE];
	enum hash_algo want_algo, got_algo;
	int want_size, got_size, i;
	char *hex;

	hex = strchr(root_image_verity, ':');
	if (!hex)
		panic("VFS: rootimageverity= expects <algorithm>:<hex digest>");
	*hex++ = '\0';
	i = match_string(hash_algo_name, HASH_ALGO__LAST, root_image_verity);
	if (i < 0)
		panic("VFS: rootimageverity=: unknown hash algorithm \"%s\"",
		      root_image_verity);
	want_algo = i;
	want_size = hash_digest_size[want_algo];
	if (strlen(hex) != 2 * want_size || hex2bin(want, hex, want_size))
		panic("VFS: rootimageverity=: expected %d-byte hex digest",
		      want_size);

	got_size = fsverity_get_digest(file_inode(file), got, NULL, &got_algo);
	if (!got_size)
		panic("VFS: root image does not have fsverity enabled");
	if (got_algo != want_algo || got_size != want_size ||
	    memcmp(want, got, want_size))
		panic("VFS: root image fsverity digest mismatch: expected %s:%*phN, got %s:%*phN",
		      hash_algo_name[want_algo], want_size, want,
		      hash_algo_name[got_algo], got_size, got);

	pr_info("VFS: verified root image fsverity digest %s:%*phN\n",
		hash_algo_name[want_algo], want_size, want);
}
#else /* !CONFIG_FS_VERITY */
static void __init verify_root_image(struct file *file)
{
	panic("VFS: rootimageverity= requires CONFIG_FS_VERITY");
}
#endif /* !CONFIG_FS_VERITY */

/*
 * Mount the actual root filesystem from the image file rootimage= on the
 * filesystem that was just mounted from root= (the "carrier"), so that
 * image-based systems can boot without an initramfs.
 *
 * Called with the carrier mounted at /root and the cwd there.  The image
 * is always mounted read-only; "ro"/"rw"/rootflags= keep applying to the
 * carrier.  On success the cwd is the image's root, ready for the pivot
 * in prepare_namespace().  The carrier mount is moved to rootimagesrcdir=
 * inside the image if set, and detached otherwise; either way the image
 * mount keeps the carrier superblock pinned.
 */
static void __init mount_root_image(void)
{
	unsigned long flags = MS_RDONLY | MS_SILENT;
	char *path, *fs_names, *p;
	struct file *file;
	int num_fs, i, err;

	if (root_image[0] != '/')
		panic("VFS: rootimage= must be an absolute path");

	path = kmalloc(PATH_MAX, GFP_KERNEL);
	fs_names = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!path || !fs_names)
		panic("VFS: unable to mount root image: not enough memory");

	if (snprintf(path, PATH_MAX, "/root%s", root_image) >= PATH_MAX)
		panic("VFS: rootimage= path too long");

	/*
	 * Nothing that could modify the carrier runs yet, so the image
	 * cannot change between this open and the mount below.
	 */
	file = filp_open(path, O_RDONLY | O_LARGEFILE, 0);
	if (IS_ERR(file))
		panic("VFS: unable to open root image %s: error %ld",
		      root_image, PTR_ERR(file));

	if (root_image_verity)
		verify_root_image(file);

	err = init_mkdir("/image", 0700);
	if (err < 0 && err != -EEXIST)
		panic("VFS: unable to create /image: error %d", err);

	if (root_image_fs_names)
		num_fs = split_fs_names(fs_names, PAGE_SIZE,
					root_image_fs_names);
	else
		num_fs = list_bdev_fs_names(fs_names, PAGE_SIZE);

	for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p) + 1) {
		if (!*p)
			continue;
		err = do_mount_root(path, "/image", p, flags,
				    root_image_mount_data);
		switch (err) {
		case 0:
			goto mounted;
		case -EACCES:
		case -EINVAL:
		case -ENOTBLK:
			continue;
		}
		panic("VFS: unable to mount root image %s: error %d",
		      root_image, err);
	}
	panic("VFS: no filesystem could mount root image %s", root_image);

mounted:
	fput(file);

	if (root_image_srcdir) {
		if (root_image_srcdir[0] != '/')
			panic("VFS: rootimagesrcdir= must be an absolute path");
		if (snprintf(path, PATH_MAX, ".%s", root_image_srcdir) >=
		    PATH_MAX)
			panic("VFS: rootimagesrcdir= path too long");
		err = init_mount("/root", path, NULL, MS_MOVE, NULL);
		if (err)
			pr_err("VFS: failed to move the root image's carrier filesystem to %s: error %d\n",
			       root_image_srcdir, err);
	} else {
		err = -EINVAL;
	}
	if (err)
		init_umount("/root", MNT_DETACH);

	kfree(path);
	kfree(fs_names);
}

/* wait for any asynchronous scanning to complete */
static void __init wait_for_root(char *root_device_name)
{
	ktime_t end;

	if (ROOT_DEV != 0)
		return;

	pr_info("Waiting for root device %s...\n", root_device_name);

	end = ktime_add_ms(ktime_get_raw(), root_wait);

	while (!driver_probe_done() ||
	       early_lookup_bdev(root_device_name, &ROOT_DEV) < 0) {
		msleep(5);
		if (root_wait > 0 && ktime_after(ktime_get_raw(), end))
			break;
	}

	async_synchronize_full();

}

static dev_t __init parse_root_device(char *root_device_name)
{
	int error;
	dev_t dev;

	if (!strncmp(root_device_name, "mtd", 3) ||
	    !strncmp(root_device_name, "ubi", 3))
		return Root_Generic;
	if (strcmp(root_device_name, "/dev/nfs") == 0)
		return Root_NFS;
	if (strcmp(root_device_name, "/dev/cifs") == 0)
		return Root_CIFS;
	if (strcmp(root_device_name, "/dev/ram") == 0)
		return Root_RAM0;

	error = early_lookup_bdev(root_device_name, &dev);
	if (error) {
		if (error == -EINVAL && root_wait) {
			pr_err("Disabling rootwait; root= is invalid.\n");
			root_wait = 0;
		}
		return 0;
	}
	return dev;
}

/*
 * Prepare the namespace - decide what/where to mount, load ramdisks, etc.
 */
void __init prepare_namespace(void)
{
	if (root_delay) {
		printk(KERN_INFO "Waiting %d sec before mounting root device...\n",
		       root_delay);
		ssleep(root_delay);
	}

	/*
	 * wait for the known devices to complete their probing
	 *
	 * Note: this is a potential source of long boot delays.
	 * For example, it is not atypical to wait 5 seconds here
	 * for the touchpad of a laptop to initialize.
	 */
	wait_for_device_probe();

	md_run_setup();

	if (saved_root_name[0])
		ROOT_DEV = parse_root_device(saved_root_name);

	initrd_load();

	if (root_wait)
		wait_for_root(saved_root_name);
	mount_root(saved_root_name);
	if (root_image)
		mount_root_image();
	devtmpfs_mount();

	if (init_pivot_root(".", ".")) {
		pr_err("VFS: Failed to pivot into new rootfs\n");
		return;
	}
	if (init_umount(".", MNT_DETACH)) {
		pr_err("VFS: Failed to unmount old rootfs\n");
		return;
	}
	pr_info("VFS: Pivoted into new rootfs\n");
}

static bool is_tmpfs;
static int rootfs_init_fs_context(struct fs_context *fc)
{
	if (IS_ENABLED(CONFIG_TMPFS) && is_tmpfs)
		return shmem_init_fs_context(fc);

	return ramfs_init_fs_context(fc);
}

struct file_system_type rootfs_fs_type = {
	.name		= "rootfs",
	.init_fs_context = rootfs_init_fs_context,
	.kill_sb	= kill_anon_super,
};

void __init init_rootfs(void)
{
	if (IS_ENABLED(CONFIG_TMPFS)) {
		if (!saved_root_name[0] && !root_fs_names)
			is_tmpfs = true;
		else if (root_fs_names && !!strstr(root_fs_names, "tmpfs"))
			is_tmpfs = true;
	}
}
