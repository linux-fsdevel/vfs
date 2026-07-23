// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAY_WRITE	0x2
#define MAY_READ	0x4
#define TMPFS_MAGIC	0x01021994

const volatile __u32 source_fsuid;
const volatile __u32 destination_fsuid;
const volatile __u64 source_ino;
const volatile __u64 destination_ino;

volatile __u32 source_checks;
volatile __u32 destination_checks;
volatile __u32 denials;
volatile __u32 target_tgid;

SEC("lsm/file_permission")
int BPF_PROG(file_range_cred_permission, struct file *file, int mask, int ret)
{
	struct super_block *sb;
	struct task_struct *task;
	struct inode *inode;
	__u32 fsuid;
	__u64 ino;

	if (ret || bpf_get_current_pid_tgid() >> 32 != target_tgid)
		return ret;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;
	sb = BPF_CORE_READ(inode, i_sb);
	if (!sb || BPF_CORE_READ(sb, s_magic) != TMPFS_MAGIC)
		return 0;

	task = bpf_get_current_task_btf();
	fsuid = BPF_CORE_READ(task, cred, fsuid.val);
	ino = BPF_CORE_READ(inode, i_ino);
	if ((mask & MAY_READ) && ino == source_ino) {
		source_checks++;
		if (fsuid != source_fsuid) {
			denials++;
			return -1;
		}
	}
	if ((mask & MAY_WRITE) && ino == destination_ino) {
		destination_checks++;
		if (fsuid != destination_fsuid) {
			denials++;
			return -1;
		}
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
