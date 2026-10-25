.. SPDX-License-Identifier: GPL-2.0

.. _discoverable_root:

Discoverable root partitions
============================

On EFI systems, the kernel can discover the root block device from GPT partition
type UUID metadata on the disk containing the active EFI System Partition.

This follows the `Discoverable Partitions Specification`_ which defines a list
of architecture-specific root partition type UUIDs.

An initramfs providing an early userspace ``init``, a ``root=`` kernel
command-line option, or a root device supplied through the boot protocol takes
precedence over this automatic root partition discovery.

Automatic discovery uses the Boot Loader Interface ``LoaderDevicePartUUID`` EFI
variable to identify the partition whose disk is searched. This variable is
provided by the boot loader or, when the kernel is booted directly by EFI
firmware, by the Linux EFI stub.

The kernel first searches for the native root partition type UUID. On
architectures that can run compatible 32-bit user space, the matching 32-bit
root partition type UUID may be used as a fallback if no partition with the
native type UUID is found. If multiple partitions on that disk match the
selected type UUID, the kernel selects the first match in block device
enumeration order, but this may change. Systems should not expose multiple
eligible root partitions.

Partitions marked with the DPS ``no-auto`` GPT attribute are skipped. This
allows a partition with an otherwise discoverable type UUID to opt out from
automatic discovery.

The DPS read-only attribute is not enforced by kernel root discovery. The
root filesystem is mounted read-only by default unless ``rw`` is specified,
and user space remains responsible for later remount policy.

.. _Discoverable Partitions Specification:
   https://uapi-group.org/specifications/specs/discoverable_partitions_specification/
