#!/usr/bin/env python3
"""Generate CI build and test matrices for fsdevel-vmtest.

Modeled after kernel-patches/bpf .github/scripts/matrix.py.
Outputs JSON matrices to GITHUB_OUTPUT for consumption by test.yml.
"""

import json
import os

# All VFS/filesystem selftest targets.
# "filesystems" covers all subdirectories: binderfs, epoll, eventfd, fat,
# fuse, mount-notify, nsfs, open_tree_ns, overlayfs, statmount.
SELFTEST_TARGETS = [
    "mount",
    "mount_setattr",
    "filesystems",
    "fchmodat2",
    "filelock",
    "tmpfs",
    "pidfd",
    "pid_namespace",
    "namespaces",
    "cachestat",
]

# Per-arch target exclusions. Targets listed here will be skipped for
# that architecture.
ARCH_EXCLUDE = {
    # Populated as needed when specific targets fail on certain arches.
    "aarch64": [],
}

# Build configurations. Each entry produces one build job and a fan-out
# of test jobs (one per selftest target).
BUILD_CONFIGS = [
    {
        "arch": "x86_64",
        "toolchain": "gcc",
        "runs_on": '["ubuntu-24.04"]',
    },
    {
        "arch": "aarch64",
        "toolchain": "gcc",
        "runs_on": '["ubuntu-24.04"]',
    },
]

# Default test timeout in minutes.
DEFAULT_TIMEOUT = 30

# Tests running under QEMU TCG emulation (no KVM) are much slower.
EMULATED_TIMEOUT = 90


def is_native(arch):
    """Whether arch matches GitHub-hosted runner arch (x86_64)."""
    return arch == "x86_64"


def get_targets(arch):
    exclude = set(ARCH_EXCLUDE.get(arch, []))
    return [t for t in SELFTEST_TARGETS if t not in exclude]


def generate_matrix():
    """Generate the combined matrix consumed by test.yml."""
    includes = []

    for config in BUILD_CONFIGS:
        arch = config["arch"]
        toolchain = config["toolchain"]
        runs_on = config["runs_on"]
        targets = get_targets(arch)
        timeout = DEFAULT_TIMEOUT if is_native(arch) else EMULATED_TIMEOUT

        # Build a per-target test matrix (consumed by kernel-build-test.yml).
        test_includes = [
            {"test": t, "timeout_minutes": timeout}
            for t in targets
        ]

        includes.append({
            "arch": arch,
            "toolchain": toolchain,
            "runs_on": runs_on,
            "selftest_targets": " ".join(targets),
            "test_matrix": json.dumps({"include": test_includes}),
        })

    return {"include": includes}


def main():
    matrix = generate_matrix()

    github_output = os.environ.get("GITHUB_OUTPUT", "")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"matrix={json.dumps(matrix)}\n")

    # Debug output
    print(json.dumps(matrix, indent=2))


if __name__ == "__main__":
    main()
