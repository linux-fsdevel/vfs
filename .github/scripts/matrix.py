#!/usr/bin/env python3
"""Generate CI build and test matrices for vfs-test.
Outputs JSON matrices to GITHUB_OUTPUT for consumption by test.yml.
"""

import json
import os

# Base build configurations (arch/toolchain/distro/runner).
BASE_CONFIGS = [
    {
        "arch": "x86_64",
        "toolchain": "gcc",
        "distro": "fedora",
        "runs_on": '["ubuntu-24.04"]',
    },
    {
        "arch": "x86_64",
        "toolchain": "gcc",
        "distro": "debian",
        "runs_on": '["ubuntu-24.04"]',
    },
    # TODO: re-enable aarch64 once we have self-hosted ARM runners.
    # QEMU TCG emulation on GitHub-hosted x86_64 runners is too slow
    # and lacks KVM.
]

# Each test suite becomes its own matrix entry with its own timeout.
TEST_SUITES = [
    {"test_suite": "selftests", "timeout_minutes": 120},
    {"test_suite": "xfstests", "timeout_minutes": 1440},
    {"test_suite": "ovl-fstests", "timeout_minutes": 1440},
]


def generate_matrix():
    """Generate the matrix consumed by test.yml.

    Produces the cross-product of BASE_CONFIGS × TEST_SUITES.
    """
    include = []
    for base in BASE_CONFIGS:
        for suite in TEST_SUITES:
            include.append({**base, **suite})
    return {"include": include}


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
