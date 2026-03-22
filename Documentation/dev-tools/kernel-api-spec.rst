.. SPDX-License-Identifier: GPL-2.0

======================================
Kernel API Specification Framework
======================================

:Author: Sasha Levin <sashal@kernel.org>

.. contents:: Table of Contents
   :depth: 3
   :local:

Introduction
============

The Kernel API Specification Framework (KAPI) provides a comprehensive system for
formally documenting, validating, and introspecting kernel APIs. This framework
addresses the long-standing challenge of maintaining accurate, machine-readable
documentation for the thousands of internal kernel APIs and system calls.

Purpose and Goals
-----------------

The framework aims to:

1. **Improve API Documentation**: Provide structured, inline documentation that
   lives alongside the code and is maintained as part of the development process.

2. **Enable Runtime Validation**: Optionally validate API usage at runtime to catch
   common programming errors during development and testing.

3. **Support Tooling**: Export API specifications in machine-readable formats for
   use by static analyzers, documentation generators, and development tools.

4. **Formalize Contracts**: Explicitly document API contracts including parameter
   constraints, execution contexts, locking requirements, and side effects.

Architecture Overview
=====================

Components
----------

The framework consists of several key components:

1. **Core Framework** (``kernel/api/kernel_api_spec.c``)

   - API specification registration and storage
   - Runtime validation engine
   - Specification lookup and querying

2. **DebugFS Interface** (``kernel/api/kapi_debugfs.c``)

   - Runtime introspection via ``/sys/kernel/debug/kapi/``
   - Per-API detailed specification output
   - List of all registered API specifications

3. **kapi Tool** (``tools/kapi/``)

   - Userspace utility for extracting specifications
   - Multiple input sources (source, binary, debugfs)
   - Multiple output formats (plain, JSON, RST)
   - Testing and validation utilities

Data Model
----------

The framework uses a hierarchical data model::

    kernel_api_spec
    ├── Basic Information
    │   ├── name (API function name)
    │   ├── version (specification version)
    │   └── description (human-readable description)
    │
    ├── Parameters (up to 16)
    │   └── kapi_param_spec
    │       ├── name
    │       ├── type (int, pointer, string, etc.)
    │       ├── direction (in, out, inout)
    │       ├── constraints (range, mask, enum values)
    │       └── validation rules
    │
    ├── Return Value
    │   └── kapi_return_spec
    │       ├── type
    │       ├── success conditions
    │       └── validation rules
    │
    ├── Error Conditions (up to 32)
    │   └── kapi_error_spec
    │       ├── error code
    │       ├── condition description
    │       └── recovery advice
    │
    ├── Execution Context
    │   ├── allowed contexts (process, interrupt, etc.)
    │   ├── locking requirements
    │   └── preemption/interrupt state
    │
    └── Side Effects
        ├── memory allocation
        ├── state changes
        └── signal handling

Usage Guide
===========

Basic API Specification
-----------------------

API specifications are written as KAPI-annotated kerneldoc comments directly in
the source file, immediately preceding the function implementation. The ``kapi``
tool extracts these annotations to produce structured specifications.

.. code-block:: c

    /**
     * kmalloc - allocate kernel memory
     * @size: Number of bytes to allocate
     * @flags: Allocation flags (GFP_*)
     *
     * context-flags: KAPI_CTX_PROCESS | KAPI_CTX_SOFTIRQ | KAPI_CTX_HARDIRQ
     * param-count: 2
     *
     * param: size
     *   type: KAPI_TYPE_UINT
     *   flags: KAPI_PARAM_IN
     *   constraint-type: KAPI_CONSTRAINT_RANGE
     *   range: 0, KMALLOC_MAX_SIZE
     *
     * param: flags
     *   type: KAPI_TYPE_UINT
     *   flags: KAPI_PARAM_IN
     *   constraint-type: KAPI_CONSTRAINT_MASK
     *   valid-mask: 0x1ffffff
     *
     * error: ENOMEM, Out of memory
     *   desc: Insufficient memory available for the requested allocation.
     *
     * side-effect: KAPI_EFFECT_ALLOC_MEMORY
     *   target: kernel heap
     *   desc: Allocates memory from kernel heap
     */
    void *kmalloc(size_t size, gfp_t flags)
    {
        /* Implementation */
    }

System Call Specification
-------------------------

System calls are documented inline in the implementation file (e.g., ``fs/open.c``)
using KAPI-annotated kerneldoc comments. When ``CONFIG_KAPI_RUNTIME_CHECKS`` is
enabled, the ``SYSCALL_DEFINEx`` macros automatically look up the specification
and validate parameters before and after the syscall executes.

Runtime Validation
==================

Enabling Validation
-------------------

Runtime validation is controlled by kernel configuration:

1. Enable ``CONFIG_KAPI_SPEC`` to build the framework
2. Enable ``CONFIG_KAPI_RUNTIME_CHECKS`` for runtime validation
3. Optionally enable ``CONFIG_KAPI_SPEC_DEBUGFS`` for debugfs interface

Validation Behavior
-------------------

When ``CONFIG_KAPI_RUNTIME_CHECKS`` is enabled, all registered API specifications
are validated automatically at call time. The framework checks parameter constraints,
execution context, and return values. Parameter violations are reported via
``pr_warn_ratelimited`` and return value violations via ``WARN_ONCE`` to avoid
flooding the kernel log.

Custom Validators
-----------------

Parameters can use the ``KAPI_CONSTRAINT_CUSTOM`` constraint type to register
custom validation functions via the ``validate`` field in the constraint spec:

.. code-block:: c

    static bool validate_buffer_size(s64 value)
    {
        size_t size = (size_t)value;

        return size > 0 && size <= MAX_BUFFER_SIZE;
    }

    /* In the constraint definition: */
    .type = KAPI_CONSTRAINT_CUSTOM,
    .validate = validate_buffer_size,

DebugFS Interface
=================

The debugfs interface provides runtime access to API specifications:

Directory Structure
-------------------

::

    /sys/kernel/debug/kapi/
    ├── list                     # Overview of all registered API specs
    └── specs/                   # Per-API specification files
        ├── sys_open             # Human-readable spec for sys_open
        ├── sys_close            # Human-readable spec for sys_close
        ├── sys_read             # Human-readable spec for sys_read
        └── sys_write            # Human-readable spec for sys_write

Usage Examples
--------------

List all available API specifications::

    $ cat /sys/kernel/debug/kapi/list
    Available Kernel API Specifications
    ===================================

    sys_open - Open or create a file
    sys_close - Close a file descriptor
    sys_read - Read data from a file descriptor
    sys_write - Write data to a file descriptor

    Total: 4 specifications

Query specific API::

    $ cat /sys/kernel/debug/kapi/specs/sys_open
    Kernel API Specification
    ========================

    Name: sys_open
    Version: 1
    Description: Open or create a file
    ...

Performance Considerations
==========================

Memory Overhead
---------------

Each API specification consumes approximately 400-450KB of memory due to the
fixed-size arrays in ``struct kernel_api_spec``. With the current 4 syscall
specifications, total memory usage is approximately 1.7MB. Consider:

1. Building with ``CONFIG_KAPI_SPEC=n`` for production kernels
2. Using ``__init`` annotations for APIs only used during boot
3. Implementing lazy loading for rarely used specifications

Runtime Overhead
----------------

When ``CONFIG_KAPI_RUNTIME_CHECKS`` is enabled:

- Each validated API call adds 50-200ns overhead
- Complex validations (custom validators) may add more
- Use validation only in development/testing kernels

Optimization Strategies
-----------------------

1. **Compile-time optimization**: When validation is disabled, all
   validation code is optimized away by the compiler.

2. **Selective enablement**: Enable ``CONFIG_KAPI_RUNTIME_CHECKS``
   only in development/testing kernels, not in production.

Documentation Generation
------------------------

The framework exports specifications via debugfs that can be used
to generate documentation. The ``kapi`` tool provides comprehensive
extraction and formatting capabilities for kernel API specifications.

The kapi Tool
=============

Overview
--------

The ``kapi`` tool is a userspace utility that extracts and displays kernel API
specifications from multiple sources. It provides a unified interface to access
API documentation whether from compiled kernels, source code, or runtime systems.

Installation
------------

Build the tool from the kernel source tree::

    $ cd tools/kapi
    $ cargo build --release

    # Optional: Install system-wide
    $ cargo install --path .

The tool requires Rust and Cargo to build. The binary will be available at
``tools/kapi/target/release/kapi``.

Command-Line Usage
------------------

Basic syntax::

    kapi [OPTIONS] [API_NAME]

Options:

- ``--vmlinux <PATH>``: Extract from compiled kernel binary
- ``--source <PATH>``: Extract from kernel source code
- ``--debugfs <PATH>``: Extract from debugfs (default: /sys/kernel/debug)
- ``-f, --format <FORMAT>``: Output format (plain, json, rst)
- ``-h, --help``: Display help information
- ``-V, --version``: Display version information

Input Modes
-----------

**1. Source Code Mode**

Extract specifications directly from kernel source::

    # Scan entire kernel source tree
    $ kapi --source /path/to/linux

    # Extract from specific file
    $ kapi --source kernel/sched/core.c

    # Get details for specific API
    $ kapi --source /path/to/linux sys_sched_yield

**2. Vmlinux Mode**

Extract from compiled kernel with debug symbols::

    # List all APIs in vmlinux
    $ kapi --vmlinux /boot/vmlinux-5.15.0

    # Get specific syscall details
    $ kapi --vmlinux ./vmlinux sys_read

**3. Debugfs Mode**

Extract from running kernel via debugfs::

    # Use default debugfs path
    $ kapi

    # Use custom debugfs mount
    $ kapi --debugfs /mnt/debugfs

    # Get specific API from running kernel
    $ kapi sys_write

Output Formats
--------------

**Plain Text Format** (default)::

    $ kapi sys_read

    Detailed information for sys_read:
    ==================================
    Description: Read from a file descriptor

    Detailed Description:
    Reads up to count bytes from file descriptor fd into the buffer starting at buf.

    Execution Context:
      - KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE

    Parameters (3):

**JSON Format**::

    $ kapi --format json sys_read
    {
      "api_details": {
        "name": "sys_read",
        "description": "Read from a file descriptor",
        "long_description": "Reads up to count bytes...",
        "context_flags": ["KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE"]
      }
    }

**ReStructuredText Format**::

    $ kapi --format rst sys_read

    sys_read
    ========

    **Read from a file descriptor**

    Reads up to count bytes from file descriptor fd into the buffer...

Usage Examples
--------------

**Generate complete API documentation**::

    # Export all kernel APIs to JSON
    $ kapi --source /path/to/linux --format json > kernel-apis.json

    # Generate RST documentation for all syscalls
    $ kapi --vmlinux ./vmlinux --format rst > syscalls.rst

    # List APIs from specific subsystem
    $ kapi --source drivers/gpu/drm/

**Integration with other tools**::

    # Find all APIs that can sleep
    $ kapi --format json | jq '.apis[] | select(.context_flags[] | contains("SLEEPABLE"))'

    # Generate markdown documentation
    $ kapi --format rst sys_mmap | pandoc -f rst -t markdown

**Debugging and analysis**::

    # Compare API between kernel versions
    $ diff <(kapi --vmlinux vmlinux-5.10) <(kapi --vmlinux vmlinux-5.15)

    # Check if specific API exists
    $ kapi --source . my_custom_api || echo "API not found"

Implementation Details
----------------------

The tool extracts API specifications from three sources:

1. **Source Code**: Parses KAPI specification macros using regular expressions
2. **Vmlinux**: Reads the ``.kapi_specs`` ELF section from compiled kernels
3. **Debugfs**: Reads from ``/sys/kernel/debug/kapi/`` filesystem interface

The tool supports all KAPI specification types:

- System calls (kerneldoc annotations)
- Kernel functions (kerneldoc annotations with KAPI tags)

IDE Integration
---------------

Modern IDEs can use the specification data for:

- Parameter hints
- Type checking
- Context validation
- Error code documentation

Testing Framework
-----------------

The framework includes test helpers::

    #ifdef CONFIG_KAPI_TESTING
    /* Verify API behaves according to specification */
    kapi_test_api("kmalloc", test_cases);
    #endif

Best Practices
==============

Writing Specifications
----------------------

1. **Be Comprehensive**: Document all parameters, errors, and side effects
2. **Keep Updated**: Update specs when API behavior changes
3. **Use Examples**: Include usage examples in descriptions
4. **Validate Constraints**: Define realistic constraints for parameters
5. **Document Context**: Clearly specify allowed execution contexts

Maintenance
-----------

1. **Version Specifications**: Increment version when API changes
2. **Deprecation**: Mark deprecated APIs and suggest replacements
3. **Cross-reference**: Link related APIs in descriptions
4. **Test Specifications**: Verify specs match implementation

Common Patterns
---------------

**Optional Parameters**:

.. code-block:: c

    /**
     * @optional_arg: Optional argument (may be NULL)
     *
     * param: optional_arg
     *   type: KAPI_TYPE_PTR
     *   flags: KAPI_PARAM_IN | KAPI_PARAM_OPTIONAL
     */

**Buffer with Size Parameter**:

.. code-block:: c

    /**
     * @buf: User-space buffer
     *
     * param: buf
     *   type: KAPI_TYPE_USER_PTR
     *   flags: KAPI_PARAM_OUT | KAPI_PARAM_USER
     *   constraint-type: KAPI_CONSTRAINT_BUFFER
     *   size-param: 2
     */

**Callback Functions**:

.. code-block:: c

    /**
     * @callback: Callback function
     *
     * param: callback
     *   type: KAPI_TYPE_FUNC_PTR
     *   flags: KAPI_PARAM_IN
     */

Troubleshooting
===============

Common Issues
-------------

**Specification Not Found**::

    kernel: KAPI: Specification for 'my_api' not found

    Solution: Ensure the KAPI-annotated kerneldoc comment is in the
    same translation unit as the function implementation.

**Validation Failures**::

    kernel: KAPI: Validation failed for kmalloc parameter 'size':
            value 5242880 exceeds maximum 4194304

    Solution: Check parameter constraints or adjust specification if
    the constraint is incorrect.

**Build Errors**::

    error: 'KAPI_TYPE_UNKNOWN' undeclared

    Solution: Include <linux/kernel_api_spec.h> and ensure
    CONFIG_KAPI_SPEC is enabled.

Debug Options
-------------

Enable verbose kernel logging to see KAPI validation messages::

    echo 8 > /proc/sys/kernel/printk

Future Directions
=================

Planned Features
----------------

1. **Automatic Extraction**: Tool to extract specifications from existing
   kernel-doc comments

2. **Contract Verification**: Static analysis to verify implementation
   matches specification

3. **Performance Profiling**: Measure actual API performance against
   documented expectations

4. **Fuzzing Integration**: Use specifications to guide intelligent
   fuzzing of kernel APIs

5. **Version Compatibility**: Track API changes across kernel versions

Research Areas
--------------

1. **Formal Verification**: Use specifications for mathematical proofs
   of correctness

2. **Runtime Monitoring**: Detect specification violations in production
   with minimal overhead

3. **API Evolution**: Analyze how kernel APIs change over time

4. **Security Applications**: Use specifications for security policy
   enforcement

Contributing
============

Submitting Specifications
-------------------------

1. Add specifications to the same file as the API implementation
2. Follow existing patterns and naming conventions
3. Test with CONFIG_KAPI_RUNTIME_CHECKS enabled
4. Verify debugfs output is correct
5. Run scripts/checkpatch.pl on your changes

Review Criteria
---------------

Specifications will be reviewed for:

1. **Completeness**: All parameters and errors documented
2. **Accuracy**: Specification matches implementation
3. **Clarity**: Descriptions are clear and helpful
4. **Consistency**: Follows framework conventions
5. **Performance**: No unnecessary runtime overhead

Contact
-------

- Maintainer: Sasha Levin <sashal@kernel.org>
