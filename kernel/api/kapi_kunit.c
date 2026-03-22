// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * KUnit tests for the Kernel API Specification Framework
 *
 * Tests registration, lookup, validation, and JSON export functionality.
 */

#include <kunit/test.h>
#include <linux/kernel_api_spec.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mm.h>

static void init_test_spec(struct kernel_api_spec *spec, const char *name)
{
	memset(spec, 0, sizeof(*spec));
	strscpy(spec->name, name, KAPI_MAX_NAME_LEN);
	spec->version = 1;
	strscpy(spec->description, "Test API", KAPI_MAX_DESC_LEN);
}

/* Test 1: kapi_register_spec with valid spec returns 0 */
static void test_register_valid(struct kunit *test)
{
	struct kernel_api_spec *spec;
	int ret;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	init_test_spec(spec, "test_register_valid");

	ret = kapi_register_spec(spec);
	KUNIT_EXPECT_EQ(test, ret, 0);

	kapi_unregister_spec("test_register_valid");
	kfree(spec);
}

/* Test 2: kapi_get_spec returns registered spec */
static void test_lookup_registered(struct kunit *test)
{
	struct kernel_api_spec *spec;
	const struct kernel_api_spec *found;
	int ret;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	init_test_spec(spec, "test_lookup_func");

	ret = kapi_register_spec(spec);
	KUNIT_ASSERT_EQ(test, ret, 0);

	found = kapi_get_spec("test_lookup_func");
	KUNIT_EXPECT_PTR_EQ(test, found, (const struct kernel_api_spec *)spec);

	kapi_unregister_spec("test_lookup_func");
	kfree(spec);
}

/* Test 3: Double registration returns -EEXIST */
static void test_double_register(struct kunit *test)
{
	struct kernel_api_spec *spec;
	int ret;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	init_test_spec(spec, "test_double_reg");

	ret = kapi_register_spec(spec);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = kapi_register_spec(spec);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);

	kapi_unregister_spec("test_double_reg");
	kfree(spec);
}

/* Test 4: Unregister makes spec unfindable */
static void test_unregister(struct kunit *test)
{
	struct kernel_api_spec *spec;
	const struct kernel_api_spec *found;
	int ret;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	init_test_spec(spec, "test_unreg_func");

	ret = kapi_register_spec(spec);
	KUNIT_ASSERT_EQ(test, ret, 0);

	kapi_unregister_spec("test_unreg_func");

	found = kapi_get_spec("test_unreg_func");
	KUNIT_EXPECT_NULL(test, found);

	kfree(spec);
}

/* Test 5: kapi_get_spec(NULL) returns NULL */
static void test_get_spec_null(struct kunit *test)
{
	const struct kernel_api_spec *found;

	found = kapi_get_spec(NULL);
	KUNIT_EXPECT_NULL(test, found);
}

/* Test 6: kapi_register_spec(NULL) returns -EINVAL */
static void test_register_null(struct kunit *test)
{
	int ret;

	ret = kapi_register_spec(NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* Test 7: Spec with empty name is rejected */
static void test_register_empty_name(struct kunit *test)
{
	struct kernel_api_spec *spec;
	int ret;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	/* name[0] == '\0' from kzalloc */
	ret = kapi_register_spec(spec);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	kfree(spec);
}

#ifdef CONFIG_KAPI_RUNTIME_CHECKS

/* Test 8: RANGE constraint - value in range is valid */
static void test_constraint_range_valid(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_param", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_RANGE;
	param.min_value = 0;
	param.max_value = 100;

	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 0));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 50));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 100));
}

/* Test 9: RANGE constraint - value out of range is invalid */
static void test_constraint_range_invalid(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_param", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_RANGE;
	param.min_value = 0;
	param.max_value = 100;

	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, -1));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 101));
}

/* Test 10: MASK constraint - valid bits pass */
static void test_constraint_mask_valid(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_flags", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_MASK;
	param.valid_mask = 0xFF;

	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 0x00));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 0x0F));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 0xFF));
}

/* Test 11: MASK constraint - extra bits fail */
static void test_constraint_mask_invalid(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_flags", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_MASK;
	param.valid_mask = 0xFF;

	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 0x100));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 0x1FF));
}

/* Test 12: POWER_OF_TWO constraint */
static void test_constraint_power_of_two(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_pot", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_POWER_OF_TWO;

	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 1));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 2));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 4));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 8));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 0));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 3));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 5));
}

/* Test 13: PAGE_ALIGNED constraint */
static void test_constraint_page_aligned(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_page", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_PAGE_ALIGNED;

	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 0));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, PAGE_SIZE));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 2 * PAGE_SIZE));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 1));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, PAGE_SIZE - 1));
}

/* Test 14: NONZERO constraint */
static void test_constraint_nonzero(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_nz", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_NONZERO;

	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 0));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 1));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, -1));
}

/* Test 15: Return value validation - success */
static void test_return_validation(struct kunit *test)
{
	struct kernel_api_spec *spec;

	spec = kunit_kzalloc(test, sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	strscpy(spec->name, "test_ret", sizeof(spec->name));
	spec->return_magic = KAPI_MAGIC_RETURN;
	spec->return_spec.check_type = KAPI_RETURN_EXACT;
	spec->return_spec.success_value = 0;

	KUNIT_EXPECT_TRUE(test, kapi_validate_return_value(spec, 0));
}

/* Test 16: Return value validation - known error */
static void test_return_known_error(struct kunit *test)
{
	struct kernel_api_spec *spec;

	spec = kunit_kzalloc(test, sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	strscpy(spec->name, "test_ret_err", sizeof(spec->name));
	spec->return_magic = KAPI_MAGIC_RETURN;
	spec->return_spec.check_type = KAPI_RETURN_FD;
	spec->error_count = 1;
	spec->errors[0].error_code = -ENOENT;
	strscpy(spec->errors[0].name, "ENOENT", sizeof(spec->errors[0].name));

	/* -ENOENT is in the error list, so it's valid */
	KUNIT_EXPECT_TRUE(test, kapi_validate_return_value(spec, -ENOENT));
}

/* Test 17: Return value validation - unknown error */
static void test_return_unknown_error(struct kunit *test)
{
	struct kernel_api_spec *spec;

	spec = kunit_kzalloc(test, sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	strscpy(spec->name, "test_ret_unk", sizeof(spec->name));
	spec->return_magic = KAPI_MAGIC_RETURN;
	spec->return_spec.check_type = KAPI_RETURN_FD;
	spec->error_count = 1;
	spec->errors[0].error_code = -ENOENT;
	strscpy(spec->errors[0].name, "ENOENT", sizeof(spec->errors[0].name));

	/* -EPERM is not in the error list, but unlisted errors are accepted
	 * since filesystem/device-specific errors may not be exhaustively listed
	 */
	KUNIT_EXPECT_TRUE(test, kapi_validate_return_value(spec, -EPERM));
}

/* Test 18: ALIGNMENT constraint */
static void test_constraint_alignment(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_align", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_ALIGNMENT;
	param.alignment = 8;

	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 0));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 8));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 16));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 1));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 7));
}

/* Test 19: FD validation rejects values > INT_MAX */
static void test_fd_int_overflow(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_fd", sizeof(param.name));
	param.type = KAPI_TYPE_FD;
	param.constraint_type = KAPI_CONSTRAINT_NONE;

	/* Value that overflows int: 0x100000003 -> truncates to 3 */
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 0x100000003LL));
}

/* Test 23: ENUM constraint */
static const s64 test_enum_vals[] = { 1, 5, 10 };

static void test_constraint_enum(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_enum", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_ENUM;
	param.enum_values = test_enum_vals;
	param.enum_count = ARRAY_SIZE(test_enum_vals);

	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 1));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 5));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 10));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 0));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 3));
	KUNIT_EXPECT_FALSE(test, kapi_validate_param(&param, 11));
}

/* Test 24: BUFFER constraint always accepts (size checked at runtime) */
static void test_constraint_buffer(struct kunit *test)
{
	struct kapi_param_spec param = {};

	strscpy(param.name, "test_buf", sizeof(param.name));
	param.constraint_type = KAPI_CONSTRAINT_BUFFER;

	/* Buffer constraint doesn't validate the value itself */
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 0));
	KUNIT_EXPECT_TRUE(test, kapi_validate_param(&param, 4096));
}

/* Test 25: RETURN_RANGE check type */
static void test_return_range(struct kunit *test)
{
	struct kernel_api_spec *spec;

	spec = kunit_kzalloc(test, sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	strscpy(spec->name, "test_ret_range", sizeof(spec->name));
	spec->return_magic = KAPI_MAGIC_RETURN;
	spec->return_spec.check_type = KAPI_RETURN_RANGE;
	spec->return_spec.success_min = 0;
	spec->return_spec.success_max = 100;

	KUNIT_EXPECT_TRUE(test, kapi_validate_return_value(spec, 0));
	KUNIT_EXPECT_TRUE(test, kapi_validate_return_value(spec, 50));
	KUNIT_EXPECT_TRUE(test, kapi_validate_return_value(spec, 100));
}

#endif /* CONFIG_KAPI_RUNTIME_CHECKS */

/* Test 26: Unregister non-existent spec is a no-op */
static void test_unregister_nonexistent(struct kunit *test)
{
	/* Should not crash or error */
	kapi_unregister_spec("nonexistent_spec_xyz");
}

/* Test 27: Multiple specs can be registered and looked up */
static void test_multiple_specs(struct kunit *test)
{
	struct kernel_api_spec *spec1, *spec2;
	const struct kernel_api_spec *found;

	spec1 = kzalloc_obj(*spec1, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec1);
	spec2 = kzalloc_obj(*spec2, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec2);

	init_test_spec(spec1, "multi_spec_1");
	init_test_spec(spec2, "multi_spec_2");

	KUNIT_ASSERT_EQ(test, kapi_register_spec(spec1), 0);
	KUNIT_ASSERT_EQ(test, kapi_register_spec(spec2), 0);

	found = kapi_get_spec("multi_spec_1");
	KUNIT_EXPECT_PTR_EQ(test, found, (const struct kernel_api_spec *)spec1);

	found = kapi_get_spec("multi_spec_2");
	KUNIT_EXPECT_PTR_EQ(test, found, (const struct kernel_api_spec *)spec2);

	kapi_unregister_spec("multi_spec_1");
	kapi_unregister_spec("multi_spec_2");
	kfree(spec1);
	kfree(spec2);
}

/* Test 20: JSON export produces valid output */
static void test_json_export(struct kunit *test)
{
	struct kernel_api_spec *spec;
	char *buf;
	int ret;

	spec = kzalloc(sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);

	buf = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);

	init_test_spec(spec, "test_json");
	spec->param_count = 1;
	strscpy(spec->params[0].name, "arg0", sizeof(spec->params[0].name));
	strscpy(spec->params[0].type_name, "int", sizeof(spec->params[0].type_name));

	ret = kapi_export_json(spec, buf, 4096);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* Verify it starts with '{' and ends with '}' */
	KUNIT_EXPECT_EQ(test, buf[0], '{');
	KUNIT_ASSERT_GT(test, ret, 1);
	/* Find last non-whitespace char */
	while (ret > 0 && (buf[ret - 1] == '\n' || buf[ret - 1] == ' '))
		ret--;
	KUNIT_EXPECT_EQ(test, buf[ret - 1], '}');

	/* Verify key fields are present */
	KUNIT_EXPECT_NOT_NULL(test, strstr(buf, "\"name\""));
	KUNIT_EXPECT_NOT_NULL(test, strstr(buf, "\"test_json\""));
	KUNIT_EXPECT_NOT_NULL(test, strstr(buf, "\"parameters\""));

	kfree(buf);
	kfree(spec);
}

/* Test 21: JSON export with NULL args returns -EINVAL */
static void test_json_export_null(struct kunit *test)
{
	struct kernel_api_spec *spec;
	char buf[64];
	int ret;

	ret = kapi_export_json(NULL, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	spec = kunit_kzalloc(test, sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);
	init_test_spec(spec, "test");

	ret = kapi_export_json(spec, NULL, 64);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ret = kapi_export_json(spec, buf, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* Test 22: JSON export with small buffer truncates gracefully */
static void test_json_export_small_buffer(struct kunit *test)
{
	struct kernel_api_spec *spec;
	char buf[64];
	int ret;

	spec = kunit_kzalloc(test, sizeof(*spec), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, spec);
	init_test_spec(spec, "test_small");

	ret = kapi_export_json(spec, buf, sizeof(buf));

	/* Should return number of bytes written, buffer too small for full JSON */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_LT(test, ret, (int)sizeof(buf));
}

static struct kunit_case kapi_test_cases[] = {
	KUNIT_CASE(test_register_valid),
	KUNIT_CASE(test_lookup_registered),
	KUNIT_CASE(test_double_register),
	KUNIT_CASE(test_unregister),
	KUNIT_CASE(test_get_spec_null),
	KUNIT_CASE(test_register_null),
	KUNIT_CASE(test_register_empty_name),
#ifdef CONFIG_KAPI_RUNTIME_CHECKS
	KUNIT_CASE(test_constraint_range_valid),
	KUNIT_CASE(test_constraint_range_invalid),
	KUNIT_CASE(test_constraint_mask_valid),
	KUNIT_CASE(test_constraint_mask_invalid),
	KUNIT_CASE(test_constraint_power_of_two),
	KUNIT_CASE(test_constraint_page_aligned),
	KUNIT_CASE(test_constraint_nonzero),
	KUNIT_CASE(test_return_validation),
	KUNIT_CASE(test_return_known_error),
	KUNIT_CASE(test_return_unknown_error),
	KUNIT_CASE(test_constraint_alignment),
	KUNIT_CASE(test_fd_int_overflow),
	KUNIT_CASE(test_constraint_enum),
	KUNIT_CASE(test_constraint_buffer),
	KUNIT_CASE(test_return_range),
#endif
	KUNIT_CASE(test_unregister_nonexistent),
	KUNIT_CASE(test_multiple_specs),
	KUNIT_CASE(test_json_export),
	KUNIT_CASE(test_json_export_null),
	KUNIT_CASE(test_json_export_small_buffer),
	{}
};

static struct kunit_suite kapi_test_suite = {
	.name = "kapi",
	.test_cases = kapi_test_cases,
};

kunit_test_suite(kapi_test_suite);

MODULE_DESCRIPTION("KUnit tests for Kernel API Specification Framework");
MODULE_LICENSE("GPL");
