/* Copyright 2007 Matthieu Estrade
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "parsing_tools.h"

#include <check.h>
#include <stdio.h>

#define LINK_STRING_1	"http://www.test.com/index.php"
#define LINK_STRING_2	"http:///index.php"
#define LINK_STRING_3	"http://www.test.com:80/index.php"
#define LINK_STRING_4	"https://www.test.com:80/index.php"
#define LINK_STRING_5	"mailto:pierre@test.com"
#define LINK_STRING_6	"poutrelle/jeanpierre"
#define LINK_STRING_7	"/poutrelle/dudulle"

#define RECURSIVE_1	"../../../index.php"
#define RECURSIVE_2	"/test/../test/../index.php"
#define RECURSIVE_3	"/././././index.php"
#define RECURSIVE_4	"/../index.php"

static void suite_setup(void)
{

}

static void suite_teardown(void)
{

}

START_TEST(test_get_resource_1)
{
	apr_pool_t *pool = NULL;
	char *resource = NULL;
	int res = 0;

	apr_pool_create(&pool, NULL);
	res = parse_resource_from_string(pool, LINK_STRING_1, &resource);
	fail_unless(resource != NULL, "No resource found in a valid link");
	fail_unless(strncasecmp(resource, "/index.php", strlen(resource)) == 0, 
		"Found resource is not the good one (expected: /index.php, got %s)", resource);

}
END_TEST

START_TEST(test_clean_recursive_1)
{
	apr_pool_t *pool = NULL;
	int res = 0;
	char *clean = NULL;

	apr_pool_create(&pool, NULL);
	res = parse_clean_recursive(pool, RECURSIVE_1, &clean);

	fail_unless(res < 0, "Function exited abnormaly (%i)", res); 
}
END_TEST

START_TEST(test_clean_recursive_2)
{
	apr_pool_t *pool = NULL;
	int res = 0;
	char *clean = NULL;


	apr_pool_create(&pool, NULL);
	res = parse_clean_recursive(pool, RECURSIVE_2, &clean);

	fail_unless(res >= 0, "Function exited abnormaly (%i)", res); 
	fail_unless(strncasecmp(clean, "/index.php", strlen(clean)) == 0, "Expected string is not valid (%s)", clean);
}
END_TEST

START_TEST(test_clean_recursive_3)
{
	apr_pool_t *pool = NULL;
	int res = 0;
	char *clean = NULL;

	apr_pool_create(&pool, NULL);
	res = parse_clean_recursive(pool, RECURSIVE_3, &clean);

	fail_unless(res >= 0, "Function exited abnormaly (%i)", res); 
	fail_unless(strncasecmp(clean, "/index.php", strlen(clean)) == 0, "Expected string is not valid (%s)", clean);
}
END_TEST

START_TEST(test_clean_recursive_4)
{
	apr_pool_t *pool = NULL;
	int res = 0;
	char *clean = NULL;

	apr_pool_create(&pool, NULL);
        res = parse_clean_recursive(pool, RECURSIVE_4, &clean);

	fail_unless(res < 0, "Function exited abnormaly (%i)", res); 
}
END_TEST



Suite *control_parsing_tools(void)
{
    	Suite *s;
    	TCase *tc_core;
    	s = suite_create("Control Parsing tools code");
    	tc_core = tcase_create("Core Tests");

    	tcase_add_checked_fixture(tc_core, suite_setup, suite_teardown);

	tcase_add_test(tc_core, test_get_resource_1);
	tcase_add_test(tc_core, test_clean_recursive_1);
 	tcase_add_test(tc_core, test_clean_recursive_2);
	tcase_add_test(tc_core, test_clean_recursive_3);
	tcase_add_test(tc_core, test_clean_recursive_4);

 	suite_add_tcase(s, tc_core);
    	return s;
}

