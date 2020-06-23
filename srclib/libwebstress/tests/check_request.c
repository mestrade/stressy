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

#include "request.h"
#include <check.h>
#include <stdio.h>

#define URI1	"/index.php"
#define URI2	"/index.php?a=1&b=2"
#define URI3	"/dir1/dir2/dir3/index.php"

static void suite_setup(void)
{

}

static void suite_teardown(void)
{

}

START_TEST(test_set_uri_1)
{
	request_t *r = NULL;
	int res = 0;
	
	res = request_init(&r);
	fail_unless(r != NULL, "Unable to init a request");
	
	request_set_resource_from_uri(r, URI1);
	fail_unless(strncasecmp(r->resource, URI1, strlen(r->resource)) == 0, "Resource set is different from resource in the request object");

}
END_TEST

START_TEST(test_set_uri_2)
{
	request_t *r = NULL;
	int res = 0;
	
	res = request_init(&r);
	fail_unless(r != NULL, "Unable to init a request");
	
	request_set_resource_from_uri(r, URI2);
	fail_unless(strncasecmp(r->resource, URI1, strlen(r->resource)) == 0, "Resource set is different from resource in the request object");

}
END_TEST

START_TEST(test_set_query_1)
{
	request_t *r = NULL;
	int res = 0;
	
	res = request_init(&r);
	fail_unless(r != NULL, "Unable to init a request");
	
	request_set_resource_from_uri(r, URI2);
	request_set_query_from_uri(r, URI2);
	fail_unless(strncasecmp(r->resource, URI1, strlen(r->resource)) == 0, "Resource set is different from resource in the request object");
	fail_unless(strncasecmp(r->query, "a=1&b=2", strlen(r->resource)) == 0, "Resource set is different from resource in the request object");
}
END_TEST

START_TEST(test_get_path_1)
{
	request_t *r = NULL;
	int res = 0;

	res = request_init(&r);
	fail_unless(r != NULL, "Unable to init a request");
	
	request_set_resource_from_uri(r, URI3);

	fail_unless(strncasecmp(r->resource, URI3, strlen(r->resource)) == 0, "Resource set is different from resource in the request object");
	fail_unless(r->path != NULL, "Unable to get path from resource");
	fail_unless(res == 0, "Unable to get path from resource");
	fail_unless(strncasecmp(r->path, "/dir1/dir2/dir3/", strlen(r->path)) == 0, "Path found is not valid (%s)", r->path);
}
END_TEST



Suite *control_request(void)
{
    	Suite *s;
    	TCase *tc_core;
    	s = suite_create("Control request code");
    	tc_core = tcase_create("Core Tests");

    	tcase_add_checked_fixture(tc_core, suite_setup, suite_teardown);

	tcase_add_test(tc_core, test_set_uri_1);
 	tcase_add_test(tc_core, test_set_uri_2);
  	tcase_add_test(tc_core, test_set_query_1);
   	tcase_add_test(tc_core, test_get_path_1);
 
	suite_add_tcase(s, tc_core);
    	return s;
}

