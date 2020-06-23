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
#include "request_list.h"
#include <check.h>
#include <stdio.h>

static void suite_setup(void)
{

}

static void suite_teardown(void)
{

}

START_TEST(test_add_request_1)
{
	request_list_t *list = NULL;
	request_t *r = NULL;
	request_t *get_r = NULL;
	int res = 0;

	res = request_init(&r);
	fail_unless(r != NULL, "Unable to init a request");
	
	res = request_list_init(&list);
	fail_unless(res == 0, "Unable to init a list");

	res = request_list_add(list, r);
	fail_unless(res == 0, "Unable to add a request");

	res = request_list_get_next(list, &get_r);
	fail_unless(r == get_r, "Unable to get inserted request");
}
END_TEST



Suite *control_request_list(void)
{
    	Suite *s;
    	TCase *tc_core;
    	s = suite_create("Control request list code");
    	tc_core = tcase_create("Core Tests");

    	tcase_add_checked_fixture(tc_core, suite_setup, suite_teardown);

	tcase_add_test(tc_core, test_add_request_1);
 
	suite_add_tcase(s, tc_core);
    	return s;
}

