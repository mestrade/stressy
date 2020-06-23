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

#include <stdlib.h>
#include <check.h>
#include <stdio.h>
#include <config.h>

#include <apr.h>
#include <apr_pools.h>

Suite *control_request_list(void);
Suite *control_parsing_tools(void);
Suite *control_request(void);

int main(int argc, char **argv)
{
    	char buf[256];
    	int nf = 0, num = 0;
    	apr_status_t status;
    	SRunner *sr;

    	if (argc > 1) {
        	nf++;
        	num = atoi(argv[1]);
    	}

    	status = apr_initialize();
    	if (APR_SUCCESS != status) {
        	apr_strerror(status, buf, 200);
        	fprintf(stderr, "ERROR: %s\n", buf);
    	}

    	atexit(apr_terminate);

	sr = srunner_create(NULL);
	if (!num || num == 1)
        srunner_add_suite(sr, control_parsing_tools());
	srunner_add_suite(sr, control_request());
	srunner_add_suite(sr, control_request_list());
	srunner_set_fork_status(sr, CK_NOFORK);
    	srunner_set_xml(sr, "check_test_log.xml");

    	srunner_run_all(sr, CK_NORMAL);
    	nf = srunner_ntests_failed(sr);

    	srunner_free(sr);


	return 0;
}

