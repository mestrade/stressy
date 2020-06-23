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

#include "cli_setup.h"
#include "logs.h"

extern int cli_setup(char **argv, stressy_ctx_t *stressy_ctx)
{
	int i = 0;
	char *verbose = NULL;

	if (!argv) return -1;

	for (i = 1; argv[i]; i++) {
		//LOG_ERR(DEBUG, store->logs, "Work in argv[%i] %s", i, argv[i]);
		
		if (argv[i] && (strncasecmp(argv[i], "-h", 2) == 0) && argv[i + 1]) {
			stressy_ctx->hostname = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-ssl", 4) == 0)) {
			stressy_ctx->use_ssl = 1;
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-port", 5) == 0) && argv[i + 1]) {
			stressy_ctx->port = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			LOG_ERR(NOTICE, stressy_ctx->logs, "Use port: %s", stressy_ctx->port);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-uri", 4) == 0) && argv[i + 1]) {
			stressy_ctx->start_uri = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-verbose", 4) == 0) && argv[i + 1]) {
			verbose = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			stressy_ctx->logs->level = set_level_filter(verbose);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-Oxml", 5) == 0) && argv[i + 1]) {
			stressy_ctx->xml_file = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			LOG_ERR(NOTICE, stressy_ctx->logs, "Using xml output file: %s", stressy_ctx->xml_file);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-proxy", strlen(argv[i])) == 0) && argv[i + 1]) {
			stressy_ctx->use_proxy = 1;
			stressy_ctx->proxy_addr = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			stressy_ctx->proxy_port = apr_pstrdup(stressy_ctx->pool, "8080");
			LOG_ERR(NOTICE, stressy_ctx->logs, "Use proxy addr: %s", stressy_ctx->proxy_addr);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-proxy-port", 10) == 0) && argv[i + 1]) {
			stressy_ctx->proxy_port = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			LOG_ERR(NOTICE, stressy_ctx->logs, "Use proxy port: %s", stressy_ctx->proxy_port);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-worker", 7) == 0) && argv[i + 1]) {
			stressy_ctx->num_worker = atoi(argv[i + 1]);
			LOG_ERR(NOTICE, stressy_ctx->logs, "Use %i threads", stressy_ctx->num_worker);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-template", strlen(argv[i])) == 0) && argv[i + 1]) {
			stressy_ctx->xml_setup_file = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			LOG_ERR(NOTICE, stressy_ctx->logs, "Use template %s", stressy_ctx->xml_setup_file);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-redis-ip", strlen(argv[i])) == 0) && argv[i + 1]) {
			stressy_ctx->redis_ip = apr_pstrdup(stressy_ctx->pool, argv[i + 1]);
			LOG_ERR(NOTICE, stressy_ctx->logs, "Use redis ip %s", stressy_ctx->redis_ip);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-redis-port", strlen(argv[i])) == 0) && argv[i + 1]) {
			stressy_ctx->redis_port = strtol(argv[i + 1], NULL, 0);
			LOG_ERR(NOTICE, stressy_ctx->logs, "Use redis port %i", stressy_ctx->redis_port);
			continue;
		}
		if (argv[i] && (strncasecmp(argv[i], "-mysql", strlen(argv[i])) == 0) && argv[i + 1]) {
			if (strncasecmp(argv[i+1], "On", strlen(argv[i+1])) == 0) {
				stressy_ctx->use_mysql = 1;
				LOG_ERR(NOTICE, stressy_ctx->logs, "Mysql logging activated");
			}
			else {
				LOG_ERR(NOTICE, stressy_ctx->logs, "Mysql logging disabled");
				stressy_ctx->use_mysql = 0;
			}
			continue;
		}
	}
	
	if (!verbose) stressy_ctx->logs->level = NOTICE;
	
	return 0;
}

extern int display_setup(char *progname)
{
	fprintf(stderr, "Usage: %s <options> ...\n", progname);
	fprintf(stderr, "-h <hosname> 		(web application hostname)\n");
	fprintf(stderr, "-uri <uri>		(uri to start browsing - default is /)\n");
	fprintf(stderr, "-port <port>		(port to connect to - default is 80 and 443 for ssl)\n");
	fprintf(stderr, "-ssl 			(enable ssl)\n");
	fprintf(stderr, "-proxy <addr>		(proxy address)\n");
	fprintf(stderr, "-proxy-port <port>	(proxy port)\n");
	fprintf(stderr, "-worker <num worker>	(number of worker processing request - default is 4)\n");
	fprintf(stderr, "-template <filename>	(xml setup template to use)\n");
	fprintf(stderr, "-verbose <level>	(verbose filter: DEBUG, WARN, NOTICE, INFO)\n");
	fprintf(stderr, "-Oxml <filename>	(filename of xml result output)\n");
	fprintf(stderr, "-redis <ip:port>	(Redis address to get setup)\n");

	return 0;
}
