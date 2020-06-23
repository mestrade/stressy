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

#include "stressy.h"
#include "request.h"
#include "setup.h"
#include "worker.h"
#include "socket_pool.h"
#include "stressy_ctx.h"
#include "stressy_core_setup.h"
#include "module.h"
#include "config.h"

#include "openssl/ssl.h"

#include "stressy_secplatform.h"

#ifdef HAVE_GUI

#include "gui_main.h"

#endif

static void set_signals(void)
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
	return;
}



int main(int argc, char **argv)
{
	stressy_ctx_t *stressy_ctx = NULL;
	char *setup_err = NULL;

	module_list_t *module_store;
	int rc = 0;

        char time_str[APR_CTIME_LEN];
        memset(time_str, 0, APR_CTIME_LEN);
        apr_ctime(time_str, apr_time_now());

	
	apr_initialize();

	/*
	 * Capture sigpipe
	 *
	 */
	set_signals();


	fprintf(stderr, "Using version %s from %s\n", VERSION, STRESSY_BASE);

	/*
	 * init stressy setup
	 *
	 */

	if(init_stressy_ctx(&stressy_ctx) < 0) {
		fprintf(stderr, "Unable to init stressy_ctx\n");
		return -1;
	}
	
	if (setup_init(&stressy_ctx->prog_setup) < 0) {
		fprintf(stderr, "Unable to init setup\n");
		return -1;
	}

	/*
	 * Start logs
	 *
	 */
	if (logs_init(stressy_ctx->pool, &stressy_ctx->logs) < 0) {
		fprintf(stderr, "Unable to init logs\n");
		return -1;
	}	
	if (apr_file_open_stderr(&stressy_ctx->logs->err_output, stressy_ctx->logs->pool) != APR_SUCCESS) {
		fprintf(stderr, "Unable to open stderr for logs");
		return -1;
	}
	stressy_ctx->logs->level = NOTICE;
	stressy_ctx->logs->time = 1;
	
	rc = init_module_list(&module_store);
       	if (rc < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to init module list (errno: %i)", rc);
		return -1;
	}
	module_list_set_logs(module_store, stressy_ctx->logs);
	LOG_ERR(NOTICE, stressy_ctx->logs, "Loading modules from %s", module_get_directory(module_store));


	if (init_map(&stressy_ctx->map) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to init map");
		return -1;
	}
	
	if (site_map_set_logs(stressy_ctx->map, stressy_ctx->logs) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to set map logs");
		return -1;
	}

	site_map_set_hook(stressy_ctx->map, stressy_ctx->level_inserted, stressy_ctx->request_inserted);
	

	/*
	 * Load modules
	 *
	 */
	rc = module_load_directory(module_store);
	if (rc < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Error while loading modules (errno: %i)", rc);
		return -1;
	}
	if (module_run_all_init(module_store, (void *)stressy_ctx) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Error while loading module"); 
		return -1;
	}

	if (module_load_builtin((void *)stressy_ctx) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Error while loading builtin modules");
		return -1;
	}
	
	/*
	 * Set cli args
	 *
	 */
	setup_set_cli_info(stressy_ctx->prog_setup, argc, argv);
	
	/*
	 * Register the core directives
	 *
	 */
	setup_add_directive(stressy_ctx->prog_setup, "hostname", SETUP_CLI_NEED_1, setup_hostname, 
			"=www.domain.com for the web application to scan");
	setup_add_directive(stressy_ctx->prog_setup, "uri", SETUP_CLI_NEED_1, setup_uri, 
			"=/start/uri to setup the first request uri");
	setup_add_directive(stressy_ctx->prog_setup, "port", SETUP_CLI_NEED_1, setup_port, 
			"=80 of the web application to scan (default 80)");
	setup_add_directive(stressy_ctx->prog_setup, "ssl", SETUP_CLI_NEED_0, setup_ssl, 
			"to enable ssl connections - set default port to 443");
	setup_add_directive(stressy_ctx->prog_setup, "proxy", SETUP_CLI_NEED_1, setup_proxy, 
			"=proxy.isp.com of the proxy used to scan");
	setup_add_directive(stressy_ctx->prog_setup, "proxy-port", SETUP_CLI_NEED_1, setup_proxy_port, 
			"=8080 of the proxy used to scan (default 8080)");
	setup_add_directive(stressy_ctx->prog_setup, "template", SETUP_CLI_NEED_1, setup_template, 
			"=template.xml of the xml template file");
	setup_add_directive(stressy_ctx->prog_setup, "worker", SETUP_CLI_NEED_1, setup_worker, 
			"=16 of threads (default: 4)");
	setup_add_directive(stressy_ctx->prog_setup, "verbose", SETUP_CLI_NEED_1, setup_verbose, 
			"=INFO can be DEBUG, WARN, NOTICE, INFO");
	setup_add_directive(stressy_ctx->prog_setup, "err-out", SETUP_CLI_NEED_1, setup_err_output, 
			"=log_file containing error logs");
	setup_add_directive(stressy_ctx->prog_setup, "xml-out", SETUP_CLI_NEED_1, setup_xml_out, 
			"=out.xml of xml report");
	setup_add_directive(stressy_ctx->prog_setup, "request-sleep", SETUP_CLI_NEED_1, setup_sleep, 
			"=5 number of second between request (per thread)");
	setup_add_directive(stressy_ctx->prog_setup, "redis-ip", SETUP_CLI_NEED_1, setup_redis_ip, 
			"=10.0.0.1 ip of redis do get Scan setup from queue");
	setup_add_directive(stressy_ctx->prog_setup, "redis-port", SETUP_CLI_NEED_1, setup_redis_port, 
			"=6379 port of redis server (default: 6379)");

#ifdef HAVE_MYSQLCLIENT
	setup_add_directive(stressy_ctx->prog_setup, "mysql_error", SETUP_CLI_NEED_0, setup_mysql_enabled, 
			"enable error log in mysql database");
	setup_add_directive(stressy_ctx->prog_setup, "mysql_hostname", SETUP_CLI_NEED_1, setup_mysql_hostname, 
			"=hostname of the mysql database");
	setup_add_directive(stressy_ctx->prog_setup, "mysql_port", SETUP_CLI_NEED_1, setup_mysql_hostname, 
			"=port of the mysql database");
	setup_add_directive(stressy_ctx->prog_setup, "mysql_database", SETUP_CLI_NEED_1, setup_mysql_database, 
			"=name of the mysql database");
	setup_add_directive(stressy_ctx->prog_setup, "mysql_user", SETUP_CLI_NEED_1, setup_mysql_user, 
			"=user to connect mysql database");
	setup_add_directive(stressy_ctx->prog_setup, "mysql_pass", SETUP_CLI_NEED_1, setup_mysql_pass, 
			"=passwd to connect mysql database");
	setup_add_directive(stressy_ctx->prog_setup, "mysql_id_scan", SETUP_CLI_NEED_1, setup_mysql_id_scan, 
			"=id_scan used to log into mysql database");

#endif


	/*
	 * Exec all setup hook
	 *
	 */
	hook_run_all(stressy_ctx->setup, stressy_ctx, NULL);

	/*
	 * If no arg sent to the scan, display available options
	 *
	 */
	if (argc <= 1) {
		setup_display_options(stressy_ctx->prog_setup);
		return -1;
	}
	
	if (setup_run_cli(stressy_ctx->prog_setup, (void *)stressy_ctx, &setup_err) < 0) {
		fprintf(stderr, "Error while cli directive setup\n");
		setup_display_options(stressy_ctx->prog_setup);
		return -1;
	}

	if (setup_run_xml(stressy_ctx->prog_setup, (void *)stressy_ctx, &setup_err) < 0) {
		fprintf(stderr, "Error while xml directive setup\n");
		return -1;
	}

	/* ---------- END OF THE SETUP ----------------- */

	/* start log file if needed */

	logs_start_err_output(stressy_ctx->logs);
	
	if (worker_init(stressy_ctx->pool, &stressy_ctx->worker, stressy_ctx->num_worker) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to init worker with %i threads", stressy_ctx->num_worker); 
		return -1;
	}

	stressy_ctx->worker->external_ctx = stressy_ctx;
	
	if (stressy_ctx->use_ssl == 1) {
#ifdef HAVE_OPENSSL
                SSL_load_error_strings();
                SSL_library_init();
                LOG_ERR(NOTICE, stressy_ctx->logs, "SSL Lib initialized");
#else
		LOG_ERR(CRIT, stressy_ctx->logs, "SSL enabled but stressy is not compiled with openssl support - please use --with-openssl");
#endif
        }


	LOG_ERR(NOTICE, stressy_ctx->logs, "Initializing %i sockets", stressy_ctx->num_worker);
	if (socket_pool_init(stressy_ctx->pool, &stressy_ctx->socket_pool, stressy_ctx->num_worker, stressy_ctx->use_ssl) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to init socket pool");
		return -1;
	}

	socket_pool_set_logs(stressy_ctx->socket_pool, stressy_ctx->logs);

	/*
	 * How we have all setup info, run hook post config
	 *
	 */
	hook_run_all(stressy_ctx->post_setup, stressy_ctx, NULL);
	
	if (!stressy_ctx->port && stressy_ctx->use_ssl == 1) stressy_ctx->port = apr_pstrdup(stressy_ctx->pool, "443");
	else if (!stressy_ctx->port && stressy_ctx->use_ssl == 0) stressy_ctx->port = apr_pstrdup(stressy_ctx->pool, "80");
	
	/*
	 * Now we did setup, start the connections
	 *
	 */
	LOG_ERR(NOTICE, stressy_ctx->logs, "Startup %i connections on port: %s ssl status: %i", 
		stressy_ctx->num_worker, stressy_ctx->port, stressy_ctx->use_ssl);
	
	if (stressy_ctx->use_proxy == 1) {
		if(socket_pool_start(stressy_ctx->socket_pool, stressy_ctx->proxy_addr, stressy_ctx->proxy_port) < 0) return -1;
	}
	else { 
		if(socket_pool_start(stressy_ctx->socket_pool, stressy_ctx->hostname, stressy_ctx->port) < 0 ) return -1;
	}

#ifdef HAVE_MYSQLCLIENT
	if (stressy_ctx->use_mysql == 1) {
		if(request_stressy_ctx_connect_mysql(stressy_ctx) < 0) return -1;
	}
#endif

	workers_t *workers = stressy_ctx->worker;

	workers_set_request_list(workers, stressy_ctx->request_list);
	workers_set_socket_pool(workers, stressy_ctx->socket_pool);

	
	LOG_ERR(INFO, stressy_ctx->logs, "---------- Start Scan at: %s ----------", time_str);
	worker_start(stressy_ctx->worker, stressy_ctx);
        worker_wait_thread(stressy_ctx->worker, stressy_ctx);

	if (site_map_is_xml(stressy_ctx->map) < 0) {
		LOG_ERR(DEBUG, stressy_ctx->logs, "Unable to find xml doc");
	}
	else {
		site_map_save_xml(stressy_ctx->map, stressy_ctx->xml_file);
	}
	
	return 0;
}

