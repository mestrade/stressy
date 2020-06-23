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

#include "stressy_core_setup.h"
#include "stressy_ctx.h"
#include "config.h"

#ifdef HAVE_MYSQLCLIENT
extern int setup_mysql_enabled(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (type == SETUP_CLI) {
		LOG_ERR(NOTICE, stressy_ctx->logs, "[mod_core] Enabled mysql database logs");
		stressy_ctx->use_mysql = 1;
	}
	else if (type == SETUP_XML) {
		LOG_ERR(NOTICE, stressy_ctx->logs, "[mod_core] Enabled mysql database logs");
		stressy_ctx->use_mysql = 1;
	}
	return 0;
}

extern int setup_mysql_database(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set mysql database to: %s", value);
		stressy_ctx->mysql_base = value;
	}
	else if (type == SETUP_XML) {
		stressy_ctx->mysql_base = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
		LOG_ERR(INFO, stressy_ctx->logs, "Set mysql database to: %s", stressy_ctx->mysql_base);	
	}
	
	return 0;
}

extern int setup_mysql_hostname(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Set mysql hostname to: %s", value);
	stressy_ctx->mysql_hostname = value;

	return 0;
}

extern int setup_mysql_port(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Set mysql port to: %s", value);
	stressy_ctx->mysql_port = atoi((char *)value);

	return 0;
}

extern int setup_mysql_user(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Set mysql user to: %s", value);
	stressy_ctx->mysql_user = value;

	return 0;
}

extern int setup_mysql_pass(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Set mysql pass to: %s", value);
	stressy_ctx->mysql_pass = value;

	return 0;
}

extern int setup_mysql_id_scan(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Set mysql id scan to: %s", value);
	stressy_ctx->mysql_id_scan = atoi(value);

	return 0;
}


#endif
extern int setup_redis_ip(void *ctx, void *value, int type)
{
        stressy_ctx_t *stressy_ctx = NULL;

        if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;

        if (!value || !stressy_ctx) return -1;

        if (type == SETUP_CLI) {
                LOG_ERR(INFO, stressy_ctx->logs, "Set redis ip to: %s", value);
                stressy_ctx->redis_ip = apr_pstrdup(stressy_ctx->pool, value);
        }
        else if (type == SETUP_XML) {
                char *sleep_value = NULL;

                sleep_value = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
                if (sleep_value == NULL) return -1;

                stressy_ctx->redis_ip = apr_pstrdup(stressy_ctx->pool, sleep_value);
		LOG_ERR(INFO, stressy_ctx->logs, "Set redis ip to: %i", stressy_ctx->redis_ip);
        }
        return 0;
}
extern int setup_redis_port(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set redis port to: %s", value);
		stressy_ctx->redis_port = strtol(value, NULL, 0);
	}
	else if (type == SETUP_XML) {
		char *sleep_value = NULL;

		sleep_value = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
		if (sleep_value == NULL) return -1;

		stressy_ctx->redis_port = strtol(sleep_value, NULL, 0);
		LOG_ERR(INFO, stressy_ctx->logs, "Set redis port to: %i", stressy_ctx->redis_port);
	}
	return 0;
}
extern int setup_sleep(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set sleep between request to: %s", value);
		stressy_ctx->request_sleep = atoi(value);
	}
	else if (type == SETUP_XML) {
		char *sleep_value = NULL;

		sleep_value = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
		if (sleep_value == NULL) return -1;

		stressy_ctx->request_sleep = atoi(sleep_value);
		LOG_ERR(INFO, stressy_ctx->logs, "Set request sleep to: %i", stressy_ctx->request_sleep);
	}
	return 0;
}
extern int setup_uri(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;
	request_t *r = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set start uri to: %s", value);
		stressy_ctx->start_uri = value;
	}
	else if (type == SETUP_XML) {
		stressy_ctx->start_uri = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
		LOG_ERR(INFO, stressy_ctx->logs, "Set start uri to: %s", stressy_ctx->start_uri);
	}
	
	if (stressy_ctx->start_uri == NULL) return 0;


	if (request_init(&r) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to init request for start_uri");
		return -1;
	}	

	r->logs = stressy_ctx->logs;
        //r->stressy_ctx = stressy_ctx;
	r->hostname = apr_pstrdup(r->pool, stressy_ctx->hostname);
        r->port = apr_pstrdup(r->pool, stressy_ctx->port);
        r->step = 0;
	r->protocol = "HTTP/1.1";

	request_set_resource_from_uri(r, stressy_ctx->start_uri);

	apr_table_set(r->headers_in, "Host", stressy_ctx->hostname);
	apr_table_set(r->headers_in, "Accept", "*/*");
	apr_table_set(r->headers_in, "User-Agent", "Mozilla/5.001 (windows; U; NT4.0; en-us) Gecko/25250101");

	

	//request_list_add(stressy_ctx->request_list, r);
	

	return 0;
}

extern int setup_hostname(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set hostname to: %s", value);
		stressy_ctx->hostname = value;
	}
	else if (type == SETUP_XML) {
		stressy_ctx->hostname = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
		LOG_ERR(INFO, stressy_ctx->logs, "Set hostname to: %s", stressy_ctx->hostname);
	}
	
	return 0;
}

extern int setup_proxy(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!value || !stressy_ctx) return -1;

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set proxy to: %s", value);
		stressy_ctx->proxy_addr = value;
		stressy_ctx->proxy_port = "8080";
		stressy_ctx->use_proxy = 1;
	}
	else if (type == SETUP_XML) {
		stressy_ctx->proxy_addr = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
		stressy_ctx->proxy_port = "8080";
		stressy_ctx->use_proxy = 1;
		LOG_ERR(INFO, stressy_ctx->logs, "Set proxy to: %s", stressy_ctx->proxy_addr);	
	}
	
	return 0;
}

extern int setup_port(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Set port to: %s", value);
	stressy_ctx->port = value;

	return 0;
}

extern int setup_proxy_port(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Set proxy port to: %s", value);
	stressy_ctx->proxy_port = value;

	return 0;
}

extern int setup_ssl(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "SSL enabled");
	stressy_ctx->use_ssl = 1;
	stressy_ctx->port = apr_pstrdup(stressy_ctx->pool, "443");
	
	return 0;
}

extern int setup_worker(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!value || !stressy_ctx) return -1;

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Use %s threads", value);
		stressy_ctx->num_worker = atoi(value);
	}
	else if (type == SETUP_XML) {
		char *num = NULL;

		num = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
		if (num) stressy_ctx->num_worker = atoi(num);
	}
	return 0;
}

extern int setup_template(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Use template file %s", value);
	stressy_ctx->xml_setup_file = value;
	setup_set_cli_xml(stressy_ctx->prog_setup, value);
	
	return 0;
}

extern int setup_xml_out(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Use xml output file %s", value);
	stressy_ctx->xml_file = value;
	return 0;
}

extern int setup_verbose(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (value == NULL || stressy_ctx == NULL) return -2;

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set verbose filter to %s", value);
		stressy_ctx->logs->level = set_level_filter(value);
	}
	else if (type == SETUP_XML) {
		char *level = NULL;

		level = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)value, "value");
		if (!level) {
			return -3;
		}

		stressy_ctx->logs->level = set_level_filter(level);
	}
	return 0;
}

extern int setup_err_output(void *ctx, void *value, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!value || !stressy_ctx) return -1;

	LOG_ERR(INFO, stressy_ctx->logs, "Set error output to %s", value);
	stressy_ctx->logs->err_filename = value;
	
	return 0;
}


