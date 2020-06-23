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

#include "request_check.h"
#include "request.h"
#include "request_tools.h"
#include "stressy_ctx.h"
#include "module_tools.h"

#define	MOD_REQUEST_CHECK 	"mod_request_check"

#define XPATH_REQUEST		"//request"

typedef struct request_check_ctx_t request_check_ctx_t;

static int load_from_directory(stressy_ctx_t * stressy_ctx, char *directory);

struct request_check_ctx_t {

	char *directory;
	char *file;
	char *firefox;
};

static int setup_from_firefox_export(stressy_ctx_t *stressy_ctx, char *filename)
{
	xmlDocPtr xml_firefox = NULL;

	if (filename == NULL) return -1;

	xml_firefox = xmlParseFile(filename);
	request_from_firefox(stressy_ctx, xml_firefox);		

	return 0;
}

static int setup_from_filename(stressy_ctx_t *stressy_ctx, char *filename)
{
	xmlDocPtr doc = NULL;
	xmlXPathContextPtr context;
        xmlXPathObjectPtr result;
        xmlNodeSetPtr xmlRequests;
	int num_request = 0;
	int index_request = 0;

	if (filename == NULL || stressy_ctx == NULL) return -1;	


	LOG_ERR(DEBUG, stressy_ctx->logs, "Add file: %s", filename);
	doc = xmlParseFile(filename);
	if (!doc) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to parse file: %s", filename);
		return -1;
	}

	context = xmlXPathNewContext(doc);
	if (!context) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to create xpath context");
		return -1;
	}

	result = xmlXPathEvalExpression((xmlChar *)XPATH_REQUEST, context);
	if (!result) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get result from xpath");
		return -1;
	}

	xmlRequests = result->nodesetval;
	num_request = xmlRequests->nodeNr;
	LOG_ERR(INFO, stressy_ctx->logs, "Found %i request(s) definitions", num_request);
		
	for (index_request = 0; index_request < num_request; index_request++) {
		request_t * r = NULL;
		
		if (request_init(&r) < 0) {
			LOG_ERR(CRIT, stressy_ctx->logs, "Unable to alloc memory for requests");
			continue;
		}

		r->hostname = apr_pstrdup(r->pool, stressy_ctx->hostname);
                r->port = apr_pstrdup(r->pool, stressy_ctx->port);
                r->logs = stressy_ctx->logs;
                r->step = 0;

		if (request_from_xml(r, stressy_ctx, xmlRequests->nodeTab[index_request]) < 0) {
			request_destroy(r);
			continue;
		}

	     	request_rebuild_cookie_line(r);
		request_rebuild_post_line(r);
		request_rebuild_arg_line(r);
                request_set_module(r, MOD_REQUEST_CHECK);
		request_clean_request(r);

		site_map_insert_request(stressy_ctx->map, r->resource, r->method, r->request, r->post_body, (void *)r);
		request_list_add(stressy_ctx->request_list, r);
	}

	return 0;
}

static int setup_firefox(void *ctx, void *value, int type)
{
	request_check_ctx_t *cfg = NULL;	
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	if (!stressy_ctx) return -1;
	if (!value) return -1;
	
	cfg = (request_check_ctx_t *) module_retrieve_setup(stressy_ctx->pool, MOD_REQUEST_CHECK);
	if (cfg == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get module setup");
		return -1;
	}

	if (type == SETUP_CLI) {
		cfg->firefox = (char *) value;
	}
	else if (type == SETUP_XML) {
	

	}

	return 0;
}


static int setup_file(void *ctx, void *value, int type)
{
	request_check_ctx_t *cfg = NULL;	
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	if (!stressy_ctx) return -1;
	if (!value) return -1;
	
	cfg = (request_check_ctx_t *) module_retrieve_setup(stressy_ctx->pool, MOD_REQUEST_CHECK);
	if (cfg == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get module setup");
		return -1;
	}

	if (type == SETUP_CLI) {
		cfg->file = (char *) value;
	}
	else if (type == SETUP_XML) {
	

	}

	return 0;
}

static int setup_directory(void *ctx, void *value, int type)
{
	request_check_ctx_t *cfg = NULL;	
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	if (!stressy_ctx) return -1;
	if (!value) return -1;
	
	cfg = (request_check_ctx_t *) module_retrieve_setup(stressy_ctx->pool, MOD_REQUEST_CHECK);
	if (cfg == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get module setup");
		return -1;
	}

	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set request check directory to: %s", value);
		cfg->directory = (char *)value;
		return 0;
	}

	return 0;
}

static int load_from_directory(stressy_ctx_t *stressy_ctx, char *directory)
{
	apr_dir_t *dir = NULL;
	apr_status_t rc;
	apr_pool_t *pool = NULL;
	apr_finfo_t finfo;

	rc = apr_dir_open(&dir, directory, stressy_ctx->pool);
	if (rc != APR_SUCCESS) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to read directory: %s", directory);
		return -1;
	}
	
	apr_pool_create(&pool, NULL);
	if (!pool) return -1;

	while (apr_dir_read(&finfo, APR_FINFO_NAME, dir) == APR_SUCCESS) {	
		
		if (finfo.filetype == APR_DIR) {
			char *new_dir = NULL;

			if (!finfo.name) {
				continue;
			}
						
			if (strncasecmp(finfo.name, ".", strlen(finfo.name)) == 0 ||
				strncasecmp(finfo.name, "..", strlen(finfo.name)) == 0) {
				
				continue;
			}

			new_dir = apr_psprintf(pool, "%s/%s", directory, finfo.name);
			LOG_ERR(INFO, stressy_ctx->logs, "Found directory: %s", new_dir);
			load_from_directory(stressy_ctx, new_dir);
		}

		if (finfo.filetype == APR_REG) {
			char *filename = NULL;
			xmlDocPtr doc = NULL;
			xmlXPathContextPtr context;
		        xmlXPathObjectPtr result;
		        xmlNodeSetPtr xmlRequests;
			int num_request = 0;
			int index_request = 0;

			filename = apr_psprintf(pool, "%s/%s", directory, finfo.name);
			LOG_ERR(INFO, stressy_ctx->logs, "Found file: %s", filename);
			doc = xmlParseFile(filename);
			if (!doc) {
				LOG_ERR(CRIT, stressy_ctx->logs, "Unable to parse file: %s", filename);
				return -1;
			}

			context = xmlXPathNewContext(doc);
			if (!context) {
				LOG_ERR(CRIT, stressy_ctx->logs, "Unable to create xpath context");
				continue;
			}

			result = xmlXPathEvalExpression((xmlChar *)XPATH_REQUEST, context);
			if (!result) {
				LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get result from xpath");
				continue;
			}

			xmlRequests = result->nodesetval;
			num_request = xmlRequests->nodeNr;
			LOG_ERR(INFO, stressy_ctx->logs, "Found %i request(s) definitions", num_request);
		
			for (index_request = 0; index_request < num_request; index_request++) {
				request_t * r = NULL;
				
				if (request_init(&r) < 0) {
					LOG_ERR(CRIT, stressy_ctx->logs, "Unable to alloc memory for requests");
					continue;
				}

				r->logs = stressy_ctx->logs;
				//r->stressy_ctx = stressy_ctx;

				if (request_from_xml(r, stressy_ctx, xmlRequests->nodeTab[index_request]) < 0) {
					request_destroy(r);
					continue;
				}

				request_list_add(stressy_ctx->request_list, r);
			}
		}

	} 

	apr_pool_destroy(pool);

	return 0;
}

static int module_post_setup(void *ctx, void *data)
{
	request_check_ctx_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;

        stressy_ctx = (stressy_ctx_t *)ctx;
        if (!stressy_ctx) return -1;

	cfg = (request_check_ctx_t *) module_retrieve_setup(stressy_ctx->pool, MOD_REQUEST_CHECK);
	if (cfg == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get module setup");
		return -1;
	}

	LOG_ERR(INFO, stressy_ctx->logs, "Start request check directory read");
	if (!cfg->directory) {
		LOG_ERR(DEBUG, stressy_ctx->logs, "Unable to find directory");
	}
	else {
		load_from_directory(stressy_ctx, cfg->directory);
	}

	if (cfg->file != NULL) {	
        	setup_from_filename(stressy_ctx, cfg->file);
	}

	if (cfg->firefox != NULL) {
		setup_from_firefox_export(stressy_ctx, cfg->firefox);
	}


	return 0;
}

static int module_setup(void *ctx, void *data)
{
	request_check_ctx_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;

	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!stressy_ctx) return -1;
	
	LOG_ERR(DEBUG, stressy_ctx->logs, "Start request check setup");
	
	cfg = apr_pcalloc(stressy_ctx->pool, sizeof(request_check_ctx_t));
	if (!cfg) return -1;

	cfg->directory = NULL;

        setup_add_directive(stressy_ctx->prog_setup, "request_insert_dir", SETUP_CLI_NEED_1, setup_directory,
                        "=directory containing request definitions (.xml files)");
        setup_add_directive(stressy_ctx->prog_setup, "request_insert_file", SETUP_CLI_NEED_1, setup_file,
                        "=file.xml containing request definitions");
        setup_add_directive(stressy_ctx->prog_setup, "request_insert_firefox", SETUP_CLI_NEED_1, setup_firefox,
                        "=firefox.xml containing export request definitions from firefox");


	if (module_set_setup(stressy_ctx->pool, MOD_REQUEST_CHECK, (void *)cfg) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to set module setup");
		return -1;
	}

	hook_add(stressy_ctx->post_setup, "Request check module post setup", module_post_setup);

	return 0;
}

extern int request_check_module_init(void *ctx)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;	

	if (!stressy_ctx) return -1;

	LOG_ERR(DEBUG, stressy_ctx->logs, "Start request check module");
	hook_add(stressy_ctx->setup, "Request check module setup", module_setup);

	return 0;
}

