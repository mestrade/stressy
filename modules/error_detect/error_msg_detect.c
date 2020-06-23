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

#include "error_msg_detect.h"
#include "request.h"
#include "module_tools.h"
#include "stressy_ctx.h"

#define MOD_ERR_DETECT	"mod_error_detect"

#define ERR_XPATH	"//item"

typedef struct error_detect_t error_detect_t;
typedef struct error_detect_item_t error_detect_item_t;

struct error_detect_t {

	char *filename;
	apr_table_t *error_table;

	int num_error;
	error_detect_item_t **list;
};

struct error_detect_item_t {

	char *name;
	char *regexp_value;
	pcre *regexp;

};

extern int error_detect(void *ctx, void *data)
{
	error_detect_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)data;
	request_t *r = (request_t *)ctx;
	const char *ct = NULL;
	void *tmp_cfg = NULL;
	const char *location = NULL;

	int index_error = 0;

	if (!stressy_ctx) {
		LOG_ERR(CRIT, r->logs, "Unable to find stressy_ctx info attached to request");
		return -1;
	}
	
	if (module_get_setup(stressy_ctx->pool, MOD_ERR_DETECT, (void **)&tmp_cfg) < 0) return -1;
	cfg = (error_detect_t *)tmp_cfg;

	if (!cfg) return -1;

	if (r->code >= 400) return 0;

	if (!r->body || r->read_bytes <= 0) return -1;
	if (!(ct = apr_table_get(r->headers_out, "Content-Type"))) return -1;
	if (!strstr(ct, "text")) return -1;

	for (index_error = 0; index_error < cfg->num_error; index_error++) {
		error_detect_item_t *item = NULL;
	        int res = 0;
        	int out_vec[OUTPUT_VECTOR_SIZE];

		item = cfg->list[index_error];
		LOG_ERR(DEBUG, r->logs, "[%s] Checking error: %s", MOD_ERR_DETECT, item->name);	
		res = pcre_exec(item->regexp, NULL, r->body, r->read_bytes, 0, 0, out_vec, OUTPUT_VECTOR_SIZE);

		if (res >= 0) {
			LOG_ERR(INFO, r->logs, "[%s] Error detected: %s", MOD_ERR_DETECT, item->name);
			request_dump(r, INFO);
			break;
		}

		if ((location = apr_table_get(r->headers_out, "Location"))) {
			int res = 0;
			int out_vec[OUTPUT_VECTOR_SIZE];
	
			res = pcre_exec(item->regexp, NULL, location, strlen(location), 0, 0, out_vec, OUTPUT_VECTOR_SIZE);
			if (res >= 0) {
				LOG_ERR(INFO, r->logs, "[%s] Error detected: %s", MOD_ERR_DETECT, item->name);
				request_dump(r, INFO);
				break;
			}
		}	
	}

	return 0;
}

extern int error_detect_post_setup(void *ctx, void *data)
{

	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	error_detect_t *cfg = NULL;
	void *tmp_cfg = NULL;
	xmlDocPtr setup_doc = NULL;
	int i = 0;

	if (stressy_ctx == NULL) return -1;
	if (module_get_setup(stressy_ctx->pool, MOD_ERR_DETECT, (void **)&tmp_cfg) < 0) return -1;
	cfg = (error_detect_t *)tmp_cfg;
	if (!cfg) return -1;

	if (cfg->filename == NULL) return -1;	
	
	setup_doc = xmlParseFile(cfg->filename);
	if (setup_doc == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to parse file: %s for error detection", cfg->filename);
		return -1;
	}

        xmlXPathContext *xpathctx;
        xmlXPathObject *xpathObj;
        xmlNode *node;

	xpathctx = xmlXPathNewContext((xmlDocPtr)setup_doc);
        xpathObj = xmlXPathEvalExpression((xmlChar *)ERR_XPATH, xpathctx);

	cfg->num_error = xpathObj->nodesetval->nodeNr;
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Loading %i error(s) definition", MOD_ERR_DETECT, cfg->num_error);

	cfg->list = apr_pcalloc(stressy_ctx->pool, cfg->num_error * sizeof(error_detect_item_t *));
	if (cfg->list == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to alloc memory for error item");
		return -1;
	}	

	for (i=0; i < cfg->num_error; i++) {
		xmlChar *name = NULL;
		error_detect_item_t *item = NULL;
	        int err_offset;
        	const char *err_str = NULL;

		node = xpathObj->nodesetval->nodeTab[i];
		if (node == NULL) continue;

		name = xmlGetProp(node, BAD_CAST"name");
		LOG_ERR(DEBUG, stressy_ctx->logs, "Loading error: %s with regexp: %s", name, xmlNodeGetContent(node));
		
		item = apr_pcalloc(stressy_ctx->pool, sizeof(error_detect_item_t));
		if (item == NULL) return -1;

		item->name = apr_pstrdup(stressy_ctx->pool, (char *)name);
		item->regexp_value = apr_pstrdup(stressy_ctx->pool, (char *)xmlNodeGetContent(node));
		item->regexp = pcre_compile(item->regexp_value, PCRE_EXTENDED | PCRE_EXTRA, &err_str, &err_offset, NULL);	
	
		cfg->list[i] = item;
	}

	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Error dectection loaded from %s", MOD_ERR_DETECT, cfg->filename);
	hook_add(stressy_ctx->worker->after_receive, "Error receive module", error_detect);
	
	return 0;
}

static int setup_error_file(void *ctx, void *arg, int type)
{
	stressy_ctx_t *stressy_ctx = NULL;
	error_detect_t *cfg = NULL;
	void *tmp_cfg = NULL;

	stressy_ctx = (stressy_ctx_t *)ctx;	
	if (!stressy_ctx) return -1;

	LOG_ERR(DEBUG, stressy_ctx->logs, "Set error detect file");
	
	if (module_get_setup(stressy_ctx->pool, MOD_ERR_DETECT, (void **)&tmp_cfg) < 0) return -1;
	cfg = (error_detect_t *)tmp_cfg;	

	if (!cfg) return -1;
	
	if (type == SETUP_CLI) {
		cfg->filename = apr_pstrdup(stressy_ctx->pool, (char *)arg);
	}
	else if (type == SETUP_XML) {
		cfg->filename = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)arg, "value");
	}
	
	LOG_ERR(DEBUG, stressy_ctx->logs, "Use error detect file: %s", cfg->filename);	
	return 0;
}

extern int error_detect_setup(void *ctx, void *data)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	error_detect_t *cfg = NULL;

	if (!stressy_ctx) return -1;
	
	LOG_ERR(DEBUG, stressy_ctx->logs, "Error detection module setup start");

	/*
	 * Register the directive
	 *
	 */
	setup_add_directive(stressy_ctx->prog_setup, "error_detect", SETUP_CLI_NEED_1, setup_error_file, 
			"=error_file containing error detection pattern");

	cfg = apr_pcalloc(stressy_ctx->pool, sizeof(error_detect_t));
	if (!cfg) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to alloc memory for error detect cfg");
		return -1;
	}

	/*
	 * Set module cfg
	 *
	 */
	if (module_set_setup(stressy_ctx->pool, MOD_ERR_DETECT, (void *)cfg) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to set module cfg");
		return -1;
	}
	
	LOG_ERR(DEBUG, stressy_ctx->logs, "End error detect setup");
	
	return 0;
}

#ifdef HAVE_ERR_DETECT_SHARED
extern int module_init(void *ctx)
{
#else 
extern int err_detect_module_init(void *ctx)
{
#endif
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!stressy_ctx) return -1;

	LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", MOD_ERR_DETECT);
	
	hook_add(stressy_ctx->setup, "Error detection setup", error_detect_setup);
	hook_add(stressy_ctx->post_setup, "Error detection post setup", error_detect_post_setup);
	
	return 0;
}
