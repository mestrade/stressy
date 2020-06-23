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

#include "fuzzer.h"

#include "stressy_ctx.h"
#include "module_tools.h"

#define MOD_PARAMETER_FUZZER "mod_parameter_fuzzer"
#define XPATH_FUZZ	"//fuzz"

#define HISTORY_VAR_CHECKED 	1
#define HISTORY_VAR_UNCHECKED	0
#define HISTORY_ERROR		-1

#define PFM_INDEX	"PFM_INDEX"

typedef struct fuzz_elem {

	char *new_value;
	char *value;
	char *encoding;
	int repeat;

	int pos;
	
	apr_hash_t *hash;

}fuzz_elem_t;


typedef struct pfm {
	const char *filename;
	int compare_body;

	int num_fuzz;
	fuzz_elem_t **list;

	apr_hash_t *history;

	int fuzz_get;
	int fuzz_post;
	int fuzz_cookies;
	int fuzz_headers;
	int fuzz_xml;

}pfm_t;


static int pfm_history_set(apr_pool_t *pool, apr_hash_t *hash, char *method, char *uri, char *var, fuzz_elem_t *elem)
{
	char *key = NULL;
	apr_pool_t *tmp_pool = NULL;

	apr_pool_create(&tmp_pool, NULL);
	key = apr_psprintf(pool, "uri:%s var: %s method: %s fuzz: %i", method, uri, var, elem->pos);

	if (key == NULL) {
		apr_pool_destroy(tmp_pool);
		return HISTORY_ERROR;
	}

	apr_hash_set(hash, key, strlen(key), apr_pstrdup(pool, "checked"));

	apr_pool_destroy(tmp_pool);
	return HISTORY_VAR_CHECKED;
}

static int pfm_history_get(apr_pool_t *pool, apr_hash_t *hash, char *method, char *uri, char *var, fuzz_elem_t *elem)
{
	char *key = NULL;
	apr_pool_t *tmp_pool = NULL;
	void *res = NULL;

	apr_pool_create(&tmp_pool, NULL);
	key = apr_psprintf(pool, "uri:%s var: %s method: %s fuzz: %i", method, uri, var, elem->pos);
	if (key == NULL) {
		apr_pool_destroy(tmp_pool);
		return HISTORY_ERROR;
	}

	res = apr_hash_get(hash, key, strlen(key));
	if (res == NULL) {
		apr_pool_destroy(tmp_pool);
		return HISTORY_VAR_UNCHECKED;
	}
	else {
		apr_pool_destroy(tmp_pool);
		return HISTORY_VAR_CHECKED;
	}	

	return 0;
}

static int pfm_set_req_previous_status(request_t *parent_r, request_t *r)
{
	char *old_status = NULL;

	old_status = apr_psprintf(r->pool, "%s", r->answer_code);

	if (old_status == NULL) return -1;

	return 0;
}

static int pfm_set_index(request_t *r, int index)
{
	char *tmp = NULL;

	if (r == NULL) return -1;

	tmp = apr_psprintf(r->pool, "%i", index);
	apr_table_set(r->notes, PFM_INDEX, tmp);

	return 0;
}

static int pfm_get_index(request_t *r)
{
	const char *index = NULL;

	if (r == NULL) return -1;

	index = apr_table_get(r->notes, PFM_INDEX);
	if (index == NULL) return -1;

	return atoi(index);
}

static int pfm_new_request(request_t *parent_r, fuzz_elem_t *elem, int index)
{
	request_t *new_req = NULL;
	var_item_t *var_ptr = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	int fuzzed = 0;

	if (parent_r == NULL || elem == NULL) return -1;

	//stressy_ctx = (stressy_ctx_t *)parent_r->stressy_ctx;

	if (request_init(&new_req) < 0) return -1;

	if (request_copy_basic(parent_r, new_req) < 0) {
        	request_destroy(new_req);
                return -1;
        }

	new_req->resource = apr_pstrdup(new_req->pool, parent_r->resource);
	
	for (var_ptr = parent_r->var_list->first_var; var_ptr; var_ptr = var_ptr->next) {
		var_item_t *new_var;

		var_item_init(new_req->pool, &new_var);
	

		if (pfm_history_get(stressy_ctx->pool, elem->hash, parent_r->method, parent_r->resource, var_ptr->name, elem) == HISTORY_VAR_CHECKED) {
			new_var->name = apr_pstrdup(new_req->pool, var_ptr->name);
	                new_var->value = apr_pstrdup(new_req->pool, var_ptr->value);
	                new_var->type = apr_pstrdup(new_req->pool, var_ptr->type);
	                var_list_add(new_req->var_list, new_var);
		}
		else {
	
			/* XXX CHECK HERE WITH REVEXP TO SEE IF WE FUZZ THIS VAR */
			new_var->name = apr_pstrdup(new_req->pool, var_ptr->name);
	                new_var->value = apr_pstrdup(new_req->pool, elem->new_value);
	                new_var->type = apr_pstrdup(new_req->pool, var_ptr->type);
			pfm_history_set(stressy_ctx->pool, elem->hash, parent_r->method, parent_r->resource, var_ptr->name, elem);
			var_list_add(new_req->var_list, new_var);
			fuzzed++;	
		}

	        continue;
	}

	if (fuzzed == 0) {
		request_destroy(new_req);
		return 0;
	}

	if (strncasecmp(parent_r->method, "POST", strlen(parent_r->method)) == 0) {
		request_set_method(new_req, "POST"); 
                request_rebuild_post_line(new_req);
                request_set_query_from_uri(new_req, parent_r->query);
	}
	else {
		request_rebuild_arg_line(new_req);
	}


	pfm_set_req_previous_status(parent_r, new_req);	
	//request_clean_uri(new_req);
        request_clean_request(new_req);
	request_set_module(new_req, MOD_PARAMETER_FUZZER);
        pfm_set_index(new_req, index);

	request_list_add(stressy_ctx->request_list, new_req);

	return 0;
}

static int pfm_insert(void *ctx, void *data)
{
        request_t *r = (request_t *)ctx;
        stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)data;
        pfm_t *conf = NULL;
	int index = 0;

        if (r == NULL || stressy_ctx == NULL) return -1;

        conf = (pfm_t *)module_retrieve_setup(stressy_ctx->pool, MOD_PARAMETER_FUZZER);
        if (!conf) return -1;


	if ((index = pfm_get_index(r)) < 0) {
		LOG_ERR(NOTICE, r->logs, "Request not inserted by param fuzzer");	
		return 0;
	}

	if ((index + 1) >= conf->num_fuzz) {
		LOG_ERR(NOTICE, r->logs, "No more fuzzer elem");
		return 0;
	}

	LOG_ERR(NOTICE, r->logs, "last index was %i", index);

	pfm_new_request(r, conf->list[index + 1], index + 1);
	LOG_ERR(NOTICE, r->logs, "Fuzz with elem %i", index + 1);

	return 0;
}

static int pfm_exec(void *ctx, void *data)
{
        request_t *r = (request_t *)ctx;
        stressy_ctx_t *stressy_ctx = NULL;      
	pfm_t *conf = NULL;

	//if (r == NULL || r->stressy_ctx == NULL) return -1;
	//stressy_ctx = (stressy_ctx_t *)r->stressy_ctx;


	conf = (pfm_t *)module_retrieve_setup(stressy_ctx->pool, MOD_PARAMETER_FUZZER);
	if (!conf) return -1;

	if (r->var_list == NULL || r->var_list->num_var <= 0) {
		LOG_ERR(DEBUG, r->logs, "No var - no fuzzing - exit");
		return 0;
	}

	if (conf->num_fuzz <= 0) return -1;
	LOG_ERR(DEBUG, r->logs, "Insert first Fuzz on elem %p", conf->list[0]);
	pfm_new_request(r, conf->list[0], 0);
	
	return 0;
}

static int init_fuzz_elem(apr_pool_t *pool, fuzz_elem_t **fuzz)
{
	if (pool == NULL) return -1;
	fuzz_elem_t *new = NULL;
	
	new = apr_pcalloc(pool, sizeof(fuzz_elem_t));
	if (new == NULL) return -1;

	*fuzz = new;

	return 0;
}

static int pfm_set_new_value(stressy_ctx_t *ctx, fuzz_elem_t *elem)
{
	int repeat = 0;

	if (ctx == NULL || elem == NULL) return -1;

	for(repeat = 0; repeat < elem->repeat; repeat++) {

		if (repeat == 0) elem->new_value = apr_pstrdup(ctx->pool, elem->value);
		else elem->new_value = apr_pstrcat(ctx->pool, elem->new_value, elem->value, NULL);
	}

	LOG_ERR(DEBUG, ctx->logs, "new value is %s", elem->new_value);

	return 0;
}

extern int pfm_post_setup(void *ctx, void *data)
{
        pfm_t *conf = NULL;
        stressy_ctx_t *stressy_ctx = NULL;
	xmlDocPtr xml_setup = NULL;	

	xmlXPathContext *xpathctx;
        xmlXPathObject *xpathObj;
        xmlNode *node;
	int i = 0;

        stressy_ctx = (stressy_ctx_t *)ctx;
        if (!stressy_ctx) return -1;

        conf = (pfm_t *)module_retrieve_setup(stressy_ctx->pool, MOD_PARAMETER_FUZZER);
        if (!conf) return -1;

	if (conf->filename == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "[%s] Post setup run without filename", MOD_PARAMETER_FUZZER);
		return -1;
	}	

	xml_setup = xmlParseFile(conf->filename);
	if (xml_setup == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load xml setup");
		return -1;
	}

	xpathctx = xmlXPathNewContext((xmlDocPtr)xml_setup);
        xpathObj = xmlXPathEvalExpression((xmlChar *)XPATH_FUZZ, xpathctx);

        conf->num_fuzz = xpathObj->nodesetval->nodeNr;
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] %i fuzz element loaded", MOD_PARAMETER_FUZZER, conf->num_fuzz);

	conf->list = apr_pcalloc(stressy_ctx->pool, conf->num_fuzz * sizeof(fuzz_elem_t *));

	for (i = 0; i < conf->num_fuzz; i++) {
		fuzz_elem_t *elem = NULL;

		xmlChar *value = NULL;
		xmlChar *encoding = NULL;
		xmlChar *repeat = NULL;

		node = xpathObj->nodesetval->nodeTab[i];
	

		value = xmlGetProp(node, BAD_CAST"value");
		encoding = xmlGetProp(node, BAD_CAST"encoding");
		repeat = xmlGetProp(node, BAD_CAST"repeat_value");	

		if (value == NULL) continue;
		init_fuzz_elem(stressy_ctx->pool, &elem);
		
		elem->value = apr_pstrdup(stressy_ctx->pool, (char *)value);
	
		if (repeat != NULL) elem->repeat = atoi((char *)repeat);
		else elem->repeat = 0;		

		if (encoding != NULL) elem->encoding = apr_pstrdup(stressy_ctx->pool, (char *)encoding);
		else elem->encoding = "None";

		LOG_ERR(DEBUG, stressy_ctx->logs, "[elem %i] Value: %s encoding: %s repeat: %i", i, elem->value, elem->encoding, elem->repeat);
		conf->list[i] = elem;

		elem->hash = conf->history;
		elem->pos = i;
	
		pfm_set_new_value(stressy_ctx, elem);
	}


	hook_add(stressy_ctx->worker->request_processed, "parameter fuzzer exec", pfm_exec);
	hook_add(stressy_ctx->worker->after_receive, "parameter fuzzer insert", pfm_insert);

	return 0;
}

extern int pfm_enable_get(void *ctx, void *arg, int type)
{

	return 0;
}

extern int pfm_enable_post(void *ctx, void *arg, int type)
{

	return 0;
}

extern int pfm_enable_cookies(void *ctx, void *arg, int type)
{

	return 0;
}

extern int pfm_enable_headers(void *ctx, void *arg, int type)
{

	return 0;
}

extern int pfm_enable_xml(void *ctx, void *arg, int type)
{

	return 0;
}

extern int pfm_filename(void *ctx, void *arg, int type)
{
        pfm_t *conf = NULL;
        stressy_ctx_t *stressy_ctx = NULL;

        stressy_ctx = (stressy_ctx_t *)ctx;
        if (!stressy_ctx) return -1;

        conf = (pfm_t *)module_retrieve_setup(stressy_ctx->pool, MOD_PARAMETER_FUZZER);
	if (!conf) return -1;

        if (type == SETUP_CLI && arg) {
                conf->filename = arg;
        }
        else if (type == SETUP_XML) {
                conf->filename = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)arg, "value");
        }

	if (conf->filename) {
		hook_add(stressy_ctx->post_setup, "Parameter fuzzer module post setup", pfm_post_setup);
		LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] use param fuzzer file %s", MOD_PARAMETER_FUZZER, conf->filename);
	}

        return 0;
}

static int pfm_setup(void *ctx, void *data)
{
	pfm_t *conf = NULL;
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	conf = apr_pcalloc(stressy_ctx->pool, sizeof(pfm_t));
	if (conf == NULL) return -1;
        if (module_set_setup(stressy_ctx->pool, MOD_PARAMETER_FUZZER, conf) < 0) return -1;

	conf->filename = NULL;
	conf->compare_body = 0;
	conf->history = apr_hash_make(stressy_ctx->pool);

	setup_add_directive(stressy_ctx->prog_setup, "fuzzer_setup", SETUP_CLI_NEED_1, pfm_filename, "=Parameter fuzzer config");
	setup_add_directive(stressy_ctx->prog_setup, "fuzzer_get", SETUP_CLI_NEED_0, pfm_enable_get, "Enable fuzzer on query string");
	setup_add_directive(stressy_ctx->prog_setup, "fuzzer_post", SETUP_CLI_NEED_0, pfm_enable_post, "Enable fuzzer on POST data");
	setup_add_directive(stressy_ctx->prog_setup, "fuzzer_cookies", SETUP_CLI_NEED_0, pfm_enable_cookies, "Enable fuzzer on cookies");
	setup_add_directive(stressy_ctx->prog_setup, "fuzzer_headers", SETUP_CLI_NEED_0, pfm_enable_headers, "Enable fuzzer on headers");
	setup_add_directive(stressy_ctx->prog_setup, "fuzzer_xml", SETUP_CLI_NEED_0, pfm_enable_xml, "Enable fuzzer on xml data");

	return 0;
}

int parameter_fuzzer_init(void *ctx)
{
        stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

        if (!stressy_ctx) return -1;

        LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", MOD_PARAMETER_FUZZER);

	hook_add(stressy_ctx->setup, "Parameter Fuzzer module", pfm_setup);

        return 0;
}

