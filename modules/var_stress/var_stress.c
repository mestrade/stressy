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

#include "var_stress.h"
#include "module_tools.h"
#include "stressy_ctx.h"
#include "variables.h"

#define MOD_VAR_STRESS	"mod_var_stress"
#define ESCAPE_XPATH 	"//item"

typedef struct var_stress_conf_t var_stress_conf_t;
typedef struct var_stress_item_t var_stress_item_t;

struct var_stress_conf_t {

	char *escape_filename;
	int num_escape;
	var_stress_item_t **escape_list;	
	apr_hash_t *escaped_var;

	char *insert_filename;	
	int num_insert;
	var_stress_item_t **insert_list;	
	apr_hash_t *inserted_var;

	int enable_cookie;
	int enable_param;
	int enable_urlencoded;
	
};

struct var_stress_item_t {

	char *name;
	char *value;

};

static int init_escape_conf(apr_pool_t *pool, var_stress_conf_t **conf)
{
	var_stress_conf_t *new = NULL;
	
	if (!pool) return -1;

	new = (var_stress_conf_t *)apr_pcalloc(pool, sizeof(var_stress_conf_t));
	if (!new) return -2;

	*conf = new;
	new->escape_filename = NULL;
	new->escaped_var = apr_hash_make(pool);

	new->insert_filename = NULL;
	new->inserted_var = apr_hash_make(pool);

	return 0;
}

static int var_stress_insert_after(request_t *r, stressy_ctx_t *stressy_ctx, var_stress_item_t *item)
{
	var_stress_conf_t *conf = NULL;
	void *tmp_conf = NULL;
	
	var_item_t *var_ptr;
	var_item_t *var_cpy;
	int pos_src = 0;
	int pos_dst = 0;
	char *hash_key = NULL;

	if (item == NULL) {
		return -1;
	}

	if (!r) return -1;
	module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
	conf = (var_stress_conf_t *)tmp_conf;
	if (!conf) {
		return -1;
	}
	if (!r->resource) {
		LOG_ERR(CRIT, r->logs, "Unable to find uri during escape");
		return -1;
	}

	if (r->var_list == NULL || r->var_list->num_var <= 0) {
		return -1;
	}

	LOG_ERR(DEBUG, r->logs, "Escape var Work on request %s", r->request);

	if (!conf->inserted_var) {
		LOG_ERR(CRIT, r->logs, "No hash table ready to do insert var");
		return -1;	
	}

	for (var_ptr = r->var_list->first_var, pos_src = 0; var_ptr; pos_src++, var_ptr = var_ptr->next) {
		char *new_value = NULL;
		char *url_var;
		request_t *new_request = NULL;
		//char *arg_line;
		int type_check = 0;

		if (pos_src >= r->var_list->num_var) {
			LOG_ERR(CRIT, r->logs, "We go too far in the var list");
			break;
		}

		type_check = var_check_type(var_ptr, VAR_COOKIE);
                if (type_check == 0 && conf->enable_cookie != 1) continue;

		url_var = apr_psprintf(r->pool, "insert_after-%s-%s-%s-%s", r->resource, var_ptr->type, var_ptr->name, item->name);
		if (apr_hash_get(conf->escaped_var, url_var, strlen(url_var)) != NULL) {
			LOG_ERR(DEBUG, r->logs, "var modification (replace) already done on %s", url_var);
			continue;
		}
		LOG_ERR(DEBUG, r->logs, "var modification (replace) on %s (uri: %s)", url_var, r->resource);

		
		if (request_init(&new_request) < 0) return -1;
		if (request_copy_basic(r, new_request) < 0) {
			request_destroy(new_request);
			return -1;
		}

		new_value = apr_pstrcat(new_request->pool, var_ptr->value, item->value, NULL);
		
		new_request->resource = apr_pstrdup(new_request->pool, r->resource);
	
		//if (strncmp(var_ptr->type, VAR_GET, strlen(var_ptr->type)) == 0) arg_line = r->query;
		//if (strncmp(var_ptr->type, VAR_POST, strlen(var_ptr->type)) == 0) arg_line = r->post_body;

		for (var_cpy = r->var_list->first_var, pos_dst = 0; var_cpy; pos_dst++, var_cpy = var_cpy->next) {	
			var_item_t *new_var;

			if (pos_dst >= r->var_list->num_var) break;
			if (strncmp(var_ptr->type, var_cpy->type, strlen(var_ptr->type)) != 0) continue;			
			var_item_init(new_request->pool, &new_var);
	
			if (pos_src == pos_dst) {
				LOG_ERR(DEBUG, r->logs, "Insert new value pos %i", pos_dst);
				
				new_var->name = apr_pstrdup(new_request->pool, var_cpy->name);
				new_var->value = apr_pstrdup(new_request->pool, new_value);
				new_var->type = apr_pstrdup(new_request->pool, var_ptr->type);
				var_list_add(new_request->var_list, new_var);
				continue;	
			}
			LOG_ERR(DEBUG, r->logs, "Add normal var pos %i", pos_dst);
			
			new_var->name = apr_pstrdup(new_request->pool, var_cpy->name);
			new_var->value = apr_pstrdup(new_request->pool, var_cpy->value);
			new_var->type = apr_pstrdup(new_request->pool, var_ptr->type);
			var_list_add(new_request->var_list, new_var);
		}

		hash_key = apr_pstrdup(stressy_ctx->pool, url_var);
		apr_hash_set(conf->escaped_var, hash_key, strlen(hash_key), hash_key);
		
		LOG_ERR(DEBUG, new_request->logs, "New request with var type: %s", var_ptr->type);
		
		if (strncmp(var_ptr->type, VAR_POST, strlen(var_ptr->type)) == 0) {
			request_set_method(new_request, "POST");
			request_rebuild_post_line(new_request);
			request_set_query_from_uri(new_request, r->request);
			LOG_ERR(DEBUG, new_request->logs, "New POST request with arg: %s and old arg: %s", new_request->query, r->query);
		}
		else {
			request_rebuild_arg_line(new_request);
			LOG_ERR(DEBUG, new_request->logs, "New GET request with arg: %s", new_request->query);
		}
		
		//request_clean_uri(new_request);
		request_clean_request(new_request);
		new_request->name = apr_psprintf(new_request->pool, "(insert before) %s(%s) with value %s -> [%s]", 
				var_ptr->type, var_ptr->name, item->name, new_value); 
		LOG_ERR(DEBUG, r->logs, "Escape request after: %s", new_request->name);
		request_set_module(new_request, MOD_VAR_STRESS);
		request_list_add(stressy_ctx->request_list, new_request);
	}

	return 1;
}

static int var_stress_insert_before(request_t *r, stressy_ctx_t *stressy_ctx, var_stress_item_t *item)
{
	var_stress_conf_t *conf = NULL;
	void *tmp_conf = NULL;
	
	var_item_t *var_ptr;
	var_item_t *var_cpy;
	int pos_src = 0;
	int pos_dst = 0;
	char *hash_key = NULL;

	if (item == NULL) return -1;

	if (!r) return -1;
	module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
	conf = (var_stress_conf_t *)tmp_conf;
	if (!conf) return -1;
	
	if (!r->resource) {
		LOG_ERR(CRIT, r->logs, "Unable to find uri during escape");
		return -1;
	}

	if (r->var_list == NULL || r->var_list->num_var <= 0) {
		return -1;
	}

	if (!conf->inserted_var) {
		LOG_ERR(CRIT, r->logs, "No hash table ready to do insert var");
		return -1;	
	}

	for (var_ptr = r->var_list->first_var, pos_src = 0; var_ptr; pos_src++, var_ptr = var_ptr->next) {
		char *new_value = NULL;
		char *url_var;
		request_t *new_request = NULL;
		//char *arg_line;
		int type_check = 0;

		if (pos_src >= r->var_list->num_var) {
			LOG_ERR(CRIT, r->logs, "We go too far in the var list");
			break;
		}

		type_check = var_check_type(var_ptr, VAR_COOKIE);
                if (type_check == 0 && conf->enable_cookie != 1) continue;

		url_var = apr_psprintf(r->pool, "insert_before-%s-%s-%s-%s", r->resource, var_ptr->type, var_ptr->name, item->name);
		if (apr_hash_get(conf->escaped_var, url_var, strlen(url_var)) != NULL) {
			LOG_ERR(DEBUG, r->logs, "var modification (replace) already done on %s", url_var);
			continue;
		}
		LOG_ERR(DEBUG, r->logs, "var modification (replace) on %s", url_var);

		
		if (request_init(&new_request) < 0) return -1;
		if (request_copy_basic(r, new_request) < 0) {
			request_destroy(new_request);
			return -1;
		}

		new_value = apr_pstrcat(new_request->pool, item->value, var_ptr->value, NULL);
		new_request->resource = apr_pstrdup(new_request->pool, r->resource);
	
		//if (strncmp(var_ptr->type, VAR_GET, strlen(var_ptr->type)) == 0) arg_line = r->query;
		//if (strncmp(var_ptr->type, VAR_POST, strlen(var_ptr->type)) == 0) arg_line = r->post_body;

		for (var_cpy = r->var_list->first_var, pos_dst = 0; var_cpy; pos_dst++, var_cpy = var_cpy->next) {	
			var_item_t *new_var;

			if (pos_dst >= r->var_list->num_var) break;
			if (strncmp(var_ptr->type, var_cpy->type, strlen(var_ptr->type)) != 0) continue;			
			var_item_init(new_request->pool, &new_var);
	
			if (pos_src == pos_dst) {
				LOG_ERR(DEBUG, r->logs, "Insert new value pos %i", pos_dst);
				
				new_var->name = apr_pstrdup(new_request->pool, var_cpy->name);
				new_var->value = apr_pstrdup(new_request->pool, new_value);
				new_var->type = apr_pstrdup(new_request->pool, var_ptr->type);
				var_list_add(new_request->var_list, new_var);
				continue;	
			}
			LOG_ERR(DEBUG, r->logs, "Add normal var pos %i", pos_dst);
			
			new_var->name = apr_pstrdup(new_request->pool, var_cpy->name);
			new_var->value = apr_pstrdup(new_request->pool, var_cpy->value);
			new_var->type = apr_pstrdup(new_request->pool, var_ptr->type);
			var_list_add(new_request->var_list, new_var);
		}

		hash_key = apr_pstrdup(stressy_ctx->pool, url_var);
		apr_hash_set(conf->escaped_var, hash_key, strlen(hash_key), hash_key);
		
		LOG_ERR(DEBUG, new_request->logs, "New request with var type: %s", var_ptr->type);
		
		if (strncmp(var_ptr->type, VAR_POST, strlen(var_ptr->type)) == 0) {
			request_set_method(new_request, "POST");
			request_rebuild_post_line(new_request);
			request_set_query_from_uri(new_request, r->request);
			LOG_ERR(DEBUG, new_request->logs, "New POST request with arg: %s and old arg: %s", new_request->query, r->query);
		}
		else {
			request_rebuild_arg_line(new_request);
			LOG_ERR(DEBUG, new_request->logs, "New GET request with arg: %s", new_request->query);
		}
		
		//request_clean_uri(new_request);
		request_clean_request(new_request);
		new_request->name = apr_psprintf(new_request->pool, "(insert before) %s(%s) with value %s -> [%s]", 
				var_ptr->type, var_ptr->name, item->name, new_value); 
		LOG_ERR(DEBUG, r->logs, "Escape request after: %s", new_request->name);
                request_set_module(new_request, MOD_VAR_STRESS);
		request_list_add(stressy_ctx->request_list, new_request);
	}

	return 1;
}


static int var_stress_replace(request_t *r, stressy_ctx_t *stressy_ctx, var_stress_item_t *item)
{
	var_stress_conf_t *conf = NULL;
	void *tmp_conf = NULL;
	
	var_item_t *var_ptr;
	var_item_t *var_cpy;
	int pos_src = 0;
	int pos_dst = 0;
	char *hash_key = NULL;

	if (item == NULL) return -1;

	if (!r) return -1;
	module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
	conf = (var_stress_conf_t *)tmp_conf;
	if (!conf) return -1;
	
	if (!r->resource) {
		LOG_ERR(CRIT, r->logs, "Unable to find uri during escape");
		return -1;
	}

	LOG_ERR(DEBUG, r->logs, "Replace var Work on request %s", r->request);
	if (r->var_list == NULL || r->var_list->num_var <= 0) {
		return -1;
	}

	if (!conf->inserted_var) {
		LOG_ERR(CRIT, r->logs, "No hash table ready to do insert var");
		return -1;	
	}

	for (var_ptr = r->var_list->first_var, pos_src = 0; var_ptr; pos_src++, var_ptr = var_ptr->next) {
		char *new_value = NULL;
		char *url_var;
		request_t *new_request = NULL;
		/*char *arg_line;*/

		if (pos_src >= r->var_list->num_var) {
			LOG_ERR(CRIT, r->logs, "We go too far in the var list");
			break;
		}

		if (var_check_type(var_ptr, VAR_COOKIE) == 0 && conf->enable_cookie != 1) continue;


		url_var = apr_psprintf(r->pool, "replace-%s-%s-%s-%s", r->resource, var_ptr->type, var_ptr->name, item->name);
		if (apr_hash_get(conf->inserted_var, url_var, strlen(url_var)) != NULL) {
			LOG_ERR(DEBUG, r->logs, "var modification (replace) already done on %s", url_var);
			continue;
		}
		LOG_ERR(DEBUG, r->logs, "var modification (replace) on %s", url_var);

		new_value = item->value;
		
		if (request_init(&new_request) < 0) return -1;
		if (request_copy_basic(r, new_request) < 0) {
			request_destroy(new_request);
			return -1;
		}

		new_request->resource = apr_pstrdup(new_request->pool, r->resource);

		/*	
		if (strncmp(var_ptr->type, VAR_GET, strlen(var_ptr->type)) == 0) arg_line = r->query;
		if (strncmp(var_ptr->type, VAR_POST, strlen(var_ptr->type)) == 0) arg_line = r->post_body;
		*/

		for (var_cpy = r->var_list->first_var, pos_dst = 0; var_cpy; pos_dst++, var_cpy = var_cpy->next) {	
			var_item_t *new_var;

			if (pos_dst >= r->var_list->num_var) break;
			if (strncmp(var_ptr->type, var_cpy->type, strlen(var_ptr->type)) != 0) continue;			
			var_item_init(new_request->pool, &new_var);
	
			if (pos_src == pos_dst) {
				LOG_ERR(DEBUG, r->logs, "Insert new value pos %i", pos_dst);
				
				new_var->name = apr_pstrdup(new_request->pool, var_cpy->name);
				new_var->value = apr_pstrdup(new_request->pool, new_value);
				new_var->type = apr_pstrdup(new_request->pool, var_ptr->type);
				var_list_add(new_request->var_list, new_var);
				continue;	
			}
			LOG_ERR(DEBUG, r->logs, "Add normal var pos %i", pos_dst);
			
			new_var->name = apr_pstrdup(new_request->pool, var_cpy->name);
			new_var->value = apr_pstrdup(new_request->pool, var_cpy->value);
			new_var->type = apr_pstrdup(new_request->pool, var_ptr->type);
			var_list_add(new_request->var_list, new_var);
		}

		hash_key = apr_pstrdup(stressy_ctx->pool, url_var);
		apr_hash_set(conf->inserted_var, hash_key, strlen(hash_key), hash_key);
		
		LOG_ERR(DEBUG, new_request->logs, "New request with var type: %s", var_ptr->type);
		
		if (strncmp(var_ptr->type, VAR_POST, strlen(var_ptr->type)) == 0) {
			request_set_method(new_request, "POST");
			request_rebuild_post_line(new_request);
			request_set_query_from_uri(new_request, r->request);
			LOG_ERR(DEBUG, new_request->logs, "New POST request with arg: %s and old arg: %s", new_request->query, r->query);
		}
		else {
			request_rebuild_arg_line(new_request);
			LOG_ERR(DEBUG, new_request->logs, "New GET request with arg: %s", new_request->query);
		}
		
		//request_clean_uri(new_request);
		request_clean_request(new_request);
		new_request->name = apr_psprintf(new_request->pool, "(replace) %s(%s) with value %s -> [%s]", 
				var_ptr->type, var_ptr->name, item->name, new_value); 
		LOG_ERR(DEBUG, r->logs, "Replace request after: %s", new_request->name);
	        request_set_module(new_request, MOD_VAR_STRESS);
		request_list_add(stressy_ctx->request_list, new_request);
	}

	return 1;
}

extern int var_stress(void *ctx, void *data)
{
	request_t *r = (request_t *)ctx;
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)data;	

	var_stress_conf_t *conf = NULL;
	void *tmp_conf = NULL;

	int index = 0;

	if (!r || !r->var_list) {
		LOG_ERR(NOTICE, r->logs, "No var to stress on this request");
		return -1;
	}

	module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
	conf = (var_stress_conf_t *)tmp_conf;
	if (!conf) return -1;

	for (index = 0; index < conf->num_escape; index++) {
		var_stress_insert_before(r, stressy_ctx, conf->escape_list[index]);
		var_stress_insert_after(r, stressy_ctx, conf->escape_list[index]);
	}	
	for (index = 0; index < conf->num_insert; index++) {
		var_stress_replace(r, stressy_ctx, conf->insert_list[index]);
	}	

	return 0;
}

extern int escape_var_set_filename(void *ctx, void *arg, int type)
{
	var_stress_conf_t *conf = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	void *tmp_conf = NULL;

	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!stressy_ctx) return -1;

	module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
	conf = (var_stress_conf_t *)tmp_conf;
	if (!conf) return -1;
	
	if (type == SETUP_CLI && arg) {
		conf->escape_filename = arg;
	}
	else if (type == SETUP_XML) {
		conf->escape_filename = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)arg, "value");
	}
	
	return 0;
}

extern int insert_var_set_filename(void *ctx, void *arg, int type)
{
	var_stress_conf_t *conf = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	void *tmp_conf = NULL;

	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!stressy_ctx) return -1;

	module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
	conf = (var_stress_conf_t *)tmp_conf;
	if (!conf) return -1;
	
	if (type == SETUP_CLI && arg) {
		conf->insert_filename = arg;
	}
	else if (type == SETUP_XML) {
		conf->insert_filename = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)arg, "value");
	}
	
	return 0;
}

extern int var_stress_post_setup(void *ctx, void *data)
{
	var_stress_conf_t *conf = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	void *tmp_conf = NULL;
	xmlDocPtr xml_doc = NULL;
	
	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
	conf = (var_stress_conf_t *)tmp_conf;
	if (!conf) return -1;

	if (conf->insert_filename) {
		int i = 0;	

		xml_doc = xmlParseFile(conf->insert_filename);
		if (xml_doc == NULL) {
                	LOG_ERR(CRIT, stressy_ctx->logs, "Unable to parse file: %s for var escape", conf->escape_filename);
                	return -1;
        	}

		xmlXPathContext *xpathctx;
	        xmlXPathObject *xpathObj;
	        xmlNode *node;

		xpathctx = xmlXPathNewContext((xmlDocPtr)xml_doc);
        	xpathObj = xmlXPathEvalExpression((xmlChar *)ESCAPE_XPATH, xpathctx);

		conf->num_insert = xpathObj->nodesetval->nodeNr;
		LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Loading %i insert definition(s)", MOD_VAR_STRESS, conf->num_insert);	
		conf->insert_list = apr_pcalloc(stressy_ctx->pool, conf->num_insert * sizeof(var_stress_item_t));
		if (conf->insert_list == NULL) {
			return -1;
		}	
		
		for (i = 0; i < conf->num_insert; i++) {
			var_stress_item_t *item = NULL;
			xmlChar *name = NULL;

			node = xpathObj->nodesetval->nodeTab[i];
	                if (node == NULL) continue;

			name = xmlGetProp(node, BAD_CAST"name");
	                LOG_ERR(DEBUG, stressy_ctx->logs, "Loading error: %s with regexp: %s", name, xmlNodeGetContent(node));

			item = apr_pcalloc(stressy_ctx->pool, sizeof(var_stress_item_t));
	                if (item == NULL) return -1;

        	        item->name = apr_pstrdup(stressy_ctx->pool, (char *)name);
			item->value = apr_pstrdup(stressy_ctx->pool, (char *)xmlNodeGetContent(node));					
		
			conf->insert_list[i] = item;	
		}

	}

	/*
	 * Look if we need to work
	 *
	 */
	if (conf->escape_filename) {
		int i = 0;	

		xml_doc = xmlParseFile(conf->escape_filename);
		if (xml_doc == NULL) {
                	LOG_ERR(CRIT, stressy_ctx->logs, "Unable to parse file: %s for var escape", conf->escape_filename);
                	return -1;
        	}

		xmlXPathContext *xpathctx;
	        xmlXPathObject *xpathObj;
	        xmlNode *node;

		xpathctx = xmlXPathNewContext((xmlDocPtr)xml_doc);
        	xpathObj = xmlXPathEvalExpression((xmlChar *)ESCAPE_XPATH, xpathctx);

		conf->num_escape = xpathObj->nodesetval->nodeNr;
		LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Loading %i escape definition(s)", MOD_VAR_STRESS, conf->num_escape);	
		conf->escape_list = apr_pcalloc(stressy_ctx->pool, conf->num_escape * sizeof(var_stress_item_t));
		if (conf->escape_list == NULL) {
			return -1;
		}	
		
		for (i = 0; i < conf->num_escape; i++) {
			var_stress_item_t *item = NULL;
			xmlChar *name = NULL;

			node = xpathObj->nodesetval->nodeTab[i];
	                if (node == NULL) continue;

			name = xmlGetProp(node, BAD_CAST"name");
	                LOG_ERR(DEBUG, stressy_ctx->logs, "Loading error: %s with regexp: %s", name, xmlNodeGetContent(node));

			item = apr_pcalloc(stressy_ctx->pool, sizeof(var_stress_item_t));
	                if (item == NULL) return -1;

        	        item->name = apr_pstrdup(stressy_ctx->pool, (char *)name);
			item->value = apr_pstrdup(stressy_ctx->pool, (char *)xmlNodeGetContent(node));					
		
			conf->escape_list[i] = item;	
		}

	}

	if (conf->enable_cookie == 1) LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] enabled on cookies", MOD_VAR_STRESS);
	if (conf->enable_param == 1) LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] enabled on GET param", MOD_VAR_STRESS);
	if (conf->enable_urlencoded == 1) LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] enabled on urlencoded POST variables", MOD_VAR_STRESS);

	/*
	 * Setup is ok, i can now register the hook
	 *
	 */
	hook_add(stressy_ctx->worker->request_processed, "Var stress hook", var_stress);
	return 0;
}

/*
 * Init module context
 *
 */

static int var_set_cookie(void *ctx, void *arg, int type)
{
	var_stress_conf_t *conf = NULL;
        stressy_ctx_t *stressy_ctx = NULL;
        void *tmp_conf = NULL;

        if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;

        module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
        conf = (var_stress_conf_t *)tmp_conf;
        if (!conf) return -1;

        conf->enable_cookie = 1;

        return 0;
}

static int var_set_param(void *ctx, void *arg, int type)
{
	var_stress_conf_t *conf = NULL;
        stressy_ctx_t *stressy_ctx = NULL;
        void *tmp_conf = NULL;

        if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;

        module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
        conf = (var_stress_conf_t *)tmp_conf;
        if (!conf) return -1;

        conf->enable_param = 1;

        return 0;
}

static int var_set_urlencoded(void *ctx, void *arg, int type)
{
	var_stress_conf_t *conf = NULL;
        stressy_ctx_t *stressy_ctx = NULL;
        void *tmp_conf = NULL;

        if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;

        module_get_setup(stressy_ctx->pool, MOD_VAR_STRESS, (void **)&tmp_conf);
        conf = (var_stress_conf_t *)tmp_conf;
        if (!conf) return -1;

        conf->enable_urlencoded = 1;

        return 0;
}




extern int var_stress_setup(void *ctx, void *data)
{
	stressy_ctx_t *stressy_ctx = NULL;
	var_stress_conf_t *conf = NULL;	

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *) ctx;

	if (init_escape_conf(stressy_ctx->pool, &conf) < 0) return -1;
	if (module_set_setup(stressy_ctx->pool, MOD_VAR_STRESS, conf) < 0) return -1;

	setup_add_directive(stressy_ctx->prog_setup, "var_stress_escape", SETUP_CLI_NEED_1, escape_var_set_filename, 
			"=var_escape_list.cfg containing char to escape variable content");
	setup_add_directive(stressy_ctx->prog_setup, "var_stress_insert", SETUP_CLI_NEED_1, insert_var_set_filename, 
			"=var_insert_list.cfg containing char to insert variable content");
	setup_add_directive(stressy_ctx->prog_setup, "var_stress_enable_cookie", SETUP_CLI_NEED_0, var_set_cookie, 
			"=var_insert_list.cfg containing char to insert variable content");
	setup_add_directive(stressy_ctx->prog_setup, "var_stress_enable_param", SETUP_CLI_NEED_0, var_set_param, 
			"=var_insert_list.cfg containing char to insert variable content");
	setup_add_directive(stressy_ctx->prog_setup, "var_stress_enable_urlencoded", SETUP_CLI_NEED_0, var_set_urlencoded, 
			"=var_insert_list.cfg containing char to insert variable content");

	return 0;
}

int var_stress_module_init(void *ctx)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!stressy_ctx) return -1;

	LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", MOD_VAR_STRESS);

	/*
	 * Add setup hook for escape module
	 *
	 */
	hook_add(stressy_ctx->setup, "Escape var module", var_stress_setup);
	hook_add(stressy_ctx->post_setup, "Escape var module post setup", var_stress_post_setup);

        return 0;
}
