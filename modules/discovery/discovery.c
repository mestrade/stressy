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

#include "discovery.h"
#include "setup.h"
#include "module_tools.h"
#include "stressy_ctx.h"
#include "config.h"

#define MOD_DISCOVERY 	"mod_discovery"
#define DISCOVERY_XPATH	"//item"


static int insert_request_from_table(void *rec, const char *key, const char *value)
{
	level_ctx_t *ctx = (level_ctx_t *)rec;
	request_t *r = (request_t *)ctx->request;
	level_item_t *level = (level_item_t *)ctx->level;
	request_t *new = NULL;
	stressy_ctx_t *stressy_ctx = NULL;

	if (!key || !value || !level || !level->full_path) return 0;
	//stressy_ctx = (stressy_ctx_t *)r->stressy_ctx;

	LOG_ERR(DEBUG, r->logs, "Adding new dir(%s): %s on level full path: %s", key, value, level->full_path);
	
	request_init(&new);
	//request_set_referer(new, r);
	request_copy_basic(r, new);

	new->resource = apr_psprintf(new->pool, "%s%s", level->full_path, value);
	new->name = apr_psprintf(new->pool, "Directory discovery: %s", new->resource);

	LOG_ERR(DEBUG, r->logs, "New request created - need add to the store");
	request_set_module(new, MOD_DISCOVERY);
	if (request_list_add(stressy_ctx->request_list, new) < 0) return -1;
	LOG_ERR(DEBUG, r->logs, "Dir: %s inserted", new->resource);
	
	return 1;
}

extern int directory_discovery_insert(void *ctx, void *data)
{
	request_t * r = (request_t *)ctx;
	level_item_t *new_level = (level_item_t *)data;
	level_ctx_t *level_ctx;
	directory_discovery_t conf;
	stressy_ctx_t *stressy_ctx = NULL;
	void *tmp_conf = NULL;
	void *tmp_module_key = NULL;
	
	if (r == NULL) return -1;
	
	//stressy_ctx = (stressy_ctx_t *)r->stressy_ctx;
	//if (!r->stressy_ctx) return -1;

	if (module_get_setup(stressy_ctx->pool, MOD_DISCOVERY, (void **)&tmp_conf) < 0) {
		LOG_ERR(CRIT, r->logs, "Unable to find module (%s) setup to insert new request", MOD_DISCOVERY);
		return -1;
	}
	conf = (directory_discovery_t)tmp_conf;
	
	if (new_level->type == R_FILE) {
		/*
		 * request_t * new = NULL;
		
		LOG_ERR(DEBUG, r->logs, "This level is not a directory - look if it can be one");	
		init_request(&new);
		request_set_referer(new, r);
		request_copy_basic(r, new);

		new->resource = apr_psprintf(new->pool, "%s%s", r->resource, "/");
		new->name = apr_psprintf(new->pool, "Directory discovery: %s", new->resource);

		LOG_ERR(DEBUG, r->logs, "New request created - need add to the store");
		store_add_request(r->store, new);
		*/	
		return 0;
		
	}
	
	LOG_ERR(WARN, r->logs, "Found new level %s (full path: %s) - bruteforcing directory", new_level->value, new_level->full_path);
        level_ctx = apr_pcalloc(r->pool, sizeof(level_ctx_t));
	level_ctx->request = r;
	level_ctx->level = new_level;

	apr_pool_userdata_get((void **)&tmp_module_key, MOD_DISCOVERY, new_level->pool);
	if (tmp_module_key) {
		LOG_ERR(DEBUG, r->logs, "Directory %s already bruteforced", new_level->full_path);
		return 0;
	}

	apr_table_do(insert_request_from_table, level_ctx, conf->directory_list, NULL);
	apr_pool_userdata_set((const void *)1, MOD_DISCOVERY, NULL, new_level->pool);

	return 0;
}

extern int directory_discovery_detect(void *ctx, void *data)
{
	request_t * r = (request_t *)ctx;

	if (!r->name) return -1;	
	if (!strstr(r->name, "Directory discovery")) return -1;

	LOG_ERR(DEBUG, r->logs, "Request inserted by directory bf: return = %s", r->answer_code);	

	/* search answer 20x or 30x */
	if (strncasecmp(r->answer_code, "20", 2) == 0) {
		LOG_INFO(MEDIUM, r->logs, "------------> Found interesting directory: %s", r->resource);	       	
	}
	
	if( strncasecmp(r->answer_code, "30", 2) == 0) {
		const char *location;
			if (!(location = apr_table_get(r->headers_out, "Location")))
			LOG_INFO(MEDIUM, r->logs, "------------> Found possible interesting"
				       		"directory: %s pointing on %s", r->resource, location);
		else
			LOG_INFO(MEDIUM, r->logs, "------------> Found possible interesting" 
						"directory: %s", r->resource);
		
		return 0;
	}

	return 0;
}

extern int setup_directory_discovery(void *ctx, void *data, int type)
{
	directory_discovery_t conf = NULL;
	void *tmp_conf = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (!stressy_ctx) return -1;

	if (module_get_setup(stressy_ctx->pool, MOD_DISCOVERY, (void **)&tmp_conf) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get module conf for %s", MOD_DISCOVERY);
		return -1;
	}
	conf = (directory_discovery_t)tmp_conf;

	if (!conf) return -1;
	
	if (type == SETUP_CLI) {
		conf->filename = data;
	}
	else if (type == SETUP_XML) {
		conf->filename = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)data, "value");
	}
	
	if (conf->filename == NULL) return -1;
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] directory guess file: %s", MOD_DISCOVERY, conf->filename);
	
	return 0;
}
	
static int directory_discovery_post_setup(void *ctx, void *data)
{
	stressy_ctx_t *stressy_ctx = NULL;
	directory_discovery_t conf = NULL;
	int dir_num = 0;
	void *tmp_conf = NULL;
	int index_dir = 0;
	
	xmlDocPtr setup_xml = NULL;
	xmlXPathContext *xpathctx;
        xmlXPathObject *xpathObj;
        xmlNode *node;
					
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (module_get_setup(stressy_ctx->pool, MOD_DISCOVERY, (void **)&tmp_conf) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get module conf for %s", MOD_DISCOVERY);
		return -1;
	}
	conf = (directory_discovery_t)tmp_conf;
	if (!conf) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get brute directory conf");
		return -1;
	}
	
	/* if no directory list file - disable */
	if (!conf->filename) {
		LOG_ERR(DEBUG, stressy_ctx->logs, "Directory discovery disabled: no list file");
		return -1;
	}

	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Directory guessing  file: %s", MOD_DISCOVERY, conf->filename);

	conf->directory_list = apr_table_make(stressy_ctx->pool, MAX_DIR);	
	
	
	setup_xml = xmlParseFile(conf->filename);
	if (setup_xml == NULL) return -1;

	xpathctx = xmlXPathNewContext((xmlDocPtr)setup_xml);
        xpathObj = xmlXPathEvalExpression((xmlChar *)DISCOVERY_XPATH, xpathctx);
	
	dir_num = xpathObj->nodesetval->nodeNr;
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Found %i directory(ies) to guess", MOD_DISCOVERY, dir_num);
	
	for (index_dir = 0; index_dir < dir_num; index_dir++) {
		xmlChar *dir = NULL;
		xmlChar *dir_name = NULL;
	
		node = xpathObj->nodesetval->nodeTab[index_dir];	
		dir = xmlNodeGetContent(node);
		dir_name = xmlGetProp(node, BAD_CAST"name");
		
		if (dir_name == NULL) continue;
		
		apr_table_set(conf->directory_list, (char *)dir_name, (char *)dir);
		LOG_ERR(DEBUG, stressy_ctx->logs, "[%s] Insert dir: %s", MOD_DISCOVERY, dir);
	}
	
	hook_add(stressy_ctx->worker->request_processed, "Directory discovery detect", directory_discovery_detect);
        hook_add(stressy_ctx->level_inserted, "Directory discovery Probe", directory_discovery_insert);
	return 0;
}

extern int directory_discovery_setup(void *ctx, void *data)
{
	stressy_ctx_t *stressy_ctx;
	directory_discovery_t conf;
	
	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;

	/*
	 * Create module context
	 *
	 */
	conf = (directory_discovery_t) apr_pcalloc(stressy_ctx->pool, sizeof(struct directory_discovery));
	if (!conf) return -1;
	conf->filename = NULL;
	
	setup_add_directive(stressy_ctx->prog_setup, "brute_dir", SETUP_CLI_NEED_1, setup_directory_discovery, 
			"=directory_list.cfg to bruteforce directory");
	
	/* XXX: try to find directory list from xml */

	if (module_set_setup(stressy_ctx->pool, MOD_DISCOVERY, (void *)conf) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to set module setup for %s", MOD_DISCOVERY);
		return -1;
	}
        
	return 0;
}

#ifdef HAVE_DISCOVERY_SHARED
extern int module_init(void *ctx)
{
#else 
extern int discovery_module_init(void *ctx)
{
#endif
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!stressy_ctx) return -1;

	LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", MOD_DISCOVERY);
	
	hook_add(stressy_ctx->setup, "Discovery var module", directory_discovery_setup);
	hook_add(stressy_ctx->post_setup, "Discovery var module", directory_discovery_post_setup);

	return 0;
}


