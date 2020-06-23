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

#include "crawler.h"
#include "request.h"
#include "parsing_tools.h"
#include "module_tools.h"
#include "site_map.h"
#include "stressy_ctx.h"

#include "libxml/tree.h"
#include "libxml/HTMLtree.h"
#include <libxml/xpath.h>
#include "pcre.h"

#include "apr_base64.h"

#define CRAWLER2_MODULE	"mod_crawler2"

#define XPATH_LINK	"//a | //iframe | //frame | //area | //link | //base"  
#define XPATH_IMG	"//img"
#define XPATH_FORM	"//form"

#define XPATH_JS_ONCLICK	"//@onclick"
#define XPATH_META_REFRESH	"//meta[@content]"

#define ENABLED		1	
#define DISABLED 	0

#define OUTPUT_VECTOR_SIZE	30

typedef struct crawler2_ctx_t {

	/* crawker2 state */
	int status;

	/* do we inject a first request */
	int start_first;

	/* regexp to include/exclude */	
	const char *exclude;	
	const char *include;
	pcre *include_regexp;
	pcre *exclude_regexp;

	const char *authorization;
	const char *hdr_auth_basic;

	stressy_ctx_t *stressy_ctx;
	
} crawler2_ctx_t;

static int crawler2_exclude(crawler2_ctx_t *ctx, char *link)
{
        int res = 0;
        int out_vec[OUTPUT_VECTOR_SIZE];

	if (ctx == NULL || link == NULL) {
		return -1;
	}

	res = pcre_exec(ctx->exclude_regexp, NULL, link, strlen(link), 0, 0, out_vec, OUTPUT_VECTOR_SIZE);
        if (res < 0) return -1; 

	return 0;
}

static int crawler2_process_link(request_t * r, stressy_ctx_t *stressy_ctx, char *link)
{
	request_t * new_request = NULL;
	char *new_link = NULL;	
	crawler2_ctx_t *cfg = NULL;
	void *tmp_cfg = NULL;	

	if (r == NULL || stressy_ctx == NULL) return -1;

	if (module_get_setup(stressy_ctx->pool, CRAWLER2_MODULE, (void **)&tmp_cfg) < 0) return -1;
	cfg = (crawler2_ctx_t *)tmp_cfg;


	if (request_init(&new_request) < 0) return -1;
	request_copy_basic(r, new_request);
	
	if (parse_resource_from_string(new_request->pool, (char *)link, &new_link) < 0) {
		LOG_ERR(DEBUG, r->logs, "Can't parse resource from string: %s", link);
		request_destroy(new_request);
		return -1;
	}

	if (new_link == NULL) {
		LOG_ERR(DEBUG, r->logs, "No new link found in string: %s", link);
		request_destroy(new_request);
		return -1;
	}	
	
	if (*new_link != '/') {
	        LOG_ERR(DEBUG, r->logs, "We are not on an absolute link (%s) - add path %s to uri", new_link, r->path);
	        if (r->html_base_href != NULL) new_link = apr_pstrcat(new_request->pool, r->html_base_href, new_link, NULL);
		else new_link = apr_pstrcat(new_request->pool, r->path, new_link, NULL);
	}

	if (request_set_resource_from_uri(new_request, new_link) < 0) {
		LOG_ERR(DEBUG, r->logs, "Unable to get resource from: %s", link);
		request_destroy(new_request);
		return -1;
	}

	if (request_set_query_from_uri(new_request, new_link) < 0) {
		LOG_ERR(DEBUG, r->logs, "Unable to get query in string: %s", link);
		request_destroy(new_request);
		return -1;
	}


	request_clean_request(new_request);

	if (crawler2_exclude(cfg, new_request->request) == 0) {
		LOG_ERR(DEBUG, r->logs, "Link excluded by setup: %s", link);
		request_destroy(new_request);
		return -1;	
	}

	if (is_request_in_map(stressy_ctx->map, new_request->method, 
			new_request->request, new_request->post_body) < 0) {
		LOG_ERR(DEBUG, r->logs, "Link already in map: %s", link);
		request_destroy(new_request);
		return -1;
	}
			
	
	LOG_ERR(DEBUG, r->logs, "Adding resource: %s in map", new_request->resource);	
	site_map_insert_request(stressy_ctx->map, new_request->resource, new_request->method, 
			new_request->request, new_request->post_body, new_request);	

	request_set_module(new_request, CRAWLER2_MODULE); 
	request_list_add(stressy_ctx->request_list, new_request);	
       	new_request->name = new_request->module;


	return 0;
}

static int crawler2_process_form(request_t * r, stressy_ctx_t *stressy_ctx, request_t * new_request, char *link, char *method)
{
	char *new_link = NULL;	
	crawler2_ctx_t *cfg = NULL;
	void *tmp_cfg = NULL;	

	if (r == NULL || stressy_ctx == NULL) return -1;

	if (module_get_setup(stressy_ctx->pool, CRAWLER2_MODULE, (void **)&tmp_cfg) < 0) return -1;
	cfg = (crawler2_ctx_t *)tmp_cfg;
	
	if (new_request == NULL) return -1;

	request_copy_basic(r, new_request);
	
	if (parse_resource_from_string(new_request->pool, (char *)link, &new_link) < 0) {
		return -1;
	}

	if (new_link == NULL) {
		return -1;
	}	

	if (*new_link != '/') {
	        LOG_ERR(DEBUG, r->logs, "We are not on an absolute link (%s) - add path %s to uri", new_link, r->path);
	       	if (r->html_base_href != NULL) new_link = apr_pstrcat(new_request->pool, r->html_base_href, new_link, NULL);
                else new_link = apr_pstrcat(new_request->pool, r->path, new_link, NULL);
	}
	
	new_request->method = apr_pstrdup(new_request->pool, method);
	
	if (request_set_resource_from_uri(new_request, new_link) < 0) {
		return -1;
	}

	if (request_set_query_from_uri(new_request, new_link) < 0) {
		return -1;
	}

	request_clean_request(new_request);

	if (crawler2_exclude(cfg, new_request->request) == 0) {
		return -1;	
	}

	if (is_request_in_map(stressy_ctx->map, new_request->method, 
			new_request->request, new_request->post_body) < 0) {
		return -1;
	}
			
	LOG_INFO(MEDIUM, r->logs, "Found a new form: %s", r->request);	

	site_map_insert_request(stressy_ctx->map, new_request->resource, new_request->method, 
			new_request->request, new_request->post_body, new_request);	

	request_set_module(new_request, CRAWLER2_MODULE);	
	request_list_add(stressy_ctx->request_list, new_request);	
        new_request->name = new_request->module;

	return 0;
}

static int crawler2_process_set_cookies(void *ctx, const char *key, const char *value)
{
	request_t * r = (request_t *)ctx;
	var_item_t * new_cookie = NULL;

	if (strncasecmp(key, "Set-Cookie", strlen(key)) != 0) return 1;

	if (var_item_init(r->pool, &new_cookie) < 0) {
		return 0;
	}
	parse_var_name(r->pool, (char *)value, '=', &new_cookie->name);
	parse_var_value(r->pool, (char *)value, '=', &new_cookie->value);
	new_cookie->type = VAR_COOKIE;
        var_list_add(r->var_list, new_cookie);

	return 1;
}

static int crawler2_meta_refresh_get_url(apr_pool_t *pool, char *unclean_link, char **content_url)
{
	char *url = NULL;
	char *end = NULL;	
	char end_sep;

	if (pool == NULL || unclean_link == NULL) return -1;

	url = strstr(unclean_link, "URL");
	if (url == NULL) return -1;
	url += 3;

	if (*url != '=') return -1;
	url++;

	if (*url == '\'') {
		end_sep = '\'';
		url++;
	}
	else if (*url == '\"') {
		end_sep = '\"';
		url++;
	}
	else end_sep = ';';

	end = memchr(url, end_sep, strlen(url));
	if (end == NULL) {
		*content_url = apr_pstrdup(pool, url);
		return 0;
	}

	int url_len = 0;
	url_len = end - url;
	if (url_len <= 0) return -1;		

	*content_url = apr_pstrndup(pool, url, url_len);
	return 0;
}

static int crawler2_process_cookies(request_t * r)
{

	if (r->headers_out) apr_table_do(crawler2_process_set_cookies, r, r->headers_out, NULL);
	request_rebuild_cookie_line(r);

	return 0;
}

extern int crawler2_browse(void *ctx, void *data)
{
        request_t * r = (request_t *)ctx;
        stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)data;
	crawler2_ctx_t *cfg = NULL;
	void *tmp_cfg = NULL;	

	const char *location = NULL;
	
	/* xml and html parsing */
	htmlDocPtr html_doc = NULL;
	xmlXPathContext *xpathctx;
        xmlXPathObject *xpathObj;
        xmlNode *node;

	int i, n;

	if (r == NULL || stressy_ctx == NULL) {
		/* we don't have the request */
		return -1;
	}

	LOG_ERR(DEBUG, r->logs, "Starting crawler2");

	if (module_get_setup(stressy_ctx->pool, CRAWLER2_MODULE, (void **)&tmp_cfg) < 0) return -1;
	cfg = (crawler2_ctx_t *)tmp_cfg;

	if (cfg->status != ENABLED) {
		LOG_ERR(DEBUG, r->logs, "Module crawler2 disabled - skipping");
		return 0;
	}
	crawler2_process_cookies(r);

	location = apr_table_get(r->headers_out, "Location");
	if (location != NULL) {
		crawler2_process_link(r, stressy_ctx, (char *)location);
	}
	
	if (r->body == NULL || r->read_bytes <= 0) {
		LOG_ERR(DEBUG, r->logs, "[%s] No body or body len <= 0 - decline", CRAWLER2_MODULE);
		return -1;
	}

	html_doc = htmlReadMemory(r->body, r->read_bytes, "/", NULL, HTML_PARSE_RECOVER|HTML_PARSE_NOWARNING|HTML_PARSE_NOERROR);
	if (html_doc == NULL) {
		LOG_ERR(INFO, r->logs, "Unable to read html");
		return 0;	
	}

	LOG_ERR(DEBUG, r->logs, "Start HTML parsing: %s", r->body);

	/* create context for href link */
	xpathctx = xmlXPathNewContext((xmlDocPtr)html_doc);
	xpathObj = xmlXPathEvalExpression((xmlChar *)XPATH_LINK, xpathctx);

	n = xpathObj->nodesetval->nodeNr;
        for (i=0; i<n; i++) {
		xmlChar *unclean_link = NULL;                
		
		node = xpathObj->nodesetval->nodeTab[i];
		if ((unclean_link = xmlGetProp(node, (xmlChar *)"href"))) {
			LOG_ERR(DEBUG, r->logs, "[%s][src: %s][href: %s]", CRAWLER2_MODULE, r->request, unclean_link);	
			
			if (strncasecmp((char *)node->name, "base", strlen((char *)node->name)) == 0) {
				parse_resource_from_string(r->pool, (char *)unclean_link, &r->html_base_href);	
			}
			else {
				crawler2_process_link(r, stressy_ctx, (char *)unclean_link);
			}
		}
		if ((unclean_link = xmlGetProp(node, (xmlChar *)"src"))) {
			LOG_ERR(DEBUG, r->logs, "[%s][src: %s][src: %s]", CRAWLER2_MODULE, r->request, unclean_link);	
			crawler2_process_link(r, stressy_ctx, (char *)unclean_link);
		}
		if ((unclean_link = xmlGetProp(node, (xmlChar *)"url"))) {
			LOG_ERR(DEBUG, r->logs, "[%s][src: %s][url: %s]", CRAWLER2_MODULE, r->request, unclean_link);	
			crawler2_process_link(r, stressy_ctx, (char *)unclean_link);
		}
	}

	/* search for onclick JS */
	xpathctx = xmlXPathNewContext((xmlDocPtr)html_doc);
	xpathObj = xmlXPathEvalExpression((xmlChar *)XPATH_JS_ONCLICK, xpathctx);

	n = xpathObj->nodesetval->nodeNr;
	for (i=0; i<n; i++) {
		xmlChar*unclean_link = NULL;                

		node = xpathObj->nodesetval->nodeTab[i];
		if ((unclean_link = xmlNodeGetContent(node))) {
			LOG_ERR(DEBUG, r->logs, "[%s][src: %s][onclick: %s]", CRAWLER2_MODULE, r->request, unclean_link);	
			/*
			 * Replace here with some javascript processing
			 *
			 * 
			 * crawler2_process_link(r, stressy_ctx, (char *)unclean_link);
			 *
			 */
		}
	
        }

	xmlXPathFreeContext(xpathctx);
	xmlXPathFreeObject(xpathObj);

	/* create context for meta refresh */
	xpathctx = xmlXPathNewContext((xmlDocPtr)html_doc);
	xpathObj = xmlXPathEvalExpression((xmlChar *)XPATH_META_REFRESH, xpathctx);

	n = xpathObj->nodesetval->nodeNr;
        for (i=0; i<n; i++) {
		xmlChar*unclean_link = NULL;                

		node = xpathObj->nodesetval->nodeTab[i];
		if ((unclean_link = xmlGetProp(node, BAD_CAST"content"))) {
			char *content_url = NULL;			

			LOG_ERR(DEBUG, r->logs, "[%s][src: %s][meta refresh content: %s]", 
				CRAWLER2_MODULE, r->request, unclean_link);	
			
			
			if (crawler2_meta_refresh_get_url(r->pool, (char *)unclean_link, &content_url) < 0) continue;
			crawler2_process_link(r, stressy_ctx, (char *)content_url);
		}
	
        }

	xmlXPathFreeContext(xpathctx);
	xmlXPathFreeObject(xpathObj);


	/* create context for img link */
	xpathctx = xmlXPathNewContext((xmlDocPtr)html_doc);
	xpathObj = xmlXPathEvalExpression((xmlChar *)XPATH_IMG, xpathctx);

	n = xpathObj->nodesetval->nodeNr;
        for (i=0; i<n; i++) {
		xmlChar*unclean_link = NULL;                

		node = xpathObj->nodesetval->nodeTab[i];
		if ((unclean_link = xmlGetProp(node, (xmlChar *)"src"))) {
			LOG_ERR(WARN, r->logs, "[%s][src: %s][img: %s]", CRAWLER2_MODULE, r->request, unclean_link);	
			crawler2_process_link(r, stressy_ctx, (char *)unclean_link);
		}
	
        }

	xmlXPathFreeContext(xpathctx);
	xmlXPathFreeObject(xpathObj);

	/* create context for form link */
	xpathctx = xmlXPathNewContext((xmlDocPtr)html_doc);
	xpathObj = xmlXPathEvalExpression((xmlChar *)XPATH_FORM, xpathctx);

	n = xpathObj->nodesetval->nodeNr;
        for (i=0; i<n; i++) {
		xmlChar *form = NULL;                
		char *input_xpath = NULL;
		xmlXPathObject *input_xpathObj;
		int num_input = 0;
		int index_input = 0;
		request_t * new_request = NULL;
		xmlChar *form_action = NULL;
		xmlChar *form_method = NULL;
		
		node = xpathObj->nodesetval->nodeTab[i];
		form = xmlGetProp(node, (xmlChar *)"action");
		if (form == NULL) form = (xmlChar *)apr_pstrdup(r->pool, r->request);
		LOG_ERR(WARN, r->logs, "[%s][src: %s][form: %s]", CRAWLER2_MODULE, r->request, form);	

		xml_node_get_path(r->pool, node, &input_xpath);
		if (input_xpath == NULL) {
			continue;
		}
	
		if (request_init(&new_request) < 0) {
			continue;
		}

		form_action = xmlGetProp(node, BAD_CAST"action");
/*		if (form_action == NULL) {
			form_action = xmlGetProp(node, BAD_CAST"onSubmit");
		}
		if (form_action == NULL) {
			form_action = xmlGetProp(node, BAD_CAST"onsubmit");
		}
*/		if (form_action == NULL) {
			form_action = (xmlChar *)apr_pstrdup(r->pool, r->request); 
		}


		form_method = xmlGetProp(node, BAD_CAST"method");
		if (form_method == NULL) form_method = (xmlChar *)"GET";
		else form_method = (xmlChar *)"POST";
		
		input_xpath = apr_pstrcat(r->pool, input_xpath, "//input", NULL);
		input_xpathObj = xmlXPathEvalExpression((xmlChar *)input_xpath, xpathctx);
		num_input = input_xpathObj->nodesetval->nodeNr;
		
		LOG_ERR(DEBUG, r->logs, "Found %i input inside form: %s", num_input, form_action);
	
		for (index_input = 0; index_input < num_input; index_input++) {
			var_item_t * new_var = NULL;
			xmlNode *input_node = NULL;		
			xmlChar *input_name = NULL;
			xmlChar *input_value = NULL;
			xmlChar *input_type = NULL;
			
			input_node = input_xpathObj->nodesetval->nodeTab[index_input];	
			input_name = xmlGetProp(input_node, BAD_CAST"name");
			input_value = xmlGetProp(input_node, BAD_CAST"value");
			input_type = xmlGetProp(input_node, BAD_CAST"type");
	
			if (input_name) {
				if (var_item_init(new_request->pool, &new_var) < 0) {
					request_destroy(new_request);
					continue;
				}
				new_var->name = apr_pstrdup(new_request->pool, (char *)input_name);
				if (input_value) new_var->value = apr_pstrdup(new_request->pool, (char *)input_value);
				if (strncasecmp((char *)form_method, "GET", strlen((char *)form_method)) == 0) {
					 new_var->type = VAR_GET;
				}
				else {
					new_var->type = VAR_POST;
					/* fix to handle multipart form data */
					apr_table_set(new_request->headers_in, "Content-Type", "application/x-www-form-urlencoded");
				}
				
				if (input_type) new_var->input_type = apr_pstrdup(new_request->pool, (char *)input_type);
		
				var_list_add(new_request->var_list, new_var);
			}

		}
        	if (crawler2_process_form(r, stressy_ctx, new_request, (char *)form_action, (char *)form_method) < 0) {
			request_destroy(new_request);
			continue;
		}

		
		request_rebuild_post_line(new_request);
	}

	xmlXPathFreeContext(xpathctx);
	xmlXPathFreeObject(xpathObj);

	xmlFreeDoc((xmlDocPtr)html_doc);

	LOG_ERR(DEBUG, r->logs, "End HTML Parsing");

	return 0;
}

static int crawler2_basic_auth(void *ctx, void *arg, int type)
{
	crawler2_ctx_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	if (stressy_ctx == NULL) return -1;

	cfg = (crawler2_ctx_t *)module_retrieve_setup(stressy_ctx->pool, CRAWLER2_MODULE);	
	if (cfg == NULL) return -1;

	if (type == SETUP_CLI) {
		cfg->authorization = apr_pstrdup(stressy_ctx->pool, arg);
	}
	else if (type == SETUP_XML) {
		cfg->authorization = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)arg, "value");
	}

	if (cfg->authorization == NULL) return -1;
	
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] use basic auth: %s", CRAWLER2_MODULE, cfg->authorization); 

	cfg->hdr_auth_basic = (char *) apr_pcalloc(stressy_ctx->pool, apr_base64_encode_len(strlen(cfg->authorization)));
	apr_base64_encode((char *)cfg->hdr_auth_basic, cfg->authorization, strlen(cfg->authorization));	

	if (cfg->hdr_auth_basic == NULL) return -1;

	cfg->hdr_auth_basic = apr_pstrcat(stressy_ctx->pool, "Basic ", cfg->hdr_auth_basic, NULL);
	
	return 0;
}

static int crawler2_exclude_setup(void *ctx, void *arg, int type)
{
	crawler2_ctx_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	void *tmp_cfg = NULL;
       	int err_offset;
        const char *err_str = NULL;

	
	if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;

	/* both xml and cli , if this directive is used, set crawler2 to on */
	if (module_get_setup(stressy_ctx->pool, CRAWLER2_MODULE, (void **)&tmp_cfg) < 0) return -1;
	cfg = (crawler2_ctx_t *)tmp_cfg;
	
	if (type == SETUP_CLI) {
		cfg->exclude = arg;
	}
	else if (type == SETUP_XML) {
		cfg->exclude = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)arg, "value");
	}

	if (cfg->exclude == NULL) return 0;
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Use exclude regexp: %s", CRAWLER2_MODULE, cfg->exclude);

	cfg->exclude_regexp = pcre_compile(cfg->exclude, PCRE_EXTENDED | PCRE_EXTRA, &err_str, &err_offset, NULL);
	if (cfg->exclude_regexp == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "[%s] Unable to compile regexp: %s", CRAWLER2_MODULE, cfg->exclude);
		return -1;
	}

	return 0;
}

static int crawler2_status_setup(void *ctx, void *arg, int type)
{
	crawler2_ctx_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	void *tmp_cfg = NULL;
	
	if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;

	/* both xml and cli , if this directive is used, set crawler2 to on */
	if (module_get_setup(stressy_ctx->pool, CRAWLER2_MODULE, (void **)&tmp_cfg) < 0) return -1;
	cfg = (crawler2_ctx_t *)tmp_cfg;
	
	cfg->status = ENABLED;

	return 0;
}

static int crawler2_start_first_setup(void *ctx, void *arg, int type)
{
	crawler2_ctx_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	void *tmp_cfg = NULL;
	
	if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;

	/* both xml and cli , if this directive is used, set crawler2 to on */
	if (module_get_setup(stressy_ctx->pool, CRAWLER2_MODULE, (void **)&tmp_cfg) < 0) return -1;
	cfg = (crawler2_ctx_t *)tmp_cfg;
	
	cfg->start_first = ENABLED;

	return 0;
}

extern int crawler2_post_setup(void *ctx, void *data)
{
	crawler2_ctx_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	void *tmp_cfg = NULL;
	
	if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;

	/* both xml and cli , if this directive is used, set crawler2 to on */
	if (module_get_setup(stressy_ctx->pool, CRAWLER2_MODULE, (void **)&tmp_cfg) < 0) return -1;
	cfg = (crawler2_ctx_t *)tmp_cfg;
	cfg->stressy_ctx = stressy_ctx;	

	if (cfg->status != ENABLED) {
		LOG_ERR(DEBUG, stressy_ctx->logs, "module: %s disabled", CRAWLER2_MODULE);
		return 0;
	}

	if (cfg->start_first == ENABLED) {
		request_t *r = NULL;
		
		request_init(&r);
		r->name = apr_pstrdup(r->pool, "Crawler2 first request");
	        r->hostname = apr_pstrdup(r->pool, stressy_ctx->hostname);
	        r->port = apr_pstrdup(r->pool, stressy_ctx->port);
	        r->logs = stressy_ctx->logs;
		r->step = 0;
		r->method = "GET";
		r->protocol = "HTTP/1.1";
		r->ctx = (void *)stressy_ctx;
		r->is_proxy = stressy_ctx->use_proxy;

		LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] (0x%x)", CRAWLER2_MODULE, r->logs);
	
		if (!stressy_ctx->start_uri) request_set_resource_from_uri(r, "/");
	        else request_set_resource_from_uri(r, stressy_ctx->start_uri);

		apr_table_set(r->headers_in, "Host", stressy_ctx->hostname);
	        apr_table_set(r->headers_in, "User-Agent", "Mozilla-5.0");
	        apr_table_set(r->headers_in, "Connection", "Keep-Alive");
	        apr_table_set(r->notes, "crawler2", "yes");
	     
		if (cfg->hdr_auth_basic != NULL) {
			apr_table_set(r->headers_in, "Authorization", cfg->hdr_auth_basic);
		}
		
		request_clean_request(r);

		if (site_map_insert_request(stressy_ctx->map, r->resource, r->method, r->request, NULL, r) < 0) {
			LOG_ERR(CRIT, r->logs, "[%s] Unable to insert first request", CRAWLER2_MODULE);
			return -1;
		}
		LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Added first request (0x%x)", CRAWLER2_MODULE, r->logs);

		request_set_module(r, CRAWLER2_MODULE);
		request_list_add(stressy_ctx->request_list, r);
	}

	hook_add(stressy_ctx->worker->after_receive, "Crawler2 browse", crawler2_browse);


	return 0;
}

extern int crawler2_setup(void *ctx, void *data)
{
	crawler2_ctx_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;
	
	if (!ctx) return -1;
        stressy_ctx = (stressy_ctx_t *)ctx;
		
	cfg = apr_pcalloc(stressy_ctx->pool, sizeof(crawler2_ctx_t));
	if (cfg == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to alloc memory for crawler2 module");
		return -1;
	}	

	cfg->status = DISABLED;
	cfg->start_first = DISABLED;	

	if (module_set_setup(stressy_ctx->pool, CRAWLER2_MODULE, (void *)cfg) < 0) return -1;

        setup_add_directive(stressy_ctx->prog_setup, "crawler2", SETUP_CLI_NEED_0,
		 crawler2_status_setup, "enable crawler2");
        
	setup_add_directive(stressy_ctx->prog_setup, "crawler2_first_req", SETUP_CLI_NEED_0,
		 crawler2_start_first_setup, "make crawler2 add first request");
       
	setup_add_directive(stressy_ctx->prog_setup, "crawler2_basic_auth", SETUP_CLI_NEED_1,
		 crawler2_basic_auth, "=login:password for a basic authentication");
 
        setup_add_directive(stressy_ctx->prog_setup, "crawler2_exclude", SETUP_CLI_NEED_1, crawler2_exclude_setup,
                        "=exclude_regexp");

	hook_add(stressy_ctx->post_setup, "Crawler2 post setup", crawler2_post_setup);

	return 0;
}	

#ifdef HAVE_CRAWLER2_SHARED
extern int module_init(void *ctx)
{
#else 
extern int crawler2_module_init(void *ctx)
{
#endif
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (!stressy_ctx) return -1;

	LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", CRAWLER2_MODULE);

	hook_add(stressy_ctx->setup, "Crawler2 setup", crawler2_setup);	


        return 0;
}
