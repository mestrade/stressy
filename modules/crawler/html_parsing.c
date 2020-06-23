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

#include "html_parsing.h"
#include "stressy_ctx.h"
#include "site_map.h"
#include "module_tools.h"
#include "request_list.h"

#include "pcre.h"


#define MOD_CRAWLER	"mod_crawler"

typedef struct html_parsing_t html_parsing_t;

static int html_parsing_add_new_request(request_t r, char *link);

struct html_parsing_t {

	int active;
	
	char *filename;
	int max_step;

	int display_link;

	char *exclude_regexp_char;
	pcre *exclude_regexp;
};

extern int is_crawler_exclude(request_t r, html_parsing_t *cfg)
{
	int res = 0;
	int out_vec[OUTPUT_VECTOR_SIZE];

	if (r == NULL || cfg == NULL || cfg->exclude_regexp == NULL) return 0;

	res = pcre_exec(cfg->exclude_regexp, NULL, r->uri, strlen(r->uri), 0, 0, out_vec, OUTPUT_VECTOR_SIZE);
	if (res >= 0) return -1;	
	
	return 0;
}

extern int html_parsing_on(request_t r)
{
	if (!r) return -1;
	apr_table_set(r->notes, "html_parsing", (const char *)r);
	return 0;
}

extern int is_html_parsing_on(request_t r)
{
	if (!r) return -1;
	if (apr_table_get(r->notes, "html_parsing") == NULL) return -1;
	return 0;
}

static int init_parsing_ctx(apr_pool_t *pool, parsing_ctx_t *ctx)
{
	parsing_ctx_t new;

	if(!pool) return -1;
	new = apr_pcalloc(pool, sizeof(struct parsing_ctx));
	if (!new) return -1;

	new->in_form = 0;
	new->request = NULL;
	new->action = NULL;
	new->request_post = NULL;

	*ctx = new;
	return 0;
}

static void html_parsing_start_elem(void* ctxt, const xmlChar* name, const xmlChar** attrs)
{
	parsing_ctx_t parsing_ctx = (parsing_ctx_t)ctxt;
	request_t r;
	int i = 0;
	
	if (!parsing_ctx) return;
	r = parsing_ctx->request;

	if (!r) {
		LOG_ERR(CRIT, r->logs, "Unable to find request");
		return;
	}

	if (parsing_ctx->in_form == 1 && parsing_ctx->action) {
		if (strncasecmp((const char *)name, "input", strlen((char *)name)) == 0) {
			var_item_t new_var;
			const char *input_name = NULL;
			const char *input_type = NULL;
			const char *input_value = NULL;

			if (!attrs) return;
			for (i = 0; attrs[i]; i++) {
				
				if (!input_name && strncasecmp((const char *)attrs[i], "name", strlen((char *)attrs[i])) == 0) { 
					input_name = (const char *)attrs[i+1];
					continue;
				}
				if (!input_type && strncasecmp((const char *)attrs[i], "type", strlen((char *)attrs[i])) == 0) {
					input_type = (const char *)attrs[i+1];
					continue;
				}
				if (!input_value && strncasecmp((const char *)attrs[i], "value", strlen((char *)attrs[i])) == 0) { 
					input_value = (const char *)attrs[i+1];
					continue;
				}
			}
			
			/*
			 * create and insert var
			 *
			 */
			if (!input_name) return;
			
			if (!parsing_ctx || !parsing_ctx->request_post) return;
			
			if (init_var_item(parsing_ctx->request_post->pool, &new_var) < 0) return;
			new_var->name = apr_pstrdup(parsing_ctx->request_post->pool, input_name);
			
			if (parsing_ctx->type) new_var->type = apr_pstrdup(parsing_ctx->request_post->pool, parsing_ctx->type);
			else new_var->type = apr_pstrdup(parsing_ctx->request_post->pool, VAR_GET);
			
			if (input_value) new_var->value = apr_pstrdup(parsing_ctx->request_post->pool, input_value);
			
			if (input_type) new_var->input_type = apr_pstrdup(parsing_ctx->request_post->pool, input_type);
			
			var_list_add(parsing_ctx->request_post->var_list, new_var);
			LOG_ERR(DEBUG, r->logs, "Add variable %s type %s to action %s", 
					new_var->name, new_var->type, parsing_ctx->request_post->clean_request);
		}
	}

	if (strncasecmp((const char *)name, "a", strlen((char *)name)) == 0 
		|| strncasecmp((const char *)name, "frame", strlen((char *)name)) == 0 
		|| strncasecmp((const char *)name, "img", strlen((char *)name)) == 0 
		|| strncasecmp((const char *)name, "link", strlen((char *)name)) == 0 
		|| strncasecmp((const char *)name, "area", strlen((char *)name)) == 0 
		|| strncasecmp((const char *)name, "meta", strlen((char *)name)) == 0
		|| strncasecmp((const char *)name, "iframe", strlen((char *)name)) == 0) {
		if (!attrs) return;
		for (i = 0; attrs[i]; i++) {
			if ( ((strncasecmp((const char *)attrs[i], "url", 3) == 0) || 
				(strncasecmp((const char *)attrs[i], "href", 4) == 0) || 
				(strncasecmp((const char *)attrs[i], "src", 3) == 0)) 
				&& (attrs[i+1])) {
				char *clean_link = NULL;

				LOG_ERR(DEBUG, r->logs, "Found link: %s", attrs[i+1]);
				if (sanitize_link_string(r, (char *)attrs[i+1], &clean_link) < 0) {
					LOG_ERR(DEBUG, r->logs, "Link is not valid");
					return;
				}
				
				if (clean_link == NULL) return;
				LOG_ERR(INFO, r->logs, "Adding element: %s", clean_link);
				
				if(html_parsing_add_new_request(r, clean_link) < 0) return;
				else r->found_links++;
			}
		}
	}
	if (strncasecmp((const char *)name, "form", strlen((char *)name)) == 0) {
		const char *type = NULL;
		const char *action = NULL;

		if (parsing_ctx->request_post) {
			LOG_ERR(CRIT, r->logs, "Found a new form and there is still a post request"
				" inside the parsing ctx (%s)", r->uri);
			request_destroy(parsing_ctx->request_post);
		}
	
		if (!attrs) return;
		parsing_ctx->in_form = 1;
		
		for (i = 0; attrs[i]; i++) {
			if ((strncasecmp((const char *)attrs[i], "action", strlen((char *)attrs[i])) == 0)) { 
				action = (const char *)attrs[i+1];
			}
			else if (action == NULL && 
					(strncasecmp((const char *)attrs[i], "onsubmit", strlen((char *)attrs[i])) == 0)) { 
				
				action = (const char *)attrs[i+1];
			}
			else if ((strncasecmp((const char *)attrs[i], "method", strlen((char *)attrs[i])) == 0)) { 
				if (!attrs[i+1]) continue;
				
				if (strncasecmp((char *)attrs[i+1], "GET", strlen((char *)attrs[i+1])) == 0) {
					parsing_ctx->type = apr_pstrdup(r->pool, VAR_GET);
					continue;
				}
				if (strncasecmp((char *)attrs[i+1], "POST", strlen((char *)attrs[i+1])) == 0) {
					parsing_ctx->type = apr_pstrdup(r->pool, VAR_POST);
					continue;
				}
			}

		}	
		if (!action) return;
		char *link = NULL;
	
		if (init_request(&parsing_ctx->request_post) < 0) return;
		parsing_ctx->request_post->method = apr_pstrdup(parsing_ctx->request_post->pool, "POST");
		parsing_ctx->in_form = 1;
		parsing_ctx->action = apr_pstrdup(r->pool, action);	
		request_copy_basic(r, parsing_ctx->request_post);

		if(sanitize_link_string(r, parsing_ctx->action, &link) < 0) {
			request_destroy(parsing_ctx->request_post);
			parsing_ctx->request_post = NULL;
			parsing_ctx->in_form = 0;
			parsing_ctx->action = NULL;
			return;
		}
	
		if (*link != '/') {
			LOG_ERR(DEBUG, r->logs, "We are not on an absolute link (%s) - add path %s to uri", link, r->path);
			link = apr_pstrcat(r->pool, r->path, link, NULL);
		}
	
		if (!type) apr_table_set(parsing_ctx->request_post->headers_in, 
				"Content-Type", "application/x-www-form-urlencoded");
		LOG_ERR(DEBUG, parsing_ctx->request_post->logs, "Add link %s", link);
		request_set_uri(parsing_ctx->request_post, link);
		request_set_arg(parsing_ctx->request_post, link);
		request_set_referer(parsing_ctx->request_post, r);
		request_clean_uri(parsing_ctx->request_post);
		if (request_clean_request(parsing_ctx->request_post) < 0) return;
		
	}

	return;
}

static void html_parsing_end_elem(void *ctx, const xmlChar *name)
{
	parsing_ctx_t parsing_ctx = (parsing_ctx_t)ctx;
	request_t r;
	stressy_ctx_t *stressy_ctx = NULL;
		
	if (!parsing_ctx) return;
	r = parsing_ctx->request;
	stressy_ctx = (stressy_ctx_t *)r->stressy_ctx; 
	
	if (parsing_ctx->in_form != 1) return;

	if (strncasecmp((char *)name, "form", strlen((char *)name)) == 0) {
		LOG_ERR(DEBUG, r->logs, "Closing form");
		
		/*
		 * XXX Insert request in store here
		 *
		 */
	
		if (!parsing_ctx->request_post) return;
		if (!parsing_ctx->type) parsing_ctx->type = apr_pstrdup(parsing_ctx->request_post->pool, VAR_GET);
		
		if (strncasecmp(parsing_ctx->type, VAR_POST, strlen(parsing_ctx->type)) == 0) 
			request_rebuild_post_line(parsing_ctx->request_post);
		if (strncasecmp(parsing_ctx->type, VAR_GET, strlen(parsing_ctx->type)) == 0) 
			request_rebuild_arg_line(parsing_ctx->request_post);
	
		request_clean_request(parsing_ctx->request_post);
		html_parsing_on(parsing_ctx->request_post);
		
		if (is_request_in_map(stressy_ctx->map, parsing_ctx->request_post->method,
					parsing_ctx->request_post->clean_request, parsing_ctx->request_post->post_arg) < 0) {

			request_destroy(parsing_ctx->request_post);
			parsing_ctx->request_post = NULL;
			parsing_ctx->in_form = 0;
			parsing_ctx->action = NULL;
			return;
		}
		
		LOG_ERR(DEBUG, r->logs, "Found form arg %s post arg %s on uri %s", parsing_ctx->request_post->arg,
						parsing_ctx->request_post->post_arg,
						parsing_ctx->request_post->uri);
	
		if(site_map_insert_request(stressy_ctx->map, parsing_ctx->request_post->clean_uri, parsing_ctx->request_post->method,
				     parsing_ctx->request_post->clean_request, parsing_ctx->request_post->post_arg,
				     (void *)parsing_ctx->request_post) < 0) {

			LOG_ERR(CRIT, r->logs, "Error inserting form request: %s with arg line: %s", 
				parsing_ctx->request_post->uri, parsing_ctx->request_post->post_arg);
	
			request_destroy(parsing_ctx->request_post);
		}
		LOG_ERR(DEBUG, r->logs, "Inserted form: %s with post arg line: %s and arg line %s", 
			parsing_ctx->request_post->clean_request,
			parsing_ctx->request_post->post_arg, parsing_ctx->request_post->arg);
	
		parsing_ctx->in_form = 0;
		parsing_ctx->request_post = NULL;
		parsing_ctx->action = NULL;
	}
	
	return;
}
	

extern int html_parsing_setup(void *ctx, void *data)
{
	request_t r = (request_t) ctx;
	
	r->sax = apr_pcalloc(r->pool, sizeof(htmlSAXHandler));

	r->sax->startDocument = NULL;
	r->sax->endDocument = NULL;
	r->sax->startElement = html_parsing_start_elem;
	r->sax->endElement = html_parsing_end_elem;
	r->sax->characters = NULL;
	r->sax->comment = NULL;
	r->sax->cdataBlock = NULL;
	return 0;
}

int html_parsing(void *ctx, void *data)
{
	request_t r = (request_t)ctx;
	parsing_ctx_t parsing_ctx;
	htmlDocPtr html_doc = NULL;

	const char *ct = NULL;
	const char *location = NULL;
	
	if (!r) return -1;

	if (is_html_parsing_on(r) < 0) {
		LOG_ERR(DEBUG, r->logs, "This request is not tagged for crawler");
		return -1;
	}

	LOG_ERR(DEBUG, r->logs, "%s is tagged for crawling", r->clean_request);

	if(init_parsing_ctx(r->pool, &parsing_ctx) < 0) return -1;
	
	if ((location = apr_table_get(r->headers_out, "Location"))) {
		char *clean_link = NULL;

		if(sanitize_link_string(r, (char *)location, &clean_link) < 0) return -1;
		if(html_parsing_add_new_request(r, clean_link) < 0) return -1;
        	else r->found_links++;
	}
	else if ((location = apr_table_get(r->headers_out, "Content-Location"))) {
		char *clean_link = NULL;

		if (sanitize_link_string(r, (char *)location, &clean_link) < 0) return -1;
		if(html_parsing_add_new_request(r, clean_link) < 0) return -1;
		else r->found_links++;
	}

	if (!(ct = apr_table_get(r->headers_out, "Content-Type"))) return -1;

	if (strncasecmp(ct, "text/html", 9) != 0) return -1;
	
	
	if (!r->sax) {
		LOG_ERR(CRIT, r->logs, "Parser is not ready");
		return -1;
	}
	
	
	if (!r->body) {
		LOG_ERR(DEBUG, r->logs, "Unable to find body to parse");
		return -1;
	}
	
	LOG_ERR(DEBUG, r->logs, "Start html parsing");
	parsing_ctx->request = r;
	html_doc = htmlSAXParseDoc((xmlChar *)r->body, NULL, r->sax, parsing_ctx);
	LOG_ERR(DEBUG, r->logs, "Stop html parsing");

	if (html_doc) {
		LOG_ERR(CRIT, r->logs, "Found a doc to free");
		
	}
	
	return 0;
}

static int html_parsing_add_new_request(request_t r, char *link) {
	request_t new;
	stressy_ctx_t *stressy_ctx = NULL;
	html_parsing_t *cfg = NULL;
	
	void *tmp_cfg = NULL;
	int request_in_map = 0;
	
	if (!r) return -1;
	if (link == NULL) return -1;
	stressy_ctx = (stressy_ctx_t *)r->stressy_ctx;

	if (stressy_ctx == NULL) return -1;
	
	/*
	 * Get module conf
	 * 
	 */	
	if (module_get_setup(stressy_ctx->pool, MOD_CRAWLER, (void **)&tmp_cfg) < 0) return -1;
	cfg = (html_parsing_t *)tmp_cfg;
	
	if(init_request(&new) < 0) { 
		LOG_ERR(CRIT, r->logs, "Unable to create new request");
		return -1;
	}
	request_copy_basic(r,new);
	
	if (!r->path) {
		if (request_get_path(r, &r->path) < 0) {
			request_destroy(new);
			return -1;
		}
	}
	
	if (*link != '/') {
		LOG_ERR(DEBUG, r->logs, "We are not on an absolute link (%s) - add path %s to uri", link, r->path);
		link = apr_pstrcat(r->pool, r->path, link, NULL);
	}
	
	/*
	 * set step + 1
	 *
	 */
	new->step = r->step + 1;
	
	request_set_uri(new, link);
	request_set_arg(new, link);
	request_set_referer(new, r);
	request_clean_uri(new);
	if (request_clean_request(new) < 0) {
		request_destroy(new);
		return -1;
	}
	new->name = apr_psprintf(new->pool, "Crawler"); 
	new->process_status = PROCESS_WAITING;

	/* look if request is not exclude */
	if (is_crawler_exclude(new, cfg) < 0) {
		request_destroy(new);
		new = NULL;
		return -1;
	}

	/*
	 * Get map status for the new request
	 *
	 */
	request_in_map = is_request_in_map(stressy_ctx->map, new->method, new->clean_request, new->post_arg); 
	
	/*
	 *
	 * If display link is on, display found link
	 *
	 */
	if (request_in_map >= 0 && cfg->display_link == 1 && new->step > cfg->max_step) {
		LOG_ERR(INFO, r->logs, "Next step(%i) link: %s", new->step, new->clean_request);
	}
	
	/*
	 * If the request step is > cfg max step - just return
	 *
	 */
	if (cfg->max_step >= 0 && new->step > cfg->max_step) {
		request_destroy(new);
		new = NULL;
		return -1;
	}	
	
	/*
	 * If request is already in map - destroy new request then exit
	 *
	 */		
	if (request_in_map < 0) {
		request_destroy(new);
                new = NULL;
                return -1;
	}
	
	html_parsing_on(new);
	/* now we have parser the request, insert the request inside the map */
        if (site_map_insert_request(r->stressy_ctx, new->uri, new->method, new->clean_request, new->post_arg, (void *)new) < 0) {
		/*
		 * The request is already in the map - destroy
		 */
		LOG_ERR(WARN, r->logs, "Error inserting new request in map");
	}
	LOG_ERR(DEBUG, r->logs, "New request added");
		

	return 0;
}

static int html_parsing_ctx_post_setup(void *ctx, void *data)
{
	stressy_ctx_t * stressy_ctx = (stressy_ctx_t *)ctx;
	request_t r = NULL;
	html_parsing_t *cfg = NULL;
	void *tmp_cfg = NULL;
	
	if (!stressy_ctx) return -1;
	if (module_get_setup(stressy_ctx->pool, MOD_CRAWLER, (void **)&tmp_cfg) < 0) return -1;
	cfg = (html_parsing_t *)tmp_cfg;
	
	if (cfg->active == 1) {
		
		hook_add(stressy_ctx->after_receive, "Crawler setup", html_parsing_setup);
		hook_add(stressy_ctx->after_receive, "Crawler parse html", html_parsing);		
	}

	init_request(&r);
        r->name = apr_pstrdup(r->pool, "Crawler first request");
	r->hostname = apr_pstrdup(r->pool, stressy_ctx->hostname);
	r->port = apr_pstrdup(r->pool, stressy_ctx->port);
        r->logs = stressy_ctx->logs;
	r->stressy_ctx = stressy_ctx;
	r->path = "/";
	
	if (!stressy_ctx->start_uri) r->uri = apr_pstrdup(r->pool, "/");
	else r->uri = apr_pstrdup(r->pool, stressy_ctx->start_uri);
	apr_table_set(r->headers_in, "Host", stressy_ctx->hostname);
	apr_table_set(r->headers_in, "User-Agent", "Mozilla-5.0");
	apr_table_set(r->headers_in, "Connection", "Keep-Alive");
	apr_table_set(r->notes, "html_parsing", "PARSING_ON");
	add_request_in_list(stressy_ctx->request_list, r);	
	
	return 0;
}

static int setup_active(void *ctx, void *arg, int type)
{
	html_parsing_t *cfg = NULL;
	stressy_ctx_t * stressy_ctx = NULL;
	void *tmp_cfg = NULL;
	
	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (module_get_setup(stressy_ctx->pool, MOD_CRAWLER, (void **)&tmp_cfg) < 0) return -1;
	cfg = (html_parsing_t *)tmp_cfg;

	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] module enabled", MOD_CRAWLER);
	
	cfg->active = 1;
	
	return 0;
}

static int setup_display_link(void *ctx, void *arg, int type)
{
	html_parsing_t *cfg = NULL;
	stressy_ctx_t * stressy_ctx = NULL;
	void *tmp_cfg = NULL;
	
	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	
	if (module_get_setup(stressy_ctx->pool, MOD_CRAWLER, (void **)&tmp_cfg) < 0) return -1;
	cfg = (html_parsing_t *)tmp_cfg;
	
	if (type == SETUP_CLI) {
		cfg->display_link = 1;
		LOG_ERR(INFO, stressy_ctx->logs, "Set crawler display link to on", cfg->max_step);
	}

	return 0;
}

static int setup_exclude_regexp(void *ctx, void *arg, int type)
{
	html_parsing_t *cfg = NULL;
	stressy_ctx_t * stressy_ctx = NULL;
	void *tmp_cfg = NULL;
	int err_offset;	
	const char *err_str = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
	if (module_get_setup(stressy_ctx->pool, MOD_CRAWLER, (void **)&tmp_cfg) < 0) return -1;
	cfg = (html_parsing_t *)tmp_cfg;
	
	if (type == SETUP_CLI) {
		cfg->exclude_regexp_char = arg;
		LOG_ERR(INFO, stressy_ctx->logs, "(cli) Set crawler exclude regexp: %s", cfg->exclude_regexp_char);
	}
	else if (type == SETUP_XML) {
		cfg->exclude_regexp_char = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)arg, "value");
		LOG_ERR(INFO, stressy_ctx->logs, "(xml) Set crawler exclude regexp: %s", cfg->exclude_regexp_char);
	}

	if (cfg->exclude_regexp_char == NULL) {
		LOG_ERR(INFO, stressy_ctx->logs, "Crawler: no exclude regexp found");
		return -1;
	}
	
	cfg->exclude_regexp = pcre_compile(cfg->exclude_regexp_char, PCRE_EXTENDED | PCRE_EXTRA, &err_str, &err_offset, NULL);
	if (cfg->exclude_regexp == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to compile regexp: %s", cfg->exclude_regexp_char);
		return -1;
	}
	
	return 0;
}

static int setup_max_step(void *ctx, void *arg, int type)
{
	html_parsing_t *cfg = NULL;
	stressy_ctx_t * stressy_ctx = NULL;
	void *tmp_cfg = NULL;
	
	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;

	if (module_get_setup(stressy_ctx->pool, MOD_CRAWLER, (void **)&tmp_cfg) < 0) return -1;
	cfg = (html_parsing_t *)tmp_cfg;
	
	if (type == SETUP_CLI) {
		cfg->max_step = atoi((char *)arg);
		LOG_ERR(INFO, stressy_ctx->logs, "Set max step of crawling to %i", cfg->max_step);
	}

	return 0;
}

static int html_parsing_ctx_setup(void *ctx, void *data)
{
	html_parsing_t *cfg = NULL;
	stressy_ctx_t * stressy_ctx = NULL;

	if (!ctx) return -1;
	stressy_ctx = (stressy_ctx_t *)ctx;
		
	cfg = apr_pcalloc(stressy_ctx->pool, sizeof(html_parsing_t));
	if (!cfg) return -1;

	cfg->max_step = -1;
	cfg->display_link = 0;
	
	if (module_set_setup(stressy_ctx->pool, MOD_CRAWLER, (void *)cfg) < 0) return -1;

	setup_add_directive(stressy_ctx->prog_setup, "crawler", SETUP_CLI_NEED_0, setup_active, 
			"enable crawler");
	setup_add_directive(stressy_ctx->prog_setup, "crawler_max_step", SETUP_CLI_NEED_1, setup_max_step, 
			"=max_depth");
	setup_add_directive(stressy_ctx->prog_setup, "crawler_display_link", SETUP_CLI_NEED_0, setup_display_link, 
			"enable display of found link for current step");
	setup_add_directive(stressy_ctx->prog_setup, "crawler_exclude", SETUP_CLI_NEED_1, setup_exclude_regexp, 
			"=regexp to exclude data");
	
	return 0;
}

#ifdef HAVE_CRAWLER_SHARED
extern int module_init(stressy_ctx_t * stressy_ctx)
{
	if (!stressy_ctx) return -1;
	
	LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", MOD_CRAWLER);
	hook_add(stressy_ctx->setup, "Crawler parse html setup", html_parsing_ctx_setup);		
	hook_add(stressy_ctx->post_setup, "Crawler parse html post setup", html_parsing_ctx_post_setup);
	
	return 0;
}
#endif
