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

#include "form_auth_bruteforce.h"

#include "stressy_ctx.h"
#include "module_tools.h"
#include "pcre.h"
#include "logs.h"

#define DEFAULT_USER_MATCH		"(?i)(user|login|name)"
#define FORM_AUTH_BRUTEFORCE_MODULE 	"mod_form_auth_bruteforce"
#define CREDENTIAL_XPATH		"/credential/item"
#define OUTPUT_VECTOR_SIZE      30

#define DEFAULT_TOLERANCE	5

typedef struct babf_t babf_t;
typedef struct credential_t credential_t;


struct credential_t {
	char *login;
	char *pass;
};

struct babf_t {

	const char *credential_filename;
	
	int num_credential;
	credential_t **list;

	const char *user_input_regexp;
	pcre *user_input_pcre;

	int tolerance;	

	apr_hash_t *already_done;
	apr_thread_mutex_t *lock;	
};

static int babf_exec(void *ctx, void *data)
{
	request_t *r = (request_t *)ctx;
	stressy_ctx_t *stressy_ctx = NULL;
	babf_t *cfg = NULL;
	int num_passwd_input = 0;
	var_item_t *var = NULL;
	int index = 0;
	
	if (r == NULL) return -1;

	//stressy_ctx = (stressy_ctx_t *)r->stressy_ctx;	
	if (stressy_ctx == NULL) return -1;

	cfg = (babf_t *)module_retrieve_setup(stressy_ctx->pool, FORM_AUTH_BRUTEFORCE_MODULE);
	if (cfg == NULL) return -1; 


	if (apr_table_get(r->notes, FORM_AUTH_BRUTEFORCE_MODULE) != NULL) {
		int num_words = 0;
		int num_lines = 0;
		int code = 0;
		const char *tmp = NULL;


		tmp = apr_table_get(r->notes, "need_answer");
               	if (tmp != NULL) code = atoi(tmp);
		else return -1;
		
		if (r->code != code) {
			request_dump(r, INFO);
			return 0;
		}
		
		tmp = apr_table_get(r->notes, "need_words");
		if (tmp != NULL) num_words = atoi(tmp);
		else return -1;
		
		tmp = apr_table_get(r->notes, "need_lines");
	       	if (tmp != NULL) num_lines = atoi(tmp);	
		else return -1;
		
		LOG_ERR(DEBUG, r->logs, "Failed authentication send back %i words and %i lines", num_words, num_lines);
		LOG_ERR(DEBUG, r->logs, "We have %i words and %i lines", r->body_words, r->body_lines);
	
		if (r->body_words > num_words + cfg->tolerance || r->body_words < num_words - cfg->tolerance) {
			request_dump(r, INFO);
			
			return 0;
		}
		if (r->body_lines > num_lines + cfg->tolerance || r->body_lines < num_lines - cfg->tolerance) {
			request_dump(r, INFO);
			
			return 0;
		}
		
		return 0;
	}
	
	/* in this case, the request doesn't contain var */
	if (r->var_list == NULL || r->var_list->num_var <= 0) return 0;

	for (var = r->var_list->first_var; var; var = var->next) {

		if (var->input_type && strncasecmp(var->input_type, "password", strlen(var->input_type)) == 0) {
			LOG_ERR(DEBUG, r->logs, "Found a password input to bruteforce (%s)",r->resource);
		       	num_passwd_input++;	
		}
	}

	/* we don't have password input fields */
	if (num_passwd_input <= 0) {
		LOG_ERR(DEBUG, r->logs, "No input to bruteforce here");
		return 0;
	}
	else {
		r->name = apr_psprintf(r->pool, "Form Authentication found");
		request_dump(r, INFO);
		LOG_ERR(DEBUG, r->logs, "Start form auth bruteforce");
	}

	/* look if we already bruteforced */
	apr_thread_mutex_lock(cfg->lock);
	if (apr_hash_get(cfg->already_done, r->resource, strlen(r->resource))) {
		apr_thread_mutex_unlock(cfg->lock);
		
		LOG_ERR(DEBUG, r->logs, "Form already bruteforced");
		return 0;
	}
	else {
		char *key = NULL;
		key = apr_pstrdup(stressy_ctx->pool, r->resource);
		apr_hash_set(cfg->already_done, key, strlen(key), key);
		LOG_ERR(DEBUG, r->logs, "This form has not been bruteforced - register it in the list");
	}
	apr_thread_mutex_unlock(cfg->lock);

	
	/* add the request inside already done url */
	for (index = 0; index < cfg->num_credential; index++) {
		request_t *new_request = NULL;
		int found_password = 0;
		
		if (cfg->list[index] == NULL) continue;
		LOG_ERR(DEBUG, r->logs, "Use cred: %s/%s", cfg->list[index]->login, cfg->list[index]->pass);
	
		if (request_init(&new_request) < 0) continue;
		
		request_copy_basic(r, new_request);
		new_request->method = apr_pstrdup(new_request->pool, r->method);
		request_set_resource_from_uri(new_request, r->resource);

		for (var = r->var_list->first_var; var; var = var->next) {
			var_item_t *new_var = NULL;
			int out_vec[OUTPUT_VECTOR_SIZE];
			
			if (var_item_init(new_request->pool, &new_var) < 0) return -1;
			
			if (var->input_type && strncasecmp(var->input_type, "password", strlen(var->input_type)) == 0) {
				new_var->type = var->type;
				new_var->name = apr_pstrdup(new_request->pool, var->name);
				new_var->value = apr_pstrdup(new_request->pool, cfg->list[index]->pass);	
				var_list_add(new_request->var_list, new_var);
				found_password = 1;
				continue;
			}
			else if ((pcre_exec(cfg->user_input_pcre, NULL, var->name, strlen(var->name), 0, 0, out_vec, OUTPUT_VECTOR_SIZE) >= 0)
					 ||(found_password == 0 && num_passwd_input == 2))
			{
				new_var->type = var->type;
				new_var->name = apr_pstrdup(new_request->pool, var->name);
				new_var->value = apr_pstrdup(new_request->pool, cfg->list[index]->login);	
				var_list_add(new_request->var_list, new_var);
				continue;
			}
			else {
				new_var->type = var->type;
				new_var->name = apr_pstrdup(new_request->pool, var->name);
				new_var->value = apr_pstrdup(new_request->pool, var->value);	
				var_list_add(new_request->var_list, new_var);
			}
		}

		new_request->login = apr_pstrdup(new_request->pool, cfg->list[index]->login);
		new_request->password = apr_pstrdup(new_request->pool, cfg->list[index]->pass);
		
		request_rebuild_cookie_line(new_request);
	        request_rebuild_post_line(new_request);
	        request_rebuild_arg_line(new_request);

		new_request->name = apr_psprintf(new_request->pool, "(%s) using login: %s pass: %s", 
				FORM_AUTH_BRUTEFORCE_MODULE, cfg->list[index]->login, 
				cfg->list[index]->pass);
		
		apr_table_set(new_request->notes, FORM_AUTH_BRUTEFORCE_MODULE, "active");
	        apr_table_set(new_request->notes, "need_words", apr_psprintf(new_request->pool, "%i", r->body_words));
		apr_table_set(new_request->notes, "need_lines", apr_psprintf(new_request->pool, "%i", r->body_lines));		
		apr_table_set(new_request->notes, "need_answer", apr_psprintf(new_request->pool, "%i", r->code));
		
		request_clean_request(new_request);
	        request_set_module(new_request, FORM_AUTH_BRUTEFORCE_MODULE);
		request_list_add(stressy_ctx->request_list, new_request);
		
	}

	
	return 0;
}

static int babf_tolerance(void *ctx, void *data, int type)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
        babf_t *cfg = NULL;
	
	if (stressy_ctx == NULL) return -1;

	cfg = (babf_t *)module_retrieve_setup(stressy_ctx->pool, FORM_AUTH_BRUTEFORCE_MODULE);
	if (cfg == NULL) return -1; 

	if (type == SETUP_CLI) {
		cfg->tolerance = atoi(data);
	}
	else if (type == SETUP_XML) {
		char *tmp = NULL;

		tmp = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)data, "value");
		if (tmp != NULL) cfg->tolerance = atoi(tmp);
	}	
		
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] using tolerance: %i", FORM_AUTH_BRUTEFORCE_MODULE, cfg->tolerance);
	
	return 0;
}

static int babf_user_input_regexp(void *ctx, void *data, int type)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
        babf_t *cfg = NULL;
        int err_offset;
        const char *err_str = NULL;
	
	if (stressy_ctx == NULL) return -1;

	cfg = (babf_t *)module_retrieve_setup(stressy_ctx->pool, FORM_AUTH_BRUTEFORCE_MODULE);
	if (cfg == NULL) return -1; 

	if (type == SETUP_CLI) {
		cfg->user_input_regexp = data;
	}
	else if (type == SETUP_XML) {
		cfg->user_input_regexp = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)data, "value");
	}	

	if (cfg->user_input_regexp == NULL) return -1;
	cfg->user_input_pcre = pcre_compile(cfg->user_input_regexp, PCRE_EXTENDED | PCRE_EXTRA, &err_str, &err_offset, NULL);

	if (cfg->user_input_pcre == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "[%s] Error compiling regular expression", FORM_AUTH_BRUTEFORCE_MODULE);
		return -1;
	}
		
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] using user input detection regexp: %s", FORM_AUTH_BRUTEFORCE_MODULE, cfg->user_input_regexp);
	
	return 0;
}

static int babf_lp_file(void *ctx, void *data, int type)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
        babf_t *cfg = NULL;
	
	if (stressy_ctx == NULL) return -1;

	cfg = (babf_t *)module_retrieve_setup(stressy_ctx->pool, FORM_AUTH_BRUTEFORCE_MODULE);
	if (cfg == NULL) return -1; 

	if (type == SETUP_CLI) {
		cfg->credential_filename = data;
	}
	else if (type == SETUP_XML) {
		cfg->credential_filename = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)data, "value");
	}	

	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] using credential login/pass filename: %s", FORM_AUTH_BRUTEFORCE_MODULE, cfg->credential_filename);
	
	return 0;
}

static int fabf_post_setup(void *ctx, void *data)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	babf_t *cfg = NULL;
	xmlDocPtr setup_xml = NULL;
        xmlXPathContext *xpathctx;
       	xmlXPathObject *xpathObj;
	int index = 0;
        int err_offset;
        const char *err_str = NULL;
	
	if (stressy_ctx == NULL) return -1;

	cfg = (babf_t *)module_retrieve_setup(stressy_ctx->pool, FORM_AUTH_BRUTEFORCE_MODULE);
        if (cfg == NULL) return -1;

	if (cfg->credential_filename == NULL) return 0;	

	if (cfg->user_input_regexp == NULL) {
		cfg->user_input_regexp = DEFAULT_USER_MATCH;
		cfg->user_input_pcre = pcre_compile(cfg->user_input_regexp, PCRE_EXTENDED | PCRE_EXTRA, &err_str, &err_offset, NULL);	
	}

	
	setup_xml = xmlParseFile(cfg->credential_filename);	
	if (setup_xml == NULL) return -1;

	xpathctx = xmlXPathNewContext((xmlDocPtr)setup_xml);
        xpathObj = xmlXPathEvalExpression((xmlChar *)CREDENTIAL_XPATH, xpathctx);

	cfg->num_credential = xpathObj->nodesetval->nodeNr;	
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Using %i login/pass definition", FORM_AUTH_BRUTEFORCE_MODULE, cfg->num_credential);

	if (cfg->num_credential <= 0) return 0;
	
	cfg->list = (credential_t **) apr_pcalloc(stressy_ctx->pool, cfg->num_credential * sizeof(credential_t *));
	if (cfg->list == NULL) return -1;

	for (index = 0; index < cfg->num_credential; index++) {
		xmlNode *node = NULL;
		xmlChar *login = NULL;
                xmlChar *pass = NULL;
		credential_t *credential = NULL;		
		
		node = xpathObj->nodesetval->nodeTab[index];
		
		login = xmlGetProp(node, BAD_CAST"login");
		pass = xmlGetProp(node, BAD_CAST"password");

		if (login == NULL) {
			index--;
			continue;
		}
	
		credential = (credential_t *)apr_pcalloc(stressy_ctx->pool, sizeof(credential_t));
		credential->login = apr_pstrdup(stressy_ctx->pool, (char *)login);
		if (pass == NULL) credential->pass = apr_pstrdup(stressy_ctx->pool, (char *)login);
		else credential->pass = apr_pstrdup(stressy_ctx->pool, (char *)pass);
		
		LOG_ERR(DEBUG, stressy_ctx->logs, "[%s] (%i) found login: %s pass: %s", FORM_AUTH_BRUTEFORCE_MODULE, index, credential->login, credential->pass);
		cfg->list[index] = credential;	
	}

	hook_add(stressy_ctx->after_receive, "form auth bruteforce exec", babf_exec);	
	
	return 0;	
}

static int fabf_setup(void *ctx, void *data)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	babf_t *cfg = NULL;


	if (stressy_ctx == NULL) return -1;

	cfg = (babf_t *)apr_pcalloc(stressy_ctx->pool, sizeof(babf_t));
	if (cfg == NULL) return -1;

	cfg->user_input_pcre = NULL;
	cfg->user_input_regexp = NULL;
	cfg->tolerance = DEFAULT_TOLERANCE;
	cfg->already_done = apr_hash_make(stressy_ctx->pool);
	apr_thread_mutex_create(&cfg->lock, APR_THREAD_MUTEX_DEFAULT, stressy_ctx->pool);
	
	setup_add_directive(stressy_ctx->prog_setup, "form_auth_bruteforce", SETUP_CLI_NEED_1, babf_lp_file,
	                        "=login/pass_file.xml enable form auth bruteforce");	
	setup_add_directive(stressy_ctx->prog_setup, "form_auth_bruteforce_user_input", SETUP_CLI_NEED_1, babf_user_input_regexp,
	                        "=regexp to find username input");	
	setup_add_directive(stressy_ctx->prog_setup, "form_auth_bruteforce_tolerance", SETUP_CLI_NEED_1, babf_tolerance,
	                        "=number of word/lines to say the auth is valid");	

	if (module_set_setup(stressy_ctx->pool, FORM_AUTH_BRUTEFORCE_MODULE, (void *)cfg) < 0) return -1;
	hook_add(stressy_ctx->post_setup, "form auth bruteforce post setup", fabf_post_setup);
		
	return 0;
}


#ifdef HAVE_FORM_AUTH_BRUTEFORCE_SHARED
extern int module_init(void *ctx)
{
#else
extern int form_auth_bruteforce_module_init(void *ctx)
{
#endif
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	if (stressy_ctx == NULL) return -1;
	LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", FORM_AUTH_BRUTEFORCE_MODULE);

	hook_add(stressy_ctx->setup, "form auth bruteforce module", fabf_setup);
	
	return 0;
}
