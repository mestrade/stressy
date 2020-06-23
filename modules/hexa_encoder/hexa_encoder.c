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

#include "hexa_encoder.h"
#include "stressy_ctx.h"
#include "module_tools.h"
#include "pcre.h"

#define HEXA_ENCODER_MODULE "mod_hexa_encoder"

typedef struct hexa_encoder_t hexa_encoder_t;

struct hexa_encoder_t {

	stressy_ctx_t *stressy_ctx;
	
	int enable;
	
	int enable_uri;
	int enable_var;
	int enable_headers;
	int enable_post;
	
	const char *exclude_regexp;
	pcre *exclude_pcre;

};

int convert_buffer_to_hex(request_t *r, char *buffer, char **result)
{
	int len = 0;
	int i = 0;
	char *encoded = NULL;

	if (buffer == NULL) return 0;
	
	len = strlen(buffer);

	for (i = 0; i < len; i++) {
	char *encoded_char;
	encoded_char = apr_psprintf(r->pool, "%%%02x", buffer[i]);

	if (!encoded)
		encoded = encoded_char;
	else
		encoded = apr_pstrcat(r->pool, encoded, encoded_char, NULL);
	}

	*result = encoded;
	return 0;
}


static int hexa_encoder_exec(void *ctx, void *data)
{
	request_t *r = (request_t *)ctx;
	request_t *new_request = NULL;
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)data;
	hexa_encoder_t *cfg = NULL;
	int modif_done = 0;
	
	char *new_uri = NULL;
	
	if (r == NULL) return -1;

	if (apr_table_get(r->notes, HEXA_ENCODER_MODULE) != NULL) return 0;

	//stressy_ctx = (stressy_ctx_t *)r->stressy_ctx;
	cfg = (hexa_encoder_t *)module_retrieve_setup(stressy_ctx->pool, HEXA_ENCODER_MODULE);	
	
	if (cfg == NULL || cfg->enable <= 0) {
		LOG_ERR(DEBUG, r->logs, "[%s] disabled", HEXA_ENCODER_MODULE);
		return 0;
	}
	
	if (request_init(&new_request) < 0) return -1;
	request_copy_basic(r, new_request);

	if (cfg->enable_uri > 0) {	
		convert_buffer_to_hex(new_request, r->resource, &new_uri);
		request_set_resource_from_uri(new_request, new_uri);	
		LOG_ERR(DEBUG, r->logs, "[%s] New uri: %s", HEXA_ENCODER_MODULE, new_uri);
		modif_done++;
	}
	else {
		request_set_resource_from_uri(new_request, r->resource);
	}

	if (cfg->enable_var && r->var_list != NULL) {
		var_item_t *var_ptr = NULL;
	
		for (var_ptr = r->var_list->first_var;
			      var_ptr;
			      var_ptr = var_ptr->next) {

			var_item_t *new_var = NULL;
			
			if (var_item_init(new_request->pool, &new_var) < 0) return -1;
			new_var->type = var_ptr->type;
			new_var->name = apr_pstrdup(new_request->pool, var_ptr->name);
			convert_buffer_to_hex(new_request, var_ptr->value, &new_var->value);	
			var_list_add(new_request->var_list, new_var);
			modif_done++;
		}			
		

	}

	if (modif_done <= 0) {
		request_destroy(new_request);
		return 0;
	}

	apr_table_set(new_request->notes, HEXA_ENCODER_MODULE, "active");
	request_rebuild_cookie_line(new_request);
	request_rebuild_post_line(new_request);
	request_rebuild_arg_line(new_request);
	
	request_clean_request(new_request);
	request_set_module(new_request, HEXA_ENCODER_MODULE);
	request_list_add(stressy_ctx->request_list, new_request);
	
	return 0;
}

static int hexa_encoder_status_setup(void *ctx, void *arg, int type)
{
	hexa_encoder_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;

	stressy_ctx = (stressy_ctx_t *)ctx;
	cfg = (hexa_encoder_t *) module_retrieve_setup(stressy_ctx->pool, HEXA_ENCODER_MODULE);
	if (cfg == NULL) return -1;
	cfg->enable = 1;
	cfg->enable_uri = 1;
	cfg->enable_var = 1;
	cfg->enable_headers = 1;
	
	return 0;
}
static int hexa_encoder_uri_status_setup(void *ctx, void *arg, int type)
{
	hexa_encoder_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;

	stressy_ctx = (stressy_ctx_t *)ctx;
	cfg = (hexa_encoder_t *) module_retrieve_setup(stressy_ctx->pool, HEXA_ENCODER_MODULE);
	if (cfg == NULL) return -1;
	cfg->enable_uri = 1;
	cfg->enable = 1;
		
	return 0;
}
static int hexa_encoder_var_status_setup(void *ctx, void *arg, int type)
{
	hexa_encoder_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;

	stressy_ctx = (stressy_ctx_t *)ctx;
	cfg = (hexa_encoder_t *) module_retrieve_setup(stressy_ctx->pool, HEXA_ENCODER_MODULE);
	if (cfg == NULL) return -1;
	cfg->enable_var = 1;
	cfg->enable = 1;
	
	return 0;
}
static int hexa_encoder_headers_status_setup(void *ctx, void *arg, int type)
{
	hexa_encoder_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = NULL;

	stressy_ctx = (stressy_ctx_t *)ctx;
	cfg = (hexa_encoder_t *) module_retrieve_setup(stressy_ctx->pool, HEXA_ENCODER_MODULE);
	if (cfg == NULL) return -1;
	cfg->enable_headers = 1;
	cfg->enable = 1;
	
	return 0;
}
static int hexa_encoder_post_setup(void *ctx, void *data)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	hexa_encoder_t *cfg = NULL;

	cfg = (hexa_encoder_t *)module_retrieve_setup(stressy_ctx->pool, HEXA_ENCODER_MODULE);
	if (cfg == NULL) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to find module cfg");
		return -1;
	}
	
	if (cfg->enable_uri > 0) LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] enabled on uri", HEXA_ENCODER_MODULE);
	if (cfg->enable_var > 0) LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] enabled on var", HEXA_ENCODER_MODULE);
	if (cfg->enable_headers > 0) LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] enabled on headers", HEXA_ENCODER_MODULE);

	if (cfg->enable > 0) {
		hook_add(stressy_ctx->worker->pre_send, "Hexa_encoder exec", hexa_encoder_exec);
	}
	
	return 0;
}	
static int hexa_encoder_setup(void *ctx, void *data)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
	hexa_encoder_t *cfg = NULL;
	
	cfg = (hexa_encoder_t *)apr_pcalloc(stressy_ctx->pool, sizeof(hexa_encoder_t));
	if (cfg == NULL) return -1;

	cfg->enable = 0;
	
	cfg->enable_uri = 0;
	cfg->enable_var = 0;
	cfg->enable_headers = 0;
	cfg->enable_post = 0;
	
	cfg->exclude_regexp = NULL;
	cfg->exclude_pcre = NULL;

        setup_add_directive(stressy_ctx->prog_setup, "hexa_encoder", SETUP_CLI_NEED_0,
		hexa_encoder_status_setup, "enable hexa_encoder");
        setup_add_directive(stressy_ctx->prog_setup, "hexa_encoder_uri", SETUP_CLI_NEED_0, 
		hexa_encoder_uri_status_setup, "enable hexa_encoder on uri");
	setup_add_directive(stressy_ctx->prog_setup, "hexa_encoder_var", SETUP_CLI_NEED_0, 
		hexa_encoder_var_status_setup, "enable hexa_encoder on parameters");			
	setup_add_directive(stressy_ctx->prog_setup, "hexa_encoder_headers", SETUP_CLI_NEED_0,
		hexa_encoder_headers_status_setup, "enable hexa_encoder on headers");			

	if (module_set_setup(stressy_ctx->pool, HEXA_ENCODER_MODULE, (void *)cfg) < 0) return -1;
	hook_add(stressy_ctx->post_setup, "Hexa_encoder post setup", hexa_encoder_post_setup);
		
	return 0;
}

#ifdef HAVE_HEXA_ENCODER_SHARED
extern int module_init(void *ctx)
{
#else
extern int hexa_encoder_module_init(void *ctx)
{
#endif
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	if (!stressy_ctx) return -1;

	LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", HEXA_ENCODER_MODULE);

	hook_add(stressy_ctx->setup, "Hexa_encoder setup", hexa_encoder_setup);

	return 0;
}
	
