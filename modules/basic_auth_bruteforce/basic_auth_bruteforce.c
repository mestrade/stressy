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

#include "basic_auth_bruteforce.h"
#include "stressy_ctx.h"
#include "module_tools.h"
#include "apr_base64.h"

#define BASIC_AUTH_BRUTEFORCE_MODULE 	"mod_basic_auth_bruteforce"

#define CREDENTIAL_XPATH                "/credential/item"


typedef struct basic_bf_t basic_bf_t;
typedef struct credential_t credential_t;

struct credential_t {

	const char *login;
	const char *password;
	const char *base64_line;

};

struct basic_bf_t {

	const char *filename;
	
	int num_credential;
	credential_t **list;	

};

static int basic_exec(void *ctx, void *data)
{
	request_t *r = (request_t *)ctx;
	stressy_ctx_t *stressy_ctx = NULL;
	basic_bf_t *cfg = NULL;
	
	if (r == NULL) return -1;
	//stressy_ctx = (stressy_ctx_t *)r->stressy_ctx;
	if (stressy_ctx == NULL) return -1;

	cfg = (basic_bf_t *)module_retrieve_setup(stressy_ctx->pool, BASIC_AUTH_BRUTEFORCE_MODULE);
	if (cfg == NULL) return -1;
	
	if (r->code == 401 && apr_table_get(r->notes, BASIC_AUTH_BRUTEFORCE_MODULE) == NULL) {
		int index = 0;
	
		LOG_ERR(NOTICE, r->logs, "Start bruteforce on %s", r->resource);
	
		r->name = apr_psprintf(r->pool, "Basic authentication found");
		request_dump(r, INFO);
	
	
		for (index = 0; index < cfg->num_credential; index++) {
			request_t *new_request = NULL;
			char *hdr_val = NULL;
			
			if (cfg->list[index]->base64_line == NULL) continue;
			
			if (request_init(&new_request) < 0) return -1;
			request_copy_basic(r, new_request);
			request_set_resource_from_uri(new_request, r->resource);
			hdr_val = apr_psprintf(new_request->pool, "Basic %s", cfg->list[index]->base64_line);
			apr_table_set(new_request->headers_in, "Authorization", hdr_val);

			apr_table_set(new_request->notes, BASIC_AUTH_BRUTEFORCE_MODULE, "active");
			new_request->login = apr_pstrdup(new_request->pool, cfg->list[index]->login);
			new_request->password = apr_pstrdup(new_request->pool, cfg->list[index]->password);

			
			request_set_module(new_request, BASIC_AUTH_BRUTEFORCE_MODULE);
	                request_list_add(stressy_ctx->request_list, new_request);
		}
		return 0;

		LOG_ERR(NOTICE, r->logs, "Stop bruteforce on %s", r->resource);

	}
	else if (r->code != 401 && r->code != 400 && apr_table_get(r->notes, BASIC_AUTH_BRUTEFORCE_MODULE) != NULL) {
		r->name = apr_psprintf(r->pool, "Valid credential %s/%s found", r->login, r->password);
		request_dump(r, INFO);

	}

	
	return 0;
}	

static int basic_lp_file(void *ctx, void *data, int type)
{
        basic_bf_t *cfg = NULL;
        stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

        if (stressy_ctx == NULL) return -1;

	cfg = (basic_bf_t *)module_retrieve_setup(stressy_ctx->pool, BASIC_AUTH_BRUTEFORCE_MODULE);
	if (cfg == NULL) return -1;	

        if (type == SETUP_CLI) {
                cfg->filename = data;
        }
        else if (type == SETUP_XML) {
                cfg->filename = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)data, "value");
        }

        LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] using credential login/pass filename: %s", BASIC_AUTH_BRUTEFORCE_MODULE, cfg->filename);
				
	return 0;
}
static int basic_bf_post_setup(void *ctx, void *data)
{
	basic_bf_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;
        xmlDocPtr setup_xml = NULL;
        xmlXPathContext *xpathctx;
        xmlXPathObject *xpathObj;
        int index = 0;
	apr_pool_t *cfg_pool = NULL;
	
	if (stressy_ctx == NULL) return -1;
	cfg = (basic_bf_t *)module_retrieve_setup(stressy_ctx->pool, BASIC_AUTH_BRUTEFORCE_MODULE);
	if (cfg == NULL) return -1;	

	if (cfg->filename == NULL) return -1;

       	setup_xml = xmlParseFile(cfg->filename);
        if (setup_xml == NULL) return -1;

	xpathctx = xmlXPathNewContext((xmlDocPtr)setup_xml);
	xpathObj = xmlXPathEvalExpression((xmlChar *)CREDENTIAL_XPATH, xpathctx);

	cfg->num_credential = xpathObj->nodesetval->nodeNr;
	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] Using %i login/pass definition", BASIC_AUTH_BRUTEFORCE_MODULE, cfg->num_credential);
        if (cfg->num_credential <= 0) return 0;

        cfg->list = (credential_t **) apr_pcalloc(stressy_ctx->pool, cfg->num_credential * sizeof(credential_t *));
        if (cfg->list == NULL) return -1;
	
	apr_pool_create(&cfg_pool, NULL);
	
	for (index = 0; index < cfg->num_credential; index++) {
		xmlNode *node = NULL;
		xmlChar *login = NULL;
		xmlChar *pass = NULL;
		credential_t *credential = NULL;
		char *tmp = NULL;
		
		node = xpathObj->nodesetval->nodeTab[index];
           	login = xmlGetProp(node, BAD_CAST"login");
		pass = xmlGetProp(node, BAD_CAST"password");
              	if (login == NULL) {
			index--;
			continue;
               	}
               
		credential = (credential_t *)apr_pcalloc(stressy_ctx->pool, sizeof(credential_t));
		credential->login = apr_pstrdup(stressy_ctx->pool, (char *)login);
		if (pass == NULL) credential->password = apr_pstrdup(stressy_ctx->pool, (char *)login);
		else credential->password = apr_pstrdup(stressy_ctx->pool, (char *)pass);

		tmp = apr_psprintf(cfg_pool, "%s:%s", credential->login, credential->password ? credential->password : "");	
		credential->base64_line = apr_pcalloc(stressy_ctx->pool, apr_base64_encode_len(strlen(tmp)));
		apr_base64_encode((char *)credential->base64_line, tmp, strlen(tmp));
		
		LOG_ERR(DEBUG, stressy_ctx->logs, "[%s] (%i) found login: %s pass: %s", BASIC_AUTH_BRUTEFORCE_MODULE, index, credential->login, credential->password);
		cfg->list[index] = credential;
	}

        hook_add(stressy_ctx->after_receive, "basic auth bruteforce exec", basic_exec);
	
	return 0;
}

static int basic_bf_setup(void *ctx, void *data)
{
	basic_bf_t *cfg = NULL;
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	if (stressy_ctx == NULL) return -1;

	cfg = (basic_bf_t *)apr_pcalloc(stressy_ctx->pool, sizeof(basic_bf_t));
	if (cfg == NULL) return -1;

	cfg->filename = NULL;
	cfg->num_credential = 0;

        setup_add_directive(stressy_ctx->prog_setup, "basic_auth_bruteforce", SETUP_CLI_NEED_1, basic_lp_file,
                               	"=login/pass_file.xml enable form auth bruteforce");
	
	if (module_set_setup(stressy_ctx->pool, BASIC_AUTH_BRUTEFORCE_MODULE, (void *)cfg) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to set cfg for module: %s", BASIC_AUTH_BRUTEFORCE_MODULE);
		return -1;
	}

	hook_add(stressy_ctx->post_setup, "basic auth bruteforce post setup", basic_bf_post_setup);
	
	return 0;
}


#ifdef HAVE_BASIC_AUTH_BRUTEFORCE_SHARED
extern int module_init(void *ctx)
{
#else
extern int basic_auth_bruteforce_module_init(void *ctx)
{
#endif
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)ctx;

	if (stressy_ctx == NULL) return -1;

	hook_add(stressy_ctx->setup, "basic auth bruteforce module", basic_bf_setup);
	
	return 0;
}
	
