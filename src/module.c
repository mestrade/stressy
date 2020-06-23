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

#include "module.h"
#include "config.h"
#include "stressy_ctx.h"

/* List of possible builtin modules */
#include "modules/crawler2/crawler.h"
#include "modules/var_stress/var_stress.h"
#include "modules/error_detect/error_msg_detect.h"
#include "modules/form_auto_fill/form_auto_fill.h"
#include "modules/discovery/discovery.h"
#include "modules/hexa_encoder/hexa_encoder.h"
#include "modules/form_auth_bruteforce/form_auth_bruteforce.h"
#include "modules/request_check/request_check.h"
#include "modules/basic_auth_bruteforce/basic_auth_bruteforce.h"
#include "modules/fuzzer/fuzzer.h"

/* APR related include */
#include "apr_pools.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_file_info.h"
#include "apr_dso.h"

typedef struct module_t module_t;

struct module_t {

	apr_pool_t *pool;
	
	char *name;
	apr_dso_handle_t *so;
	apr_dso_handle_sym_t load_sym;
	int (*load_fct)(void *);
};

struct module_list_t {

	apr_pool_t *pool;
	logs_t logs;

	int num_modules;
	module_t **list;
	apr_hash_t *hash;

	char *directory;
	
};

extern int module_list_set_logs(module_list_t *list, logs_t logs)
{
	if (!list || !logs) return -1;
	list->logs = logs;
	return 0;
}

/*
 * Init external modules
 *
 */
extern int init_module_list(module_list_t **list)
{
	apr_pool_t *new_pool = NULL;
	module_list_t *new = NULL;
	
	apr_pool_create(&new_pool, NULL);
	if (!new_pool) return -1;

	new = (module_list_t *)apr_pcalloc(new_pool, sizeof(module_list_t));
	if (!new) return -2;

	*list = new;
	new->pool = new_pool;
	new->num_modules = 0;
	new->directory = NULL;
	new->list = NULL;

	new->hash = apr_hash_make(new_pool);
	new->directory = (char *)apr_psprintf(new->pool, "%s/libexec/stressy/", STRESSY_BASE);
	if (!new->directory) return -4;
	
	if (!new->hash) return -3;
	
	return 0;
}

extern int module_set_directory(module_list_t *list, char *dir)
{
	if (!list) return -1;
	list->directory = apr_pstrdup(list->pool, dir);
	return 0;
}

extern char *module_get_directory(module_list_t *list)
{
	if (!list) return NULL;
	return list->directory; 
}

/*
 * Init module
 *
 */
static int init_module(apr_pool_t *pool, module_t **module)
{
	module_t *new = NULL;

	if (!pool) return -1;
	new = apr_pcalloc(pool, sizeof(module_t));
	if (!new) return -2;

	*module = new;
	new->name = NULL;
	
	return 0;
}


/*
 * Scan module directory in order to load all modules inside
 *
 */
extern int module_load_directory(module_list_t *list)
{
	apr_dir_t *dir = NULL;
	apr_status_t rc;
	int index_module = 0;
	
	if (!list) return -1;
	if (!list->directory) return -2;
	
	rc = apr_dir_open(&dir, list->directory, list->pool);
	if (rc != APR_SUCCESS) return 0;

	do {	
		apr_finfo_t finfo;
		int name_len = 0;
		
		rc = apr_dir_read(&finfo, APR_FINFO_NAME|APR_FINFO_TYPE, dir);
		if (!finfo.name) continue;
		if (strncasecmp(finfo.name, "lib", 3) != 0) continue;
		name_len = strlen(finfo.name);
		if (finfo.name[name_len - 1] == 'o' 
				&& finfo.name[name_len - 2] == 's' 
				&& finfo.name[name_len - 3] == '.') {
			list->num_modules++;
		}	
	} while (rc == APR_SUCCESS);
	
	if (list->num_modules <= 0) return 0;
	
	list->list = (module_t **)apr_pcalloc(list->pool, list->num_modules * sizeof(module_t *));
	if (!list->list) return -4;

	/*
	 * We come back to the first entry
	 *
	 */	
	apr_dir_rewind(dir);

	/*
	 * Then now, load modules
	 *
	 */
	for (index_module = 0; index_module < list->num_modules; ) {
		apr_finfo_t finfo;
		int name_len = 0;
		
		apr_dir_read(&finfo, APR_FINFO_NAME, dir);
		if (strncasecmp(finfo.name, "lib", 3) != 0) continue;
		name_len = strlen(finfo.name);
		if (finfo.name[name_len - 1] == 'o' && finfo.name[name_len - 2] == 's' 
				&& finfo.name[name_len - 3] == '.') {

			/*
			 * Setup new module
			 *
			 */
			module_t *module = NULL;
			
			if (init_module(list->pool, &list->list[index_module]) < 0) return -5;
			module = list->list[index_module];
			module->name = apr_psprintf(list->pool, "%s/lib/%s", STRESSY_BASE, finfo.name);
			rc = apr_dso_load(&module->so, module->name, list->pool);
			if (rc != APR_SUCCESS) {
				char buff[256];
				/*
				 * If unable to load the shared object
				 *
				 */
				
				apr_dso_error(module->so, buff, 256);
				fprintf(stderr, "Error on module %s: %s\n", module->name, buff);
				return -5;	
			}		
		
			rc = apr_dso_sym(&module->load_sym, module->so, "module_init");
			if (rc != APR_SUCCESS) {
				char buff[256];
				/*
				 * If unable to load the shared object
				 *
				 */
				
				apr_dso_error(module->so, buff, 256);
				fprintf(stderr, "Error on module %s: %s\n", module->name, buff);
				return -6;	
			}
			
			module->load_fct = module->load_sym;
			LOG_ERR(NOTICE, list->logs, "Module %s loaded", module->name);		
	
			index_module++;
		}
	}
	
	return list->num_modules;
}

extern int module_load_builtin(void *data)
{
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)data;
	int res = 0;

	if (stressy_ctx == NULL) return -1;

	LOG_ERR(NOTICE, stressy_ctx->logs, "Loading builtin modules");
	
#ifdef HAVE_CRAWLER2
	res = crawler2_module_init(data);
	if (res < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting crawler2 module");
		return -1;
	}
#endif
#ifdef HAVE_VAR_STRESS
	res = var_stress_module_init(data);
	if (res < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting var_stress module");
		return -1;
	}
#endif
#ifdef HAVE_ERR_DETECT
	res = err_detect_module_init(data);
	if (res < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting err_detect module");
		return -1;
	}
#endif
#ifdef HAVE_FORM_AUTO_FILL
        res = form_auto_fill_module_init(data);
        if (res < 0) {
                LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting form_auto_fill module");
                return -1;
        }
#endif			
#ifdef HAVE_DISCOVERY
        res = discovery_module_init(data);
        if (res < 0) {
                LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting discovery module");
                return -1;
        }
#endif			
#ifdef HAVE_HEXA_ENCODER
        res = hexa_encoder_module_init(data);
        if (res < 0) {
                LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting hexa_encoder module");
                return -1;
        }
#endif			
#ifdef HAVE_FORM_AUTH_BRUTEFORCE
        res = form_auth_bruteforce_module_init(data);
        if (res < 0) {
                LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting form_auth_bruteforce module");
                return -1;
        }
#endif			
#ifdef HAVE_BASIC_AUTH_BRUTEFORCE
        res = basic_auth_bruteforce_module_init(data);
        if (res < 0) {
                LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting basic_auth_bruteforce module");
                return -1;
        }
#endif			
#ifdef HAVE_REQUEST_CHECK
        res = request_check_module_init(data);
        if (res < 0) {
                LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting form_auth_bruteforce module");
                return -1;
        }
#endif
#ifdef HAVE_FUZZER
	res = parameter_fuzzer_init(data);
        if (res < 0) {
                LOG_ERR(CRIT, stressy_ctx->logs, "Unable to load buiting parameter fuzzer module");
                return -1;
        }
#endif
		
	return 0;
}

extern int module_run_all_init(module_list_t *list, void *data)
{
	int index_module = 0;
	
	if (!list) return -1;

	if (list->num_modules <= 0) return 0;

	for (index_module = 0; index_module < list->num_modules; index_module++) {
		module_t *module;
		
		module = list->list[index_module];
		if (!module->load_fct) continue;

		/* 
		 * Execute load fct of the module
		 *
		 */
		(module->load_fct)(data);
	}

	return 0;
}
