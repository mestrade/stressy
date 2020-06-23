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

#include "setup.h"

/*
 * apr related includes
 *
 */
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_hash.h"

#define SETUP_ERROR                     -1
#define SETUP_POOL_ERROR                -2
#define SETUP_ALLOC_ERROR               -3
#define SETUP_DIRECTIVE_ALREADY_INSIDE  -4
#define SETUP_BAD_DIRECTIVE             -5

/*
 * libxml2 related includes
 *
 */
#include "libxml/tree.h"

typedef struct setup_item_t setup_item_t;

/*
 * Maximum directive inside setup
 *
 */
#define MAX_SETUP_ITEM	64

/*
 * Setup item contain keyword and function to launch
 *
 */
struct setup_item_t {

	/*
	 * Keyword used for -keyword in cli or as tag name in xml
	 *
	 */
	char *keyword;

	/*
	 * function launched to setup
	 * First arg receive the cli value or the xml elem
	 *
	 */
	int (*fct)(void *, void *, int);

	/*
	 * What is the directive for
	 *
	 */
	const char *info;

	/*
	 * Type, can need 1 arg or nothing
	 *
	 */
	int type;
};


struct setup_t	{

	/*
	 * Pool of the setup
	 *
	 */
	apr_pool_t *pool;
	
	/*
	 * Number of setup item 
	 *
	 */
	int num_item;

	/*
	 * hash table containing all keyword
	 *
	 */
	apr_hash_t *keyword_hash;

	/*
	 * List of directives
	 *
	 */
	setup_item_t **list;

	/*
	 * Setup cli
	 *
	 */
	int argc;
	char **argv;

	/*
	 * xml setup
	 *
	 */
	xmlDocPtr xml_doc;
};

extern char *setup_get_tag_value(apr_pool_t *pool, xmlNodePtr node, char *name)
{
	char *active = NULL;
	
	if (!node) return NULL;
	
	active = (char *)xmlGetProp(node, BAD_CAST "active");
	if (active == NULL) return NULL;
	if (strncasecmp(active, "no", strlen(active)) == 0) return NULL;
        return (char *)xmlGetProp(node, BAD_CAST name);
}

extern int setup_init(setup_t **setup)
{
	setup_t *new = NULL;
	apr_pool_t *pool = NULL;
	
	apr_pool_create(&pool, NULL);
	if (!pool) return SETUP_POOL_ERROR;	

	new = apr_pcalloc(pool, sizeof(setup_t));
	if (!new) return SETUP_ALLOC_ERROR;

	new->pool = pool;
	new->keyword_hash = apr_hash_make(pool);
	new->num_item = 0;
	
	new->list = apr_pcalloc(pool, MAX_SETUP_ITEM * sizeof(setup_item_t *));
	if (!new->list) return SETUP_ALLOC_ERROR;
	
	*setup = new;
	return 0;
}

static int init_setup_item(apr_pool_t *pool, setup_item_t **item)
{
	setup_item_t *new = NULL;

	if (!pool) return SETUP_POOL_ERROR;
	
	new = apr_pcalloc(pool, sizeof(setup_item_t));
	if (!new) return SETUP_ALLOC_ERROR;

	new->fct = NULL;
	new->keyword = NULL;

	*item = new;
	return 0;
}

extern int setup_add_directive(setup_t *setup, char *keyword, int type, int (*fct)(void *, void *, int), const char *info)
{
	setup_item_t *directive = NULL;
	
	if (!setup || !keyword) return SETUP_ERROR;
	if (!setup->keyword_hash) return SETUP_ERROR;

	if (apr_hash_get(setup->keyword_hash, keyword, strlen(keyword)) != NULL) return SETUP_DIRECTIVE_ALREADY_INSIDE;
	
	if (init_setup_item(setup->pool, &directive) < 0) return SETUP_ALLOC_ERROR;
	
	directive->keyword = apr_pstrdup(setup->pool, keyword);
	directive->fct = fct;
	directive->info = apr_pstrdup(setup->pool, info);
	directive->type = type;
	
	apr_hash_set(setup->keyword_hash, keyword, strlen(keyword), directive);
	setup->list[setup->num_item] = directive;
	setup->num_item++;
	
	return setup->num_item;
}

extern int setup_set_cli_info(setup_t *setup, int argc, char **argv)
{
	if (!setup || argc <= 0) return SETUP_ERROR;

	setup->argc = argc;
	setup->argv = argv;

	return 0;
}

extern int setup_set_cli_xml(setup_t *setup, char *filename)
{
	if (!setup || !filename) return SETUP_ERROR;

	setup->xml_doc = xmlParseFile(filename);
	
	return 0;
}

extern int setup_run_cli(setup_t *setup, void *data, char **bad_directive)
{
	int index_arg = 0;
	
	/*
	 * Look cli setup
	 */ 
	if (setup->argc <= 0 || !setup->argv) return -1;

	/*
	 * We start at 1 coz argv[0] is the prog name
	 *
	 */
	for (index_arg = 1; index_arg < setup->argc; index_arg++) {
		setup_item_t *directive = NULL;
		
		char *key = NULL;
		char *arg = NULL;
		
		if ((arg = memchr(setup->argv[index_arg], '=', strlen(setup->argv[index_arg])))) {
			/* find key */
			key = apr_pstrndup(setup->pool, setup->argv[index_arg], arg - setup->argv[index_arg]);
			/* set argument after the = */
			arg++;

		}	
		else {
			key = setup->argv[index_arg];
		}
		
		/* go after the - */
		key++;
		directive = apr_hash_get(setup->keyword_hash, key, strlen(key));
		
		/*
		 * No directive for this keyword
		 *
		 */
		if (!directive) {
			fprintf(stderr, "[ERROR] Unknown directive: %s\n", key);
			return -1;;
		}
		if (!directive->fct) {
			fprintf(stderr, "[ERROR] Directive without effect: %s\n", key);
			continue;
		}
		
		/* 
		 * Run the directive setup function
		 *
		 */
		if (directive->type == SETUP_CLI_NEED_1 && index_arg == setup->argc) {
			*bad_directive = directive->keyword;
			return -1;
		}
		
		if (directive->type == SETUP_CLI_NEED_1) {
			int res = 0;
			if (directive->fct) {
				res = (directive->fct)(data, arg, SETUP_CLI);
			}
			if (res < 0) {
				fprintf(stderr, "Error while executing directive: %s (errno: %i)\n", directive->keyword, res);
				return -1;
			}
		}
		else {
			int res = 0;
			
			if (directive->fct) {
				res = (directive->fct)(data, NULL, SETUP_CLI);
			}
			if (res < 0) {
				fprintf(stderr, "Error while executing directive: %s (errno: %i)\n", directive->keyword, res);
				return -1;
			}
		}
	}
	
	return 0;
}

extern int setup_run_xml(setup_t *setup, void *data, char **bad_directive)
{
	xmlNodePtr ptr = NULL;
	/*
	 * Look if we have xml file
	 *
	 */
	if (!setup->xml_doc)  {
		return 0;
	}

	ptr = setup->xml_doc->children;
	
	for (ptr = ptr->children; ptr ; ptr = ptr->next) {
		setup_item_t *directive = NULL;
		xmlChar *active = NULL;

		
		if (!ptr->name) continue;

		active = xmlGetProp(ptr, BAD_CAST"active");
		if (active != NULL && strncasecmp((char *)active, "no", strlen((char *)active)) == 0) continue;

		directive = apr_hash_get(setup->keyword_hash, ptr->name, strlen((char *)ptr->name));
		if (!directive) {
			continue;
		}
			
		if (directive->fct) (directive->fct)(data, ptr, SETUP_XML);
	}
	
	return 0;
}

extern int setup_display_options(setup_t *setup)
{
	int index = 0;
	
	if (!setup) return SETUP_ERROR;
	
	if (setup->num_item <= 0) {
		fprintf(stderr, "No directive available\n");
		return -1;
	}
	
	for (index = 0; index < setup->num_item; index++) {
		if (setup->list[index]->type == SETUP_CLI_NEED_0) {
			fprintf(stderr, "-%s %s\n", setup->list[index]->keyword, setup->list[index]->info);
		}
		else {
			fprintf(stderr, "-%s%s\n", setup->list[index]->keyword, setup->list[index]->info);
		}
	}
	
	return 0;
}

extern char *setup_get_error(int code)
{
	if (code == SETUP_ERROR) return "setup error";
	if (code == SETUP_POOL_ERROR) return "setup pool error";
	if (code == SETUP_ALLOC_ERROR) return "setup alloc error";
	if (code == SETUP_DIRECTIVE_ALREADY_INSIDE) return "setup directive already exist";

	return NULL;
}

