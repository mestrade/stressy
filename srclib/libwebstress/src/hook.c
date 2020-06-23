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

#include "hook.h"

#include <stdio.h>
#include "apr_pools.h"
#include "apr_strings.h"

typedef struct hook_item *hook_item_t;


struct hook_list {

        apr_pool_t *pool;
        int num_hook;
        hook_item_t first;
        hook_item_t last;

};

struct hook_item {

        hook_item_t prev;

        char *name;
        int (*fct)(void *, void *);

        hook_item_t next;

};

extern int hook_list_init(hook_list_t *hook_list)
{
	hook_list_t new;
	
	apr_pool_t *new_pool;

	apr_pool_create(&new_pool, NULL);

	if((new = apr_pcalloc(new_pool, sizeof(struct hook_list))) == NULL) {
		return -1;
	}

	*hook_list = new;
	new->pool = new_pool;
	return 0;
}

static int hook_item_init(apr_pool_t *pool, hook_item_t *item)
{
	hook_item_t new;

	if ((new = apr_pcalloc(pool, sizeof(struct hook_item))) == NULL) {
		return -1;
	}

	*item = new;
	new->name = NULL;
	new->fct = NULL;
	new->prev = NULL;
	new->next = NULL;
	return 0;
}

extern int hook_add(hook_list_t list, char *name, int (*fct)(void *, void*))
{
	hook_item_t new_item;
	
	if (!list || !name || !fct) {
		fprintf(stderr, "Error when adding new hook");
		return -1;
	}

	if (!list->first) {
		if (hook_item_init(list->pool, &list->first) < 0) {
			fprintf(stderr, "Error when adding new hook");
			return -1;
		}
		list->first->name = apr_pstrdup(list->pool, name);
		list->first->fct = fct;
		list->num_hook++;
		list->last = list->first;
		return 0;
	}	

	if (!list->last) {
		fprintf(stderr, "Error when adding new hook");
		return -1;
	}
	if (hook_item_init(list->pool, &new_item) < 0) {
		fprintf(stderr, "Error when adding new hook");
		return -1;
	}
	
	new_item->name = apr_pstrdup(list->pool, name);
	new_item->fct = fct;
	list->last->next = new_item;
	new_item->prev = list->last;
	list->last = new_item;
	list->num_hook++;
	
	return 0;
}

extern int hook_run_all(hook_list_t list, void *ctx, void *data)
{
	int i = 0;
	hook_item_t ptr = NULL;

	if (!list) {
		fprintf(stderr, "Error running hook: invalid list\n");
		return -1;
	}
	
	if (!list->first) {
		return -1;
	}

	ptr = list->first;
	
	for (i = 0; i < list->num_hook; i++) {

		if (ptr == NULL) {
			continue;
		}
	
		if(ptr->fct != NULL) {
			(ptr->fct)(ctx,data);	
		}
		ptr = ptr->next;
	}

	return 0;
}
