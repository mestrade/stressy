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

#include "variables.h"

#include <stdio.h>
#include <string.h>
#include "apr_strings.h"

extern int var_list_add(var_list_t *list, var_item_t *item)
{

        if (!list| !item) return -1;

        if (!list->first_var) {
                list->first_var = item;
                item->prev = NULL;
                item->next = NULL;
                list->last_var = item;
                list->num_var++;
                return 0;
        }

        if (!list->last_var) return -1;
        list->last_var->next = item;
        item->prev = list->last_var;
        list->last_var = item;
        list->num_var++;
        return 0;
}

extern int var_item_init(apr_pool_t *pool, var_item_t **item)
{
        var_item_t *new;

        if (!pool) return -1;
        if ((new = apr_pcalloc(pool, sizeof(struct var_item))) == NULL) {
                return -1;
        }
        *item = new;
        new->name = NULL;
        new->value = NULL;
        return 0;
}

extern int var_list_init(apr_pool_t *pool, var_list_t **list)
{
	var_list_t *new = NULL;

        if (pool == NULL) return -1;
        if((new = apr_pcalloc(pool, sizeof(struct var_list))) == NULL) {
                return -1;
        }

	//apr_pool_create(&new->pool, NULL);
	new->pool = pool;
	new->num_var = 0;
	new->first_var = NULL;
	new->last_var = NULL;
	*list = new;
	return 0;
}

extern int var_check_type(var_item_t *item, char *type)
{

	if (type == NULL || item == NULL || item->type == NULL) return -1;

	if (strncmp(item->type, type, strlen(type)) == 0) return 0;

	return -1;
}
