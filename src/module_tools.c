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

#include "module_tools.h"

extern void *module_retrieve_setup(apr_pool_t *pool, const char *name)
{
	void *data = NULL;
	apr_pool_userdata_get((void **)&data, name, pool);
	return data;
}

extern int module_set_setup(apr_pool_t *pool, const char *name, void *data)
{
	apr_pool_userdata_set((void *)data, name, NULL, pool);
	return 0;
}

extern int module_get_setup(apr_pool_t *pool, const char *name, void **data)
{
	void *ptr = NULL;
	
	apr_pool_userdata_get((void **)&ptr, name, pool);
	if (!ptr) return -1;

	*data = ptr;
	return 0;
}
