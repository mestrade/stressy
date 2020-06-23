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

#ifndef DIRECTORY_DISCOVERY_H
#define DIRECTORY_DISCOVERY_H

#include "request.h"
#include "site_map.h"

#define MAX_DIR	1024

typedef struct directory_discovery *directory_discovery_t;
typedef struct level_ctx_t level_ctx_t;

extern int directory_discovery_insert(void *ctx, void *data);
extern int directory_discovery_detect(void *ctx, void *data);
extern int directory_discovery_setup(void *ctx, void *data);

#ifndef HAVE_DISCOVERY_SHARED
extern int discovery_module_init(void *ctx);
#endif

struct level_ctx_t {
	
	request_t *request;
	level_item_t *level;

};

struct directory_discovery {

	char *filename;
	apr_table_t *directory_list;
	
};

#endif
