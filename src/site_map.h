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

#ifndef SITE_MAP_H
#define SITE_MAP_H

#include "modules_export.h"
#include "logs.h"
#include "hook.h"

#include "libxml/tree.h"

#define R_FILE		0
#define R_DIRECTORY	1

typedef struct site_map_t site_map_t;
typedef struct level_item_t level_item_t;
typedef struct level_t level_t;

extern int init_map(site_map_t **map);
extern int site_map_is_xml(site_map_t *map);
extern int site_map_save_xml(site_map_t *map, char *filename);
extern int site_map_insert_request(site_map_t *map, char *uri, char *method, char *clean_request, char *post_arg, void *data);
extern int site_map_set_logs(site_map_t *map, logs_t logs);
extern int is_request_in_map(site_map_t *map, char *method, char *clean_request, char *post_arg);
extern int site_map_set_hook(site_map_t *map, hook_list_t level, hook_list_t request);



struct level_item_t {

apr_pool_t *pool;

level_item_t *prev;
level_item_t *parent;
int type;
char *value;
char *full_path;
xmlNodePtr node;
int num_child;
level_item_t *next;
level_item_t *children;

};

struct level_t {
apr_pool_t *pool;
int num;
apr_hash_t *item_table;
level_item_t **item_list;
level_t *children;
level_t *parent;
};










#endif

