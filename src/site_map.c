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

#include "site_map.h"
#include "config.h"
#include "request.h"
#include "stressy_ctx.h"

struct site_map_t {
        apr_thread_mutex_t *lock;
        apr_pool_t *pool;
        apr_hash_t *ressource_table;
        level_item_t *root;
        xmlDocPtr doc;
	logs_t logs;

	hook_list_t level_inserted;
        hook_list_t request_inserted;

};

extern int site_map_set_hook(site_map_t *map, hook_list_t level, hook_list_t request)
{
	if (map == NULL) return -1;
	map->level_inserted = level;
	map->request_inserted = request;
	return 0;
}

extern int site_map_set_logs(site_map_t *map, logs_t logs)
{
	if (map == NULL || logs == NULL) return -1;
	map->logs = logs;
	return 0;
}

extern int site_map_save_xml(site_map_t *map, char *filename)
{
	if (filename == NULL || map == NULL) return -1;
	if (xmlSaveFormatFile(filename, map->doc, 1) < 0) return -1; 
        xmlFreeDoc(map->doc);
	return 0;
}

extern int site_map_is_xml(site_map_t *map)
{
	if (map == NULL || map->doc == NULL) return -1;
	return 0;
}

static int item_add_child(level_item_t *item, level_item_t *child)
{
	level_item_t *ptr;

	if (!child || !item) return -1;

	if (!item->children) {
		item->type = R_DIRECTORY;
		item->children = child;
		child->parent = item;
		item->num_child++;
		return 0;
	}

	for (ptr = item->children; ptr; ptr = ptr->next) {
		
		if (!ptr->value || !child->value) {
			return -1;
		}
		
		if ((strncasecmp(ptr->value, child->value, strlen(ptr->value)) == 0)
			&& strncasecmp(ptr->full_path, child->full_path, strlen(ptr->full_path)) == 0) {
			return -1;
		}
		if (!ptr->next) {
			ptr->type = R_DIRECTORY; 
			ptr->next = child;
			child->parent = item;
			item->num_child++;
			return 0;
		}
	}

	return -1;
}

static int item_is_child(level_item_t *item, char *value, level_item_t **found)
{
	level_item_t *ptr;

	if (!value||!item) return -1;

	for (ptr = item->children; ptr; ptr = ptr->next) {
		if (strncasecmp(ptr->value, value, strlen(ptr->value)) == 0) {
			*found = ptr;
			return 0;
		}
	}
	
	return -1;
}


static int get_children_directory(xmlNodePtr children, xmlNodePtr *children_ok)
{
	char *prop = NULL;
	
	if (!children) return -1;
	
	while (children) {
		prop = (char *) xmlGetProp(children, BAD_CAST "type");
		if (!prop) {
			children = children->next;
			continue;
		}

		if (strcmp(prop, "directory") == 0) {
			*children_ok = children;
			return 0;
		}	
		children = children->next;
	}
	return -1;
}

static int get_children_directory_name(xmlNodePtr children, xmlNodePtr *children_ok, char *name)
{
	char *prop = NULL;
	char *value = NULL;
	
	if (!children || !name) return -1;
	
	while (children) {
		prop = (char *) xmlGetProp(children, BAD_CAST "type");
		if (!prop) {
			children = children->next;
			continue;
		}

		if (strcmp(prop, "directory") == 0) {
			value = (char *) xmlGetProp(children, BAD_CAST "value");
			if (!value) {
				children = children->next;
				continue;
			}

			if (strncmp(value, name, strlen(name)) == 0) {
				*children_ok = children;
				return 0;
			}
		}	
		children = children->next;
	}
	return -1;
}


extern int init_map(site_map_t **map)
{
	apr_pool_t *new_pool;
	site_map_t *new;

	apr_pool_create(&new_pool, NULL);
		
	if ((new = apr_pcalloc(new_pool, sizeof(site_map_t))) == NULL) {
		return -1;
	}

	*map = new;
	new->pool = new_pool;
	apr_thread_mutex_create(&new->lock, APR_THREAD_MUTEX_DEFAULT, new_pool);
	new->doc = NULL;

	if ((new->ressource_table = apr_hash_make(new->pool)) == NULL) return -1;
	return 0;
}


extern int init_item(apr_pool_t *pool, level_item_t **item)
{
	level_item_t *new;

	if (!pool) return -1;

	if ((new = apr_pcalloc(pool, sizeof(level_item_t))) == NULL) {
		return -1;
	}
	
	apr_pool_create(&new->pool, pool);
	
	*item = new;
	new->children = NULL;
	new->num_child = 0;
	new->full_path = NULL;
	new->next = NULL;
	new->prev = NULL;
	new->parent = NULL;
	
	return 0;
}

extern int is_request_in_map(site_map_t *map, char *method, char *clean_request, char *post_arg)
{
	char *url = NULL;
	apr_pool_t *pool;
	
	if (map == NULL || clean_request == NULL) {
		return -1;
	}
	
	apr_pool_create(&pool, NULL);
	
	url = apr_psprintf(pool, "%s %s %s", method ? method : "GET", clean_request, post_arg ? post_arg : "NO-POST");
	
        apr_thread_mutex_lock(map->lock);
	LOG_ERR(DEBUG, map->logs, "Searching for key: %s", url);
	if (apr_hash_get(map->ressource_table, url, strlen(url)) == NULL) {
		LOG_ERR(DEBUG, map->logs, "Request %s is not in map", 
				url, apr_hash_count(map->ressource_table));
	        
		apr_thread_mutex_unlock(map->lock);
		apr_pool_destroy(pool);
		return 0;
	}
        apr_thread_mutex_unlock(map->lock);
		
	apr_pool_destroy(pool);
	return -1;
}

extern int add_request_in_map(site_map_t *map, char *method, char *clean_request, char *post_arg)
{
	char *url = NULL;
	
	if (map == NULL || clean_request == NULL) {
		return -1;
	}

	LOG_ERR(DEBUG, map->logs, "Add in map: method: %s path: %s arg: %s", method, clean_request, post_arg);

	url = apr_psprintf(map->pool, "%s %s %s", method ? method : "GET", clean_request, post_arg ? post_arg : "NO-POST");
	
	apr_thread_mutex_lock(map->lock);
	apr_hash_set(map->ressource_table, url, strlen(url), "INSERTED");
	LOG_ERR(DEBUG, map->logs, "Request %s is now in map", 
				url, apr_hash_count(map->ressource_table));
	apr_thread_mutex_unlock(map->lock);
	
	return 0;
}

extern int site_map_insert_request(site_map_t *map, char *uri, char *method, char *clean_request, char *post_arg, void *data)
{
	char *level_ptr;
	char *level_next_slash;
	int num_level = 0;
	xmlNodePtr node = NULL;
	level_item_t *found_level = NULL;
	level_item_t *item_ptr = NULL;
	//request_t *r = (request_t *)data;
	
	if (uri == NULL) {
		LOG_ERR(CRIT, map->logs, "Unable to add uri inside map without uri");
		return -1;
	}

	if (add_request_in_map(map, method, clean_request, post_arg) < 0) return -1;

	apr_thread_mutex_lock(map->lock);
	
	/*
	 * Create xml doc
	 *
	 */
	if (map->doc == NULL) {
		map->doc = xmlNewDoc(BAD_CAST "1.0");
		LOG_ERR(DEBUG, map->logs, "XML Doc created");
		node = xmlNewNode(NULL, BAD_CAST "root");
		xmlDocSetRootElement(map->doc, node);
	}

	level_ptr = uri + 1;
	
	node = xmlDocGetRootElement(map->doc);

	if (!map->root) {
		if (init_item(map->pool, &map->root) < 0) {
			apr_thread_mutex_unlock(map->lock);
			return -1;
		}
		map->root->value = apr_pstrdup(map->pool, "root");
		map->root->full_path = apr_pstrdup(map->pool, "root");
		map->root->node = node;
	
		//r->ressource_level = map->root;
		hook_run_all(map->level_inserted, data, map->root);
	}	
	item_ptr = map->root;

	for (num_level = 0; num_level < 10; num_level ++) {
		char *item_name = NULL;
		int len = 0;
		char *id_buff = NULL;	

		/* look if we are at the last level or not and insert it */	
		if (!(level_next_slash = memchr(level_ptr, '/', strlen(level_ptr)))) {
			
			if (*level_ptr == 0) { 
				/*
				 * Create a fake level_item with no value and the correct full path
				 * The node pointing on previous node, root for the first level
				 */

				if (item_is_child(item_ptr, level_ptr, &found_level) == 0) break;
				
				LOG_ERR(DEBUG, map->logs, "Seems we have a new empty level %s - map on previous", uri);
				//r->ressource_level = item_ptr;
				break;
			}
			LOG_ERR(DEBUG, map->logs, "We are at the last level: (%s)", level_ptr);
			
			if (item_is_child (item_ptr, level_ptr, &found_level) < 0) {
				level_item_t *item;
				init_item(map->pool, &item);
				xmlNodePtr new_node = NULL;
				
				item->value = apr_pstrdup(map->pool, level_ptr);

				/*
				 * 
				len = level_next_slash - uri;
				if (len < 0) {
					LOG_ERR(CRIT, store->logs, "Found level len(%i) < 0 - level1: %s", len, level_ptr);
					return -1;
				}
				item->full_path = apr_pstrndup(store->pool, uri, len);
				*/
				item->full_path = apr_pstrdup(map->pool, uri);
				
				if (level_ptr[strlen(level_ptr) - 1] == '/') {
					item->type = R_DIRECTORY;
					LOG_ERR(DEBUG, map->logs, "Last level is a directory");
				}
				else {	
					item->type = R_FILE;
				}

				/*
				 * Now fill the xml node
				 *
				 */
				
				
				LOG_ERR(DEBUG, map->logs, "Actual node is %s", node->name);		
				new_node = xmlNewNode(NULL, BAD_CAST "resource");
				xmlNewProp(new_node, BAD_CAST "id", BAD_CAST id_buff);
				
				if (item->type == R_FILE) {
					LOG_ERR(DEBUG, map->logs, "Create a file node");
					xmlNewProp(new_node, BAD_CAST "type", BAD_CAST "file");
				}
				else {
					LOG_ERR(DEBUG, map->logs, "Create a directory node");
					xmlNewProp(new_node, BAD_CAST "type", BAD_CAST "directory");
				}
				xmlNewProp(new_node, BAD_CAST "value", BAD_CAST item->value);
				xmlNewProp(new_node, BAD_CAST "full_path", BAD_CAST item->full_path);	

				if (!node) {
					LOG_ERR(CRIT, map->logs, "Unable to find parent node - exit");
					apr_thread_mutex_unlock(map->lock);
				return -1;
				
				if (!node->children) {
					LOG_ERR(DEBUG, map->logs, "No children node - add first child");
					xmlAddChild(node, new_node);
				}
				else {
					xmlNodePtr insert_node;
					if (get_children_directory(node->children, &insert_node) < 0) {
					/*
					 *  XXX fixme: if the only level inserted is a file 
					 *  and we have to insert a child to a file 
					 */	
						xmlAddChild(node, new_node);
				}
					else {	
						LOG_ERR(DEBUG, map->logs, "Already a children - add next");
						xmlAddPrevSibling(insert_node, new_node);
					}
				}
				LOG_ERR(DEBUG, map->logs, "This last level %s is not inserted - inserting", item->value);
				item->node = new_node;
			}
				//r->ressource_level = item;
				item_add_child(item_ptr, item);
				LOG_ERR(DEBUG, map->logs, "Last Item %s inserted as child - current item %s has now %i children", 
								item->value, item_ptr->full_path, item_ptr->num_child);	
		
				hook_run_all(map->level_inserted, data, item);
							
			}
			else {
				//r->ressource_level = found_level;
				LOG_ERR(DEBUG, map->logs, "This item is already inside level %i - link request to ressource level %s", 
						num_level, found_level->value);
			}
			break;
		}

		
		/* seems we are not in the last level */	
		if (*level_ptr == 0) {
			level_ptr = level_next_slash + 1;	
			continue;
		}
	
		len = level_next_slash - level_ptr;
		if (len < 0) {
			LOG_ERR(CRIT, map->logs, "Found level len(%i) < 0 - level2: %s", len, level_ptr);
			return -1;
		}
		item_name = apr_pstrndup(map->pool, level_ptr, len);
		
		LOG_ERR(DEBUG, map->logs, "Work on level(%i): %s - actual item ptr is %s", num_level, item_name, item_ptr->value);
		if (item_is_child(item_ptr, item_name, &found_level) < 0) {
			level_item_t *item;
			init_item(map->pool, &item);
			xmlNodePtr new_node = NULL;
			
			item->value = apr_pstrdup(map->pool, item_name);	
			
			len = level_next_slash - uri;
			if (len < 0) {
				LOG_ERR(CRIT, map->logs, "Found level len(%i) < 0 - level3: %s", len, uri);
				return -1;
			}
			item->full_path = apr_pstrndup(map->pool, uri, len);
			item->type = R_DIRECTORY;

			if (item_add_child(item_ptr, item) < 0) {
				LOG_ERR(CRIT, map->logs, "Unable to insert item in map - exit");
				apr_thread_mutex_unlock(map->lock);
				return -1;
			}
			LOG_ERR(DEBUG, map->logs, "Level(%i)->[%s] inserted - item %s has now %i children", 
					num_level, item->value, item_ptr->full_path, item_ptr->num_child);
			
			LOG_ERR(DEBUG, map->logs, "Actual node is %s", node->name);
			new_node = xmlNewNode(NULL, BAD_CAST "resource");
			xmlNewProp(new_node, BAD_CAST "id", BAD_CAST id_buff);
				
			if (item->type == R_FILE) {
				LOG_ERR(DEBUG, map->logs, "Create a new file node");
				xmlNewProp(new_node, BAD_CAST "type", BAD_CAST "file");
			}
			else {
				LOG_ERR(DEBUG, map->logs, "Create a new directory node");
				xmlNewProp(new_node, BAD_CAST "type", BAD_CAST "directory");
			}
			xmlNewProp(new_node, BAD_CAST "value", BAD_CAST item->value);
		        xmlNewProp(new_node, BAD_CAST "full_path", BAD_CAST item->full_path);
	
			if (!node) {
				LOG_ERR(CRIT, map->logs, "Error while trying to add node - no parent node");
				apr_thread_mutex_unlock(map->lock);
				return -1;
			}
			if (!node->children) {
				LOG_ERR(DEBUG, map->logs, "No children node, add the first one");
				xmlAddChild(node, new_node);
			}
			else {
				xmlNodePtr insert_node;
				if (get_children_directory(node->children, &insert_node) < 0) {
					/* 
					 * XXX fixme: if the only level inserted is a file 
					 * and we have to insert a child to a file 
					 */ 	
					xmlAddChild(node, new_node);
				}
				else {
					LOG_ERR(DEBUG, map->logs, "Already a children - add next");
					xmlAddNextSibling(insert_node, new_node);
				}
			}
			item->node = new_node;
			node = new_node;
		
			item_ptr = item;

			hook_run_all(map->level_inserted, data, item);
				
		}
		else {
			xmlNodePtr next_node_level;
			
			if (get_children_directory_name(node->children, &next_node_level, item_name) < 0) {
				LOG_ERR(DEBUG, map->logs, "Unable to find a node children with value %s", item_name);
				apr_thread_mutex_unlock(map->lock);
				return -1;
			}
			node = next_node_level;
			//r->ressource_level = found_level;	
			LOG_ERR(DEBUG, map->logs, "This item is already inside level %i", num_level);
			item_ptr = found_level;
		}
		
		level_ptr = level_next_slash + 1;
	}

 	hook_run_all(map->request_inserted, data, NULL);
	apr_thread_mutex_unlock(map->lock);
	return 0;
}

/*
extern int site_map_mysql_insert_request(request_t r)
{
#ifdef HAVE_MYSQLCLIENT
        char *sql_query = NULL;
        level_item_t item = (level_item_t)data;
        void *tmp_setup = NULL;
        map_mysql_ctx_t *map_ctx = NULL;
        int res = 0;

        MYSQL_RES *result;

        if (!r || !r->store || !item) return -1;

        if (module_get_setup(r->store->pool, MODULE_KEY_MAP_MYSQL, &tmp_setup) < 0) {
                LOG_ERR(CRIT, r->logs, "Unable to find module ctx");
                return -1;
        }
        map_ctx = (map_mysql_ctx_t *)tmp_setup;


        apr_thread_mutex_lock(r->logs->lock);
        sql_query = apr_psprintf(r->pool, "SELECT * FROM web_app_map where id_web_app='%i' AND full_path='%s'",
                                map_ctx->app_id, item->full_path);

        if ((res = mysql_query(&r->store->mysql_sock, sql_query)) != 0) {
                apr_thread_mutex_unlock(r->logs->lock);
                LOG_ERR(CRIT, r->logs, "Mysql(select) result: %s", mysql_error(&r->store->mysql_sock));
                LOG_ERR(CRIT, r->logs, "Query: %s", sql_query);
                return -1;
        }

        result = mysql_store_result(&r->store->mysql_sock);

        sql_query = apr_psprintf(r->pool, "INSERT INTO web_app_map (id, root_elem, this_elem, full_path, id_web_app)"
                                " VALUES ('', '%s', '%s', '%s', '%i')",
                                item->parent?item->parent->full_path:NULL, item->value, item->full_path,
                                map_ctx->app_id);

        if ((res = mysql_query(&r->store->mysql_sock, sql_query)) != 0) {
                apr_thread_mutex_unlock(r->logs->lock);
                LOG_ERR(CRIT, r->logs, "Mysql(insert delayed) result: %s", mysql_error(&r->store->mysql_sock));
                LOG_ERR(CRIT, r->logs, "Query: %s", sql_query);
                return -1;
        }
        apr_thread_mutex_unlock(r->logs->lock);

        return 0;

#endif
}

*/
