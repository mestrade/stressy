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

#ifndef UTIL_XML
#include "global_apr.h"
#include "logs.h"

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

int load_xml(apr_pool_t *pool, char *data, apr_xml_doc **doc);
int xml_dump_elem(apr_pool_t *pool, logs_t logs, apr_xml_elem *elem);
char *xml_text_to_string (apr_pool_t *pool, apr_text *text);
extern int get_node_with_xpath(xmlDocPtr doc, const char *xpath, xmlNodePtr *node);
extern char *get_attr_value(apr_pool_t *pool, xmlNodePtr node);
extern char *get_attr_key(apr_pool_t *pool, xmlNodePtr node);
extern int xml_node_get_path(apr_pool_t *pool, xmlNodePtr node, char **value);

#define UTIL_XML
#endif

