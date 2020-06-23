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

#include "util_xml.h"
#include "apr_base64.h"
#include "apr_strings.h"

#define MAX_DEPTH	120

extern int xml_node_get_path(apr_pool_t *pool, xmlNodePtr node, char **value)
{
	char *path = NULL;
	xmlNodePtr ptr = NULL;

	for (ptr = node; ptr->name; ptr = ptr->parent) {
		
		if (path == NULL) {
			path = apr_pstrcat(pool, "/", (char *)ptr->name, NULL);
		}
		else {
			path = apr_pstrcat(pool, "/", ptr->name, path, NULL);
		}

		if (ptr->parent == NULL) break;
	}

	*value = path;
	return 0;
}

extern int xml_is_node_name(xmlNodePtr node, char *name)
{
	if (!node || !name) return -1;
	if (!node->name) return -1;

	if ((strncasecmp((char *)node->name, name, strlen((char *)node->name)) == 0) && (strlen((char *)node->name) == strlen((char *)name))) return 0;
	return -1;
}

extern int get_node_with_xpath(xmlDocPtr doc, const char *xpath, xmlNodePtr *node)
{
	xmlXPathContextPtr context;
        xmlXPathObjectPtr result;
        xmlNodeSetPtr xml_node_set;

        context = xmlXPathNewContext(doc);
        if (!context) {
                return -1;
        }
        result = xmlXPathEvalExpression((xmlChar *)xpath, context);
        if (!result) {
                return -1;
        }
       	xml_node_set = result->nodesetval;
	if (xml_node_set->nodeNr <= 0) return -1;

	/*
	 * return the first node found
	 *
	 */

	*node = xml_node_set->nodeTab[0]; 
	return 0;
}

extern int get_nodeset_with_xpath(xmlDocPtr doc, const char *xpath, xmlNodePtr **node)
{
	xmlXPathContextPtr context;
        xmlXPathObjectPtr result;
        xmlNodeSetPtr xml_node_set;

        context = xmlXPathNewContext(doc);
        if (!context) {
                return -1;
        }
        result = xmlXPathEvalExpression((xmlChar *)xpath, context);
        if (!result) {
                return -1;
        }
       	xml_node_set = result->nodesetval;
	if (xml_node_set->nodeNr <= 0) return -1;

	/*
	 * return the first node found
	 *
	 */

	*node = xml_node_set->nodeTab; 
	return 0;
}



int
load_xml (apr_pool_t * pool, char *data, apr_xml_doc ** doc)
{
  apr_status_t xml_parse_result;
  apr_xml_parser *xmldata = apr_xml_parser_create (pool);
  apr_xml_doc *new;


  if (!data) return -1;

  if ((xml_parse_result =
       apr_xml_parser_feed (xmldata, data,
			    (apr_size_t) strlen (data))) != APR_SUCCESS)
    {
      return -1;
    }

  if ((xml_parse_result = apr_xml_parser_done (xmldata, &new)) != APR_SUCCESS)
    {
      return -1;
    }


  *doc = new;
  return 0;
}

char *
xml_text_to_string (apr_pool_t * pool, apr_text * text)
{
  apr_text *t;
  apr_size_t size;
  char *str, *s;

  if (!text)
    {
      return NULL;
    }

  /* get size of whole text to malloc() it */

  for (t = text, size = 0; t; t = t->next)
    {
      size += strlen (t->text);
    }

  if (!size)
    {
      return NULL;
    }

  /* finished with a NUL */

  size++;

  if (!(str = apr_pcalloc (pool, size)))
    {
      return NULL;
    }

  /* copy it */

  for (t = text, s = str; t; t = t->next)
    {
      apr_size_t len = strlen (t->text);

      memcpy (s, t->text, len);
      s += len;
    }

  return str;
}

int
xml_dump_elem (apr_pool_t * pool, logs_t logs, apr_xml_elem * elem)
{
  apr_xml_elem *ptr = elem;

  while (ptr)
    {

      LOG_ERR (DEBUG, logs, "Elem [%s] Value [%s]", ptr->name,
	       xml_text_to_string (pool, ptr->first_cdata.first));

      if (ptr->first_child)
	{
	  xml_dump_elem (pool, logs, ptr->first_child);
	}

      ptr = ptr->next;
    }


  return 0;
}

int
xml_is_tag (apr_xml_elem * elem, char *name)
{
  if (!name || !elem  || !elem->name) return -1;
  
  if ((strncasecmp (elem->name, name, strlen (elem->name)) == 0)
      && (strlen (elem->name) == strlen (name)))
    return 0;

  return -1;
}

int
xml_get_elem_data (apr_pool_t *pool, apr_xml_elem *elem, char *name, char **buffer)
{
  apr_xml_elem *ptr;

  ptr = elem;
  while (ptr)
    {

      if (xml_is_tag (ptr, name) == 0)
	{
	  char *data;

	  data = xml_text_to_string (pool, ptr->first_cdata.first);
	  *buffer = data;
	  return 0;
	}
      ptr = ptr->next;
    }

  *buffer = NULL;
  return -1;
}

int xml_get_elem(apr_pool_t *pool, apr_xml_elem *elem, char *name, apr_xml_elem **dst)
{
	apr_xml_elem *ptr;

	ptr = elem;
	while (ptr) {
		if (xml_is_tag (ptr, name) == 0) {
			*dst = ptr;
			return 0;
		}
		ptr = ptr->next;
	}
	return -1;
}

int xml_count_elem_name(apr_xml_elem *elem, char *name)
{
	apr_xml_elem *ptr;
	int num_tag = 0;

	ptr = elem;
	while (ptr) {
		if (strncasecmp(ptr->name, name, strlen(ptr->name)) == 0 && strlen(ptr->name) == strlen(name)) num_tag++;
		ptr = ptr->next;
	}

	return num_tag;
}

char *xml_create_elem(apr_pool_t *pool, char *elem_name, char *elem_data)
{
	return apr_psprintf(pool, "<%s>%s</%s>\n", elem_name, elem_data, elem_name);
}

char *xml_create_start_tag(apr_pool_t *pool, char *name)
{
	if (!name) return NULL;
	return apr_psprintf(pool, "<%s>\n", name);
}

char *xml_create_end_tag(apr_pool_t *pool, char *name)
{
	if (!name) return NULL;
	return apr_psprintf(pool, "</%s>\n", name);
}
extern char *get_attr_value(apr_pool_t *pool, xmlNodePtr node)
{
        char *type = NULL;
        char *val = NULL;
        char *final = NULL;

        if (!pool || !node) return NULL;

        type = (char *)xmlGetProp(node, BAD_CAST "value_type");
        val = (char *)xmlGetProp(node, BAD_CAST "value");

        if (!val) return NULL;

        if (type && strncasecmp(type, "b64", strlen(type)) == 0) {
                int len = 0;

                len = apr_base64_decode_len(val);
                if (len < 0) return NULL;
                final = apr_pcalloc(pool, len + 1);
                apr_base64_decode(final, val);
                return final;
        }

        return apr_pstrdup(pool, val);
}

extern char *get_attr_key(apr_pool_t *pool, xmlNodePtr node)
{
        char *type = NULL;
        char *val = NULL;
        char *final = NULL;

        if (!pool || !node) return NULL;

        type = (char *)xmlGetProp(node, BAD_CAST "key_type");
        val = (char *)xmlGetProp(node, BAD_CAST "key");

        if (!val) return NULL;

        if (type && strncasecmp(type, "b64", strlen(type)) == 0) {
                int len = 0;

                len = apr_base64_decode_len(val);
                if (len < 0) return NULL;
                final = apr_pcalloc(pool, len + 1);
                apr_base64_decode(final, val);
                return final;
        }

        return apr_pstrdup(pool, val);
}
