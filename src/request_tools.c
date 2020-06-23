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

#include "request_tools.h"
#include "parsing_tools.h"
#include "util_xml.h"

#define XPATH_FF	"//tdRequests/tdRequest"

static char htoi(char *s)
{
    int value;
    int c;
    c = s[0];
    if (isupper(c))
	c = tolower(c);

    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;
    c = s[1];
    if (isupper(c))
	c = tolower(c);

    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
    return (value);
}

static int url_decode(char *str, int len)
{
    char *dest = str;
    char *data = str;
    char dch;

    if (!str)
	return -1;

    while (len--) {
	/* FUFU: url_decode function must also decode '+' to ' ', I will uncomment later (may have strong impact)
 * 	   if( *data == '+' ) {
 * 	   	   *dest = ' ';
 * 	   	   	   }
 * 	   	   	   	   else
 * 	   	   	   	           */
	if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1))
	    && isxdigit((int) *(data + 2))
	    && !(*(data + 1) == '0' && (*(data + 2) == '0'))) {
	    /* those last 2 lines are here to avoid decoding \r and \n */
	    dch = (char) htoi(data + 1);
	    if (dch) {
		*dest = dch;
		data += 2;
		len -= 2;
	    }
	}
	else {
	    *dest = *data;
	}
	data++;
	dest++;
    }
    *dest = '\0';

    return dest - str;
}

static int request_from_firefox_hdr_post(request_t *r, xmlNodePtr request)
{
	xmlNodePtr ptr = NULL;
	xmlNodePtr hdr = NULL;
	int found = 0;

	for (ptr = request; ptr != NULL; ptr = ptr->next) {

		if (strncasecmp((char *)ptr->name, "tdPostHeaders", strlen((char *)ptr->name)) != 0) continue;

		for (hdr = ptr->children; hdr != NULL; hdr = hdr->next) {

			xmlChar *hdr_name = NULL;
			xmlChar *hdr_value = NULL;			

			if (strncasecmp((char *)hdr->name, "tdPostHeader", strlen((char *)hdr->name)) != 0) continue;
			hdr_name = xmlGetProp(hdr, BAD_CAST"name");
			if (hdr_name == NULL) continue;

			hdr_value = xmlNodeGetContent(hdr);
			if (*hdr_value == '\n') hdr_value++; 
			if (hdr_value[strlen((char *)hdr_value) - 1] == '\n') hdr_value[strlen((char *)hdr_value) - 1] = 0;

			apr_table_set(r->headers_in, (char *)hdr_name, (char *)hdr_value);
			found++;
		}
	}

	if (found > 0) request_set_method(r, "POST");

	return 0;
}

static int request_from_firefox_hdr(request_t *r, xmlNodePtr request)
{
	xmlNodePtr ptr = NULL;
	xmlNodePtr hdr = NULL;

	for (ptr = request; ptr != NULL; ptr = ptr->next) {

		if (strncasecmp((char *)ptr->name, "tdRequestHeaders", strlen((char *)ptr->name)) != 0) continue;

		for (hdr = ptr->children; hdr != NULL; hdr = hdr->next) {

			xmlChar *hdr_name = NULL;
			xmlChar *hdr_value = NULL;

			if (strncasecmp((char *)hdr->name, "tdRequestHeader", strlen((char *)hdr->name)) != 0) continue;
			hdr_name = xmlGetProp(hdr, BAD_CAST"name");
			if (hdr_name == NULL) continue;
			
			hdr_value = xmlNodeGetContent(hdr);
			if (*hdr_value == '\n') hdr_value++; 
			if (hdr_value[strlen((char *)hdr_value) - 1] == '\n') hdr_value[strlen((char *)hdr_value) - 1] = 0;


			apr_table_set(r->headers_in, (char *)hdr_name, (char *)hdr_value);
		}
	}

	return 0;
}

static int request_from_firefox_var(request_t *r, xmlNodePtr request)
{
	xmlNodePtr ptr = NULL;
	xmlNodePtr var = NULL;

	for (ptr = request; ptr != NULL; ptr = ptr->next) {

		if (strncasecmp((char *)ptr->name, "tdPostElements", strlen((char *)ptr->name)) != 0) continue;

		for (var = ptr->children; var != NULL; var = var->next) {
			var_item_t *item = NULL;

			xmlChar *var_name = NULL;
			xmlChar *var_value = NULL;

			if (strncasecmp((char *)var->name, "tdPostElement", strlen((char *)var->name)) != 0) continue;
			var_name = xmlGetProp(var, BAD_CAST"name");
			if (var_name == NULL) continue;

			var_value = xmlNodeGetContent(var);
			if (*var_value == '\n') var_value++; 
			if (var_value[strlen((char *)var_value) - 1] == '\n') var_value[strlen((char *)var_value) - 1] = 0;

			var_item_init(r->pool, &item);
			item->type = VAR_POST;			
			item->name = apr_pstrdup(r->pool, (char *)var_name);
			if (var_value) item->value = apr_pstrdup(r->pool, (char *)var_value);
			var_list_add(r->var_list, item);
		}
	}

	return 0;
}

extern int request_from_firefox(stressy_ctx_t *ctx, xmlDocPtr document)
{
        xmlXPathContext *xpathctx;
        xmlXPathObject *xpathObj;
        xmlNode *node; 
        int num_request = 0;
	int i = 0;
	

	if (ctx == NULL || document == NULL) return -1;

	xpathctx = xmlXPathNewContext((xmlDocPtr)document);
        xpathObj = xmlXPathEvalExpression((xmlChar *)XPATH_FF, xpathctx);

        num_request = xpathObj->nodesetval->nodeNr;
	LOG_ERR(NOTICE, ctx->logs, "Found %i firefox request", num_request);	

	for (i = 0 ; i < num_request; i++) {
		request_t *r = NULL;		
		xmlChar *tmp_uri = NULL;
		char *uri = NULL;
		int res;

		node = xpathObj->nodesetval->nodeTab[i];
	
		request_init(&r);
		r->logs = ctx->logs;
		//r->stressy_ctx = ctx;
		r->hostname = apr_pstrdup(r->pool, ctx->hostname);
        	
		tmp_uri = xmlGetProp(node, BAD_CAST"uri");

		url_decode((char *)tmp_uri, strlen((char *)tmp_uri));		
		res = parse_resource_from_string(r->pool, (char *)tmp_uri, &uri); 

		if (res < 0) {
			fprintf(stderr, "Can't parse ressource from string");
		}

		request_set_resource_from_uri(r, (char *)uri);
		request_set_query_from_uri(r, (char *)uri);
		
		LOG_ERR(DEBUG, r->logs, "Uri: %s", r->resource);

		request_from_firefox_hdr(r, node->children);	
		request_from_firefox_hdr_post(r, node->children);	
		request_from_firefox_var(r, node->children);

                r->port = apr_pstrdup(r->pool, ctx->port);
                r->logs = ctx->logs;
                r->step = 0;

		request_rebuild_cookie_line(r);
                request_rebuild_post_line(r);
                request_rebuild_arg_line(r);
                request_set_module(r, "core_insert_from_firefox");
                request_clean_request(r);

                site_map_insert_request(ctx->map, r->resource, r->method, r->resource, r->post_body, (void *)r);
                request_list_add(ctx->request_list, r);
	}


	return 0;
}

extern int request_from_xml(request_t *r, stressy_ctx_t *stressy_ctx, xmlNodePtr node)
{
        xmlNodePtr ptr = NULL;

        if (!r || !node) return -1;

        if (!stressy_ctx) {
                LOG_ERR(CRIT, r->logs, "Unable to find stressy_ctx inside request");
                return -1;
        }

	r->logs = stressy_ctx->logs;
	//r->stressy_ctx = stressy_ctx;

        for (ptr = node->children; ptr; ptr = ptr->next) {

                if (!ptr->name) continue;

                if (strncasecmp((char *)ptr->name, "name", strlen((char *)ptr->name)) == 0) {
                        char *name = NULL;

                        name = get_attr_value(r->pool, ptr);
                        if (!name) continue;
                        LOG_ERR(DEBUG, r->logs, "Found name: %s", name);
                        r->name = name;
                        continue;
                }

                if (strncasecmp((char *)ptr->name, "method", strlen((char *)ptr->name)) == 0) {
                        char *method = NULL;

                        method = get_attr_value(r->pool, ptr);
                        if (!method) continue;
                        LOG_ERR(DEBUG, r->logs, "Found method: %s", method);
                        r->method = method;
                        continue;
                }

                if (strncasecmp((char *)ptr->name, "uri", strlen((char *)ptr->name)) == 0) {
                        char *uri = NULL;

                        uri = get_attr_value(r->pool, ptr);
                        if (!uri) continue;
                        LOG_ERR(DEBUG, r->logs, "Found uri: %s", uri);
                        r->resource = uri;
                        continue;
                }

                if (strncasecmp((char *)ptr->name, "arg", strlen((char *)ptr->name)) == 0) {
                        char *arg = NULL;

                        arg = get_attr_value(r->pool, ptr);
                        if (!arg) continue;
                        LOG_ERR(DEBUG, r->logs, "Found arg: %s", arg);
                        r->query = arg;
                        continue;
                }
                if (strncasecmp((char *)ptr->name, "protocol", strlen((char *)ptr->name)) == 0) {
                        char *protocol = NULL;

                        protocol = get_attr_value(r->pool, ptr);
                        if (!protocol) continue;
                        LOG_ERR(DEBUG, r->logs, "Found protocol: %s", protocol);
                        r->protocol = protocol;
                        continue;
                }

                if (strncasecmp((char *)ptr->name, "header", strlen((char *)ptr->name)) == 0) {
                        char *key = NULL;
                        char *val = NULL;

                        key = get_attr_key(r->pool, ptr);
                        val = get_attr_value(r->pool, ptr);
                        if (!key || !val) continue;
                        LOG_ERR(DEBUG, r->logs, "Found header: %s: %s", key, val);
                        apr_table_set(r->headers_in, key, val);
                        continue;
                }
                if (strncasecmp((char *)ptr->name, "var", strlen((char *)ptr->name)) == 0) {
                        xmlChar *name = NULL;
                        xmlChar *value = NULL;
			xmlChar *type = NULL;
			xmlChar *input_type = NULL;
			var_item_t *new_var = NULL;

			name = xmlGetProp(ptr, BAD_CAST"name");
			value = xmlGetProp(ptr, BAD_CAST"value");
			type = xmlGetProp(ptr, BAD_CAST"type");
			input_type = xmlGetProp(ptr, BAD_CAST"input_type");

			if (name == NULL) continue;
			LOG_ERR(DEBUG, stressy_ctx->logs, "Found var: %s value: %s", name, value);
                       
			if (var_item_init(r->pool, &new_var) < 0) return -1;
			new_var->name = apr_pstrdup(r->pool, (char *)name);
			new_var->value = apr_pstrdup(r->pool, (char *)value);	
			new_var->input_type = apr_pstrdup(r->pool, (char *)input_type); 

			if (strncasecmp((char *)type, "GET", strlen((char *)type)) == 0) new_var->type = VAR_GET;
			else if (strncasecmp((char *)type, "POST", strlen((char *)type)) == 0) new_var->type = VAR_POST;
			else if (strncasecmp((char *)type, "COOKIE", strlen((char *)type)) == 0) new_var->type = VAR_COOKIE;

			var_list_add(r->var_list, new_var);

                        continue;
                }
        }

        /* add host header if not present */
        if (!apr_table_get(r->headers_in, "Host")) {
                apr_table_set(r->headers_in, "Host", stressy_ctx->hostname);
        }


        return 0;
}
