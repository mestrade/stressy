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

#include "request.h"
#include "parsing_tools.h"

#include "apr_tables.h"
#include "apr_base64.h"
#include "apr_md5.h"

extern int request_set_module(request_t *r, char *module)
{
        if (r == NULL || r->pool == NULL) return -1;
        r->module = apr_pstrdup(r->pool, module);
        return 0;
}

static int create_var_item_from_string(apr_pool_t *pool, char *string, var_item_t **item, char *type)
{
	var_item_t *new_var;
	
	if (!pool | !string | !type) return -1;
	
	if (var_item_init(pool, &new_var) < 0) {
		return -1;
	}
	if (parse_var_name(pool, string, '=', &new_var->name) < 0) {
		return -1;
	}
	if (parse_var_value(pool, string, '=', &new_var->value) < 0) {
		new_var->value = NULL;
	}
	new_var->type = apr_pstrdup(pool, type);
	
	*item = new_var;	
	return 0;
}

static int parse_var(request_t *r, char *string, char sep, char *type)
{
	char *ptr = NULL;
	char *start = NULL;
	
	apr_pool_t *tmp_pool;
	
	if (!r || !string) return -1;
	apr_pool_create(&tmp_pool, NULL);
	
	start = string;
	
	if (!(ptr = memchr(start, sep, strlen(start)))) {
		var_item_t *new_var;
		
		if (strlen(start) <= 0) {
			apr_pool_destroy(tmp_pool);
			return -1;
		}
		LOG_ERR(DEBUG, r->logs, "We don't have separator, so only one variable");
		if (create_var_item_from_string(r->var_list->pool, start, &new_var, type) < 0) return -1;	
		if (var_list_add(r->var_list, new_var) < 0) {
			apr_pool_destroy(tmp_pool);
			return -1;
		}
		new_var->type = type;
		apr_pool_destroy(tmp_pool);
		return 0;
	}

	do {
		char *couple = NULL;
		var_item_t *new_var;
		int len = 0;
		
		if (!start) break;
		
		len = ptr - start;
		if (len < 0) {
			apr_pool_destroy(tmp_pool);
			return -1;
		}
		couple = apr_pstrndup(tmp_pool, start, len);
		if (create_var_item_from_string(r->var_list->pool, couple, &new_var, type) < 0) {
			start = ptr + 1;
			continue;
		}	
		if (var_list_add(r->var_list, new_var) < 0) {
			apr_pool_destroy(tmp_pool);
			return -1;
		}
		new_var->type = apr_pstrdup(r->pool, type);

		start = ptr + 1;
	} while ((ptr = memchr(start, sep, strlen(start))));
	
	/* Look if there is no data after the latest sep */
	if (strlen(start) > 0) {
		var_item_t *new_var;
		if (create_var_item_from_string(r->var_list->pool, start, &new_var, type) < 0) return -1;	
		if (var_list_add(r->var_list, new_var) < 0) {
			apr_pool_destroy(tmp_pool);
			return -1;
		}
		new_var->type = apr_pstrdup(r->pool, type);
	}
	apr_pool_destroy(tmp_pool);
	return 0;
}

extern int request_body_count_words(request_t *r)
{
	int num_words = 0;
	char *ptr = NULL;
	int index = 0;

	if (r == NULL) return -1;
	r->body_words = 0;
	r->body_lines = 0;
	
	if (r->body == NULL || r->read_bytes <= 0) return -1;

	ptr = r->body;
	while (*ptr != 0) {

		if (index > r->read_bytes) break;
		if (*ptr == '\n' ) {
			r->body_words++;
			r->body_lines++;
		}

		if(*ptr == ' ') num_words++;
		
		index++;
		ptr++;
	}
	
	return num_words;
}


extern int request_dump(request_t *r, int severity)
{

	if (!r) return -1;


	LOG_ERR(severity, r->logs, "-----> Request <-----");
	if (r->hostname) LOG_ERR(severity, r->logs, "Hostname: %s", r->hostname);
	if (r->name) LOG_ERR(severity, r->logs, "Name: %s", r->name);
	if (r->method) LOG_ERR(severity, r->logs, "Method: %s", r->method);
	else LOG_ERR(severity, r->logs, "Method: not set - default is GET");

	if (r->resource) LOG_ERR(severity, r->logs, "uri: %s", r->resource);
	else LOG_ERR(severity, r->logs, "uri: not set -  default is /");


	if (r->query) LOG_ERR(severity, r->logs, "args: %s", r->query);
	if (r->post_body) LOG_ERR(severity, r->logs, "post_arg: %s", r->post_body);
	
	if (r->answer_code) LOG_ERR(severity, r->logs, "answer code: %s", r->answer_code);
	if (r->answer_msg) LOG_ERR(severity, r->logs, "answer msg: %s", r->answer_msg);
	if (r->code == 301 || r->code == 302) {
		const char *location = NULL;
		if ((location = apr_table_get(r->headers_in, "Location"))) {
			LOG_ERR(severity, r->logs, "Redirect to: %s", location);
		}
	}
	
	LOG_ERR(severity, r->logs, "Step: %i", r->step);

	if (apr_table_get(r->headers_in, "Content-Length")) {
		LOG_ERR(severity, r->logs, "Transfer: content-length");
	}
	else if (apr_table_get(r->headers_in, "Transfer-Encoding")) {
		LOG_ERR(severity, r->logs, "Transfer: chunked");
	}
	else {
		LOG_ERR(severity, r->logs, "Transfer: conn close");
	}

	LOG_ERR(severity, r->logs, "---------------------");
	
	return 0;
}

extern int request_log_access(request_t *r)
{
	char *line = NULL;

	if (r == NULL) return -1;

	if (r->query != NULL) {
		line = apr_psprintf(r->pool, "%s %s?%s", r->method, r->request, r->query);
	}
	else {
		line = apr_psprintf(r->pool, "%s %s", r->method, r->request);
	}

	line = apr_psprintf(r->pool, "(%s) %s - %s (%"APR_OFF_T_FMT" bytes) => %s", r->module, line, r->answer_code, r->read_bytes, r->name);

        LOG_ACCESS(r->logs, "%s", line);
	return 0;
}

extern int request_set_method(request_t *r, char *method)
{
	if (!method) return -1;
	r->method = (char *)apr_pstrdup(r->pool, method);
	return 0;
}


extern char *get_request_method(request_t *r)
{
	if (!r) return NULL;

	if (!r->method) {
		r->method = apr_pstrdup(r->pool, "GET");
		return r->method;
	}
	else return r->method;

	return NULL;
}

extern int clean_html(request_t *r, char *uri)
{
	char *ptr = NULL;

	return 0;
	
	if (!r || !r->resource) return -1;
	
	ptr = r->resource;
	while ((ptr = memchr(ptr, '&', strlen(ptr)))) {

		if (strncasecmp(ptr, "&amp;", 5) == 0) {
			memmove(ptr + 1, ptr + 4, strlen(ptr) - 4); 
		}
		ptr++;
	}
	return 0;
}

static int copy_hdr(void *rec, const char *key, const char *value)
{
	request_t *r = (request_t *)rec;

	if (!key || !value) return 1;

	/* do not copy some specific headers */
	if (strncasecmp(key, "content-length", strlen(key)) == 0) return 1;
	
	apr_table_add(r->headers_in, apr_pstrdup(r->pool, key), apr_pstrdup(r->pool, value));
	
	return 1;
}

extern int request_set_referer(request_t *new, request_t *prev)
{
	char *referer = NULL;
	
	if (!prev || !new) return -1;

	else if (prev->query) referer = apr_psprintf(new->pool, "http://%s%s?%s", new->hostname,prev->resource, prev->query);
	else referer = apr_pstrdup(new->pool, prev->resource);

	apr_table_set(new->headers_in, "Referer", referer);

	return 0;
}

static int request_set_path(request_t *r)
{
	int end = 0;
	int i = 0;
	
	if (!r->resource) {
		return -1;
	}

	end = strlen(r->resource);
	for (i = end; i >= 0; i--) {
		if (r->resource[i] == '/') {
			r->path = apr_pstrndup(r->pool, r->resource, i + 1);
			return 0;
		}
	}

	r->path = NULL;
	return -1;
}

extern int request_set_cookies(request_t *r)
{
	const char *cookie_line = NULL;
	
	if (!r->headers_in) return -1;
	if (!(cookie_line = apr_table_get(r->headers_out, "Cookie"))) return -1;
	
	parse_var(r, (char *)cookie_line, ';', "COOKIE");
	return 0;
}

extern int request_set_resource_from_uri(request_t *r, char *link)
{
	char *ptr;
	char *anchor;
	
	if (!link) return -1;
	
	if ((ptr = memchr(link, '?', strlen(link)))) {
		int len = 0;

		len = ptr - link;
		if (len < 0) return -1;
		r->resource = apr_pstrndup(r->pool, link, len);
	}
	else {
		r->resource = apr_pstrdup(r->pool, link);
	}
	
	if ((anchor = memchr(r->resource, '#', strlen(r->resource)))) {
		int len = 0;
		
		len = anchor - r->resource;
		if (len < 0) return -1;
		r->resource = apr_pstrndup(r->pool, r->resource, len);
	}
	
	//link_clean_recursive(r->pool, r->resource, &r->resource);
	request_set_path(r);
	
	return 0;
}

extern int request_set_query_from_uri(request_t *r, char *link)
{
	char *sep;
	
	if (!link) return -1;

	if (!(sep = memchr(link, '?', strlen(link)))) {
		return 0;
	}
	sep++;

	r->query = apr_pstrdup(r->pool, sep);
	parse_var(r, r->query, '&', VAR_GET);

	return 0;
}


extern int request_copy_basic(request_t *src, request_t *dst)
{
	dst->hostname = apr_pstrdup(dst->pool, src->hostname);
	dst->ip = apr_pstrdup(dst->pool, src->ip);
	dst->port = apr_pstrdup(dst->pool, src->port);
	dst->method = apr_pstrdup(dst->pool, src->method);
	dst->protocol = apr_pstrdup(dst->pool, src->protocol);
	dst->is_proxy = src->is_proxy;
	dst->logs = src->logs;

	if (src->login) dst->login = apr_pstrdup(dst->pool, src->login);
	if (src->password) dst->password = apr_pstrdup(dst->pool, src->password);
	
	apr_table_do(copy_hdr, dst, src->headers_in, NULL);
	return 0;		
}

extern int request_init(request_t **request)
{
	request_t *new;
	apr_pool_t *request_pool;

	apr_pool_create(&request_pool, NULL);
	if (!request_pool) return -1;	
	
	if ((new = (apr_pcalloc(request_pool, sizeof(request_t)))) == NULL) {
		return -1;
	}

	new->step = 0;
	new->pool = request_pool;
	new->path = NULL;
	new->method = NULL;
	new->resource = NULL;
	new->headers_in = apr_table_make(request_pool, MAX_HDR_IN);
	new->headers_out = apr_table_make(request_pool, MAX_HDR_OUT);
	new->notes = apr_table_make(request_pool, MAX_HDR_OUT);
	new->created_time = apr_time_now();
	new->process_status = PROCESS_WAITING;
	if (var_list_init(new->pool, &new->var_list) < 0) return -1;
	
	*request = new;
	return 0;
}

extern int request_destroy(request_t *request)
{
	if (!request) return -1;

	LOG_ERR(DEBUG, request->logs, "Destroying request");

	if (request->pool) {
		request->logs = NULL;
		request->resource = NULL;
		request->query = NULL;
		request->headers_in = NULL;
		request->headers_out = NULL;
		apr_pool_destroy(request->pool);
		request = NULL;
	}
	return 0;
}

extern int request_rebuild_arg_line(request_t *r)
{
	int i = 0;
	var_item_t *ptr = NULL;
	char *line = NULL;
	
	if (!r || !r->var_list || r->var_list->num_var == 0) return -1;

	ptr = r->var_list->first_var;
	for (i = 0; i < r->var_list->num_var; i++) {
		if (!ptr || !ptr->type || (strncmp(ptr->type, VAR_GET, strlen(ptr->type)) != 0)) {
			ptr = ptr->next;
			continue;
		}

		if (!line) {
			if (ptr->value)	line = apr_pstrcat(r->pool, ptr->name, "=", ptr->value, "&", NULL);
			else line = apr_pstrcat(r->pool, ptr->name, "=&", NULL);
		}
		else {	
			if (ptr->value) line = apr_pstrcat(r->pool, line, ptr->name, "=", ptr->value, "&", NULL);
			else line = apr_pstrcat(r->pool, line, ptr->name, "=&", NULL);
		}
		ptr = ptr->next;
	}

	r->query = line;
	return 0;
}

extern int request_rebuild_cookie_line(request_t *r)
{
	int i = 0;
	var_item_t *ptr = NULL;
	char *line = NULL;
	
	if (!r || !r->var_list || r->var_list->num_var == 0) return -1;

	ptr = r->var_list->first_var;
	for (i = 0; i < r->var_list->num_var; i++) {

		if (!ptr || !ptr->type || (strncmp(ptr->type, VAR_COOKIE, strlen(ptr->type)) != 0)) {
			ptr = ptr->next;
			continue;
		}

		if (!line) {
			if (ptr->value) {
				line = apr_pstrcat(r->pool, ptr->name, "=", ptr->value, "; ", NULL);
			}
			else {
				line = apr_pstrcat(r->pool, ptr->name, "=; ", NULL);
			}
		}
		else {	
			if (ptr->value) {
				line = apr_pstrcat(r->pool, line, ptr->name, "=", ptr->value, "; ", NULL);
			}
			else {
				line = apr_pstrcat(r->pool, line, ptr->name, "=; ", NULL);
			}
		}
		ptr = ptr->next;
	}

	apr_table_set(r->headers_in, "Cookie", line);
	return 0;
}

extern int request_rebuild_post_line(request_t *r)
{
	int i = 0;
	var_item_t *ptr = NULL;
	char *line = NULL;
	
	if (!r || !r->var_list || r->var_list->num_var == 0) return -1;

	ptr = r->var_list->first_var;
	for (i = 0; i < r->var_list->num_var; i++) {

		if (!ptr || !ptr->type || (strncmp(ptr->type, VAR_POST, strlen(ptr->type)) != 0)) {
			ptr = ptr->next;
			continue;
		}

		if (!line) {
			if (ptr->value) {
				line = apr_pstrcat(r->pool, ptr->name, "=", ptr->value, "&", NULL);
			}
			else {
				line = apr_pstrcat(r->pool, ptr->name, "=&", NULL);
			}
		}
		else {	
			if (ptr->value) {
				line = apr_pstrcat(r->pool, line, ptr->name, "=", ptr->value, "&", NULL);
			}
			else {
				line = apr_pstrcat(r->pool, line, ptr->name, "=&", NULL);
			}
		}
		ptr = ptr->next;
	}

	r->post_body = line;
	return 0;
}

extern int request_clean_request(request_t *r)
{
	char *clean_resource = NULL;
        if (!r) return -1;

        if (parse_clean_recursive(r->pool, r->resource, &clean_resource) < 0) return -1;
	clean_html(r, r->query);
	if (clean_resource) {
		r->resource = clean_resource; 
		r->request = r->resource;
	}

        return 0;
}

extern int md5_binary(apr_pool_t *p, const unsigned char *buf, int length, char **md5)
{
        const char *hex = "0123456789abcdef";
        apr_md5_ctx_t my_md5;
        unsigned char hash[APR_MD5_DIGESTSIZE];
        char *r, result[33]; /* (MD5_DIGESTSIZE * 2) + 1 */
        int i;

        apr_md5_init(&my_md5);
        apr_md5_update(&my_md5, buf, (unsigned int)length);
        apr_md5_final(hash, &my_md5);

        for (i = 0, r = result; i < APR_MD5_DIGESTSIZE; i++) {
                *r++ = hex[hash[i] >> 4];
                *r++ = hex[hash[i] & 0xF];
        }
        *r = '\0';

        *md5 = (char *)apr_pstrndup(p, result, APR_MD5_DIGESTSIZE*2);
        return 0;
}

