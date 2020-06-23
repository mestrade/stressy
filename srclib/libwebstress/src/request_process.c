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

#include "request_process.h"
#include "hook.h"

#include <stdlib.h>
#include "apr_lib.h"

int process_send_request_line(request_t *r)
{
	char *line;
	apr_size_t bytes = 0;
	char *resource;

	if(r == NULL) {
		fprintf(stderr, "request is empty\n");
		return -1;
	}
	
	resource = r->resource;

	if (r->query) resource = apr_pstrcat(r->pool, resource, "?", r->query, NULL);
	if (r->is_proxy == 1) resource = apr_pstrcat(r->pool, "http://", r->hostname, resource, NULL);
	if (!r->method) {
		r->method = apr_pstrdup(r->pool, "GET");
	}
	
	if (r->protocol != NULL) line = apr_psprintf(r->pool, "%s %s HTTP/1.1", r->method, resource);
	else line = apr_psprintf(r->pool, "%s %s", r->method, resource);
	
	bytes = strlen(line);
	if (socket_item_write(r->conn, line, bytes) < 0) return -1;
	if (socket_item_write(r->conn, "\r\n", 2) < 0) return -1;

	LOG_ERR(DEBUG, r->logs, "Request line sent: %s", line);

	
	return 0;
}

/* 
 * create an md5 sum of the body received
 *
 */
int process_md5_body(request_t *r)
{
	if (!r->body || r->read_bytes <= 0) return -1;
	//md5_binary(r->pool, r->body, r->read_bytes, &(r->body_md5));
	if (!r->body_md5) return -1;
	return 0;
}

/*
 * Send headers to the server
 *
 *  Header Name: Header value \r\n
 *
 */
int process_send_hdr(request_t *r)
{
	const apr_array_header_t *headers_in_array;
	const apr_table_entry_t *headers;

	int counter = 0;

	if (apr_table_get(r->headers_in, "Host") == NULL) {
		apr_table_set(r->headers_in, "Host", r->hostname);
	}

	headers_in_array = apr_table_elts(r->headers_in);
	headers = (const apr_table_entry_t *) headers_in_array->elts;
	    
	for (counter = 0; counter < headers_in_array->nelts; counter++) {
		char *line = NULL;
		apr_size_t bytes = 0;
		
		if (!headers[counter].key) {
			continue;
		}

		if (!headers[counter].val) {
			line = apr_psprintf(r->pool, "%s: ", headers[counter].key);
		}
		else {
			line = apr_psprintf(r->pool, "%s: %s", headers[counter].key, headers[counter].val);
		}

		bytes = strlen(line);
		socket_item_write(r->conn, line, bytes);
		socket_item_write(r->conn, "\r\n", 2);

		LOG_ERR(DEBUG, r->logs, "Header sent: %s", line);

	}

	return counter;
}

int process_send_end_hdr(request_t *r)
{
	
	socket_item_write(r->conn, "\r\n", 2);
	return 0;
}

/* 
 * Connect to the server before sending data
 *
 */
int process_send_body_xxx_enc_cl(request_t *r)
{
	const char *cl = NULL;

	if ((cl = apr_table_get(r->headers_in, "Content-Length")) && !r->post_body) {
		apr_table_unset(r->headers_in, "Content-Length");
		return -1;
	}

	if (!r->post_body) {
		return 0;
	}
	
	r->send_cl = strlen(r->post_body);
	cl = apr_psprintf(r->pool, "%i", r->send_cl);
	apr_table_set(r->headers_in, "Content-Length", cl);

	return 0;
}

int process_send_body_xxx_enc(request_t *r)
{
	if (r->send_cl <= 0) return 0;	
	
	socket_item_write(r->conn, r->post_body, r->send_cl);
	return 0;
}

int process_read_answer_line(request_t *r)
{
	char *line = NULL;
	int line_len;

	char *ptr;
	
	char *tmp_protocol = NULL;
	int tmp_protocol_len = 0;
	
	char *tmp_code = NULL;
	int tmp_code_len = 0;

	r->first_byte_time = apr_time_now();	
	if ((line_len = socket_item_read_line(r->pool, r->conn, &line)) <= 0) {
		return -1;
	}

	if (line == NULL) {
		return -2;
	}
	LOG_ERR(DEBUG, r->logs, "Parsing answer line: %s", line);

	ptr = line;
	if (*ptr == ' ') ptr++;
	
	if (!(tmp_protocol = memchr(ptr, ' ', strlen(ptr)))) {
		LOG_ERR(CRIT, r->logs, "Failed parsing protocol");
		return -3;
	}
	
	tmp_protocol_len = tmp_protocol - ptr;
	if (tmp_protocol_len < 0) return -4;
	r->answer_protocol = apr_pstrndup(r->pool, ptr, tmp_protocol_len);
	
	/* go to code */
	ptr = tmp_protocol;
	while (*ptr == ' ') ptr++;

	/* read code */
	if (!(tmp_code = memchr(ptr, ' ', strlen(ptr)))) {
		tmp_code_len = strlen(ptr);
		if (tmp_code_len < 0) return -5;
		r->answer_code = apr_pstrndup(r->pool, ptr, tmp_code_len);
		r->code = atoi(r->answer_code);
		r->answer_msg = NULL;
		return 0;
	}
	
	tmp_code_len = tmp_code - ptr;
	if (tmp_code_len < 0) return -6;
	r->answer_code = apr_pstrndup(r->pool, ptr, tmp_code_len);
	r->code = atoi(r->answer_code);
	
	ptr = tmp_code;
	while (*ptr == ' ') ptr++;
	r->answer_msg = apr_pstrdup(r->pool, ptr);

	return 0;
}

int process_read_answer_header(request_t *r)
{
	char *line = NULL;
	int line_len;
	
	while (1) {
		char *key;
		int key_len = 0;
		
		char *value;
		char *sep;

		
		/* get the line */
		line_len = socket_item_read_line(r->pool, r->conn, &line);
		
		if (line_len == 0) {
			break;
		}
	
		if (line_len < 0) {
			return -1;
		}

		if (line_len == 2 && line[0] == '\r' && line[1] == '\n') return 0;

		if (!(sep = strchr(line, ':'))) {
			return -1;
		}

		/* copy key */
		key_len = sep - line;
		if (key_len < 0) return -1; 
		key = apr_pstrndup(r->pool, line, key_len);	
	
		/* go after : and clean space */
		sep++;
		while (*sep == ' ') sep++;

		/* look if there is a value */
		if (*sep == '\r') continue;

		value = apr_pstrdup(r->pool, sep);
		apr_table_add(r->headers_out, key, value);
	}

	return 0;
}

int process_read_body_cl(request_t *r)
{
	const char *cl;
	int cl_num = 0;
	char buff[MAX_READ_BUF];
	
	if (r == NULL) return -1;

	r->body = NULL;
	r->read_bytes = 0;
	
	if (!(cl = apr_table_get(r->headers_out, "Content-Length"))) {
		return -1;
	}	

	cl_num = strtol(cl, NULL, 10);
	if (cl_num == 0) return 0;
	if (cl_num > 0) r->remaining = cl_num;
	else return -1;
	
	r->body = apr_pcalloc(r->body_pool, r->remaining + 1 + 1);	

	while (r->remaining > 0) {
		apr_size_t read_bytes_data;
		
		if (r->remaining > MAX_READ_BUF) read_bytes_data = MAX_READ_BUF;
		else read_bytes_data = r->remaining;

                if(socket_item_read_simple(r->conn, buff, &read_bytes_data) < 0) break;
		memcpy(r->body + r->read_bytes, buff, read_bytes_data);
		
		r->remaining -= read_bytes_data;
		r->read_bytes += read_bytes_data;
	}

	if (r->remaining > 0) {
		return -1;
	}

	r->body[cl_num] = 0;
	return 0;
}

static long get_chunk_size(request_t *r)
{
	apr_size_t char_len = 1;
	char buff[1];
	int end = 0;
	char *chunk_size = NULL;
	long chunk_size_num = 0;
	int num_char = 0;
	int end_state = 0;

	if (!r) return -4;

	if (!r->conn) {
		return -3;
	}

	/*
	 * read byte per byte until we find a non-digit char
	 *
	 */
	do {
		char_len = 1;
		if (socket_item_read_simple(r->conn, buff, &char_len) < 0) {
			return -1;
		}

		if (buff[0] == 0 && num_char <= 0) continue;
		//if (buff[0] == '0' && num_char == 0) return 0;
		
		/* find CR */
		if (buff[0] == '\r' && num_char > 0) {
			end_state = 1;
			continue;
		}
		if (buff[0] == '\n' && end_state == 1) {
			if (!chunk_size) return -1;
			chunk_size = apr_psprintf(r->pool, "0x%s", chunk_size);
			chunk_size_num = strtol(chunk_size, NULL, 16);
			return chunk_size_num;
		}

		if (apr_isxdigit(buff[0])) {
			char *byte = 0;
	
			byte = apr_psprintf(r->pool, "%c", buff[0]);
			if (!chunk_size) chunk_size = byte;
			else {
				chunk_size = apr_pstrcat(r->body_pool, chunk_size, byte, NULL); 
				continue;
			}
			num_char++;
		}
		
	} while (end == 0);

	return -2;
}


int process_read_body_chunked(request_t *r)
{
	int end = 0;
	long chunk_size;
	char *tmp = NULL;
	apr_size_t zero_chunk = 2;

	if (!r) return -1;

	/*
	 * init body context
	 *
	 */
	r->body = NULL;
	r->read_bytes = 0;

	/*
	 * Get the first chunk size
	 *
	 */
	if ((chunk_size = get_chunk_size(r)) < 0) {
		return -1;
	}
	if (chunk_size == 0) {
        	char buff[2];        
		socket_item_read_simple(r->conn, buff, &zero_chunk);
		return 0;
	}
	if (chunk_size < 0) {
		return -1;
	}	
	/*
	 * Register how many bytes remain to read
	 *
	 */
	r->remaining = chunk_size;

	/*
	 * First, read the remaining bytes, then, get the next chunk size
	 *
	 */
	do {	
		char buff[MAX_READ_BUF];
		apr_size_t read_bytes_data = MAX_READ_BUF;
		
		read_bytes_data = chunk_size;
		/*
		 * Loop until we have received all chunk data
		 *
		 */
		while (r->remaining > 0) {
			if (read_bytes_data > MAX_READ_BUF) read_bytes_data = MAX_READ_BUF;
			memset(buff, 0, sizeof(buff));
			
			if(socket_item_read_simple(r->conn, buff, &read_bytes_data) < 0) break;
		
			tmp = NULL;
			if (r->body == NULL) {
				r->body = calloc(read_bytes_data, sizeof(char));
				if (r->body == NULL) return -1;
			}
			else {
				tmp = realloc(r->body, r->read_bytes + read_bytes_data);
				if (!tmp) {
					return -1;
				}
				r->body = tmp;
			}

			memcpy(r->body + r->read_bytes, buff, read_bytes_data);
			r->read_bytes += read_bytes_data;
			r->remaining -= read_bytes_data;
			read_bytes_data = r->remaining;

			if (r->remaining == 0) {
				/* read the \r\n at the end of the chunk */
				read_bytes_data = 2;
				socket_item_read_simple(r->conn, buff, &read_bytes_data);
				memset(buff, 0, MAX_READ_BUF);
			}
		}
		
		/*
		 * Get the next chunk size and continue the loop
		 *
		 */
		chunk_size = get_chunk_size(r);
		if (chunk_size < 0) {
			if (tmp) {
				free(tmp);
				tmp = NULL;
			}
			return -1;
		}
		
		if (chunk_size == 0) {
			/* read the last 2 bytes for \r\n */
			read_bytes_data = 2;
			socket_item_read_simple(r->conn, buff, &read_bytes_data);
			break;
		}

		r->remaining = chunk_size;
	} while (end == 0);

	if (r->remaining > 0) {
		if (tmp) {
			free(tmp);
			tmp = NULL;
		}
		return -1;
	}

	tmp = r->body;

	if (r->read_bytes < 0) return -1;
	r->body = apr_pstrndup(r->body_pool, tmp, r->read_bytes);
	/* considering strdup add one \0 */
	r->read_bytes++;
	if (tmp) {
		free(tmp);
		tmp = NULL;
	}

	return 0;	
}

int process_read_body_connclose(request_t *r)
{
	char *data = NULL;
	int end = 0;
	
	r->read_bytes = 0;	

	do {
		char *temp = NULL;
		apr_size_t len = 0;
		char buff[MAX_READ_BUF];
		apr_status_t rc;

		len = MAX_READ_BUF;
		memset(buff, 0, MAX_READ_BUF);
		rc = socket_item_read_simple(r->conn, buff, &len);

		if (rc != APR_SUCCESS && rc != APR_EOF) break;

		if (len <= 0) {
			end = 1;
			break;
		}
		
		temp = realloc(r->body, len + r->read_bytes);
		if (!temp) {
			LOG_ERR(CRIT, r->logs, "Can't realloc while reading body conn close");
			return -1;
		}
		r->body = temp;	
		memcpy(r->body + r->read_bytes, buff, len);
		r->read_bytes += len;
		temp = NULL;

		if (rc == APR_EOF) break;
		
	} while (end == 0);

	data = r->body;
	r->body = apr_pstrndup(r->body_pool, data, r->read_bytes);
	free(data);

	return 0;
}

int process_read_answer(request_t *request)
{
	const char *answer_type = NULL;
	int conn_close = 0;
	int res = 0;
	
	if (!request) return -1;
	
	if ((res = process_read_answer_line(request)) < 0) {
		LOG_ERR(CRIT, request->logs, "Error reading answer line");
		return -2;
	}

	if (process_read_answer_header(request) < 0) {
		LOG_ERR(CRIT, request->logs, "Error reading answer headers");
		return -3;
	}

	apr_pool_create(&request->body_pool, NULL);
	if (!request->body_pool) return -4;
	
	/*
	 *
	 * Look if we have content-length
	 *
	 */
	if ((answer_type = apr_table_get(request->headers_out, "Content-Length"))) {
		const char *keepalive = NULL;
		const char *close = NULL;
		
		keepalive = apr_table_get (request->headers_in, "Connection");
		if (keepalive == NULL) conn_close = 1;	

		close = apr_table_get (request->headers_out, "Connection");
		if ((close != NULL) && (strncasecmp(close, "Close", strlen(close)) == 0)) conn_close = 1;
		else if (close == NULL) conn_close = 1;

		if (strncasecmp(request->method, "HEAD", 4) == 0) {
			/* We don't try here to really read the content */
		}
		else if (process_read_body_cl(request) < 0) {
			return -5;	
		}
			
		if (conn_close >=1) {
			LOG_ERR(DEBUG, request->logs, "Closing connection");
			socket_item_close(request->conn);
		}
		return 0;
	}
	
	/*
	 *
	 * Look if we have transfer encoding chunked
	 *
	 */
	else if ((answer_type = apr_table_get(request->headers_out, "Transfer-Encoding"))) {
		if (strncasecmp(answer_type, "Chunked", strlen(answer_type)) == 0) {
			const char *keepalive = NULL;		
			const char *close = NULL;;
		
			keepalive = apr_table_get (request->headers_in, "Connection");
			if (keepalive == NULL) {
				conn_close = 1;
			}	

			close = apr_table_get (request->headers_out, "Connection");
			if ((close != NULL) && (strncasecmp(close, "Close", strlen(close)) == 0)) conn_close = 1;

			if (strncasecmp(request->method, "HEAD", 4) == 0) {
			/* We don't try here to really read the content */
			}
			else if (process_read_body_chunked(request) < 0) {
				return -6;
			}
			
			if (conn_close >= 1) {
				socket_item_close(request->conn);
				LOG_ERR(DEBUG, request->logs, "Closing connection");
			}
			return 0;
		}
	}
	
	/*
	 * Look if we can read until connclose
	 *
	 */
	else if((answer_type = apr_table_get(request->headers_out, "Connection"))) {
		if (strncasecmp(answer_type, "close", 5) != 0) {
			LOG_ERR(CRIT, request->logs, "No CL and no TE and no connection close... What can i do ?");
		}
		else {
			if (strncasecmp(request->method, "HEAD", 4) == 0) {
			/* We don't try here to really read the content */
			}
			else if (process_read_body_connclose(request) < 0) {
				return -7;
			}
			LOG_ERR(DEBUG, request->logs, "Closing connection");
			socket_item_close(request->conn);
			return 0;	
		}
	}

	/*
	 *
	 * Else read until connclose
	 *
	 */
	if (strncasecmp(request->method, "HEAD", 4) == 0) { 
                        /* We don't try here to really read the content */
        }
	else if (process_read_body_connclose(request) < 0) {
			socket_item_close(request->conn);
			return -8;
	}

	LOG_ERR(DEBUG, request->logs, "Closing connection");
	socket_item_close(request->conn);
	return 0;
}

extern int request_process(request_t *r, worker_item_ctx_t *w_ctx) 
{
	socket_pool_t socket_pool = w_ctx->workers->socket_pool;
	int res = 0;

	if (!r) return -1;

	if (r->process_status != PROCESS_WAITING) {
		LOG_ERR(CRIT, r->logs, "Don't know if the request has been processed or not (status=%i)", r->process_status); 
		return -2;
	}

	/* establish connect */
	if (socket_item_acquire(socket_pool, &r->conn) < 0) {
		return -3;
	}

	socket_item_get_time(r->conn, &r->start_resolv, &r->start_connect, &r->end_connect);

        hook_run_all(w_ctx->workers->pre_send, r, w_ctx->workers->external_ctx);

	/* send data */
	r->send_first_byte_time = apr_time_now();
	if (process_send_request_line(r) < 0) {
		fprintf(stderr, "Unable to send request line");	
		socket_item_close(r->conn);
		socket_item_release(socket_pool, r->conn);
		return -4;
	}
	if (process_send_body_xxx_enc_cl(r) < 0) {
		fprintf(stderr, "Unable to process xxx-enc cl\n");
		socket_item_close(r->conn);
		socket_item_release(socket_pool, r->conn);
		return -5;
	}
	if (process_send_hdr(r) < 0) {
		fprintf(stderr, "Unable to process headers\n");
		socket_item_close(r->conn);
		socket_item_release(socket_pool, r->conn);
		return -6;
	}
	if (process_send_end_hdr(r) < 0) {
		socket_item_close(r->conn);
		socket_item_release(socket_pool, r->conn);
		return -7;
	}
	if (process_send_body_xxx_enc(r) < 0) {
		socket_item_close(r->conn);
		socket_item_release(socket_pool, r->conn);
		return -8;
	}
	r->end_send_time = apr_time_now();

	/* receive data */
	if ((res = process_read_answer(r)) < 0) {
		socket_item_close(r->conn);
		socket_item_release(socket_pool, r->conn);
		fprintf(stderr, "Error reading answer: %i\n", res);
		return -9;
	}
	r->end_time = apr_time_now();	

	hook_run_all(w_ctx->workers->after_receive, r, w_ctx->workers->external_ctx);

	/* if (process_md5_body(request) < 0) {
		LOG_ERR(DEBUG, request->logs, "Unable to calculate md5 sum of ressource %s", request->resource);
	}
	*/
	request_body_count_words(r);
	r->process_status = PROCESS_DONE;
	
	if (r->body_pool) {
		apr_pool_destroy(r->body_pool);
		r->body_pool = NULL;
		LOG_ERR(DEBUG, r->logs, "Destroying body pool");
	}	

	if (socket_item_release(socket_pool, r->conn) < 0) {
		return -10;
	}
	
	return 0;
}

