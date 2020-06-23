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

#ifndef REQUEST_H
#define REQUEST_H

/**
 * @file request.h
 *
 * @brief Utils for creating and manipulating request
 * 
 */

/** @defgroup request_tools Request manipulation 
 * 
 *  Request utilities 
 *  @{
 */


#include "logs.h"
#include "variables.h"
#include "socket_pool.h"

#include "apr_time.h"
#include "apr_strings.h"

#define MAX_HDR_IN	50			/**< Maximum number of sent headers */
#define MAX_HDR_OUT	50			/**< Maximum number of received headers */

#define PROCESS_WAITING         0               /**< request still waiting to be processed */
#define PROCESS_DONE            1               /**< request processed */


typedef struct request request_t;		/**< Request object */


/**
 * Request to clean
 * @return < 0 if it failed
*/
extern int request_clean_request(request_t *r);

/**
 * Request set module info
 * @param request receive request to set module into
 * @param module name
 * @return < 0 if it failed
*/
extern int request_set_module(request_t *r, char *module);

/**
 * Request initializer
 *
 * @param request receive initialized request
 * @return < 0 if it failed
 
*/
extern int request_init(request_t **request);

/**
 * Request destroy
 *
 * @param request destroyed request 
 * @return < 0 if it failed 
 */
extern int request_destroy(request_t *request);

/**
 * Method setter
 *
 * @param request where to set the method
 * @param method to set
 * @result < 0 if it failed
 */
extern int request_set_method(request_t *request, char *method);

/**
 * URI setter
 *
 * @param request where to set the uri
 * @param link where to find the resource
 * @result < if it failed
 */
extern int request_set_resource_from_uri(request_t *request, char *link);

/**
 * Query string setter
 *
 * @param request where to set the query string
 * @param link where to find the query string
 * @result < 0 if it failed
 * 
 */
extern int request_set_query_from_uri(request_t *request, char *link);

/**
 * Set referer from the previous request 
 *
 * @param new request where to set the new referer
 * @param prev request to build the referer with
 * @result < 0 if it failed
 */
extern int request_set_referer_from_request(request_t new, request_t prev);

/**
 * Parse header cookie and add all cookies in the variable list
 *
 * @param request where to find the header cookie
 * @result < if it failed
 */
extern int request_set_cookies_from_header(request_t *request);

/**
 * Copy basic headers between two request
 *
 * @param src source request
 * @param dst destination request
 * @result < 0 if it failed
 */
extern int request_copy_basic(request_t *src, request_t *dst);

/**
 * Rebuild Cookie header from variables in the list with VAR_COOKIE type
 *
 * @param request where to rebuild cookie line
 * @return < 0 if it failed
 */
extern int request_rebuild_cookie_line(request_t *request);

/**
 * Rebuild query string from variables in the list with VAR_GET type 
 *
 * @param request where to rebuild query string
 * @result < 0 if it failed
 */
extern int request_rebuild_arg_line(request_t *request);

/**
 * Rebuild POST data for xxx-urlencoded from variables in the list with VAR_POST type
 *
 * @param request where to rebuild POST body
 * @result < 0 if it failed
 */
extern int request_rebuild_post_line(request_t *request);

/**
 * Count words in body received after request being processed
 *
 * @param request where to count words
 * @result < 0 if it failed, or the number of found words
 */
extern int request_body_count_words(request_t *request);

/**
 * dump requests
 * 
 * @param request request to dump
 * @param severity when it has to dump
 * @result < 0 if it failed
 */
extern int request_dump(request_t *r, int severity);

/**
 * Log access for requests
 * 
 * @param request request to log
 * @result < 0 if it failed
 */
extern int request_log_access(request_t *r);


/**
 * Request structure
 *
 */
struct request {

	int step;				/**< step of an attack */
	/*
	 * time info
	 *
	 */
	apr_time_t start_resolv;
	apr_time_t start_connect;
	apr_time_t end_connect;
	apr_time_t created_time;		/**< time of request creation */
	apr_time_t send_first_byte_time;	/**< time of first byte sent */
	apr_time_t end_send_time;		/**< time of last byte sent */
	apr_time_t first_byte_time;		/**< time of first byte received */
	apr_time_t end_time;			/**< time of last byte received */
	int process_status;			/**< status of request processing */

	char *name;				/**< name of the request */
	
	apr_pool_t *pool;			/**< request pool for memory alloc */
	
	logs_t logs;				/**< logs pointer */

	socket_pool_item_t conn;			/**< connection */ 	
	char *hostname;				/**< hostname of the request */
	char *ip;				/**< destination IP */
	char *port;				/**< destination port */

	int is_proxy;				/**< enable proxy */	
	int enable_ssl;				/**< enable ssl */
	
	char *method;				/**< method */
	int n_method;				/**< method number */

	char *protocol;				/**< protocol */

	char *request;	
	char *resource;				/**< resource */
	char *query;				/**< query string */	
	char *path;				/**< resource directory */
	char *post_body;			/**< POST body data */

	int send_cl;				/**< content length if the request has a body */
	int keepalive;				/**< enable keepalive */

	const char *login;			/**< login credential */
	const char *password;			/**< password credential */
	
	var_list_t *var_list;			/**< variables list */
	apr_table_t *headers_in;		/**< headers to send */

   	char *answer_protocol;			/**< received protocol */
	int code;				/**< received code number */
	char *answer_code;			/**< received code string */
	char *answer_msg;			/**< received message */
	apr_table_t *headers_out;		/**< received headers */
	apr_off_t read_bytes;			/**< read bytes from the server */
	apr_off_t remaining;			/**< remaining bytes to read */
	apr_pool_t *body_pool;			/**< body pool */
	char *body;				/**< received data */
	char *body_md5;				/**< received data md5 */

	int body_words;				/**< number of received words */
	int body_lines;				/**< number of received lines */

	char *html_base_href;

	apr_table_t *notes;			/**< internal note array */
	char *module;

	void *ctx;
};

/* @} */

#endif

