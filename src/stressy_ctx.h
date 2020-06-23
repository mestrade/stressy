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

#ifndef STRESSY_CTX_H
#define STRESSY_CTX_H

#include "site_map.h"
#include "hook.h"
#include "request_list.h"
#include "worker.h"
#include "socket_pool.h"
#include "setup.h"
#include "config.h"
#include "apr_pools.h"

typedef struct stressy_ctx_t stressy_ctx_t;

extern int init_stressy_ctx(stressy_ctx_t **ctx);
extern int request_stressy_ctx_connect_mysql(stressy_ctx_t *ctx);
extern int stressy_ctx_xml_output(stressy_ctx_t *stressy_ctx);
extern stressy_ctx_t *stressy_ctx_extract(void *data);

struct stressy_ctx_t {

        int argc;
        char **argv;

        int use_proxy;
        char *proxy_addr;
        char *proxy_port;
        int use_ssl;
        char *port;
        char *hostname;
        char *start_uri;
        int use_mysql;

	int show_request;

#ifdef HAVE_MYSQLCLIENT
        MYSQL mysql_sock;
        char *mysql_hostname;
        char *mysql_user;
        char *mysql_pass;
        char *mysql_base;
        int mysql_id_scan;
        int mysql_port;
#endif
        setup_t *prog_setup;

        apr_pool_t *pool;
        logs_t logs;
	char *request_directory;
	int request_sleep;

        const char *xml_setup_file;
        xmlDocPtr xml_setup;

	const char *redis_ip;
	unsigned int redis_port;

        int num_worker;
        workers_t *worker;

        socket_pool_t socket_pool;

        int working_thread;

        request_list_t *request_list;
        site_map_t *map;

        hook_list_t setup;
        hook_list_t post_setup;
        hook_list_t pre_connect;
        hook_list_t pre_send;
        hook_list_t pre_receive;
        hook_list_t after_receive;
        hook_list_t level_inserted;
        hook_list_t request_inserted;
        hook_list_t request_processed;

        char *xml_file;

};


#endif
