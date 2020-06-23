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

#include "stressy_ctx.h"
#include "request_list.h"
#include "hook.h"

extern stressy_ctx_t *stressy_ctx_extract(void *data)
{
	if (data == NULL) return NULL;
	return (stressy_ctx_t *)data;
}

extern int init_stressy_ctx(stressy_ctx_t **ctx)
{
        stressy_ctx_t *new;
        apr_pool_t *stressy_ctx_pool;

        apr_pool_create(&stressy_ctx_pool, NULL);

        if ((new = apr_pcalloc(stressy_ctx_pool, sizeof(stressy_ctx_t))) < 0) {
                return -1;
        }

        *ctx = new;
        new->pool = stressy_ctx_pool;
        new->request_directory = NULL;
        new->xml_setup = NULL;
	new->xml_setup_file = NULL;
        new->use_ssl = 0;
        new->port = NULL;

        hook_list_init(&new->setup);
        hook_list_init(&new->post_setup);
        hook_list_init(&new->pre_connect);
        hook_list_init(&new->pre_connect);
        hook_list_init(&new->pre_send);
        hook_list_init(&new->pre_receive);
        hook_list_init(&new->after_receive);
        hook_list_init(&new->request_inserted);
        hook_list_init(&new->level_inserted);
        hook_list_init(&new->request_processed);

        if (request_list_init(&new->request_list) < 0) {
                fprintf(stderr, "Error while init request list");
                return -1;
        }
        new->num_worker = 4;
        new->use_mysql = 0;
#ifdef HAVE_MYSQLCLIENT
        new->mysql_hostname = NULL;
        new->mysql_user = NULL;
        new->mysql_port = 3306;
        new->mysql_pass = NULL;
        new->mysql_base = NULL;

#endif
        
	*ctx = new;
	return 0;
}

extern int request_stressy_ctx_connect_mysql(stressy_ctx_t *ctx)
{
#ifdef HAVE_MYSQLCLIENT
        if (!ctx) return -1;

        if (ctx->use_mysql == 0) {
                LOG_ERR(DEBUG, ctx->logs, "Mysql log is disabled");
                return 0;
        }

        if (!ctx->mysql_hostname) {
                ctx->mysql_hostname = apr_pstrdup(ctx->pool, "localhost");
        }
        if (!ctx->mysql_port) {
                ctx->mysql_port = 3306;
        }

        if (!mysql_real_connect(&ctx->mysql_sock, ctx->mysql_hostname, ctx->mysql_user, ctx->mysql_pass,
                        ctx->mysql_base, ctx->mysql_port, NULL, CLIENT_COMPRESS)) {

                LOG_ERR(CRIT, ctx->logs, "Unable to connect on mysql: %s:%i (user: %s pass: %s)",
                        ctx->mysql_hostname, ctx->mysql_port, ctx->mysql_user, ctx->mysql_pass);
                LOG_ERR(CRIT, ctx->logs, "Mysql result: %s", mysql_error(&ctx->mysql_sock));
                return -1;
        }

        LOG_ERR(INFO, ctx->logs, "MySQL connect successfull");
#endif
        return 0;
}

extern int stressy_ctx_xml_output(stressy_ctx_t *stressy_ctx)
{
	if (!stressy_ctx) return -1;
	if (!stressy_ctx->xml_file) return -1;
	return 1;
}

