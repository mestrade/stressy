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

#ifndef WORKER_H
#define WORKER_H

#include "apr_pools.h"
#include "request_list.h"
#include "hook.h"

#include "apr_thread_proc.h"
#include "apr_thread_mutex.h"
#include "apr_thread_cond.h"

typedef struct worker workers_t;

typedef struct worker_item {

        apr_thread_t *th;
        apr_threadattr_t *th_attr;

        int id;
        int status;

        apr_thread_mutex_t *lock;
        workers_t *workers;

} worker_item_t;

typedef struct worker_item_ctx {

        workers_t *workers;
        worker_item_t *worker;
        int request_sleep;
        void *ctx;

} worker_item_ctx_t;


struct worker {

        apr_pool_t *pool;
        apr_thread_mutex_t *lock;

        int num_worker;
        apr_thread_t **exec_th;
        apr_threadattr_t *exec_fct_attr;
        worker_item_t **list;

        apr_thread_t *manager;
        apr_threadattr_t *manager_attr;

        request_list_t *request_list;
        socket_pool_t socket_pool;

        int working_thread;
        int (* exec_fct)(void *);

        hook_list_t pre_connect;
        hook_list_t pre_send;
        hook_list_t pre_receive;
        hook_list_t after_receive;
        hook_list_t request_processed;

	void *external_ctx;

};


#define WORKER_WAITING	0
#define WORKER_WORKING	1

extern int worker_init(apr_pool_t *pool, workers_t **workers, int num_worker);
extern int worker_start(workers_t *workers, void *ctx);
extern int worker_signal(void *ctx, void *data);
extern int worker_wait_end(workers_t *workers, void *ctx);
extern int worker_wait_thread(workers_t *workers, void *ctx);

extern int workers_set_request_list(workers_t *workers, request_list_t *list);
extern int workers_set_socket_pool(workers_t *workers, socket_pool_t pool);

#endif
