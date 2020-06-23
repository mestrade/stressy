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

#include "worker.h"
#include "request.h"
#include "request_list.h"
#include "request_process.h"

#include "apr_thread_proc.h"
#include "apr_thread_mutex.h"
#include "apr_thread_cond.h"


extern int workers_set_request_list(workers_t *workers, request_list_t *list) 
{
	if (workers == NULL) return -1;

	workers->request_list = list;

	return 0;
}

extern int workers_set_socket_pool(workers_t *workers, socket_pool_t pool)
{
	if (workers == NULL) return -1;

	workers->socket_pool = pool;

	return 0;
}

static int worker_item_ctx_init(apr_pool_t *pool, worker_item_ctx_t **ctx)
{
	worker_item_ctx_t *new = NULL;

	if (!pool) return -1;
	new = (worker_item_ctx_t *)apr_pcalloc(pool, sizeof(worker_item_ctx_t));
	if (!new) return -1;

	new->ctx = NULL;
	new->worker = NULL;
	*ctx = new;

	return 0;
}

static int worker_item_init(apr_pool_t *pool, worker_item_t **item)
{
	worker_item_t *new;

	if (!pool) return -1;
	new = (worker_item_t *)apr_pcalloc(pool, sizeof(worker_item_t));
	if (!new) return -1;

	new->id = 0;
	new->status = WORKER_WAITING;
	apr_thread_mutex_create(&new->lock, APR_THREAD_MUTEX_DEFAULT, pool);
	*item = new;

	return 0;
}

extern int worker_init(apr_pool_t *pool, workers_t **workers, int num_worker)
{
	apr_pool_t *new_pool;
	workers_t *new;
	int i = 0;

	if (num_worker <= 0) return -1;

	apr_pool_create(&new_pool, pool);

	if ((new = apr_pcalloc(new_pool, sizeof(workers_t))) == NULL)  {
		return -1;
	}

	new->pool = new_pool;
	new->list = (worker_item_t **) apr_pcalloc(new_pool, num_worker * sizeof(worker_item_t));

	for (i = 0; i < num_worker; i++) {
		if (worker_item_init(new_pool, &new->list[i]) < 0) return -1; 
	}

	apr_thread_mutex_create(&new->lock, APR_THREAD_MUTEX_DEFAULT, new_pool);

        hook_list_init(&new->pre_connect);
        hook_list_init(&new->pre_connect);
        hook_list_init(&new->pre_send);
        hook_list_init(&new->pre_receive);
        hook_list_init(&new->after_receive);
        hook_list_init(&new->request_processed);

	new->num_worker = num_worker;
	new->working_thread = 0;

	*workers = new;
	return 0;
}

static void register_worker(workers_t *w) 
{
	apr_thread_mutex_lock(w->lock);
	w->working_thread++;
	apr_thread_mutex_unlock(w->lock);
}

static void unregister_worker(workers_t *w) 
{
	apr_thread_mutex_lock(w->lock);
	w->working_thread--;
	apr_thread_mutex_unlock(w->lock);
}

static int workers_status(workers_t *w) 
{
	int num_worker = 0;

	apr_thread_mutex_lock(w->lock);
	num_worker = w->working_thread;
	apr_thread_mutex_unlock(w->lock);
	return num_worker;
}

static void *worker_process(apr_thread_t *th, void *worker_ctx)
{
	worker_item_ctx_t *w_ctx = (worker_item_ctx_t *)worker_ctx;
	int pos = 0;
	
	if (!w_ctx) {
		apr_thread_exit(th, APR_SUCCESS);
		return NULL;
	}

	if (w_ctx->workers == NULL) return NULL;
	
	if (w_ctx->workers->request_list == NULL) return NULL;

	while (1) {
		request_t *r;
		int success = 0;
	
		if ((pos = request_list_get_next(w_ctx->workers->request_list, &r)) < 0) {
			
			if (workers_status(w_ctx->workers) <= 0) {
				request_list_wake_up(w_ctx->workers->request_list);
				apr_thread_exit(th, APR_SUCCESS);
			}

			if (request_list_wait_new(w_ctx->workers->request_list) < 0) {
				break;
			}
		
			if ((pos = request_list_get_next(w_ctx->workers->request_list, &r)) < 0) {
				continue;
			}
		}

		/*
		 * Register the thread as working
		 *
		 */
		register_worker(w_ctx->workers);
		
		/*
		 * I have been awaken coz it seems the list can be feeded with new url
		 * I broadcast the signal to another worker
		 */
		request_list_wake_up(w_ctx->workers->request_list);

		if (!r) continue;
		/*
		 * Processing request 
		 *
		 */
		
		/* XXX Add here function processing */
		success = request_process(r, w_ctx);	


		if (success < 0) {
			LOG_ERR(CRIT, r->logs, "Unable to process request: %i", success);
		}

		request_dump(r, DEBUG);
		request_log_access(r);

	        hook_run_all(w_ctx->workers->request_processed, r, w_ctx->workers->external_ctx);


		request_list_wake_up(w_ctx->workers->request_list);
		request_destroy(r);
		r = NULL;
		unregister_worker(w_ctx->workers);
 		if (w_ctx->request_sleep > 0) apr_sleep(w_ctx->request_sleep * APR_USEC_PER_SEC);
	}

	request_list_wake_up(w_ctx->workers->request_list);
	apr_thread_exit(th, APR_SUCCESS);	
	return NULL;
}


extern int worker_start(workers_t *w, void *ctx)
{
	int i = 0;
	
	if (!w) return -1;

	for (i = 0; i < w->num_worker; i++) {
		worker_item_ctx_t *worker_ctx = NULL;
		worker_item_t *worker = NULL;

		worker = w->list[i];
		worker->id = i;
		apr_threadattr_create (&worker->th_attr, w->pool);
		apr_threadattr_detach_set (worker->th_attr, 0);
		
		if (worker_item_ctx_init(w->pool, &worker_ctx) < 0) return -1;	
		worker_ctx->worker = worker;
		worker_ctx->workers = w;
		if (apr_thread_create(&worker->th, worker->th_attr, (void *)worker_process, (void *)worker_ctx, w->pool) != APR_SUCCESS) {
			fprintf(stderr, "Workers thread init failed\n");
		}
	}

	return 0;
}

extern int worker_wait_thread(workers_t *w, void *ctx)
{
	int i = 0;

	for (i = 0; i < w->num_worker; i++) {
		apr_status_t th_status;
		worker_item_t *worker;

		worker = w->list[i];
		
		if (apr_thread_join(&th_status, worker->th) != APR_SUCCESS) {
			fprintf(stderr, "Unable to join thread[%i]\n", i);
		}
	}

	return 0;
}
