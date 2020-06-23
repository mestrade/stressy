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

#include "request_list.h"

#include "apr_pools.h"
#include "apr_thread_cond.h"
#include "apr_thread_mutex.h"

typedef struct request_item_t request_item_t;

struct request_list_t {

        apr_pool_t *pool;

        apr_thread_mutex_t *lock;
        apr_thread_mutex_t *signal_lock;
        apr_thread_cond_t *signal;

        int processed_item;
        int num_item;
        request_item_t *first_item;
        request_item_t *next_processed;
        request_item_t *last_item;

};

struct request_item_t {

        request_item_t *prev;

        apr_thread_mutex_t *lock;
        void *request;
        int pos;

        request_item_t *next;
};

extern int request_list_init(request_list_t **list)
{
        request_list_t *new;
        apr_pool_t *new_pool;

        apr_pool_create(&new_pool, NULL);

        new = apr_pcalloc(new_pool, sizeof(request_list_t));
        if (!new) return -1;

        apr_thread_mutex_create(&new->lock, APR_THREAD_MUTEX_DEFAULT, new_pool);

        /* condition for threads */
        if (apr_thread_mutex_create(&new->signal_lock, APR_THREAD_MUTEX_DEFAULT, new_pool) != APR_SUCCESS) return -1;
        if (apr_thread_cond_create(&new->signal, new_pool) != APR_SUCCESS) return -1;

        new->next_processed = new->last_item = new->first_item = NULL;
        new->pool = new_pool;
        new->num_item = 0;
        new->processed_item = 0;
        *list = new;
        return 0;
}

static int init_list_item(apr_pool_t *pool, request_item_t **item)
{
        request_item_t *new;

        if (!pool) return -1;

        new = apr_pcalloc(pool, sizeof(request_item_t));
        if (!new) return -1;

        apr_thread_mutex_create(&new->lock, APR_THREAD_MUTEX_DEFAULT, pool);
        new->prev = new->next = new->request = NULL;
        new->pos = 0;
        *item = new;
        return 0;
}


extern int request_list_get_next(request_list_t *list, request_t **r)
{
        if (!list) return -1;
        int pos = 0;

        apr_thread_mutex_lock(list->lock);
        if (list->next_processed) {
                *r = list->next_processed->request;
                pos = list->next_processed->pos;
                if (list->next_processed->next) list->next_processed = list->next_processed->next;
                else (list->next_processed = NULL);
                list->processed_item++;
                apr_thread_mutex_unlock(list->lock);
                return pos;
        }
	else {
		*r = NULL;
	}

        apr_thread_mutex_unlock(list->lock);
        return -1;
}


extern int request_list_status(request_list_t *list)
{
        int num_item = 0;
        apr_thread_mutex_lock(list->lock);
        num_item = list->num_item;
        apr_thread_mutex_unlock(list->lock);
        return num_item;
}

extern int request_list_processed_status(request_list_t *list)
{
        int num_item = 0;
        apr_thread_mutex_lock(list->lock);
        num_item = list->processed_item;
        apr_thread_mutex_unlock(list->lock);
        return num_item;
}

extern int request_list_add(request_list_t *list, request_t *r)
{
        if (!list || !r) return -1;

        apr_thread_mutex_lock(list->lock);

        if (list->num_item <= 0) {
                if (init_list_item(list->pool, &list->first_item) < 0) {
                        apr_thread_mutex_unlock(list->lock);
                        return -1;
                }

                list->first_item->pos = list->num_item;
                list->last_item = list->first_item;
                list->first_item->request = r;
                list->first_item->next = NULL;
                list->first_item->prev = NULL;
                list->next_processed = list->first_item;
                list->num_item = 1;

        }
        else {
                if (!list->last_item && !list->first_item) {
                        apr_thread_mutex_unlock(list->lock);
                        return -1;
                }

                if (list->last_item->next) {
                        apr_thread_mutex_unlock(list->lock);
                        return -1;
                }
                if (init_list_item(list->pool, &list->last_item->next) < 0) {
                        apr_thread_mutex_unlock(list->lock);
                        return -1;
                }
                list->last_item->next->prev = list->last_item;
                list->last_item = list->last_item->next;
                list->last_item->request = r;
                list->last_item->next = NULL;

                if (!list->next_processed) list->next_processed = list->last_item;

                list->num_item++;
                list->last_item->pos = list->num_item;
        }

        apr_thread_mutex_unlock(list->lock);
        return 0;
}

extern int request_list_wake_up(request_list_t *list)
{
        apr_thread_mutex_lock(list->signal_lock);
        apr_thread_cond_broadcast(list->signal);
        apr_thread_mutex_unlock(list->signal_lock);
        return 0;
}

extern int request_list_wait_new(request_list_t *list)
{
        apr_status_t rv;

        rv = apr_thread_mutex_lock(list->signal_lock);
        if (rv != APR_SUCCESS) {
                return -1;
        }

        /*
         * Wait the cond
         *
         */
        rv = apr_thread_cond_wait(list->signal, list->signal_lock);
        if (rv != APR_SUCCESS) {
                apr_thread_mutex_unlock(list->signal_lock);
                return -1;
        }

        /*
         * Unlock the cond wait
         *
         */
        rv = apr_thread_mutex_unlock(list->signal_lock);
        if (rv != APR_SUCCESS) {
                return -1;
        }

        return 0;
}
