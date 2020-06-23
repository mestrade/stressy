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

#ifndef REQUEST_LIST_H
#define REQUEST_LIST_H

/**
 * @file request_list.h
 * @brief Request management inside a processing list
 * 
 */

/** @defgroup request_list Request Management using a list
 *  This is a set of function to manage request to process inside a list
 *  @{
 */

#include "request.h"

typedef struct request_list_t request_list_t;	/**< request list object */	

/**
 * Init requests list object
 *
 * @param list receive created structure
 * @result < 0 if it failed
 */
extern int request_list_init(request_list_t **list);

/**
 * Get next request to process from the list
 *
 * @param list where to get the request
 * @param r receive the next request to process
 * @result < 0 if it failed
 */
extern int request_list_get_next(request_list_t *list, request_t **r);

/**
 * Get list status (number of requests inside the list)
 *
 * @param list to get the status from
 * @result The number of all requests in the list, or < 0 if it failed
 */
extern int request_list_status(request_list_t *list);

/**
 * Get the number of processed requests in the list
 *
 * @param list to get the status from
 * @result the number of processed requests, or < 0 if it failed
 */
extern int request_list_processed_status(request_list_t *list);

/**
 * Add a request in the list
 *
 * @param list to add the new request in
 * @param r request to add
 * @result < 0 if it failed
 */
extern int request_list_add(request_list_t *list, request_t *r);

/**
 * Wake up the thread cond mutex of the list
 *
 * @param list to wake up
 * @result < 0 if it failed
 */
extern int request_list_wake_up(request_list_t *list);

/**
 * Block until a new request inserted in the list
 *
 * @param list to wait for
 * @result < 0 if it failed
 */
extern int request_list_wait_new(request_list_t *list);

/* @} */

#endif
