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

#ifndef REQUEST_PROCESS_H 
#define REQUEST_PROCESS_H

#include "request.h"
#include "worker.h"

/**
 * @file request_process.h
 * @brief request processing function
 * 
 */

/** @defgroup request_processing Request Processing function
 *  This is a function to process a request
 *  @{
 */



#include "socket_pool.h"

/**
 * Process request using a connection pool
 *
 * @param r request to process
 * @param socket_pool connection pool to process the request
 * @result < 0 if it failed
 */
extern int request_process(request_t *r, worker_item_ctx_t *ctx);

#define MAX_READ_BUF 		8196		/**< max read size */

/* @} */

#endif
