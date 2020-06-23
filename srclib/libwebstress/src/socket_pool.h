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

#ifndef SOCKET_POOL_H
#define SOCKET_POOL_H

/**
 * @file socket_pool.h
 * @brief Socket pool management
 *  
 */

/** @defgroup socket_pool Socket Pool management
 * This is a set of function to manage a pool of socket
 *  @{
 */



#include "apr_pools.h"
#include "apr_network_io.h"

#include "logs.h"

typedef struct socket_pool *socket_pool_t;		/**< Socket pool */
typedef struct socket_pool_item *socket_pool_item_t;	/**< Socket Item */

/**
 * @param item is the socket item
 * @param resolv is the time starting resolv hostname
 * @param connect is time starting connect
 * @param end is end of connect
 * @result < 0 if a problem occured
*/
extern int socket_item_get_time(socket_pool_item_t item, apr_time_t *resolv, apr_time_t *connect, apr_time_t *end);


/**
 * Initialize a pool of socket
 *
 * @param pool to allocate new socket pool memory
 * @param spool socket pool inialized
 * @param num_item number of socket in the pool
 * @param use_ssl to enable ssl
 * @result < 0 if it failed
 */
extern int socket_pool_init(apr_pool_t *pool, socket_pool_t *spool, int num_item, int use_ssl);

/**
 * Start connections from a socket pool
 *
 * @param spool socket pool
 * @param hostname to connect to
 * @param port to connect to
 * @result < 0 if it failed
 */
extern int socket_pool_start(socket_pool_t spool, char *hostname, char *port);

/**
 * set pool async - connection will not be pre-started
 * @param spool socket pool
 * @result < 0 if it failed
 */
extern int socket_pool_setasync(socket_pool_t spool);

/**
 * Set socket pool logs informations
 *
 * @param spool socket pool
 * @param logs informations
 * @result < 0 if it failed
 */
extern int socket_pool_set_logs(socket_pool_t spool, logs_t logs);

/**
 * Acquire a socket to use it
 *
 * @param spool socket pool
 * @param s_item acquired socket
 * @result < o if it failed
 */
extern int socket_item_acquire(socket_pool_t spool, socket_pool_item_t *s_item);

/**
 * Release socket when you don't need it anymore
 *
 * @param spool socket pool
 * @param item to release
 * @result < 0 if it failed
 */
extern int socket_item_release(socket_pool_t spool, socket_pool_item_t item);

/**
 * Read data from socket, allocate memory for read data.
 *
 * @param pool to allocate received data
 * @param item to read data from
 * @param data receiving read data
 * @param len of data to received
 * @result < 0 if it failed
 */
extern int socket_item_read(apr_pool_t *pool, socket_pool_item_t item, char **data, apr_size_t len);

/**
 * Close a socket item (close connection)
 *
 * @param item to close
 * @result < 0 if it failed
 */
extern int socket_item_close(socket_pool_item_t item);

/**
 * Write data to a socket
 *
 * @param item to write data to
 * @param data to write
 * @param len of the data to write
 * @result < 0 if it failed
 */
extern int socket_item_write(socket_pool_item_t item, char *data, apr_size_t len);

/**
 * Read line from a socket
 *
 * @param pool to allocate memory for read data
 * @param item to read data from
 * @param data containing read line
 * @result < 0 if it failed
 */
extern int socket_item_read_line(apr_pool_t *pool, socket_pool_item_t item, char **data);

/** 
 * Read data from socket, no memory allocation for read data
 *
 * @param item to read data from
 * @param data read
 * @param len to read
 * @result < 0 if it failed
 */
extern int socket_item_read_simple(socket_pool_item_t item, char *data, apr_size_t *len);

#define S_CLOSE		0		/**< Socket state closed */
#define S_CONNECTED	1		/**< Socket state connected */
#define SOCKET_MAX_READ 8196		/**< Socket max read size */

/* @} */

#endif
