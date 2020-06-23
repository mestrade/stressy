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

/**
 * @file parsing_tools.h
 * @brief Utils for parsing links and data
 * 
 */

/** @defgroup parsint_tools Parsing Utilities
 * This is a set of function to help parsing
 *  @{
 */


#ifndef PARSING_TOOLS_H
#define PARSING_TOOLS_H

#include "apr_pools.h"

#define PROTO_HTTP		0	/**< HTTP Protocol */
#define PROTO_HTTPS		1	/**< HTTPS Protocol */
#define PROTO_NOT_SUPPORTED	2	/**< Not supported protocol */
#define PROTO_UNDEFINED		-1	/**< Undefined Protocol when link is not an URI or URL */

/**
 * Get an hostname from a link
 *
 * @param pool to allocate resource
 * @param string to parse for resource
 * @param hostname receive parsed result
 * @return < 0 if something failed
 *
 */
extern int parse_hostname_from_string(apr_pool_t *pool, char *string, char **hostname);



/**
 * Get a resource from a link
 *
 * @param pool to allocate resource
 * @param string to parse for resource
 * @param resource receive parsed result
 * @return < 0 if something failed
 *
 */
extern int parse_resource_from_string(apr_pool_t *pool, char *string, char **resource);

/**
 * Clean a resource when containing some recursive directories 
 *
 * @param pool to allocate clean data
 * @param src source data
 * @param dst receive the clean data 
 * @result < 0 if there is too much recursive directories or if it failed
 *
 */
extern int parse_clean_recursive(apr_pool_t *pool, char *src, char **dst);

/**
 * Get variable name from a variable name(sep)value
 *
 * @param pool to alloc memory for the found name
 * @param string to search name in
 * @param sep separator between name and value
 * @param data receive name
 * @result < 0 if it failed
 */
extern int parse_var_name(apr_pool_t *pool, char *string, char sep, char **data);

/**
 * Get variable value from a variable name(sep)value
 *
 * @param pool to alloc memory for the found name
 * @param string to search value in
 * @param sep separator between name and value
 * @param data receive value
 * @result < 0 if it failed
 */
extern int parse_var_value(apr_pool_t *pool, char *string, char sep, char **data);

/** @} */
#endif
