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
 * @file variables.h
 * @brief Utils for variables manipulation
 * 
 */

/** @defgroup variables_manipulation Variables manipulation
 * This is a set of function to help variables manipulation
 *  @{
 */


#ifndef VARIABLES_H
#define VARIABLES_H

#include "apr_pools.h"

#define VAR_GET         "VAR_GET"       /**< GET (query string) variable type*/
#define VAR_COOKIE      "VAR_COOKIE"	/**< Cookies (header) variable type */
#define VAR_POST        "VAR_POST"	/**< POST (body) variable type */

typedef struct var_item var_item_t;	/**< type definition for variable item structure */
typedef struct var_list var_list_t;	/**< type definition for variables list structure */

/**
 * Variables (parameter and cookies) structure
 *
 */
struct var_item {

        var_item_t *prev;	/**< Previous item in the chained list */

        char *name;		/**< variable name */
        char *value;		/**< variable value */
        char *type;		/**< variable type */
        char *input_type;	/**< post variable type */

        var_item_t *next;	/**< next item in the chained list */

};

/** 
 * Variables (parameters and cookies) list
 *
 */
struct var_list {

        apr_pool_t *pool;	/**< pool for the list */
        int num_var;		/**< current number of variables in the list */
        var_item_t *first_var;	/**< first variable in the list */
        var_item_t *last_var;	/**< last variable in the list */

};

/**
 * Check for variable type
 *
 * @param item is the variable to check
 * @param type is the type to check
 * @result = 0 if the variable type is the type from param
 */
extern int var_check_type(var_item_t *item, char *type);


/**
 * Create a variable list
 *
 * @param pool for list allocation
 * @param list receiving created structure
 * @result < 0 if it failed
 */
extern int var_list_init(apr_pool_t *pool, var_list_t **list);

/**
 * Create a variable item
 *
 * @param pool for memory allocation
 * @param item to received created structure
 * @result < 0 if it failed
 */
extern int var_item_init(apr_pool_t *pool, var_item_t **item);

/**
 * Add a variable item inside variable list
 *
 * @param list to add the var in
 * @param item to add
 * @result < 0 if it failed
 */
extern int var_list_add(var_list_t *list, var_item_t *item);

/** @} */
#endif
