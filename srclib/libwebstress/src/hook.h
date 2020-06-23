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

#ifndef HOOK_H
#define HOOK_H

/**
 * @file hook.h
 * @brief Utils for hooking functions
 * 
 */

/** @defgroup hook Hook management
 *  This is a set of function to use hooks during request processing
 *  @{
 */


typedef struct hook_list *hook_list_t;		/**< Hook list object */

/**
 * Initialize hook list
 *
 * @param hook_list receiving created object
 * @result < 0 if it failed
 */
extern int hook_list_init(hook_list_t *hook_list);

/**
 * Add a function in hook
 * 
 * @param list hook list
 * @param name of the function added
 * @param "(*fct)(void *, void*)" function to add
 * @result < 0 if it failed
 */
extern int hook_add(hook_list_t list, char *name, int (*fct)(void *, void*));

/**
 * Execute hook functions
 *
 * @param list hook list
 * @param ctx context passed to the launched functions
 * @param data passed to launched functions
 * @result < 0 if it failed
 */
extern int hook_run_all(hook_list_t list, void *ctx, void *data);

/* @} */

#endif

