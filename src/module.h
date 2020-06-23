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

#ifndef MODULE_H
#define MODULE_H

#include <stdio.h>
#include "logs.h"

typedef struct module_list_t module_list_t;


extern int module_list_set_logs(module_list_t *list, logs_t logs);
extern int init_module_list(module_list_t **list);
extern int module_set_directory(module_list_t *list, char *dir);
extern char *module_get_directory(module_list_t *list);
extern int module_load_directory(module_list_t *list);
extern int module_run_all_init(module_list_t *list, void *data);
extern int module_load_builtin(void *data);

#endif
