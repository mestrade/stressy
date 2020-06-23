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

#ifndef ESCAPE_VAR_H
#define ESCAPE_VAR_H

#include "global_apr.h"
#include "request.h"
#include "variables.h"

#define ESCAPEVAR_XML_SETUP_XPATH "/stressy/escapevar"
#define MAX_ESCAPE_CHAR	64
#define ESCAPE_VAR_MODULE_NAME "escape_var_module"

extern int escape_var_setup(void *ctx, void *data);
extern int escape_cmp_answer(void *ctx, void *data);
extern int escape_var(void *ctx, void *data);

#ifndef HAVE_VAR_STRESS_SHARED
int var_stress_module_init(void *ctx);
#endif

#endif
