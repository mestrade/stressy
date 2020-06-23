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

#ifndef REQUEST_TOOLS_H
#define REQUEST_TOOLS_H

#include "request.h"
#include "stressy_ctx.h"

extern int request_from_xml(request_t *r, stressy_ctx_t *stressy_ctx, xmlNodePtr node);
extern int request_from_firefox(stressy_ctx_t *ctx, xmlDocPtr document);

#endif
