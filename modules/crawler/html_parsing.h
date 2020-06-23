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

#ifndef HTML_PARSING_H
#define HTML_PARSING_H

#include "request.h"

#define OUTPUT_VECTOR_SIZE	60

typedef struct parsing_ctx *parsing_ctx_t;

struct parsing_ctx {
	request_t request;

	char *last_elem_open;

	request_t request_post;
	int in_form;
	char *action;

	char *type;
};


extern int html_parsing_setup(void *ctx, void *data);
extern int html_parsing(void *ctx, void *data);




#endif
