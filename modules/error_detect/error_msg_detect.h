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

#ifndef ERR_DETECT_H
#define ERR_DETECT_H

#include "global_apr.h"
#include "request.h"
#include "pcre.h"


#ifndef HAVE_ERR_DETECT_SHARED
extern int err_detect_module_init(void *ctx);
#endif

extern int error_detect(void *ctx, void *data);
extern int error_detect_post_setup(void *ctx, void *data);

#define ERRORDETECT_XML_SETUP_XPATH "/stressy/errordetect"
#define MAX_ERROR	64
#define ERR_DETECTION_MODULE_NAME	"err_detection"
#define OUTPUT_VECTOR_SIZE	60

#endif
