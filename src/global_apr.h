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

#ifndef GLOBAL_APR

#ifdef HAVE_EFENCE

#endif

#include "apr.h"
#include "apr_strings.h"
#include "apr_md5.h"
#include "apr_lib.h"            /* for apr_is* */
#include "apr_want.h"
#include "apr_optional.h"
#include "apr_shm.h"
#include "apr_rmm.h"
#include "apr_xml.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_thread_mutex.h"
#include "apr_thread_cond.h"
#include "apr_proc_mutex.h"
#include "apr_dso.h"
#include "apr_queue.h"
#include "apr_network_io.h"
#include "apr_poll.h"
#include "apr_hash.h"

#define GLOBAL_APR
#endif

