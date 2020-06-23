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

#ifndef STRESSY_CORE_SETUP_H
#define STRESSY_CORE_SETUP_H

#include "config.h"

extern int setup_uri(void *ctx, void *value, int type);
extern int setup_hostname(void *ctx, void *value, int type);
extern int setup_proxy(void *ctx, void *value, int type);
extern int setup_port(void *ctx, void *value, int type);
extern int setup_proxy_port(void *ctx, void *value, int type);
extern int setup_ssl(void *ctx, void *value, int type);
extern int setup_worker(void *ctx, void *value, int type);
extern int setup_template(void *ctx, void *value, int type);
extern int setup_xml_out(void *ctx, void *value, int type);
extern int setup_verbose(void *ctx, void *value, int type);
extern int setup_err_output(void *ctx, void *value, int type);
extern int setup_sleep(void *ctx, void *value, int type);
extern int setup_redis_ip(void *ctx, void *value, int type);
extern int setup_redis_port(void *ctx, void *value, int type);


#ifdef HAVE_MYSQLCLIENT
extern int setup_mysql_enabled(void *ctx, void *value, int type);
extern int setup_mysql_database(void *ctx, void *value, int type);
extern int setup_mysql_hostname(void *ctx, void *value, int type);
extern int setup_mysql_port(void *ctx, void *value, int type);
extern int setup_mysql_user(void *ctx, void *value, int type);
extern int setup_mysql_pass(void *ctx, void *value, int type);
extern int setup_mysql_id_scan(void *ctx, void *value, int type);
#endif

#endif
