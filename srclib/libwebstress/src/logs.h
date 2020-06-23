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

#ifndef LOGS_H
#define LOGS_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <netinet/in.h>

#include "apr_pools.h"
#include "apr_file_io.h"

#define MAXLOGLINE 8096

/* application information */
#define ALARM	20

/* for error logs */
#define CRIT	5
#define INFO	4
#define ALERT	3
#define NOTICE 	2
#define WARN	1
#define DEBUG	0

/* for info logs */
#define LOW	6	
#define MEDIUM	7
#define HIGH	8 

/* a is conf, b is loglevel */
#define LOG_ERR(severity, conf, format, arg...) f_log(severity, conf, __FUNCTION__, __FILE__, __LINE__, format, ## arg)
#define LOG_INFO(severity, conf, format, arg...) f_log(severity, conf, __FUNCTION__, __FILE__, __LINE__, format, ## arg)
#define LOG_ACCESS(conf, format, arg...) access_log(conf, __FUNCTION__, __FILE__, __LINE__, format, ## arg)



typedef struct logs *logs_t;

extern int logs_init (apr_pool_t *pool, logs_t * logs);
extern int f_log (int severity, logs_t logs, const char *fct, char *file, int line, char *fmt, ...);
extern int access_log (logs_t logs, const char *fct, char *file, int line, char *fmt, ...);
extern int set_level_filter(char *data);
extern int logs_start_err_output(logs_t logs);

struct logs {
  	apr_pool_t *pool;
  	int level;
  	int debug_thread;
  	int display_file;
  	int display_function;
  	int time;
  	char *err_filename;
	char *access_filename;
	char *debug_filename;

	apr_thread_mutex_t *lock;
	apr_file_t *err_output;
	apr_file_t *err_debug;
	apr_file_t *err_access;
	apr_file_t *err_stdout;
};

#endif
