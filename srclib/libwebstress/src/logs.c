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

#include "logs.h"
#include "pthread.h"
#include "apr_strings.h"
#include "libxml/tree.h"

extern int logs_init (apr_pool_t * pool, logs_t * logs)
{
  	logs_t new;
  	apr_pool_t *new_pool;

  	apr_pool_create (&new_pool, pool);
  	if (!new_pool) return -1;	

  	if (!(new = apr_pcalloc (new_pool, sizeof (struct logs)))) return -1;
  
	*logs = new;
  	new->pool = new_pool;
  	new->level = 0;
  	apr_thread_mutex_create(&new->lock, APR_THREAD_MUTEX_DEFAULT, new->pool);
  
  	return 0;
}

extern int logs_start_err_output(logs_t logs)
{
	apr_status_t rv;

	if (!logs) return -1;

	if ((rv = apr_file_open(&logs->err_output, logs->err_filename ? logs->err_filename : "error.log", APR_APPEND|APR_WRITE|APR_CREATE|APR_LARGEFILE, APR_OS_DEFAULT, 
			logs->pool)) != APR_SUCCESS) {
        	char err[64];
                apr_strerror(rv, err, 64);
                LOG_ERR(NOTICE, logs, "Unable to open error logs %s res: %s", logs->err_filename ? logs->err_filename : "error.log", err);
               	logs->err_output = NULL;
        }

	if ((rv = apr_file_open(&logs->err_access, logs->access_filename ? logs->access_filename:"access.log",  APR_APPEND|APR_WRITE|APR_CREATE|APR_LARGEFILE, APR_OS_DEFAULT, 
			logs->pool)) != APR_SUCCESS) {
        	char err[64];
                apr_strerror(rv, err, 64);
		LOG_ERR(CRIT, logs, "Unable to open access logs %s res: %s", logs->access_filename ? logs->access_filename: "access.log", err);
               	logs->err_access = NULL;
	}

	if (logs->err_filename == NULL) {
        	if (apr_file_open_stderr(&logs->err_stdout, logs->pool) != APR_SUCCESS) {
	        	        fprintf(stderr, "Unable to open stderr for logs");
       		}
	}	

	LOG_ERR(DEBUG, logs, "Logs successfuly initialized");

	return 0;
}

static char *get_level_filter(int level)
{
	switch (level) {
		case DEBUG:
			return "DEBUG";
			break;
		case NOTICE:
			return "[NOTICE]";
			break;
		case CRIT:
			return "[CRITICAL]";
			break;
		case WARN:
			return "[WARN]";
			break;
		case INFO:
			return "[INFO]";
			break;
		case ALERT:
			return "[ALERT]";
			break;
		case LOW:
			return "[LOW]";
			break;
		case MEDIUM:
			return "[MEDIUM]";
			break;
		case HIGH:
			return "[HIGH]";
			break;
	}

	return NULL;
}

extern int access_log (logs_t logs, const char *fct, char *file, int line, char *fmt, ...)
{
	apr_pool_t *pool = NULL;
	va_list ap;
  	char log_line[MAXLOGLINE];
  	char time_str[APR_CTIME_LEN];

  	char *final_log_line = NULL;
 	char *display_line = NULL;
	apr_size_t display_len = 0;	 
       	
  	memset(time_str, 0, APR_CTIME_LEN);
  	apr_ctime(time_str, apr_time_now());

	if (!logs) {
		fprintf(stderr, "logs: unable to find log context for %s(%i): %s\n", file, line, fct);
		return 0;
	}

	apr_pool_create(&pool, NULL);
	if (!pool) return 0;
	
	final_log_line = apr_psprintf(pool, "[%s]", time_str);

  	va_start (ap, fmt);
  	memset (log_line, 0, MAXLOGLINE);
  	vsnprintf (log_line, MAXLOGLINE, fmt, ap);
	display_line = apr_pstrcat(pool, final_log_line, " ", log_line, "\n", NULL);
	display_len = strlen(display_line);
	
  	apr_thread_mutex_lock(logs->lock);
  	if (logs->err_access) apr_file_write(logs->err_access, display_line, &display_len);
        if (logs->err_stdout) apr_file_write(logs->err_stdout, display_line, &display_len);
	if (logs->err_access) apr_file_flush(logs->err_access);
	if (logs->err_stdout) apr_file_flush(logs->err_stdout);
	
	apr_thread_mutex_unlock(logs->lock);
  	va_end (ap);

	/*
	 * destroy pool of the log line
	 *
	 */
	apr_pool_destroy(pool);
  	return 0;
}


extern int f_log (int severity, logs_t logs, const char *fct, char *file, int line, char *fmt, ...)
{
	apr_pool_t *pool = NULL;
	va_list ap;
  	char log_line[MAXLOGLINE];
  	char time_str[APR_CTIME_LEN];

  	char *final_log_line = NULL;
 	char *display_line = NULL;
	apr_size_t display_len = 0;	 
       	
  	memset(time_str, 0, APR_CTIME_LEN);
  	apr_ctime(time_str, apr_time_now());

	if (!logs) {
		fprintf(stderr, "logs: unable to find log context for %s(%i): %s\n", file, line, fct);
		return 0;
	}

	/*
	 * Check log level
	 *
	 */	
	if (severity < logs->level) {
		return 0;
	}

	apr_pool_create(&pool, NULL);
	if (!pool) return 0;
	
	if (logs->time == 1) final_log_line = apr_psprintf(pool, "[%s]", time_str);
	if (final_log_line) final_log_line = apr_pstrcat(pool, final_log_line, get_level_filter(severity), NULL);
	else final_log_line = apr_pstrdup(pool, get_level_filter(severity));	

	/*
	 * display thread id
	 *
	 */
      	if (logs->debug_thread == 1 || severity == CRIT || severity == DEBUG) {
		char *id = NULL;

		id = apr_psprintf(pool, "[%p]", (void *)pthread_self ());
		final_log_line = apr_pstrcat(pool, final_log_line, id, NULL); 
	}		
	
	if (logs->display_function == 1) final_log_line = apr_pstrcat(pool, final_log_line, fct, NULL);

      	/*
	 * display file and line
	 *
	 */
	if (logs->display_file == 1 || severity == CRIT || severity == DEBUG) {
		char *file_line = NULL;

		file_line = apr_psprintf(pool, "[%s:%i]", file, line);
		final_log_line = apr_pstrcat(pool, final_log_line, file_line, NULL);
	}
		
  	va_start (ap, fmt);
  	memset (log_line, 0, MAXLOGLINE);
  	vsnprintf (log_line, MAXLOGLINE, fmt, ap);
	display_line = apr_pstrcat(pool, final_log_line, " ", log_line, "\n", NULL);
	display_len = strlen(display_line);
	
  	apr_thread_mutex_lock(logs->lock);
	if (logs->err_output) apr_file_write(logs->err_output, display_line, &display_len);
  	if (logs->err_stdout) apr_file_write(logs->err_stdout, display_line, &display_len);
	if (logs->err_output) apr_file_flush(logs->err_output);
	if (logs->err_stdout) apr_file_flush(logs->err_stdout);
	apr_thread_mutex_unlock(logs->lock);
  	va_end (ap);

	/*
	 * destroy pool of the log line
	 *
	 */
	apr_pool_destroy(pool);
  	return 0;
}

extern int set_level_filter(char *data)
{
      	if (strncasecmp (data, "ALERT", strlen (data)) == 0) return ALERT;
      	if (strncasecmp (data, "DEBUG", strlen (data)) == 0) return DEBUG;
      	if (strncasecmp (data, "NOTICE", strlen (data)) == 0) return NOTICE;
      	if (strncasecmp (data, "CRITICAL", strlen (data)) == 0) return CRIT;
      	if (strncasecmp (data, "WARN", strlen (data)) == 0) return WARN;
	if (strncasecmp (data, "INFO", strlen (data)) == 0) return INFO;

	if (strncasecmp (data, "LOW", strlen (data)) == 0) return LOW;
	if (strncasecmp (data, "MEDIUM", strlen (data)) == 0) return MEDIUM;
	if (strncasecmp (data, "HIGH", strlen (data)) == 0) return HIGH;




	/* here is default */
	return WARN;
}

extern int logs_setup_from_xml(logs_t logs, xmlNodePtr node)
{
	xmlNodePtr ptr = NULL;
	int num_syslog_setup = 0;

	if (!logs || !node) return -1;

	/*
	 * default debug setup
	 *
	 */
  	logs->debug_thread = 0;
  	logs->display_function = 0;
  	logs->display_file = 0;
  	logs->time = 0;

	LOG_ERR(NOTICE, logs, "Initializing logs from xml");
	for (ptr = node->children; ptr; ptr = ptr->next) {

		if (strncasecmp((char *)ptr->name, "log_level", strlen((char *)ptr->name)) == 0) {
			char *level = NULL;
			level = (char *)xmlNodeGetContent(ptr);
			logs->level = set_level_filter(level);
			LOG_ERR(INFO, logs, "Found log level: %s", level);
			continue;
		}
		if (strncasecmp((char *)ptr->name, "log_file", strlen((char *)ptr->name)) == 0) {
			char *filename = NULL;
			filename = (char *)xmlNodeGetContent(ptr);
			LOG_ERR(INFO, logs, "Found log file: %s", filename);
			if (apr_file_open(&logs->err_output, filename, APR_APPEND | APR_WRITE | APR_CREATE | APR_LARGEFILE, APR_OS_DEFAULT, 
						logs->pool) != APR_SUCCESS) {
				LOG_ERR(CRIT, logs, "Unable to open log file: %s", logs->err_filename);
				return -1;
			}
			continue;
		}
		if (strncasecmp((char *)ptr->name, "debug_threads", strlen((char *)ptr->name)) == 0) {
			char *enable = NULL;
			enable = (char *)xmlNodeGetContent(ptr);
			if (strncasecmp(enable, "On", strlen(enable)) != 0) continue;
			logs->debug_thread = 1;
			LOG_ERR(INFO, logs, "Enable thread debug");
			continue;
		}
		if (strncasecmp((char *)ptr->name, "debug_file", strlen((char *)ptr->name)) == 0) {
			char *enable = NULL;
			enable = (char *)xmlNodeGetContent(ptr);
			if (strncasecmp(enable, "On", strlen(enable)) != 0) continue;
			logs->display_file = 1;
			LOG_ERR(INFO, logs, "Enable source filename debug");
			continue;
		}
		if (strncasecmp((char *)ptr->name, "debug_function", strlen((char *)ptr->name)) == 0) {
			char *enable = NULL;
			enable = (char *)xmlNodeGetContent(ptr);
			if (strncasecmp(enable, "On", strlen(enable)) != 0) continue;
			logs->display_function = 1;
			LOG_ERR(INFO, logs, "Enable source function debug");
			continue;
		}
		if (strncasecmp((char *)ptr->name, "log_time", strlen((char *)ptr->name)) == 0) {
			char *enable = NULL;
			enable = (char *)xmlNodeGetContent(ptr);
			if (strncasecmp(enable, "On", strlen(enable)) != 0) continue;
			logs->time = 1;
			LOG_ERR(INFO, logs, "Enable timestamp");
			continue;
		}
		if (strncasecmp((char *)ptr->name, "log_syslog", strlen((char *)ptr->name)) == 0) {
			/* XXX ADD SYSLOG SETUP HERE */
			num_syslog_setup++;
			continue;
		}
	}

	return 0;
}
