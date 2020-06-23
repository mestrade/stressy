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

#include "parsing_tools.h"

#include <stdio.h>
#include <string.h>
#include "apr_strings.h"


extern int parse_var_name(apr_pool_t *pool, char *string, char sep, char **data)
{
        char *ptr;
        char *end;

        if (!pool || !string) return -1;

        if (!(ptr = memchr(string, sep, strlen(string)))) {
                *data = string;
        }
        else {
                int len = 0;
                len = ptr - string;
                if (len < 0) return -1;
                end = apr_pstrndup(pool, string, len);
                *data = end;
        }
        return 0;
}

extern int parse_var_value(apr_pool_t *pool, char *string, char sep, char **data)
{
        char *ptr;
        char *end;

        if (!pool || !string) return -1;

        if (!(ptr = memchr(string, sep, strlen(string)))) {
                return -1;
        }
        else {
                end = apr_pstrdup(pool, ptr + 1);
                *data = end;
        }

        return 0;
}


extern int parse_clean_recursive(apr_pool_t *src_pool, char *src, char **dst)
{
        char *ptr = NULL;
        int src_len = 0;
        int index_dir = 0;
        char **directory_list;
        int num_directory = 0;
        int real_dir = 0;
        char *clean_link = NULL;
        apr_pool_t *pool = NULL;
	int ending_slash = 0;	

	if (apr_pool_create(&pool, NULL) != APR_SUCCESS) return -1;
	if (pool == NULL) return -1;

	if (src_pool == NULL || src == NULL) return -1;
	src_len = strlen(src);

	if (src[strlen(src) -1] == '/') ending_slash = 1;

        ptr = src;
        for (index_dir = 0; index_dir < src_len; index_dir++) {
                if (*ptr == '/') num_directory++;
                ptr++;
        }

        ptr = src;
        if (*ptr != '/') {
                num_directory++;
        }
        else {
                ptr++;
        }

        directory_list = apr_pcalloc(pool, (num_directory + 1) * sizeof(char *));
        for (index_dir = 0; index_dir < num_directory; index_dir++) {
                char *tmp_dir = NULL;
                char *start_dir = NULL;
                int tmp_dir_len = 0;

                start_dir = ptr;

		if (*start_dir == '\0') {
			if (index_dir <= 0) {
				*dst = src;
				apr_pool_destroy(pool);
				return 0;
			}
			break;
		}

                if ((ptr = memchr(ptr, '/', strlen(ptr))) == NULL) {
			tmp_dir = apr_pstrdup(pool, start_dir);
			tmp_dir_len = strlen(tmp_dir);
		}
                else {
                        int len = 0;

                        len = ptr - start_dir;
                        if (len <= 0) {
				if (index_dir > 0) break;
				else {
					*dst = src;
					apr_pool_destroy(pool);
                                	return 0;
				}
                        }
                        tmp_dir = apr_pstrndup(pool, start_dir, ptr - start_dir);
                	tmp_dir_len = len;
		}

                if (tmp_dir_len <= 0 || tmp_dir == NULL) break;
                if (tmp_dir_len == 1 && *tmp_dir == '.') {
                        ptr++;
                        continue;
                }

                if (tmp_dir_len == 2 && *tmp_dir == '.' && *(tmp_dir + 1) == '.') {
                        real_dir--;
                        ptr++;
                        continue;
                }

                if (real_dir < 0) {
                        apr_pool_destroy(pool);
                        return -1;
                }
                directory_list[real_dir] = tmp_dir;

                real_dir++;
                ptr++;
        }
        
	for (index_dir = 0; index_dir < real_dir; index_dir++) {

                if (*directory_list[index_dir] == 0) {
                        if (index_dir == 0 && (index_dir + 1) == real_dir) {
                                clean_link = apr_pstrdup(pool, "/");
                                *dst = clean_link;
                                break;
                        }

                        if ((index_dir + 1) == real_dir) {
                                clean_link = apr_pstrcat(pool, clean_link, "/", NULL);
                                break;
                        }
                        apr_pool_destroy(pool);
                        return -1;
                }


                if (!clean_link) clean_link = apr_psprintf(src_pool, "/%s", directory_list[index_dir]);
                else clean_link = apr_pstrcat(src_pool, clean_link, "/", directory_list[index_dir], NULL);
        }

	if (ending_slash == 1) clean_link = apr_pstrcat(src_pool, clean_link, "/", NULL);

        apr_pool_destroy(pool);
        *dst = clean_link;
        return 0;
}


extern int parse_resource_from_string(apr_pool_t *pool, char *link, char **resource)
{
        int complete_url = 0;

	if (pool == NULL || link == NULL) return -1;

        while (*link == ' ') link++;

        if (strncasecmp(link, "http://", 7) == 0) {
                link += 7;
                complete_url = 1;
        }
        else if (strncasecmp(link, "https://", 8) == 0) {
                link += 8;
                complete_url = 1;
	}
        else if (strncasecmp(link, "file:", 5) == 0) {
		return -1;
        }
        else if (strncasecmp(link, "mailto:", 7) == 0) {
		return -1;
        }
        else if (strncasecmp(link, "javascript", 10) == 0) {
		return -1;
        }
        else if (link[0] == '/') {
        
	}
 
	/* if we have a complete url: protocol://hostname/resource - we need to get the hostname */
	if (complete_url == 1) {
        	int hostname_len = 0;
		int hostname_port_len = 0;
		char *end_delim = NULL;
		char *port_delim = NULL;

		end_delim = memchr(link, '/', strlen(link));        
		/* look if we have a port information here */
		if (end_delim == NULL) {
			*resource = apr_pstrdup(pool, "/");
			return 0;
		}
		
		hostname_len = end_delim - link;
		if (hostname_len <= 0) {
			return -1;
		}
	
		if ((port_delim = memchr(link, ':', hostname_len))) {
			
			hostname_port_len = port_delim - link;
			if (hostname_port_len <= 0) {
				return -1;
			} 
		}
        
		link += hostname_len;
	}

	if (link) *resource = apr_pstrdup(pool, link);
        else *resource = apr_pstrdup(pool, "/");

	return 0;
}

extern int parse_hostname_from_string(apr_pool_t *pool, char *link, char **hostname)
{
        int complete_url = 0;

	if (pool == NULL || link == NULL) return -1;

        while (*link == ' ') link++;

        if (strncasecmp(link, "http://", 7) == 0) {
                link += 7;
                complete_url = 1;
        }
        else if (strncasecmp(link, "https://", 8) == 0) {
                link += 8;
                complete_url = 1;
	}
        else if (strncasecmp(link, "file:", 5) == 0) {
		return -1;
        }
        else if (strncasecmp(link, "mailto:", 7) == 0) {
		return -1;
        }
        else if (strncasecmp(link, "javascript", 10) == 0) {
		return -1;
        }
        else if (link[0] == '/') {
        
	}
 
	/* if we have a complete url: protocol://hostname/resource - we need to get the hostname */
	if (complete_url == 1) {
        	int hostname_len = 0;
		int hostname_port_len = 0;
		char *end_delim = NULL;
		char *port_delim = NULL;

		end_delim = memchr(link, '/', strlen(link));        
		/* look if we have a port information here */
		if (end_delim == NULL) {
			*hostname = apr_pstrdup(pool, link);
			return 0;
		}
		
		hostname_len = end_delim - link;
		if (hostname_len <= 0) {
			return -1;
		}
	
		if ((port_delim = memchr(link, ':', hostname_len))) {
			
			hostname_port_len = port_delim - link;
			if (hostname_port_len <= 0) {
				return -1;
			}

			*hostname = apr_pstrndup(pool, link, hostname_len); 
			return 0;
		}
       
		*hostname = apr_pstrndup(pool, link, hostname_len); 
		return 0;	
	}


	return 0;
}

                                                                   
