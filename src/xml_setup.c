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

#include "xml_setup.h"
#include "stressy_ctx.h"
#include "util_xml.h"

extern int xml_setup(stressy_ctx_t *stressy_ctx)
{
	xmlNodePtr node = NULL;
	
	if (!stressy_ctx || !stressy_ctx->xml_setup) return -1;

        if (get_node_with_xpath(stressy_ctx->xml_setup, "/stressy/hostname", &node) == 0)
        	stressy_ctx->hostname = apr_pstrdup(stressy_ctx->pool, (char *)xmlNodeGetContent(node));
        
	if (get_node_with_xpath(stressy_ctx->xml_setup, "/stressy/mysql", &node) == 0) {
		char *mysql_status;
		
		mysql_status = (char *)xmlNodeGetContent(node);
		if (strncasecmp(mysql_status, "On", strlen(mysql_status)) == 0) stressy_ctx->use_mysql = 1;	
	}
	
	return 0;
}
