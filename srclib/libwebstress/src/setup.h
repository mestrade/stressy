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

#ifndef SETUP_H
#define SETUP_H

/**
 * @file setup.h
 * @brief Setup utilities
 * 
 */

/** @defgroup setup Setup management 
 *  This is a set of function to help setup for a program
 *  @{
 */

#include "libxml/tree.h"
#include "apr_pools.h"



typedef struct setup_t setup_t;		/**< Setup object */


/*
 * error codes
 *
 */

#define SETUP_CLI_NEED_0		0	/**< CLI directive need no argument */
#define SETUP_CLI_NEED_1                1	/**< ClI directive need one argument */

#define SETUP_CLI			1	/**< Setup is command line */
#define SETUP_XML			2	/**< Setup is xml */

/**
 * Start setup context
 *
 * @param setup receive created context
 * @result < 0 if it failed
 */
extern int setup_init(setup_t **setup);

/**
 * Add setup directive
 *
 * @param setup context
 * @param keyword for directive
 * @param type of the directive (if need arguments)
 * @param (*fct)(void *, void *, int) function to run when the directive is called
 * @param info about the directive
 * @result < 0 if it failed
 */
extern int setup_add_directive(setup_t *setup, char *keyword, int type, int (*fct)(void *, void *, int), const char *info);

/**
 * Add information from command line
 *
 * @param setup context
 * @param argc number of arguments
 * @param argv table of arguments
 * @result < 0 if it failed
 */
extern int setup_set_cli_info(setup_t *setup, int argc, char **argv);

/**
 * Set the xml filename for an xml setup
 *
 * @param setup context
 * @param filename for xml setup
 * @result < 0 if it failed
 */
extern int setup_set_cli_xml(setup_t *setup, char *filename);

/**
 * Execute setup with command line arguments 
 *
 * @param setup context
 * @param data to give as argument to all directive launched (ex: program structure)
 * @param bad_directive in case something failed
 * @result < 0 if it failed
 */
extern int setup_run_cli(setup_t *setup, void *data, char **bad_directive);

/**
 * Execute setup with an xml file
 *
 * @param setup context
 * @param data to give as argument to all directive launched (ex: program structure)
 * @param bad_directive in case something failed
 * @result < 0 if it failed
 */ 
extern int setup_run_xml(setup_t *setup, void *data, char **bad_directive);

/**
 * Log on stderr the list of directive registered in the setup
 *
 * @param setup context
 * @result < 0 if it failed
 */
extern int setup_display_options(setup_t *setup);

/**
 * Get element attribute "value" value from element name from an xml setup
 *
 * @param pool to allocate memory
 * @param node of the xml setup
 * @param name of the tag
 * @result contain the tag value
 *
 * @note if the element contain an attribute disabled, the function return nothing
 *
 */
extern char *setup_get_tag_value(apr_pool_t *pool, xmlNodePtr node, char *name);


/* @} */

#endif

