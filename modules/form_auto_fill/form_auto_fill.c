#include "form_auto_fill.h"
#include "module_tools.h"
#include "stressy_ctx.h"

#include "pcre.h"

#define MOD_FORM_AUTO_FILL	"mod_form_auto_fill"

/*
 * XPath to find var setup
 *
 */
#define FAF_XPATH_SETUP	"/form_auto_fill/var"

#define OUTPUT_VECTOR_SIZE	30

typedef struct form_auto_fill_ctx_t form_auto_fill_ctx_t;
typedef struct var_autofill_t var_autofill_t;

struct var_autofill_t {

	char *var_detect;
	pcre *var_detect_pcre;
	char *fill_value;
};

struct form_auto_fill_ctx_t {

	/* setup info */
	char *filename;
	xmlDocPtr xml_setup;

	/* list of autofill var */
	int num_var;
	var_autofill_t **var_list;

	int display_unknown;
};


extern int form_auto_fill_exec(void *ctx, void *data)
{
	form_auto_fill_ctx_t *cfg = NULL;
	request_t *r = (request_t *)ctx;	
	stressy_ctx_t *stressy_ctx = (stressy_ctx_t *)data;
	void *tmp_cfg = NULL;
	
	int index_var = 0;
	var_item_t *ptr = NULL;
	int index_fill = 0;
	
	int found_post = 0;
	int found_get = 0;

	if (!r) return -1;

	if (module_get_setup(stressy_ctx->pool, MOD_FORM_AUTO_FILL, (void **)&tmp_cfg) < 0) {
		LOG_ERR(CRIT, r->logs, "Unable to get form auto fill setup");
		return -1;
	}
	cfg = (form_auto_fill_ctx_t *)tmp_cfg;
	
	LOG_ERR(DEBUG, r->logs, "Start Post variables autofill");
	
	if (!r->var_list || r->var_list->num_var <= 0) {
		LOG_ERR(DEBUG, r->logs, "No variable found - exit");
		return 0;
	}

	for (index_var = 0, ptr = r->var_list->first_var;	/* from first var */
		 index_var < r->var_list->num_var;		/* while we don't reach end */
		 index_var++, ptr = ptr->next) {		/* we go to next var */

		/* data */
		int var_matched = 0;

		if (ptr->value && *ptr->value != 0) continue;
		LOG_ERR(DEBUG, r->logs, "Found empty var: %s", ptr->name);

		for (index_fill = 0; index_fill < cfg->num_var; index_fill++) {
			var_autofill_t *autofill = NULL;
			int pcre_res = 0;
			int out_vec[OUTPUT_VECTOR_SIZE];	
			
			autofill = cfg->var_list[index_fill];
			if (!autofill) continue;

			LOG_ERR(DEBUG, r->logs, "Look if var %s match with regexp %s", ptr->name, autofill->var_detect);
			pcre_res = pcre_exec(autofill->var_detect_pcre, NULL, ptr->name, strlen(ptr->name), 0, 0, 
					out_vec, OUTPUT_VECTOR_SIZE);
		
			if (pcre_res >= 0) {
				LOG_ERR(DEBUG, r->logs, "Empty var %s match regexp %s - fill with value %s",
					ptr->name, autofill->var_detect, autofill->fill_value);
					ptr->value = apr_pstrdup(r->pool, autofill->fill_value);
					var_matched = 1;
					if (strncasecmp(ptr->type ,VAR_GET, strlen(VAR_GET))== 0) found_get = 1;
					if (strncasecmp(ptr->type, VAR_POST, strlen(VAR_POST)) == 0) found_post = 1;
					break;
			}
			
			/* end var match */
		}
		if (var_matched == 0 && cfg->display_unknown == 1) {
			LOG_ERR(INFO, r->logs, "Empty var %s is unknown - try to add it in setup",
				ptr->name);
		}	

		/* end variable match */
	}

	/* Rebuild the line */
	if (found_get == 1) {
		LOG_ERR(DEBUG, r->logs, "Found GET var autofilled - rebuild arg line");
		request_rebuild_arg_line(r);
		LOG_ERR(DEBUG, r->logs, "New arg line is: [%s]", r->query); 
	}
	if (found_post == 1) {
		LOG_ERR(DEBUG, r->logs, "Found POST var autofilled - rebuild post data");
		request_rebuild_post_line(r);
		LOG_ERR(DEBUG, r->logs, "New POST line is: [%s]", r->post_body);
	}
	return 0;
}

static int faf_set_filename(void *ctx, void *arg, int type)
{
	form_auto_fill_ctx_t *cfg = NULL;
	stressy_ctx_t * stressy_ctx = (stressy_ctx_t *)ctx;	
	void *tmp_cfg = NULL;
	
	if (!stressy_ctx) return -1;

	if (module_get_setup(stressy_ctx->pool, MOD_FORM_AUTO_FILL, (void **)&tmp_cfg) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get form auto fill setup");
		return -1;
	}
	cfg = (form_auto_fill_ctx_t *)tmp_cfg;
	
	if (type == SETUP_CLI) {
		cfg->filename = arg;
		LOG_ERR(INFO, stressy_ctx->logs, "Set form auto fill definition filename to: %s", 
				cfg->filename);
	
		return 0;
	}
	else if (type == SETUP_XML) {
		cfg->filename = setup_get_tag_value(stressy_ctx->pool, (xmlNodePtr)arg, "value");
		LOG_ERR(NOTICE, stressy_ctx->logs, "[%s] definition filename to: %s", MOD_FORM_AUTO_FILL,
				cfg->filename);
	}


	return 0;
}

static int faf_set_display_unknown(void *ctx, void *arg, int type)
{
	form_auto_fill_ctx_t *cfg = NULL;
	stressy_ctx_t * stressy_ctx = (stressy_ctx_t *)ctx;	
	void *tmp_cfg = NULL;
	
	if (!stressy_ctx) return -1;

	if (module_get_setup(stressy_ctx->pool, MOD_FORM_AUTO_FILL, (void **)&tmp_cfg) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to get form auto fill setup");
		return -1;
	}
	cfg = (form_auto_fill_ctx_t *)tmp_cfg;
	
	if (type == SETUP_CLI) {
		LOG_ERR(INFO, stressy_ctx->logs, "Set display of autofill unsupported variables to on");
		cfg->display_unknown = 1;
	}

	return 0;
}

extern int form_auto_fill_post_setup(void *ctx, void *data)
{
	form_auto_fill_ctx_t *cfg = NULL;
	stressy_ctx_t * stressy_ctx = (stressy_ctx_t *)ctx;
	void *tmp_cfg = NULL;
	
	/* XPATH info to get setup */
	xmlXPathContextPtr context;
	xmlXPathObjectPtr result;
	xmlNodeSetPtr xml_var;
	int index_var = 0;

	if (!stressy_ctx) return -1;
	
	LOG_ERR(DEBUG, stressy_ctx->logs, "Form auto fill start post setup");

	if (module_get_setup(stressy_ctx->pool, MOD_FORM_AUTO_FILL, (void **)&tmp_cfg) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to setup module conf for form auto fill");
		return -1;
	}
	cfg = (form_auto_fill_ctx_t *)tmp_cfg;
	if (!cfg) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to find module ctx");
		return -1;
	}

	if (!cfg->filename) return 0;
	
	cfg->xml_setup = xmlParseFile(cfg->filename);
	if (!cfg->xml_setup) {
		LOG_ERR(CRIT, stressy_ctx->logs, "An error occured while parsing file: %s", cfg->filename);
		return -1;
	}

	/* create xpath context */
	context = xmlXPathNewContext(cfg->xml_setup);
	if (!context) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to create XPath context to find setup");
		return -1;
	}

	result = xmlXPathEvalExpression((xmlChar *)FAF_XPATH_SETUP, context);
	if (!result) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to do XPATH on setup document");
		return -1;
	}
	
	xml_var = result->nodesetval;
	cfg->num_var = xml_var->nodeNr;
	LOG_ERR(DEBUG, stressy_ctx->logs, "Found %i setup for variable autofill", cfg->num_var);
	if (cfg->num_var <=0) return 0;	

	/* init var list */
	cfg->var_list = (var_autofill_t **)apr_pcalloc(stressy_ctx->pool, (cfg->num_var + 1)  * sizeof(var_autofill_t *));
	if (!cfg->var_list) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to create var_list for %i items", cfg->num_var);
		return -1;
	}

	for (index_var = 0; index_var < cfg->num_var; index_var++) {
		var_autofill_t *var = NULL;
		xmlNodePtr var_node = NULL;
		char *regexp = NULL;
		char *value = NULL;
		char *type = NULL;
		
		/* pcre compile defs */
		const char *err_str;
		int err_offset = 0;

		var_node = xml_var->nodeTab[index_var];
		
		regexp = (char *)xmlGetProp(var_node, BAD_CAST"pattern");
		value = (char *)xmlGetProp(var_node, BAD_CAST"fill_with");
		type = (char *)xmlGetProp(var_node, BAD_CAST"pattern_type");

		/* look if we have all values */
		if (!regexp || !value) {
			LOG_ERR(CRIT, stressy_ctx->logs, "Var autofill(%i) doesn't have all info needed", index_var);
			return -1;
		}

		/* init var */
		var = (var_autofill_t *)apr_pcalloc(stressy_ctx->pool, sizeof(var_autofill_t));
		if (!var) {
			LOG_ERR(CRIT, stressy_ctx->logs, "Unable to alloc memory for var autofill");
			return -1;
		}
		
		if (!type) type = apr_pstrdup(stressy_ctx->pool, "clear");
		if (strncasecmp(type, "b64", 3) == 0) {
			/* XXX Decode base 64 before set the value */

		}
		else {
			LOG_ERR(DEBUG, stressy_ctx->logs, "Set var_autofill(%i) regexp to %s", index_var, regexp);
			var->var_detect = apr_pstrdup(stressy_ctx->pool, regexp);
			var->var_detect_pcre = pcre_compile(regexp, PCRE_EXTENDED | PCRE_EXTRA, 
							&err_str, &err_offset, NULL);
		
			if (!var->var_detect_pcre) {
				LOG_ERR(CRIT, stressy_ctx->logs, "Unable to compile regexp: %s", regexp);
				cfg->var_list[index_var] = NULL;
				continue;
			}
		}
		
		LOG_ERR(DEBUG, stressy_ctx->logs, "Set var_autofill(%i) value to: %s", index_var, value);
		var->fill_value = apr_pstrdup(stressy_ctx->pool, value);

		cfg->var_list[index_var] = var;

	}

	LOG_ERR(NOTICE, stressy_ctx->logs, "[%s]: Found %i autofill values", MOD_FORM_AUTO_FILL,
		cfg->num_var);
	
	hook_add(stressy_ctx->worker->pre_send, "Form auto fill on request", form_auto_fill_exec); 

	return 0;
}

/*
 * Create setup for the module
 *
 */
extern int form_auto_fill_setup(void *ctx, void *data)
{
	stressy_ctx_t * stressy_ctx = (stressy_ctx_t *)ctx;
	form_auto_fill_ctx_t *cfg = NULL;

	/* if no stressy_ctx - exit */
	if (!stressy_ctx) return -1;

	cfg = apr_pcalloc(stressy_ctx->pool, sizeof(form_auto_fill_ctx_t));
	if (!cfg) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to alloc memory for form auto fill module");
		return -2;
	}

	if (module_set_setup(stressy_ctx->pool, MOD_FORM_AUTO_FILL, (void *)cfg) < 0) {
		LOG_ERR(CRIT, stressy_ctx->logs, "Unable to setup module conf for form auto fill");
		return -1;
	}

	cfg->display_unknown = 0;
	
	setup_add_directive(stressy_ctx->prog_setup, "form_auto_fill", SETUP_CLI_NEED_1, faf_set_filename,
		"=filename with variable auto fill definition");
	setup_add_directive(stressy_ctx->prog_setup, "form_auto_fill_unknown", SETUP_CLI_NEED_0, faf_set_display_unknown,
		"enable display of unsupported variables name");

	return 0;
}

#ifdef HAVE_FORM_AUTO_FILL_SHARED
extern int module_init(void *ctx)
{
#else
extern int form_auto_fill_module_init(void *ctx)
{
#endif
	stressy_ctx_t * stressy_ctx = (stressy_ctx_t *)ctx;

	if (!stressy_ctx) return -1;

	LOG_ERR(NOTICE, stressy_ctx->logs, "Init module: %s", MOD_FORM_AUTO_FILL);
	hook_add(stressy_ctx->setup, "Form auto fill", form_auto_fill_setup);
	hook_add(stressy_ctx->post_setup, "Form auto fill post setup", form_auto_fill_post_setup);

	return 0;
}
