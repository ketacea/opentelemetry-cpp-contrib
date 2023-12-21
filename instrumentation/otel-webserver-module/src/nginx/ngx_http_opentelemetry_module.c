/*
* Copyright 2022, OpenTelemetry Authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "ngx_http_opentelemetry_module.h"
#include "ngx_http_opentelemetry_log.h"
#include "script.h"
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_http_opentelemetry_worker_conf_t *worker_conf;
static unsigned int c_count = 0;
static ngx_str_t hostname;
static char* sName;
static char* sNamespace;
static char* sInstanceId;

const struct ScriptAttributeDeclaration kDefaultScriptAttributes[] = {
  {"http.scheme", "$scheme"},
  {"net.host.port", "$server_port"},
  {"net.peer.ip", "$remote_addr"},
  {"net.peer.port", "$remote_port"},
};

/*
List of modules being monitored
*/
otel_ngx_module otel_monitored_modules[] = {
    {
        NGX_HTTP_POST_READ_PHASE,
        ngx_http_otel_start_handler
    },
    {
        NGX_HTTP_LOG_PHASE,
        ngx_http_otel_stop_handler
    }
};


/*
	Here's the list of directives specific to our module, and information about where they
	may appear and how the command parser should process them.
*/
static ngx_command_t ngx_http_opentelemetry_commands[] = {

    { ngx_string("NginxModuleEnabled"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleEnabled),
      NULL},

    { ngx_string("NginxModuleOtelSpanExporter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelSpanExporter),
      NULL},

    { ngx_string("NginxModuleOtelSslEnabled"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelSslEnabled),
      NULL},

    { ngx_string("NginxModuleOtelSslCertificatePath"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelSslCertificatePath),
      NULL},

    { ngx_string("NginxModuleOtelExporterEndpoint"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelExporterEndpoint),
      NULL},

    { ngx_string("NginxModuleOtelExporterOtlpHeaders"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelExporterOtlpHeaders),
      NULL},

    { ngx_string("NginxModuleOtelSpanProcessor"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelSpanProcessor),
      NULL},

    { ngx_string("NginxModuleOtelSampler"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelSampler),
      NULL},

    { ngx_string("NginxModuleServiceName"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleServiceName),
      NULL},

    { ngx_string("NginxModuleServiceNamespace"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleServiceNamespace),
      NULL},

    { ngx_string("NginxModuleServiceInstanceId"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleServiceInstanceId),
      NULL},

    { ngx_string("NginxModuleOtelMaxQueueSize"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelMaxQueueSize),
      NULL},

    { ngx_string("NginxModuleOtelScheduledDelayMillis"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelScheduledDelayMillis),
      NULL},

    { ngx_string("NginxModuleOtelExportTimeoutMillis"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelExportTimeoutMillis),
      NULL},

    { ngx_string("NginxModuleOtelMaxExportBatchSize"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleOtelMaxExportBatchSize),
      NULL},

    { ngx_string("NginxModuleResolveBackends"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleResolveBackends),
      NULL},

    { ngx_string("NginxModuleTraceAsError"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleTraceAsError),
      NULL},

    { ngx_string("NginxModuleReportAllInstrumentedModules"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleReportAllInstrumentedModules),
      NULL},

    { ngx_string("NginxModuleWebserverContext"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_otel_context_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("NginxModuleMaskCookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleMaskCookie),
      NULL},

    { ngx_string("NginxModuleCookieMatchPattern"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleCookieMatchPattern),
      NULL},

    { ngx_string("NginxModuleMaskSmUser"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleMaskSmUser),
      NULL},

    { ngx_string("NginxModuleDelimiter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleDelimiter),
      NULL},

    { ngx_string("NginxModuleSegment"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleSegment),
      NULL},

    { ngx_string("NginxModuleMatchfilter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleMatchfilter),
      NULL},

    { ngx_string("NginxModuleMatchpattern"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleMatchpattern),
      NULL},

    { ngx_string("NginxModuleSegmentType"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleSegmentType),
      NULL},

    { ngx_string("NginxModuleSegmentParameter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleSegmentParameter),
      NULL},

    { ngx_string("NginxModuleRequestHeaders"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleRequestHeaders),
      NULL},

    { ngx_string("NginxModuleResponseHeaders"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, nginxModuleResponseHeaders),
      NULL},

    ngx_null_command	/* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_opentelemetry_module_ctx = {
    NULL,						/* preconfiguration */
    ngx_http_opentelemetry_init,	                        /* postconfiguration */

    NULL,	                                        /* create main configuration */
    NULL,	                                        /* init main configuration */

    NULL,	                                        /* create server configuration */
    NULL,	                                        /* merge server configuration */

    ngx_http_opentelemetry_create_loc_conf,	        /* create location configuration */
    ngx_http_opentelemetry_merge_loc_conf		        /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_opentelemetry_module = {
    NGX_MODULE_V1,							/* module version and a signature */
    &ngx_http_opentelemetry_module_ctx,		                        /* module context */
    ngx_http_opentelemetry_commands,			                /* module directives */
    NGX_HTTP_MODULE, 						        /* module type */
    NULL, 								/* init master */
    NULL, 								/* init module */
    ngx_http_opentelemetry_init_worker, 	                                /* init process */
    NULL, 								/* init thread */
    NULL, 								/* exit thread */
    ngx_http_opentelemetry_exit_worker,   				/* exit process */
    NULL, 								/* exit master */
    NGX_MODULE_V1_PADDING
};

/*
	Create loc conf to be used by the module
	It takes a directive struct (ngx_conf_t) and returns a newly
	created module configuration struct
 */
static void* ngx_http_opentelemetry_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_opentelemetry_loc_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_opentelemetry_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* Initialize */
    conf->nginxModuleEnabled                   = NGX_CONF_UNSET;
    conf->nginxModuleResolveBackends           = NGX_CONF_UNSET;
    conf->nginxModuleOtelScheduledDelayMillis  = NGX_CONF_UNSET;
    conf->nginxModuleOtelExportTimeoutMillis   = NGX_CONF_UNSET;
    conf->nginxModuleOtelMaxExportBatchSize    = NGX_CONF_UNSET;
    conf->nginxModuleReportAllInstrumentedModules = NGX_CONF_UNSET;
    conf->nginxModuleMaskCookie                = NGX_CONF_UNSET;
    conf->nginxModuleMaskSmUser                = NGX_CONF_UNSET;
    conf->nginxModuleTraceAsError              = NGX_CONF_UNSET;
    conf->nginxModuleOtelMaxQueueSize          = NGX_CONF_UNSET;
    conf->nginxModuleOtelSslEnabled            = NGX_CONF_UNSET;

    return conf;
}

static char* ngx_http_opentelemetry_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_opentelemetry_loc_conf_t *prev = (ngx_http_opentelemetry_loc_conf_t*)parent;
    ngx_http_opentelemetry_loc_conf_t *conf = (ngx_http_opentelemetry_loc_conf_t*)child;
    ngx_otel_set_global_context(prev);

    ngx_conf_merge_value(conf->nginxModuleEnabled, prev->nginxModuleEnabled, 1);
    ngx_conf_merge_value(conf->nginxModuleReportAllInstrumentedModules, prev->nginxModuleReportAllInstrumentedModules, 0);
    ngx_conf_merge_value(conf->nginxModuleResolveBackends, prev->nginxModuleResolveBackends, 1);
    ngx_conf_merge_value(conf->nginxModuleTraceAsError, prev->nginxModuleTraceAsError, 0);
    ngx_conf_merge_value(conf->nginxModuleMaskCookie, prev->nginxModuleMaskCookie, 0);
    ngx_conf_merge_value(conf->nginxModuleMaskSmUser, prev->nginxModuleMaskSmUser, 0);

    ngx_conf_merge_str_value(conf->nginxModuleOtelSpanExporter, prev->nginxModuleOtelSpanExporter, "");
    ngx_conf_merge_str_value(conf->nginxModuleOtelExporterEndpoint, prev->nginxModuleOtelExporterEndpoint, "");
    ngx_conf_merge_str_value(conf->nginxModuleOtelExporterOtlpHeaders, prev->nginxModuleOtelExporterOtlpHeaders, "");
    ngx_conf_merge_value(conf->nginxModuleOtelSslEnabled, prev->nginxModuleOtelSslEnabled, 0);
    ngx_conf_merge_str_value(conf->nginxModuleOtelSslCertificatePath, prev->nginxModuleOtelSslCertificatePath, "");
    ngx_conf_merge_str_value(conf->nginxModuleOtelSpanProcessor, prev->nginxModuleOtelSpanProcessor, "");
    ngx_conf_merge_str_value(conf->nginxModuleOtelSampler, prev->nginxModuleOtelSampler, "");
    ngx_conf_merge_str_value(conf->nginxModuleServiceName, prev->nginxModuleServiceName, "");
    ngx_conf_merge_str_value(conf->nginxModuleServiceNamespace, prev->nginxModuleServiceNamespace, "");
    ngx_conf_merge_str_value(conf->nginxModuleServiceInstanceId, prev->nginxModuleServiceInstanceId, "");
    ngx_conf_merge_str_value(conf->nginxModuleCookieMatchPattern, prev->nginxModuleCookieMatchPattern, "");
    ngx_conf_merge_str_value(conf->nginxModuleDelimiter, prev->nginxModuleDelimiter, "");
    ngx_conf_merge_str_value(conf->nginxModuleMatchfilter, prev->nginxModuleMatchfilter, "");
    ngx_conf_merge_str_value(conf->nginxModuleSegment, prev->nginxModuleSegment, "");
    ngx_conf_merge_str_value(conf->nginxModuleMatchpattern, prev->nginxModuleMatchpattern, "");

    ngx_conf_merge_size_value(conf->nginxModuleOtelMaxQueueSize, prev->nginxModuleOtelMaxQueueSize, 2048);
    ngx_conf_merge_msec_value(conf->nginxModuleOtelScheduledDelayMillis, prev->nginxModuleOtelScheduledDelayMillis, 5000);
    ngx_conf_merge_msec_value(conf->nginxModuleOtelExportTimeoutMillis, prev->nginxModuleOtelExportTimeoutMillis, 30000);
    ngx_conf_merge_size_value(conf->nginxModuleOtelMaxExportBatchSize, prev->nginxModuleOtelMaxExportBatchSize, 512);

    ngx_conf_merge_str_value(conf->nginxModuleSegmentType, prev->nginxModuleSegmentType, "First");
    ngx_conf_merge_str_value(conf->nginxModuleSegmentParameter, prev->nginxModuleSegmentParameter, "2");
    ngx_conf_merge_str_value(conf->nginxModuleRequestHeaders, prev->nginxModuleRequestHeaders, "");
    ngx_conf_merge_str_value(conf->nginxModuleResponseHeaders, prev->nginxModuleResponseHeaders, "");

    return NGX_CONF_OK;
}

/*
	Function to initialize the module and used to register all the phases handlers and filters.
	-------------------------------------------------------------------------------------------------
	For reference: HTTP Request phases

	Each HTTP request passes through a sequence of phases. In each phase a distinct type of processing
	is performed on the request. Module-specific handlers can be registered in most phases, and many
	standard nginx modules register their phase handlers as a way to get called at a specific stage of
	request processing. Phases are processed successively and the phase handlers are called once the
	request reaches the phase. Following is the list of nginx HTTP phases:

	NGX_HTTP_POST_READ_PHASE
	NGX_HTTP_SERVER_REWRITE_PHASE
	NGX_HTTP_FIND_CONFIG_PHASE
	NGX_HTTP_REWRITE_PHASE
	NGX_HTTP_POST_REWRITE_PHASE
	NGX_HTTP_PREACCESS_PHASE
	NGX_HTTP_ACCESS_PHASE
	NGX_HTTP_POST_ACCESS_PHASE
	NGX_HTTP_PRECONTENT_PHASE
	NGX_HTTP_CONTENT_PHASE
	NGX_HTTP_LOG_PHASE

	On every phase you can register any number of your handlers. Exceptions are following phases:

	NGX_HTTP_FIND_CONFIG_PHASE
	NGX_HTTP_POST_ACCESS_PHASE
	NGX_HTTP_POST_REWRITE_PHASE
	NGX_HTTP_TRY_FILES_PHASE
	-------------------------------------------------------------------------------------------------
 */
static ngx_int_t ngx_http_opentelemetry_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t    *cmcf;
    ngx_uint_t                   m, cp, ap, pap, srp, prp, rp, lp, pcp;
    ngx_http_phases              ph;
    ngx_uint_t                   phase_index;
    ngx_int_t                    res;

    // ngx_writeError(cf->cycle->log, __func__, "Starting Opentelemetry Module init");

    cp = ap = pap = srp = prp = rp = lp = pcp = 0;

    res = -1;

    OtelMainConf* otelMainConf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

      if (!otelMainConf) {
        return NGX_ERROR;
      }

      int attrLen = sizeof(kDefaultScriptAttributes) / sizeof(kDefaultScriptAttributes[0]);
      otelMainConf->scriptAttributes = ngx_array_create(cf->pool, attrLen,
        sizeof(struct CompiledScriptAttribute));

      if (otelMainConf->scriptAttributes == NULL) {
        return NGX_ERROR;
      }

      for (int j = 0; j < attrLen; j++) {
        struct CompiledScriptAttribute* compiledAttrib = ngx_array_push(otelMainConf->scriptAttributes);

        if (compiledAttrib == NULL) {
          return false;
        }

        ngx_str_t attribute = ngx_string(kDefaultScriptAttributes[j].attribute);
        ngx_str_t script = ngx_string(kDefaultScriptAttributes[j].script);
        if (!CompileScriptAttribute(cf, &attribute, &script, compiledAttrib)) {
          return NGX_ERROR;
        }
      }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    // ngx_writeError(cf->cycle->log, __func__, "Registering handlers for modules in different phases");

    /*
  for (const PhaseHandler& ph : handlers) {
    ngx_http_handler_pt* ngx_handler =
      (ngx_http_handler_pt*)ngx_array_push(&main_conf->phases[ph.phase].handlers);

    if (ngx_handler == nullptr) {
      continue;
    }

    *ngx_handler = ph.handler;
  }
    */
    otel_ngx_module module;
    for (m = 0; m < 2; m++) {
        module = otel_monitored_modules[m];
        ngx_http_handler_pt* ngx_handler =
          (ngx_http_handler_pt*)ngx_array_push(&cmcf->phases[module.phase].handlers);
        if (ngx_handler == NULL) {
          continue;
        }
        *ngx_handler = module.handler;
    }

    /* Register header_filter */
    // ngx_http_next_header_filter = ngx_http_top_header_filter;
    // ngx_http_top_header_filter = ngx_http_opentelemetry_header_filter;

    /* Register body_filter */
    // ngx_http_next_body_filter = ngx_http_top_body_filter;
    // ngx_http_top_body_filter = ngx_http_opentelemetry_body_filter;

    hostname = cf->cycle->hostname;
    /* hostname is extracted from the nginx cycle. The attribute hostname is needed
    for OTEL spec and the only place it is available is cf->cycle
    */
    // ngx_writeError(cf->cycle->log, __func__, "Opentelemetry Module init completed!");
    return NGX_OK;
}

/*
    This function gets called when master process creates worker processes
*/
static ngx_int_t ngx_http_opentelemetry_init_worker(ngx_cycle_t *cycle)
{
    int p = getpid();
    char * s = (char *)ngx_pcalloc(cycle->pool, 6);
    sprintf(s, "%d", p);
    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "mod_opentelemetry: ngx_http_opentelemetry_init_worker: Initializing Nginx Worker for process with PID: %s", s);

    /* Allocate memory for worker configuration */
    worker_conf = (ngx_http_opentelemetry_worker_conf_t*)ngx_pcalloc(cycle->pool, sizeof(ngx_http_opentelemetry_worker_conf_t));
    if (worker_conf == NULL) {
       ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "mod_opentelemetry: ngx_http_opentelemetry_init_worker: Not able to allocate memeory for worker conf");
       return NGX_ERROR;
    }

    worker_conf->pid = s;

    return NGX_OK;
}

/*
    This function gets called when a worker process pool is destroyed
*/
static void ngx_http_opentelemetry_exit_worker(ngx_cycle_t *cycle)
{
    if (worker_conf && worker_conf->isInitialized)
    {
        opentelemetry_core_term();
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "mod_opentelemetry: ngx_http_opentelemetry_exit_worker: Exiting Nginx Worker for process with PID: %s**********", worker_conf->pid);
    }
}

static char* ngx_otel_context_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
    ngx_str_t* value;

    value = (ngx_str_t*)cf->args->elts;
    ngx_http_opentelemetry_loc_conf_t * otel_conf_temp=(ngx_http_opentelemetry_loc_conf_t *)conf;
    if(cf->args->nelts == 4){
        sName = (char*)malloc(value[2].len);
        strcpy(sName, (char*)value[2].data);
        sNamespace = (char*)malloc(value[1].len);
        strcpy(sNamespace, (char*)value[1].data);
        sInstanceId = (char*)malloc(value[3].len);
        strcpy(sInstanceId, (char*)value[3].data);
        otel_conf_temp->nginxModuleServiceNamespace = value[1];
        otel_conf_temp->nginxModuleServiceName = value[2];
        otel_conf_temp->nginxModuleServiceInstanceId = value[3];
        c_count++;
    }
    return NGX_CONF_OK;
}
static void ngx_otel_set_global_context(ngx_http_opentelemetry_loc_conf_t * prev)
{
    if((prev->nginxModuleServiceName).data != NULL && (prev->nginxModuleServiceNamespace).data != NULL && (prev->nginxModuleServiceInstanceId).data != NULL){
        sName = (char*)malloc((prev->nginxModuleServiceName).len);
        strcpy(sName, (char*)(prev->nginxModuleServiceName).data);
        sNamespace = (char*)malloc((prev->nginxModuleServiceNamespace).len);
        strcpy(sNamespace, (char*)(prev->nginxModuleServiceNamespace).data);
        sInstanceId = (char*)malloc((prev->nginxModuleServiceInstanceId).len);
        strcpy(sInstanceId, (char*)(prev->nginxModuleServiceInstanceId).data);
        c_count = 1;
   }
}

static void otel_payload_decorator(ngx_http_request_t* r, OTEL_SDK_ENV_RECORD* propagationHeaders, int count)
{
   ngx_list_part_t  *part;
   ngx_table_elt_t  *header;
   ngx_table_elt_t            *h;
   ngx_http_header_t          *hh;
   ngx_http_core_main_conf_t  *cmcf;
   ngx_uint_t       nelts;

   part = &r->headers_in.headers.part;
   header = (ngx_table_elt_t*)part->elts;
   nelts = part->nelts;

   for(int i=0; i<count; i++){

       int header_found=0;
       for(ngx_uint_t j = 0; j<nelts; j++){
           h = &header[j];
           if(strcmp(httpHeaders[i], (char *)h->key.data)==0){

               header_found=1;

               if(h->key.data)
                    ngx_pfree(r->pool, h->key.data);
               if(h->value.data)
                    ngx_pfree(r->pool, h->value.data);

               break;
           }
       }
       if(header_found==0)
       {
           h = (ngx_table_elt_t*)ngx_list_push(&r->headers_in.headers);
       }

       if(h == NULL )
            return;

       h->key.len = strlen(propagationHeaders[i].name);
       h->key.data = (u_char*)ngx_pcalloc(r->pool, sizeof(char)*((h->key.len)+1));
       strcpy((char *)h->key.data, propagationHeaders[i].name);

       ngx_writeTrace(r->connection->log, __func__, "Key : %s", propagationHeaders[i].name);

       h->hash = ngx_hash_key(h->key.data, h->key.len);

       h->value.len = strlen(propagationHeaders[i].value);
       h->value.data = (u_char*)ngx_pcalloc(r->pool, sizeof(char)*((h->value.len)+1));
       strcpy((char *)h->value.data, propagationHeaders[i].value);
       h->lowcase_key = h->key.data;

       cmcf = (ngx_http_core_main_conf_t*)ngx_http_get_module_main_conf(r, ngx_http_core_module);
       hh = (ngx_http_header_t*)ngx_hash_find(&cmcf->headers_in_hash, h->hash,h->lowcase_key, h->key.len);
       if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
           return;
       }

       ngx_writeTrace(r->connection->log, __func__, "Value : %s", propagationHeaders[i].value);

   }

   ngx_http_otel_handles_t* ctx = ngx_http_get_module_ctx(r, ngx_http_opentelemetry_module);
   ctx->propagationHeaders = propagationHeaders;
   ctx->pheaderCount = count;
}

static OTEL_SDK_STATUS_CODE otel_startClientInteraction(ngx_http_request_t* r){
    OTEL_SDK_STATUS_CODE res = OTEL_SUCCESS;

    if(!r || r->internal)
    {
        ngx_writeTrace(r->connection->log, __func__, "Not a Main Request(sub-request or internal redirect)");
        return res;
    }
    else if (!ngx_initialize_opentelemetry(r))    /* check if Otel Agent Core is initialized */
    {
        return res;
    }

    ngx_http_otel_handles_t* ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_opentelemetry_module);
    if(ctx && ctx->otel_req_handle_key){
        OTEL_SDK_ENV_RECORD* propagationHeaders = (OTEL_SDK_ENV_RECORD*)ngx_pcalloc(r->pool, 5 * sizeof(OTEL_SDK_ENV_RECORD));
        if (propagationHeaders == NULL)
        {
            ngx_writeError(r->connection->log, __func__, "Failed to allocate memory for propagation headers");
            return OTEL_STATUS(fail);
        }
        int ix = 0;
        char *request_method = (char *)ngx_pcalloc(r->pool, (strlen((char *)(r->method_name).data))+1);
        strcpy(request_method,(const char*)(r->method_name).data);
        request_method[(r->method_name).len]='\0';
        res = startClientInteraction((void*)ctx->otel_req_handle_key, request_method, propagationHeaders, &ix);

        if (OTEL_ISSUCCESS(res))
        {
            removeUnwantedHeader(r);
            otel_payload_decorator(r, propagationHeaders, ix);
            ngx_writeTrace(r->connection->log, __func__, "Interaction client begin successful");
        }
        else
        {
            ngx_writeError(r->connection->log, __func__, "Error: Interaction client begin result code: %d", res);
        }
        for(int i=0;i<ix;i++)
        {
          if(propagationHeaders[i].name)
            free((char *)propagationHeaders[i].name);
          if(propagationHeaders[i].value)
            free((char *)propagationHeaders[i].value);
        }
    }
    return res;
}

static void otel_stopClientInteraction(ngx_http_request_t* r, void* request_handle_key)
{
    OTEL_SDK_STATUS_CODE res = OTEL_SUCCESS;
    if(!r || r->internal)
    {
        return;
    }

    OTEL_SDK_HANDLE_REQ otel_req_handle_key = OTEL_SDK_NO_HANDLE;
    ngx_http_otel_handles_t* ctx = ngx_http_get_module_ctx(r, ngx_http_opentelemetry_module);
    if (r->pool == NULL && request_handle_key != NULL)
    {
        otel_req_handle_key = request_handle_key;
    }
    else if (ctx && ctx->otel_req_handle_key)
    {
        otel_req_handle_key = ctx->otel_req_handle_key;
    }
    else
    {
        return;
    }

    unsigned int errCode=200;
    if(otel_requestHasErrors(r))
    {
        errCode=(unsigned int)otel_getErrorCode(r);
    }
    char *peer_name = NULL;
    char *schema = NULL;
    char *uri = NULL;
    ngx_http_upstream_t *upstream = r -> upstream;
    if (upstream) {
        if ((upstream->peer).name && (upstream->peer).name->data) {
            peer_name = (char *)ngx_pcalloc(r->pool, strlen((char *)(upstream->peer).name -> data)+1);
            strcpy(peer_name, (const char*)(upstream->peer).name -> data);
            peer_name[(upstream->peer).name -> len]='\0';
        }
    }
    if (peer_name == NULL) {
        peer_name = "";
    }
    res = stopClientInteraction(otel_req_handle_key, peer_name, errCode);
    if (OTEL_ISFAIL(res))
    {
        ngx_writeError(r->connection->log, __func__, "Error: Stop Client Interaction failed, result code: %d", res);
    }
}

static ngx_flag_t otel_requestHasErrors(ngx_http_request_t* r)
{
    return (r->err_status >= LOWEST_HTTP_ERROR_CODE)||(r->headers_out.status >= LOWEST_HTTP_ERROR_CODE);
}
static ngx_uint_t otel_getErrorCode(ngx_http_request_t* r)
{
    if(r->err_status >= LOWEST_HTTP_ERROR_CODE)
      return r->err_status;
    else if(r->headers_out.status >= LOWEST_HTTP_ERROR_CODE)
      return r->headers_out.status;
    else return 200;
}

static ngx_flag_t ngx_initialize_opentelemetry(ngx_http_request_t *r)
{
    // check to see if we have already been initialized
    if (worker_conf && worker_conf->isInitialized)
    {
        ngx_writeTrace(r->connection->log, __func__, "Opentelemetry SDK already initialized for process with PID: %s", worker_conf->pid);
        return true;
    }

    ngx_http_opentelemetry_loc_conf_t	*conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_opentelemetry_module);
    if (conf == NULL)
    {
        ngx_writeError(r->connection->log, __func__, "Module location configuration is NULL");
        return false;
    }

    traceConfig(r, conf);

    if (conf->nginxModuleEnabled)
    {
        OTEL_SDK_STATUS_CODE res = OTEL_SUCCESS;
        char            *qs = (char *)malloc(6);
        char            *et = (char *)malloc(6);
        char            *es = (char *)malloc(6);
        char            *sd = (char *)malloc(6);
        ngx_uint_t      i;

        logState = conf->nginxModuleTraceAsError; //Setting Logging Flag

        initDependency();

        struct cNode *cn = ngx_pcalloc(r->pool, sizeof(struct cNode));
        // (cn->cInfo).cName = computeContextName(r, conf);
        struct cNode *rootCN = NULL;
        cn = NULL;


        // Update the apr_pcalloc if we add another parameter to the input array!
        OTEL_SDK_ENV_RECORD* env_config = (OTEL_SDK_ENV_RECORD*)ngx_pcalloc(r->pool, CONFIG_COUNT * sizeof(OTEL_SDK_ENV_RECORD));
        if(env_config == NULL)
        {
            ngx_writeError(r->connection->log, __func__, "Not Able to allocate memory for the Env Config");
            return false;
        }
        int ix = 0;

        // Otel Exporter Type
        env_config[ix].name = OTEL_SDK_ENV_OTEL_EXPORTER_TYPE;
        env_config[ix].value = (const char*)((conf->nginxModuleOtelSpanExporter).data);
        ++ix;

        // sdk libaray name
        env_config[ix].name = OTEL_SDK_ENV_OTEL_LIBRARY_NAME;
        env_config[ix].value = "Nginx";
        ++ix;

        // Otel Exporter Endpoint
        env_config[ix].name = OTEL_SDK_ENV_OTEL_EXPORTER_ENDPOINT;
        env_config[ix].value = (const char*)(conf->nginxModuleOtelExporterEndpoint).data;
        ++ix;

        // Otel Exporter OTEL headers
        env_config[ix].name = OTEL_SDK_ENV_OTEL_EXPORTER_OTLPHEADERS;
        env_config[ix].value = (const char*)(conf->nginxModuleOtelExporterOtlpHeaders).data;
        ++ix;

        // Otel SSL Enabled
        env_config[ix].name = OTEL_SDK_ENV_OTEL_SSL_ENABLED;
        env_config[ix].value = conf->nginxModuleOtelSslEnabled == 1 ? "1" : "0";
        ++ix;

        // Otel SSL Certificate Path
        env_config[ix].name = OTEL_SDK_ENV_OTEL_SSL_CERTIFICATE_PATH;
        env_config[ix].value = (const char*)(conf->nginxModuleOtelSslCertificatePath).data;
        ++ix;

        // Otel Processor Type
        env_config[ix].name = OTEL_SDK_ENV_OTEL_PROCESSOR_TYPE;
        env_config[ix].value = (const char*)(conf->nginxModuleOtelSpanProcessor).data;
        ++ix;

        // Otel Sampler Type
        env_config[ix].name = OTEL_SDK_ENV_OTEL_SAMPLER_TYPE;
        env_config[ix].value = (const char*)(conf->nginxModuleOtelSampler).data;
        ++ix;

        // Service Namespace
        env_config[ix].name = OTEL_SDK_ENV_SERVICE_NAMESPACE;
        env_config[ix].value = (const char*)(conf->nginxModuleServiceNamespace).data;
        ++ix;

        // Service Name
        env_config[ix].name = OTEL_SDK_ENV_SERVICE_NAME;
        env_config[ix].value = (const char*)(conf->nginxModuleServiceName).data;
        ++ix;

        // Service Instance ID
        env_config[ix].name = OTEL_SDK_ENV_SERVICE_INSTANCE_ID;
        env_config[ix].value = (const char*)(conf->nginxModuleServiceInstanceId).data;
        ++ix;

        // Otel Max Queue Size
        env_config[ix].name = OTEL_SDK_ENV_MAX_QUEUE_SIZE;
        sprintf(qs, "%lu", conf->nginxModuleOtelMaxQueueSize);
        env_config[ix].value = qs;
        ++ix;

        // Otel Scheduled Delay
        env_config[ix].name = OTEL_SDK_ENV_SCHEDULED_DELAY;
        sprintf(sd, "%lu", conf->nginxModuleOtelScheduledDelayMillis);
        env_config[ix].value = sd;
        ++ix;

        // Otel Max Export Batch Size
        env_config[ix].name = OTEL_SDK_ENV_EXPORT_BATCH_SIZE;
        sprintf(es, "%lu", conf->nginxModuleOtelMaxExportBatchSize);
        env_config[ix].value = es;
        ++ix;

        // Otel Export Timeout
        env_config[ix].name = OTEL_SDK_ENV_EXPORT_TIMEOUT;
        sprintf(et, "%lu", conf->nginxModuleOtelExportTimeoutMillis);
        env_config[ix].value = et;
        ++ix;

        // Segment Type
        env_config[ix].name = OTEL_SDK_ENV_SEGMENT_TYPE;
        env_config[ix].value = (const char*)(conf->nginxModuleSegmentType).data;
        ++ix;

        // Segment Parameter
        env_config[ix].name = OTEL_SDK_ENV_SEGMENT_PARAMETER;
        env_config[ix].value = (const char*)(conf->nginxModuleSegmentParameter).data;
        ++ix;


        // !!!
        // Remember to update the ngx_pcalloc call size if we add another parameter to the input array!
        // !!!

        // Adding the webserver context here
        for(unsigned int context_i=0; context_i<c_count; context_i++){
            struct cNode *temp_cn  = ngx_pcalloc(r->pool, sizeof(struct cNode));
        char* name = (char*)ngx_pcalloc(r->pool,strlen(sNamespace) + strlen(sName) + strlen(sInstanceId) + 1);
            if(name != NULL){
                strcpy(name, (const char*)sNamespace);
                strcat(name, (const char*)sName);
                strcat(name, (const char*)sInstanceId);
            }
            (temp_cn->cInfo).cName = name;
            (temp_cn->cInfo).sNamespace = (const char*)sNamespace;
            (temp_cn->cInfo).sName = (const char*)sName;
            (temp_cn->cInfo).sInstanceId = (const char*)sInstanceId;
            if(context_i==0)
            {
              cn = temp_cn;
              rootCN = cn;
            }
            else
            {
              cn->next = temp_cn;
              cn = cn->next;
            }
        }
        setRequestResponseHeaders((const char*)(conf->nginxModuleRequestHeaders).data,
           (const char*)(conf->nginxModuleResponseHeaders).data);
           // entry
        res = opentelemetry_core_init(env_config, ix, rootCN);
        free(qs);
        free(sd);
        free(et);
        free(es);
        if (OTEL_ISSUCCESS(res))
        {
            worker_conf->isInitialized = 1;
            ngx_writeTrace(r->connection->log, __func__, "Initializing Agent Core succceeded for process with PID: %s", worker_conf->pid);
            return true;
        }
        else
        {
           ngx_writeError(r->connection->log, __func__, "Agent Core Init failed, result code is %d", res);
           return false;
        }
    }
    else
    {
        // Agent core is not enabled
        ngx_writeError(r->connection->log, __func__, "Agent Core is not enabled");
        return false;
    }
    return false;
}

static void stopMonitoringRequest(ngx_http_request_t* r,
    OTEL_SDK_HANDLE_REQ request_handle_key)
{
    ngx_http_opentelemetry_loc_conf_t  *ngx_conf = ngx_http_get_module_loc_conf(r, ngx_http_opentelemetry_module);
    if(!ngx_conf->nginxModuleEnabled)
    {
        ngx_writeError(r->connection->log, __func__, "Agent is Disabled");
        return;
    }

    OTEL_SDK_HANDLE_REQ otel_req_handle_key = OTEL_SDK_NO_HANDLE;
    ngx_http_otel_handles_t* ctx = ngx_http_get_module_ctx(r, ngx_http_opentelemetry_module);
    if (r->pool == NULL && request_handle_key != NULL)
    {
        otel_req_handle_key = request_handle_key;
    }
    else if (ctx && ctx->otel_req_handle_key)
    {
        otel_req_handle_key = ctx->otel_req_handle_key;
    }
    else
    {
        return;
    }

    if (r->pool) {
        ngx_pfree(r->pool, ctx);
    }

    ngx_writeTrace(r->connection->log, __func__, "Stopping the Request Monitoring");

    response_payload* res_payload = NULL;
    if (r->pool) {
        res_payload = (response_payload*)ngx_pcalloc(r->pool, sizeof(response_payload));
        res_payload->response_headers_count = 0;
        fillResponsePayload(res_payload, r);
    }

    OTEL_SDK_STATUS_CODE res;
    char* msg = NULL;

    if (otel_requestHasErrors(r))
    {
        res_payload->status_code = (unsigned int)otel_getErrorCode(r);
        msg = (char*)malloc(STATUS_CODE_BYTE_COUNT * sizeof(char));
        sprintf(msg, "%d", res_payload->status_code);
        res = endRequest(otel_req_handle_key, msg, res_payload);
    }
    else
    {
        res_payload->status_code = r->headers_out.status;
        res = endRequest(otel_req_handle_key, msg, res_payload);
    }

    if (OTEL_ISSUCCESS(res))
    {
        ngx_writeTrace(r->connection->log, __func__, "Request Ends with result code: %d", res);
    }
    else
    {
        ngx_writeError(r->connection->log, __func__, "Request End FAILED with code: %d", res);
    }
    if(msg){
        free(msg);
    }
}

static void startMonitoringRequest(ngx_http_request_t* r){
    // If a not a the main request(sub-request or internal redirect), calls Realip handler and return
    if(r->internal)
    {
        ngx_writeTrace(r->connection->log, __func__, "Not a Main Request(sub-request or internal redirect)");
        return;
    }
    else if (!ngx_initialize_opentelemetry(r))    /* check if Otel Agent Core is initialized */
    {
        //ngx_writeError(r->connection->log, __func__, "Opentelemetry Agent Core did not get initialized");
        return;
    }

    ngx_http_otel_handles_t* ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_opentelemetry_module);
    if(ctx && ctx->otel_req_handle_key){
        return;
    }

    ngx_writeTrace(r->connection->log, __func__, "Starting Request Monitoring for: %s", r->uri.data);

    // Handle request for static contents (Nginx is used for habdling static contents)

    OTEL_SDK_STATUS_CODE res = OTEL_SUCCESS;
    OTEL_SDK_HANDLE_REQ reqHandle = OTEL_SDK_NO_HANDLE;

    const char* wscontext = NULL;

    ngx_http_opentelemetry_loc_conf_t  *ngx_conf = ngx_http_get_module_loc_conf(r, ngx_http_opentelemetry_module);

    if(ngx_conf)
    {
        wscontext = computeContextName(r, ngx_conf);
    }

    if(wscontext)
    {
        ngx_writeTrace(r->connection->log, __func__, "WebServer Context: %s", wscontext);
    }
    else
    {
        ngx_writeTrace(r->connection->log, __func__, "Using Default context ");
    }

    // Fill the Request payload information and start the request monitoring
    request_payload* req_payload = (request_payload*)ngx_pcalloc(r->pool, sizeof(request_payload));
    if(req_payload == NULL)
    {
        ngx_writeError(r->connection->log, __func__, "Not able to get memory for request payload");
    }
    fillRequestPayload(req_payload, r);
    res = startRequest(wscontext, req_payload, &reqHandle);

    if (OTEL_ISSUCCESS(res))
    {
        if (ctx == NULL)
        {
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_otel_handles_t));
            if (ctx == NULL)
            {
                ngx_writeError(r->connection->log, __func__, "Cannot allocate memory for handles");
                return;
            }
            // Store the Request Handle on the request object
            OTEL_SDK_HANDLE_REQ reqHandleValue = ngx_pcalloc(r->pool, sizeof(OTEL_SDK_HANDLE_REQ));
            if (reqHandleValue)
            {
                reqHandleValue = reqHandle;
                ctx->otel_req_handle_key = reqHandleValue;
                ngx_http_set_ctx(r, ctx, ngx_http_opentelemetry_module);
            }
        }
        ngx_writeTrace(r->connection->log, __func__, "Request Monitoring begins successfully ");
    }
    else if (res == OTEL_STATUS(cfg_channel_uninitialized) || res == OTEL_STATUS(bt_detection_disabled))
    {
        ngx_writeTrace(r->connection->log, __func__, "Request begin detection disabled, result code: %d", res);
    }
    else
    {
        ngx_writeError(r->connection->log, __func__, "Request begin error, result code: %d", res);
    }
}

static ngx_int_t ngx_http_otel_start_handler(ngx_http_request_t *r){

    // This will be the first hanndler to be encountered,
    // Here, Init and start the Request Processing by creating Trace, spans etc
    if(!r->internal)
    {
        startMonitoringRequest(r);
        otel_startClientInteraction(r);
    }
    return NGX_DECLINED;
}

static ngx_int_t ngx_http_otel_stop_handler(ngx_http_request_t *r){
    //This will be last handler to be be encountered before a request ends and response is finally sent back to client
    // Here, End the main trace, span created by Webserver Agent and the collected data will be passed to the backend
    // It will work as ngx_http_opentelemetry_log_transaction_end
    otel_stopClientInteraction(r, OTEL_SDK_NO_HANDLE);
    stopMonitoringRequest(r, OTEL_SDK_NO_HANDLE);

    return NGX_DECLINED;
}

static char* computeContextName(ngx_http_request_t *r, ngx_http_opentelemetry_loc_conf_t* conf){
    char* name = (char*)ngx_pcalloc(r->pool,(conf->nginxModuleServiceNamespace).len + (conf->nginxModuleServiceName).len + (conf->nginxModuleServiceInstanceId).len + 1);

    if(name != NULL){
        strcpy(name, (const char*)(conf->nginxModuleServiceNamespace).data);
        strcat(name, (const char*)(conf->nginxModuleServiceName).data);
        strcat(name, (const char*)(conf->nginxModuleServiceInstanceId).data);
    }
    return name;
}

static void traceConfig(ngx_http_request_t *r, ngx_http_opentelemetry_loc_conf_t* conf){
    ngx_writeTrace(r->connection->log, __func__, " Config { :"
                                                      "(Enabled=\"%ld\")"
                                                      "(OtelExporterEndpoint=\"%s\")"
                                                      "(OtelExporterOtlpHeader=\"%s\")"
                                                      "(OtelSslEnabled=\"%ld\")"
                                                      "(OtelSslCertificatePath=\"%s\")"
                                                      "(OtelSpanExporter=\"%s\")"
                                                      "(OtelSpanProcessor=\"%s\")"
                                                      "(OtelSampler=\"%s\")"
                                                      "(ServiceNamespace=\"%s\")"
                                                      "(ServiceName=\"%s\")"
                                                      "(ServiceInstanceId=\"%s\")"
                                                      "(OtelMaxQueueSize=\"%lu\")"
                                                      "(OtelScheduledDelayMillis=\"%lu\")"
                                                      "(OtelExportTimeoutMillis=\"%lu\")"
                                                      "(OtelMaxExportBatchSize=\"%lu\")"
                                                      "(ResolveBackends=\"%ld\")"
                                                      "(TraceAsError=\"%ld\")"
                                                      "(ReportAllInstrumentedModules=\"%ld\")"
                                                      "(MaskCookie=\"%ld\")"
                                                      "(MaskSmUser=\"%ld\")"
                                                      "(SegmentType=\"%s\")"
                                                      "(SegmentParameter=\"%s\")"
                                                      " }",
                                                      conf->nginxModuleEnabled,
                                                      (conf->nginxModuleOtelExporterEndpoint).data,
                                                      (conf->nginxModuleOtelExporterOtlpHeaders).data,
                                                      conf->nginxModuleOtelSslEnabled,
                                                      (conf->nginxModuleOtelSslCertificatePath).data,
                                                      (conf->nginxModuleOtelSpanExporter).data,
                                                      (conf->nginxModuleOtelSpanProcessor).data,
                                                      (conf->nginxModuleOtelSampler).data,
                                                      (conf->nginxModuleServiceNamespace).data,
                                                      (conf->nginxModuleServiceName).data,
                                                      (conf->nginxModuleServiceInstanceId).data,
                                                      conf->nginxModuleOtelMaxQueueSize,
                                                      conf->nginxModuleOtelScheduledDelayMillis,
                                                      conf->nginxModuleOtelExportTimeoutMillis,
                                                      conf->nginxModuleOtelMaxExportBatchSize,
                                                      conf->nginxModuleResolveBackends,
                                                      conf->nginxModuleTraceAsError,
                                                      conf->nginxModuleReportAllInstrumentedModules,
                                                      conf->nginxModuleMaskCookie,
                                                      conf->nginxModuleMaskSmUser,
                                                      (conf->nginxModuleSegmentType).data,
                                                      (conf->nginxModuleSegmentParameter).data);
}

static void removeUnwantedHeader(ngx_http_request_t* r)
{
  ngx_list_part_t  *part;
  ngx_table_elt_t  *header;
  ngx_table_elt_t            *h;
  ngx_http_header_t          *hh;
  ngx_http_core_main_conf_t  *cmcf;
  ngx_uint_t       nelts;

  part = &r->headers_in.headers.part;
  header = (ngx_table_elt_t*)part->elts;
  nelts = part->nelts;

  for(ngx_uint_t j = 0; j<nelts; j++){
    h = &header[j];
    if(strcmp("singularityheader", (char *)h->key.data)==0){
      if (h->value.len == 0) {
        break;
      }
      if(h->value.data)
        ngx_pfree(r->pool, h->value.data);

      char str[] = "";
      h->hash = ngx_hash_key(h->key.data, h->key.len);

      h->value.len = 0;
      h->value.data = (u_char*)ngx_pcalloc(r->pool, sizeof(char)*((h->value.len)+1));
      strcpy((char *)h->value.data, str);
      h->lowcase_key = h->key.data;

      cmcf = (ngx_http_core_main_conf_t*)ngx_http_get_module_main_conf(r, ngx_http_core_module);
      hh = (ngx_http_header_t*)ngx_hash_find(&cmcf->headers_in_hash, h->hash,h->lowcase_key, h->key.len);
      if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
       return;
      }

      break;
    }
  }
}

static void fillRequestPayload(request_payload* req_payload, ngx_http_request_t* r){
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_uint_t       nelts;
    ngx_table_elt_t  *h;

    // creating a temporary uri for uri parsing 
    // (r->uri).data has an extra component "HTTP/1.1 connection" so to obtain the uri it
    // has to trimmed. This is done by putting a '/0' after the uri length
    // WEBSRV-558
    char *temp_uri = (char*)ngx_pcalloc(r->pool, (strlen((char *)(r->uri).data))+1);
    strcpy(temp_uri,(const char*)(r->uri).data);
    temp_uri[(r->uri).len]='\0';
    req_payload->uri = temp_uri;

    ngx_http_core_srv_conf_t* cscf = (ngx_http_core_srv_conf_t*)ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    char *temp_server_name = (char*)ngx_pcalloc(r->pool, (strlen((char *)(cscf->server_name).data))+1);
    strcpy(temp_server_name, (const char*)(cscf->server_name).data);
    temp_server_name[(cscf->server_name).len]='\0';
    req_payload->server_name = temp_server_name;

    #if (NGX_HTTP_SSL)

      if(r->connection->ssl)
      {
        req_payload->scheme = "https";
      }
      else
      {
        req_payload->scheme = "http";
      }

    #else

      req_payload->scheme = "http";

    #endif

    // TODO - use strncpy function to just create memory of size (r->http_protocol.len)
    char *temp_http_protocol = (char *)ngx_pcalloc(r->pool, (strlen((char *)(r->http_protocol).data))+1);
    strcpy(temp_http_protocol,(const char*)(r->http_protocol).data);
    temp_http_protocol[(r->http_protocol).len]='\0';
    req_payload->protocol = temp_http_protocol;

    char *temp_request_method = (char *)ngx_pcalloc(r->pool, (strlen((char *)(r->method_name).data))+1);
    strcpy(temp_request_method,(const char*)(r->method_name).data);
    temp_request_method[(r->method_name).len]='\0';
    req_payload->request_method = temp_request_method;

    // flavor has to be scraped from protocol in future
    req_payload->flavor = temp_http_protocol;

    char *temp_hostname = (char *)ngx_pcalloc(r->pool, (strlen((char *)hostname.data))+1);
    strcpy(temp_hostname,(const char*)hostname.data);
    temp_hostname[hostname.len]='\0';
    req_payload->hostname = temp_hostname;

    req_payload->http_post_param = (const char*)ngx_pcalloc(r->pool, sizeof(u_char*));
    req_payload->http_get_param = (const char*)ngx_pcalloc(r->pool, sizeof(u_char*));

    if(strstr(req_payload->request_method, "GET") !=NULL){
        req_payload->http_post_param = "No param";
        if((r->args).len){
            req_payload->http_get_param = (const char*)(r->args).data;
        }else{
            req_payload->http_get_param = "No param";
        }
    }else if(strstr(req_payload->request_method, "POST") != NULL){
        req_payload->http_get_param = "No param";
        if((r->args).len){
            req_payload->http_post_param = (const char*)(r->args).data;
        }else{
            req_payload->http_post_param = "No param";
        }
    }

    req_payload->client_ip = (const char*)(r->connection->addr_text).data;
    char *temp_client_ip = (char *)ngx_pcalloc(r->pool, (strlen((char *)(r->connection->addr_text).data))+1);
    strcpy(temp_client_ip,(const char*)(r->connection->addr_text).data);
    temp_client_ip[(r->connection->addr_text).len]='\0';
    req_payload->client_ip = temp_client_ip;

    ngx_http_opentelemetry_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_opentelemetry_module);
    part = &r->headers_in.headers.part;
    header = (ngx_table_elt_t*)part->elts;
    nelts = part->nelts;

    req_payload->propagation_headers = ngx_pcalloc(r->pool, nelts * sizeof(http_headers));
    req_payload->request_headers = ngx_pcalloc(r->pool, nelts * sizeof(http_headers));
    int request_headers_idx = 0;
    int propagation_headers_idx = 0;
    for (ngx_uint_t j = 0; j < nelts; j++) {

        h = &header[j];
        for (long unsigned int i = 0; i < headers_len; i++) {

            if (strcmp((char *)h->key.data, httpHeaders[i]) == 0) {
                req_payload->propagation_headers[propagation_headers_idx].name = (char *)httpHeaders[i];
                req_payload->propagation_headers[propagation_headers_idx].value = (char*)(h->value).data;
                if (req_payload->propagation_headers[propagation_headers_idx].value == NULL) {
                    req_payload->propagation_headers[propagation_headers_idx].value = "";
                }
                propagation_headers_idx++;
                break;
            }
        }

        req_payload->request_headers[request_headers_idx].name = (char*)(h->key).data;
        req_payload->request_headers[request_headers_idx].value = (char*)(h->value).data;
        if (req_payload->request_headers[request_headers_idx].value == NULL) {
            req_payload->request_headers[request_headers_idx].value = "";
        }
        request_headers_idx++;
    }

    req_payload->propagation_count = propagation_headers_idx;
    req_payload->request_headers_count = request_headers_idx;

    addScriptAttributes(req_payload, r);
}

static void fillResponsePayload(response_payload* res_payload, ngx_http_request_t* r)
{
    if (!r->pool) {
        return;
    }

    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    ngx_uint_t       nelts;
    ngx_table_elt_t  *h;

    part = &r->headers_out.headers.part;
    header = (ngx_table_elt_t*)part->elts;
    nelts = part->nelts;

    res_payload->response_headers = ngx_pcalloc(r->pool, nelts * sizeof(http_headers));
    ngx_uint_t headers_count = 0;

    for (ngx_uint_t j = 0; j < nelts; j++) {
        h = &header[j];

        if (headers_count < nelts) {
            res_payload->response_headers[headers_count].name = (char*)(h->key).data;
            res_payload->response_headers[headers_count].value = (char*)(h->value).data;
            if (res_payload->response_headers[headers_count].value == NULL) {
                res_payload->response_headers[headers_count].value = "";
            }
            headers_count++;
        }
    }
    res_payload->response_headers_count = headers_count;
}

void addScriptAttributes(request_payload* req_payload, ngx_http_request_t* r) {
  OtelMainConf* otelMainConf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
  const ngx_array_t* attributes = otelMainConf -> scriptAttributes;
  if (!attributes) {
    return;
  }

  req_payload->attributes = ngx_pcalloc(r->pool, attributes->nelts * sizeof(http_headers));
  struct CompiledScriptAttribute* elements = attributes->elts;
  int attributes_idx = 0;
  for (ngx_uint_t i = 0; i < attributes->nelts; i++) {
    struct CompiledScriptAttribute* attribute = &elements[i];
    ngx_str_t key = ngx_null_string;
    ngx_str_t value = ngx_null_string;
    if (runScript(r, &key, &attribute->key) && runScript(r, &value, &attribute->value)) {
        char *temp_key = (char *)ngx_pcalloc(r->pool, key.len+1);
        strcpy(temp_key, (const char*)key.data);
        temp_key[key.len] = '\0';

        char *temp_value = (char *)ngx_pcalloc(r->pool, value.len+1);
        strcpy(temp_value, (const char*)value.data);
        temp_key[value.len] = '\0';

        req_payload->attributes[attributes_idx].name = temp_key;
        req_payload->attributes[attributes_idx].value = temp_value;
        attributes_idx++;
    }
  }
  req_payload->attributes_count = attributes_idx;
}
