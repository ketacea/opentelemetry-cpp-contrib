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

#ifndef __NGX_HTTP_OPENTELEMETRY_MODULE_H
#define __NGX_HTTP_OPENTELEMETRY_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdbool.h>
#include "../../include/core/api/OpentelemetrySdk.h"
#include "../../include/core/api/opentelemetry_ngx_api.h"

#define LOWEST_HTTP_ERROR_CODE 400
#define STATUS_CODE_BYTE_COUNT 6
static const int CONFIG_COUNT = 17; // Number of key value pairs in config

/*  The following enum has one-to-one mapping with
    otel_monitored_modules[] defined in .c file.
    The order should match with the below indices.
    Any new handler should be added before
    NGX_HTTP_MAX_HANDLE_COUNT
*/
enum NGX_HTTP_INDEX {
    NGX_HTTP_REALIP_MODULE_INDEX=0,         // 0
    NGX_HTTP_LOG_MODULE_INDEX,              // 1
    NGX_HTTP_MAX_HANDLE_COUNT               // 2
}ngx_http_index;

typedef struct {
  ngx_array_t* scriptAttributes;
}OtelMainConf;

/*
Function pointer struct for module specific hooks
*/
typedef ngx_int_t (*mod_handler)(ngx_http_request_t*);
mod_handler h[NGX_HTTP_MAX_HANDLE_COUNT];

/*
 Structure for storing module details for mapping module handlers with their respective module
*/
typedef struct {
        ngx_http_phases phase;
        mod_handler handler;
}otel_ngx_module;

/*
	Configuration struct for module
*/
typedef struct {
    ngx_flag_t  nginxModuleEnabled;		// OPTIONAL: ON or OFF to enable the OpenTelemetry NGINX Agent or not respectively. (defaults to true)
    ngx_str_t	nginxModuleOtelSpanExporter;
    ngx_str_t	nginxModuleOtelExporterEndpoint;
    ngx_flag_t  nginxModuleOtelSslEnabled;
    ngx_str_t   nginxModuleOtelSslCertificatePath;
    ngx_str_t	nginxModuleOtelSpanProcessor;
    ngx_str_t	nginxModuleOtelSampler;
    ngx_str_t	nginxModuleServiceName;
    ngx_str_t   nginxModuleServiceNamespace;
    ngx_str_t   nginxModuleServiceInstanceId;
    ngx_uint_t  nginxModuleOtelMaxQueueSize;
    ngx_uint_t  nginxModuleOtelScheduledDelayMillis;
    ngx_uint_t  nginxModuleOtelExportTimeoutMillis;
    ngx_uint_t  nginxModuleOtelMaxExportBatchSize;
    ngx_flag_t  nginxModuleReportAllInstrumentedModules;
    ngx_flag_t	nginxModuleResolveBackends;
    ngx_flag_t	nginxModuleTraceAsError;
    ngx_flag_t  nginxModuleMaskCookie;
    ngx_flag_t  nginxModuleMaskSmUser;
    ngx_str_t   nginxModuleCookieMatchPattern;
    ngx_str_t   nginxModuleDelimiter;
    ngx_str_t   nginxModuleSegment;
    ngx_str_t   nginxModuleMatchfilter;
    ngx_str_t   nginxModuleMatchpattern;
    ngx_str_t   nginxModuleSegmentType;
    ngx_str_t   nginxModuleSegmentParameter;
    ngx_str_t   nginxModuleRequestHeaders;
    ngx_str_t   nginxModuleResponseHeaders;
    ngx_str_t   nginxModuleOtelExporterOtlpHeaders;
} ngx_http_opentelemetry_loc_conf_t;

/*
    Configuration structure for storing information throughout the worker process life-time
*/
typedef struct {
    ngx_flag_t  isInitialized;
    char* pid;
} ngx_http_opentelemetry_worker_conf_t;

typedef struct{
    const char* key;
    const char* value;
}NGX_HTTP_OTEL_RECORDS;

typedef struct {
   OTEL_SDK_HANDLE_REQ otel_req_handle_key;
   OTEL_SDK_ENV_RECORD* propagationHeaders;
   int pheaderCount;
}ngx_http_otel_handles_t;

typedef struct{
    ngx_str_t sNamespace;
    ngx_str_t sName;
    ngx_str_t sInstanceId;
}contextNode;

/* Function prototypes */
static void *ngx_http_opentelemetry_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_opentelemetry_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_opentelemetry_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_opentelemetry_init_worker(ngx_cycle_t *cycle);
static void ngx_http_opentelemetry_exit_worker(ngx_cycle_t *cycle);
static ngx_flag_t ngx_initialize_opentelemetry(ngx_http_request_t *r);
static void fillRequestPayload(request_payload* req_payload, ngx_http_request_t* r);
static void fillResponsePayload(response_payload* res_payload, ngx_http_request_t* r);
static void startMonitoringRequest(ngx_http_request_t* r);
static void stopMonitoringRequest(ngx_http_request_t* r,
        OTEL_SDK_HANDLE_REQ request_handle_key);
static void otel_payload_decorator(ngx_http_request_t* r, OTEL_SDK_ENV_RECORD* propagationHeaders, int count);
static ngx_flag_t otel_requestHasErrors(ngx_http_request_t* r);
static ngx_uint_t otel_getErrorCode(ngx_http_request_t* r);
static char* ngx_otel_context_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_otel_set_global_context(ngx_http_opentelemetry_loc_conf_t * prev);
static void removeUnwantedHeader(ngx_http_request_t* r);
static void addScriptAttributes(request_payload* req_payload, ngx_http_request_t* r);
/*
    Module specific handler
*/
static ngx_int_t ngx_http_otel_start_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_otel_stop_handler(ngx_http_request_t *r);


/*
    Utility fuction to check if the given module is monitored by Opentelemetry Agent
*/

static void traceConfig(ngx_http_request_t *r, ngx_http_opentelemetry_loc_conf_t* conf);
static char* computeContextName(ngx_http_request_t *r, ngx_http_opentelemetry_loc_conf_t* conf);

/* Filters */
// static ngx_int_t ngx_http_opentelemetry_header_filter(ngx_http_request_t *r);
// static ngx_int_t ngx_http_opentelemetry_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

#endif