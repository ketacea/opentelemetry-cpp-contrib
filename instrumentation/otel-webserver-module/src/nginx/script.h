#ifndef __NGX_HTTP_OPENTELEMETRY_SCRIPT_H
#define __NGX_HTTP_OPENTELEMETRY_SCRIPT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

struct NgxCompiledScript {
  ngx_str_t pattern;
  ngx_array_t* lengths;
  ngx_array_t* values;
};

struct ScriptAttributeDeclaration {
  char attribute[30];
  char script[30];
};

struct CompiledScriptAttribute {
  struct NgxCompiledScript key;
  struct NgxCompiledScript value;
};

int runScript(ngx_http_request_t* req, ngx_str_t* result, struct NgxCompiledScript* script);
int CompileScript(ngx_conf_t* conf, ngx_str_t pattern, struct NgxCompiledScript* script);
int CompileScriptAttribute(
  ngx_conf_t* conf,
  ngx_str_t* attribute,
  ngx_str_t* script,
  struct CompiledScriptAttribute* compiledAttribute);

#endif