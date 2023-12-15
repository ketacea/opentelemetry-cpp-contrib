#include "script.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <string.h>
#include <stdio.h>

int runScript(ngx_http_request_t* req, ngx_str_t* result, struct NgxCompiledScript* script) {
    if (!script -> lengths) {
        *result = script->pattern;
        return 1;
    }

    if (!ngx_http_script_run(req, result, script->lengths->elts, 0, script->values->elts)) {
        return 0;
    }

    return 1;
}

int CompileScript(ngx_conf_t* conf, ngx_str_t pattern, struct NgxCompiledScript* script) {
  script->pattern = pattern;
  script->lengths = NULL;
  script->values = NULL;
  ngx_uint_t numVariables = ngx_http_script_variables_count(&script->pattern);
  if (numVariables == 0) {
    return 1;
  }
  ngx_http_script_compile_t compilation;
  ngx_memzero(&compilation, sizeof(compilation));
  compilation.cf = conf;
  compilation.source = &script->pattern;
  compilation.lengths = &script->lengths;
  compilation.values = &script->values;
  compilation.variables = numVariables;
  compilation.complete_lengths = 1;
  compilation.complete_values = 1;

  return ngx_http_script_compile(&compilation) == NGX_OK;
}

int CompileScriptAttribute(
  ngx_conf_t* conf,
  ngx_str_t* attribute,
  ngx_str_t* script,
  struct CompiledScriptAttribute* compiledAttribute) {
  if (!CompileScript(conf, *attribute, &compiledAttribute->key)) {
    return 0;
  }

  return CompileScript(conf, *script, &compiledAttribute->value);
}