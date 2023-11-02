#pragma once

extern "C" {
#include <ngx_string.h>
}

inline const char* FromNgxString(ngx_str_t str) {
  return (const char*)str.data;
}

inline ngx_str_t ToNgxString(const char* str) {
  return {strlen(str), (u_char*)str};
}