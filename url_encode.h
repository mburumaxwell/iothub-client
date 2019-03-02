#ifndef __URL_ENCODE_H
#define __URL_ENCODE_H

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t url_encode(const char *src, const size_t srclen, char *dest, const size_t destlen);

#ifdef __cplusplus
}
#endif

#endif /* __URL_ENCODE_H */
