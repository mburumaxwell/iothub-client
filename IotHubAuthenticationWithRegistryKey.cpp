#include <mbed.h>
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "url_encode.h"
#include "IotHubAuthenticationWithRegistryKey.h"
#include "mbed_trace.h"

// ensure we have the tr_hex_dump function available
#ifndef tr_hex_dump
#define tr_hex_dump( ... )
#endif

#define TRACE_GROUP								"IOTHUB_AUTH_KEYS"

IotHubAuthenticationWithRegistryKey::IotHubAuthenticationWithRegistryKey(char *hostname, char *device_id, char *key, uint32_t ttl_sec)
	: IotHubAuthenticationWithToken::IotHubAuthenticationWithToken(hostname, device_id, ttl_sec), _key(key)
{
}

IotHubAuthenticationWithRegistryKey::IotHubAuthenticationWithRegistryKey(IotHubConnectionString *cs, uint32_t ttl_sec)
	: IotHubAuthenticationWithToken::IotHubAuthenticationWithToken(NULL, NULL, ttl_sec), _key(NULL)
{
	// populate values from connection string
	populate_from(cs);
}

iothub_authentication_type_t IotHubAuthenticationWithRegistryKey::get_type()
{
	return IOTHUB_AUTHENTICATION_TYPE_REGISTRY_KEY;
}

void IotHubAuthenticationWithRegistryKey::populate_from(IotHubConnectionString *cs)
{
	IotHubAuthenticationWithToken::populate_from(cs);
	_key = cs->get_shared_access_key();
}

void IotHubAuthenticationWithRegistryKey::populate_to(IotHubConnectionString *cs)
{
	IotHubAuthenticationWithToken::populate_to(cs);
	cs->with_shared_access_key(_key);
}

int32_t IotHubAuthenticationWithRegistryKey::sign(const char* request, size_t rlen, char* result, size_t result_sz, size_t* wlen)
{
	int32_t ret;
	size_t devicekey_len, decoded_len, hashed_len, temp_len;
	uint8_t *decoded, *hashed_request;
	mbedtls_md_context_t md_ctx;

	mbedtls_md_init(&md_ctx);
	ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	if (ret) return ret;
	
	// attempt to decode with NULL buffer so as to get the required size
	devicekey_len = strlen(_key);
	ret = mbedtls_base64_decode(NULL, 0, &decoded_len, (uint8_t *)_key, devicekey_len);
	if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) decoded = (uint8_t *)malloc(decoded_len);
	else return ret;
	
	if (decoded != NULL)
	{
		// decode with the right buffer size
		memset(decoded, 0, decoded_len);
		ret = mbedtls_base64_decode(decoded, decoded_len, &decoded_len, (uint8_t *)_key, devicekey_len);
		if (ret == 0)
		{
			tr_debug("> decoded key: %d bytes", decoded_len);
			tr_hex_dump(decoded, decoded_len);

			ret = mbedtls_md_hmac_starts(&md_ctx, decoded, decoded_len);
			if (ret == 0)
			{
				ret = mbedtls_md_hmac_update(&md_ctx, (uint8_t *)request, rlen);
				if (ret == 0)
				{
					temp_len = rlen + decoded_len;
					hashed_request = (uint8_t *)malloc(temp_len);
					if (hashed_request != NULL)
					{
						memset(hashed_request, 0, temp_len);
						ret = mbedtls_md_hmac_finish(&md_ctx, hashed_request);
						if (ret == 0)
						{
							hashed_len = strlen((const char*)hashed_request);

							tr_debug("> hashed request: %d bytes", hashed_len);
							tr_hex_dump(hashed_request, hashed_len);

							ret = mbedtls_base64_encode((uint8_t *)result, result_sz, wlen, hashed_request, hashed_len);

							tr_debug("> result: %d bytes", *wlen);
							tr_hex_dump(result, *wlen);
						}
						free(hashed_request);
					}
				}
			}                
		}
		free(decoded);
	}

	return ret;
}
