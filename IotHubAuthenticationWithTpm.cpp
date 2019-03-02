#include <mbed.h>
#include "IotHubAuthenticationWithTpm.h"
#include "mbed_trace.h"

// ensure we have the tr_hex_dump function available
#ifndef tr_hex_dump
#define tr_hex_dump( ... )
#endif

#define TRACE_GROUP						"IOTHUB_AUTH_TPM"

IotHubAuthenticationWithTpm::IotHubAuthenticationWithTpm(char *hostname, char *device_id, uint32_t ttl_sec)
	: IotHubAuthenticationWithToken::IotHubAuthenticationWithToken(hostname, device_id, ttl_sec), sign_request_cb(NULL)
{
}

IotHubAuthenticationWithTpm::IotHubAuthenticationWithTpm(IotHubConnectionString *cs, uint32_t ttl_sec)
	: IotHubAuthenticationWithToken::IotHubAuthenticationWithToken(NULL, NULL, ttl_sec), sign_request_cb(NULL)
{
	// populate values from connection string
	populate_from(cs);
}

iothub_authentication_type_t IotHubAuthenticationWithTpm::get_type()
{
	return IOTHUB_AUTHENTICATION_TYPE_TPM;
}

void IotHubAuthenticationWithTpm::sign_request(Callback<size_t(const uint8_t*, size_t, uint8_t*, size_t)> cb)
{
	sign_request_cb = cb;
}

int32_t IotHubAuthenticationWithTpm::sign(const char* request, size_t rlen, char* result, size_t result_sz, size_t* wlen)
{
	if (!sign_request_cb)
	{
		error("TPM signing/hashing callback must be set using sign_request(cb) function");
		return -1;
	}
	
	*wlen = sign_request_cb((const uint8_t *)request, rlen, (uint8_t *)result, result_sz);
	return 0;
}

