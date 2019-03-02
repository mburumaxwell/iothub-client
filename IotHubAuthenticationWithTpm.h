#ifndef __IOTHUB_AUTHENTICATION_WITH_TPM_H
#define __IOTHUB_AUTHENTICATION_WITH_TPM_H

#include "IotHubAuthenticationWithToken.h"

class IotHubAuthenticationWithTpm : public IotHubAuthenticationWithToken {
public:
	IotHubAuthenticationWithTpm(char *hostname = NULL, char *device_id = NULL, uint32_t ttl_sec = MBED_CONF_IOTHUB_CLIENT_SAS_DEFAULT_TTL_SEC);
	IotHubAuthenticationWithTpm(IotHubConnectionString *cs, uint32_t ttl_sec = MBED_CONF_IOTHUB_CLIENT_SAS_DEFAULT_TTL_SEC);
	
	iothub_authentication_type_t get_type();
	void sign_request(Callback<size_t(const uint8_t*, size_t, uint8_t*, size_t)> cb);

private:
	int32_t sign(const char* request, size_t rlen, char* result, size_t result_sz, size_t* wlen);
	
private:
	Callback<size_t(const uint8_t*, size_t, uint8_t*, size_t)> sign_request_cb;
};

#endif /* __IOTHUB_AUTHENTICATION_WITH_TPM_H */
