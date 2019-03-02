#ifndef __IOTHUB_AUTHENTICATION_WITH_REGISTRY_KEY_H
#define __IOTHUB_AUTHENTICATION_WITH_REGISTRY_KEY_H

#include "IotHubAuthenticationWithToken.h"

class IotHubAuthenticationWithRegistryKey : public IotHubAuthenticationWithToken {
public:
	IotHubAuthenticationWithRegistryKey(char *hostname = NULL, char *device_id = NULL, char *key = NULL, uint32_t ttl_sec = MBED_CONF_IOTHUB_CLIENT_SAS_DEFAULT_TTL_SEC);
	IotHubAuthenticationWithRegistryKey(IotHubConnectionString *cs, uint32_t ttl_sec = MBED_CONF_IOTHUB_CLIENT_SAS_DEFAULT_TTL_SEC);
	
	iothub_authentication_type_t get_type();
	void populate_from(IotHubConnectionString *cs);
	void populate_to(IotHubConnectionString *cs);

private:
	int32_t sign(const char* request, size_t rlen, char* result, size_t result_sz, size_t* wlen);

private:
	char *_key;
};

#endif /* __IOTHUB_AUTHENTICATION_WITH_REGISTRY_KEY_H */
