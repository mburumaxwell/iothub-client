#ifndef __IOTHUB_AUTHENTICATION_WITH_TOKEN_H
#define __IOTHUB_AUTHENTICATION_WITH_TOKEN_H

#include "IotHubAuthenticationMethod.h"
#include "rtos/Mutex.h"

class IotHubAuthenticationWithToken : public IotHubAuthenticationMethod {
public:
	IotHubAuthenticationWithToken(char *hostname = NULL, char *device_id = NULL, uint32_t ttl_sec = MBED_CONF_IOTHUB_CLIENT_SAS_DEFAULT_TTL_SEC);
	IotHubAuthenticationWithToken(IotHubConnectionString *cs, uint32_t ttl_sec = MBED_CONF_IOTHUB_CLIENT_SAS_DEFAULT_TTL_SEC);
	~IotHubAuthenticationWithToken();

	virtual iothub_authentication_type_t get_type() = 0;
	virtual void populate_from(IotHubConnectionString *cs);
	virtual void populate_to(IotHubConnectionString *cs);
	char* get_password();
	time_t get_expiry();
	bool is_valid();

protected:
	virtual int32_t sign(const char* request, size_t rlen, char* result, size_t result_sz, size_t* wlen) = 0;

private:
	char* make_audience();
	char* make_request(const char *aud, uint32_t exp, size_t *rlen);
	char* make_signature(const char *request, size_t rlen);
	char* make_token(const char *aud, const char *sig);

private:
	char *_hostname, *_device_id;
	char *_token;
	time_t expiry;
	uint32_t _ttl_sec;
	Mutex _mtx_token;
};

#endif /* __IOTHUB_AUTHENTICATION_WITH_TOKEN_H */
