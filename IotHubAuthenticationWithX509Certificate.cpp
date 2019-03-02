#include <mbed.h>
#include "IotHubAuthenticationWithX509Certificate.h"
#include "mbed_trace.h"

#define TRACE_GROUP						"IOTHUB_AUTH_X509"

IotHubAuthenticationWithX509Certificate::IotHubAuthenticationWithX509Certificate(char *client_cert_pem, char *client_private_key_pem)
	: _client_cert_pem(client_cert_pem), _client_private_key_pem(client_private_key_pem)
{
	
}

iothub_authentication_type_t IotHubAuthenticationWithX509Certificate::get_type()
{
	return IOTHUB_AUTHENTICATION_TYPE_X509_CERT;
}

char* IotHubAuthenticationWithX509Certificate::get_password()
{
	// X509 authentication does not require a password because its authentication happens at the TLS level with client certificates
	return NULL;
}

const char* IotHubAuthenticationWithX509Certificate::get_client_cert()
{
	return _client_cert_pem;
}

const char* IotHubAuthenticationWithX509Certificate::get_client_private_key()
{
	return _client_private_key_pem;
}
