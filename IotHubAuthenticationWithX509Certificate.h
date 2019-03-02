#ifndef __IOTHUB_AUTHENTICATION_WITH_X509_CERTIFICATE_H
#define __IOTHUB_AUTHENTICATION_WITH_X509_CERTIFICATE_H

#include "IotHubAuthenticationMethod.h"

class IotHubAuthenticationWithX509Certificate : public IotHubAuthenticationMethod {
public:
	IotHubAuthenticationWithX509Certificate(char *client_cert_pem, char *client_private_key_pem);

	iothub_authentication_type_t get_type();
	char* get_password();
	const char *get_client_cert();
	const char *get_client_private_key();
	
private:
	char *_client_cert_pem;
	char *_client_private_key_pem;
	
	
};

#endif /* __IOTHUB_AUTHENTICATION_WITH_X509_CERTIFICATE_H */
