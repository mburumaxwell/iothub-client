#ifndef __IOTHUB_AUTHENTICATION_METHOD_H
#define __IOTHUB_AUTHENTICATION_METHOD_H

#include "iothub_types.h"
#include "IotHubConnectionString.h"

class IotHubAuthenticationMethod {
public:
	virtual iothub_authentication_type_t get_type() = 0;
	virtual void populate_from(IotHubConnectionString *cs) = 0;
	virtual void populate_to(IotHubConnectionString *cs) = 0;
	virtual char* get_password() = 0;
};

#endif /* __IOTHUB_AUTHENTICATION_METHOD_H */
