#ifndef __IOTHUB_CONNECTION_STRING_BUILDER_H
#define __IOTHUB_CONNECTION_STRING_BUILDER_H

#include <stdint.h>
#include <stddef.h>

class IotHubConnectionString {

public:
	IotHubConnectionString();
	IotHubConnectionString(char *cs);
	
	char* get_hostname() { return hostname; }
	char* get_device_id() { return device_id; }
	char* get_module_id() { return module_id; }
	char* get_shared_access_key_name() { return shared_access_key_name; }
	char* get_shared_access_key() { return shared_access_key; }
	char* get_shared_access_signature() { return shared_access_signature; }
	bool get_using_x509_cert() { return using_x509_cert; }
	
	size_t write(char *dest, size_t dlen);
	bool is_valid();
	bool is_module();
	IotHubConnectionString *parse(char *cs);
	IotHubConnectionString *reset();
	
public:
	IotHubConnectionString *with_hostname(char *hostname);
	IotHubConnectionString *with_device_id(char *device_id);
	IotHubConnectionString *with_module_id(char *module_id);
	IotHubConnectionString *with_shared_access_key_name(char *shared_access_key_name);
	IotHubConnectionString *with_shared_access_key(char *shared_access_key);
	IotHubConnectionString *with_shared_access_signature(char *shared_access_signature);
	IotHubConnectionString *with_using_x509_cert(bool using_x509_cert);
	
private:
	char *hostname;
	char *device_id;
	char *module_id;
	char *shared_access_key_name;
	char *shared_access_key;
	char *shared_access_signature;
	bool using_x509_cert;
};

#endif /* __IOTHUB_CONNECTION_STRING_BUILDER_H */
