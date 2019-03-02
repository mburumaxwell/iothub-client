#include <mbed.h>
#include "IotHubConnectionString.h"
#include "mbed_trace.h"

#define TRACE_GROUP						"IOTHUB_CSB"

#define KEY_VALUE_PAIR_SEPARATOR		";"
#define KEY_VALUE_PAIR_SETTER			"="

#define PROPERTY_NAME_HOSTNAME			"HostName"
#define PROPERTY_NAME_DEVICEID			"DeviceId"
#define PROPERTY_NAME_MODULEID			"ModuleId"
#define PROPERTY_NAME_SAKNAME			"SharedAccessKeyName"
#define PROPERTY_NAME_SAK				"SharedAccessKey"
#define PROPERTY_NAME_SAS				"SharedAccessSignature"
#define PROPERTY_NAME_X509CERT			"X509Cert"

#define PARSE_PROPERTY_NAME_HOSTNAME	PROPERTY_NAME_HOSTNAME KEY_VALUE_PAIR_SETTER
#define PARSE_PROPERTY_NAME_DEVICEID	PROPERTY_NAME_DEVICEID KEY_VALUE_PAIR_SETTER
#define PARSE_PROPERTY_NAME_MODULEID	PROPERTY_NAME_MODULEID KEY_VALUE_PAIR_SETTER
#define PARSE_PROPERTY_NAME_SAKNAME		PROPERTY_NAME_SAKNAME KEY_VALUE_PAIR_SETTER
#define PARSE_PROPERTY_NAME_SAK			PROPERTY_NAME_SAK KEY_VALUE_PAIR_SETTER
#define PARSE_PROPERTY_NAME_SAS			PROPERTY_NAME_SAS KEY_VALUE_PAIR_SETTER
#define PARSE_PROPERTY_NAME_X509CERT	PROPERTY_NAME_X509CERT KEY_VALUE_PAIR_SETTER

static char* strstr_to_after(const char *s1, const char *s2)
{
	char *p1 = NULL;
	if ((p1 = strstr(s1, s2))) return p1 + strlen(s2);
	return NULL;
}

IotHubConnectionString::IotHubConnectionString() 
{
	reset();
}

IotHubConnectionString::IotHubConnectionString(char *cs)
{
	reset();
	parse(cs);
	is_valid();
}

IotHubConnectionString *IotHubConnectionString::parse(char *cs)
{
	MBED_ASSERT(cs != NULL);
	
	// TODO: find a better way to split instead of strtok e.g. using span
	
	char *kvp = NULL, *val = NULL;
	
	// find first token
	kvp = strtok(cs, KEY_VALUE_PAIR_SEPARATOR);
	
	while (kvp != NULL)
	{
		// extract value from the key value pair. the format is '{key}={value}' e.g. HostName=myhub.azure-devices.net
		if((val = strstr_to_after(kvp, PARSE_PROPERTY_NAME_HOSTNAME))) hostname = val;
		else if((val = strstr_to_after(kvp, PARSE_PROPERTY_NAME_DEVICEID))) device_id = val;
		else if((val = strstr_to_after(kvp, PARSE_PROPERTY_NAME_MODULEID))) module_id = val;
		else if((val = strstr_to_after(kvp, PARSE_PROPERTY_NAME_SAKNAME))) shared_access_key_name = val;
		else if((val = strstr_to_after(kvp, PARSE_PROPERTY_NAME_SAK))) shared_access_key = val;
		else if((val = strstr_to_after(kvp, PARSE_PROPERTY_NAME_SAS))) shared_access_signature = val;
		else if((val = strstr_to_after(kvp, PARSE_PROPERTY_NAME_X509CERT)))
			using_x509_cert = (strcmp("TRUE", val) == 0 || strcmp("true", val) || strcmp("1", val));
		
		// find next token
		kvp = strtok(NULL, KEY_VALUE_PAIR_SEPARATOR);
	}
	
	return this;
}

size_t IotHubConnectionString::write(char *dest, size_t dlen)
{
	char *tdst = (char *)dest; // advance-able destination pointer
	size_t rem_len; // remaining length

	// write hostname (mandatory)
	rem_len = dest == NULL ? 0 : (dlen - (tdst - (char *)dest));
	tdst += snprintf(tdst, rem_len, PARSE_PROPERTY_NAME_HOSTNAME "%s", hostname);
	
	// write device_id (if available or when module_id is not set)
	if(device_id != NULL || module_id == NULL)
	{
		rem_len = dest == NULL ? 0 : (dlen - (tdst - (char *)dest));
		tdst += snprintf(tdst, rem_len, ";" PARSE_PROPERTY_NAME_DEVICEID "%s", device_id);
	}
	
	// write module_id
	if(module_id != NULL)
	{
		rem_len = dest == NULL ? 0 : (dlen - (tdst - (char *)dest));
		tdst += snprintf(tdst, rem_len, ";" PARSE_PROPERTY_NAME_MODULEID "%s", module_id);
	}
	
	// write shared_access_key_name
	if(shared_access_key_name != NULL)
	{
		rem_len = dest == NULL ? 0 : (dlen - (tdst - (char *)dest));
		tdst += snprintf(tdst, rem_len, ";" PARSE_PROPERTY_NAME_SAKNAME "%s", shared_access_key_name);
	}
	
	// write shared_access_key
	if(shared_access_key != NULL)
	{
		rem_len = dest == NULL ? 0 : (dlen - (tdst - (char *)dest));
		tdst += snprintf(tdst, rem_len, ";" PARSE_PROPERTY_NAME_SAK "%s", shared_access_key);
	}
	
	// write shared_access_signature
	if(shared_access_signature != NULL)
	{
		rem_len = dest == NULL ? 0 : (dlen - (tdst - (char *)dest));
		tdst += snprintf(tdst, rem_len, ";" PARSE_PROPERTY_NAME_SAS "%s", shared_access_signature);
	}
	
	// write using_x509_cert
	if(using_x509_cert)
	{
		rem_len = dest == NULL ? 0 : (dlen - (tdst - (char *)dest));
		tdst += snprintf(tdst, rem_len, ";" PARSE_PROPERTY_NAME_X509CERT "true");
	}
	
	// return the written length
	return (tdst - (char*)dest);
}

bool IotHubConnectionString::is_valid()
{
	// hostname must be provided
	if(hostname == NULL || strlen(hostname) == 0)
	{
		tr_warn("property " PROPERTY_NAME_HOSTNAME " is missing");
		return false;
	}
	
	// either deviceId or moduleId must be there
	if((device_id == NULL || strlen(device_id) == 0) && (module_id == NULL || strlen(module_id) == 0))
	{
		tr_warn("either " PROPERTY_NAME_HOSTNAME " or " PROPERTY_NAME_MODULEID " must be provided");
		return false;
	}
	
	// if we are not using x509, there must be a key or a signature
	// TODO: validate if this remains the case when using TPM
	if(!using_x509_cert
		&& ((shared_access_key == NULL || strlen(shared_access_key) == 0) && (shared_access_signature == NULL || strlen(shared_access_signature) == 0)))
	{
		tr_warn("either " PARSE_PROPERTY_NAME_SAK " or " PARSE_PROPERTY_NAME_SAS " must be provided");
		return false;
	}
	
	return true;
}

IotHubConnectionString *IotHubConnectionString::reset()
{
	hostname = NULL;
	device_id  = NULL;
	module_id  = NULL;
	shared_access_key_name  = NULL;
	shared_access_key  = NULL;
	shared_access_signature = NULL;
	using_x509_cert = false;
	return this;
}

IotHubConnectionString* IotHubConnectionString::with_hostname(char *hostname) 
{
	this->hostname = hostname;
	return this;
}

IotHubConnectionString* IotHubConnectionString::with_device_id(char *device_id)
{
	this->device_id = device_id;
	return this;
}

IotHubConnectionString* IotHubConnectionString::with_module_id(char *module_id)
{ 
	this->module_id = module_id;
	return this;
}

IotHubConnectionString* IotHubConnectionString::with_shared_access_key_name(char *shared_access_key_name)
{ 
	this->shared_access_key_name = shared_access_key_name;
	return this;
}

IotHubConnectionString* IotHubConnectionString::with_shared_access_key(char *shared_access_key)
{ 
	this->shared_access_key = shared_access_key;
	return this;
}

IotHubConnectionString* IotHubConnectionString::with_shared_access_signature(char *shared_access_signature)
{
	this->shared_access_signature = shared_access_signature;
	return this;
}

IotHubConnectionString* IotHubConnectionString::with_using_x509_cert(bool using_x509_cert)
{
	this->using_x509_cert = using_x509_cert;
	return this;
}
