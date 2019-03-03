#ifndef __IOTHUB_TYPES_H
#define __IOTHUB_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	IOTHUB_CONNECTION_STATUS_DISCONNECTED,
	IOTHUB_CONNECTION_STATUS_CONNECTED,
	IOTHUB_CONNECTION_STATUS_DISABLED
} iothub_connection_status_t;

typedef enum {
    IOTHUB_CONNECTION_STATUS_CHANGE_REASON_CONNECTION_OK,
    IOTHUB_CONNECTION_STATUS_CHANGE_REASON_BAD_CREDENTIAL,
    IOTHUB_CONNECTION_STATUS_CHANGE_REASON_COMMUNICATION_ERROR,
    IOTHUB_CONNECTION_STATUS_CHANGE_REASON_CLIENT_CLOSE                    	
} iothub_connection_status_change_reason_t;

typedef enum {
	IOTHUB_TRANSPORT_TYPE_MQTT,
	IOTHUB_TRANSPORT_TYPE_MQTT_WS,
	IOTHUB_TRANSPORT_TYPE_HTTP,
	IOTHUB_TRANSPORT_TYPE_AMQP,
	IOTHUB_TRANSPORT_TYPE_AMQP_WS,
} iothub_transport_type_t;

typedef enum {
	IOTHUB_AUTHENTICATION_TYPE_REGISTRY_KEY,
	IOTHUB_AUTHENTICATION_TYPE_X509_CERT,
	IOTHUB_AUTHENTICATION_TYPE_TPM,
} iothub_authentication_type_t;
	
typedef struct {
	char* name;
	char* value;
} iothub_message_property_t;

typedef struct {
	void*	p;
	size_t	len;
} iothub_raw_body_t;

typedef struct {
	iothub_message_property_t* properties;
	size_t	properties_count;
	iothub_raw_body_t body;
} iothub_message_t;

typedef struct {
	long version;
	iothub_raw_body_t body;
} iothub_twin_desired_property_update_t;

typedef struct {
	iothub_raw_body_t body;
} iothub_twin_reported_property_update_t;

typedef struct {
	char* method_name;
	size_t method_name_length;
	char* rid;
	size_t rid_length;
	iothub_raw_body_t body;
} iothub_direct_method_request_t;

typedef struct {
	uint16_t status;
	char* rid;
	size_t rid_length;
	iothub_raw_body_t body;
} iothub_direct_method_response_t;
	
//#define METHOD_RESPOSE_STATUS_CODE_BAD_REQUEST				(400)
//#define METHOD_RESPOSE_STATUS_CODE_USER_CODE_EXCEPTION		(500)
#define METHOD_RESPOSE_STATUS_CODE_METHOD_NOT_IMPLEMENTED	(501)


#ifdef __cplusplus
}
#endif

#endif /* __IOTHUB_TYPES_H */

