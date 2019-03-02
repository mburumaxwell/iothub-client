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
	size_t	length;
	void*	content;
} iothub_message_body_t;

typedef struct {
	iothub_message_property_t* properties;
	size_t	properties_count;
	iothub_message_body_t body;
} iothub_message_t;

typedef struct {
	long version;
	size_t	length;
	void*	content;
} iothub_twin_desired_property_update_t;

typedef struct {
	size_t	length;
	void*	content;
} iothub_twin_reported_property_update_t;

#ifdef __cplusplus
}
#endif

#endif /* __IOTHUB_TYPES_H */

