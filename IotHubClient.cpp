#include "iothub_ca_certs.h"
#include "IotHubClient.h"
#include "IotHubAuthenticationWithX509Certificate.h"
#include "mbed_trace.h"

// default keep alive timeout if not specified
#ifndef MBED_CONF_IOTHUB_CLIENT_KEEPALIVE_TIMEOUT
#define MBED_CONF_IOTHUB_CLIENT_KEEPALIVE_TIMEOUT		(100)
#endif

#define IOTHUB_CLIENT_PING_THRESHOLD					(MBED_CONF_IOTHUB_CLIENT_KEEPALIVE_TIMEOUT * 0.8f)

#define TRACE_GROUP										"IOTHUB_CLIENT"

// Topic formats, filters and prefixes
#define IOTHUB_CLIENT_PORT								(8883)
#define IOTHUB_CLIENT_USERNAME_FORMAT					"%s/%s/api-version=2016-11-14" // {hostname}/{device_id}/api-version={api_version}
#define IOTHUB_CLIENT_TOPIC_D2C_FORMAT					"devices/%s/messages/events/" // devices/{device_id}/messages/events/
#define IOTHUB_CLIENT_TOPIC_C2D_FORMAT_PREFIX			"devices/%s/messages/devicebound/"
#define IOTHUB_CLIENT_TOPIC_C2D_FORMAT_FILTER			"devices/%s/messages/devicebound/#" // devices/{device_id}/messages/devicebound/{property_bag}
#define IOTHUB_CLIENT_TOPIC_DESIRED_PROPS_FORMAT_PREFIX	"$iothub/twin/PATCH/properties/desired/"
#define IOTHUB_CLIENT_TOPIC_DESIRED_PROPS_FORMAT_FILTER	"$iothub/twin/PATCH/properties/desired/#" // $iothub/twin/PATCH/properties/desired/?$version={new version}
#define IOTHUB_CLIENT_TOPIC_REPORTED_PROPS_FORMAT		"$iothub/twin/PATCH/properties/reported/?$rid=%d" // $iothub/twin/PATCH/properties/reported/?$rid={0}
#define IOTHUB_CLIENT_TOPIC_TWIN_RESPONSE_FORMAT_PREFIX	"$iothub/twin/res/"
#define IOTHUB_CLIENT_TOPIC_TWIN_RESPONSE_FORMAT_FILTER	"$iothub/twin/res/#" // $iothub/twin/res/{status}/?$rid={request id}

#if MBED_CONF_MBED_TRACE_ENABLE
static const char * const mqtt_connect_returncode_str[15] =
{
	"ACCEPTED",
	"REFUSED_UNACCEPTABLE_VERSION",
	"REFUSED_ID_REJECTED",
	"REFUSED_SERVER_UNAVAIL",
	"REFUSED_BAD_USERNAME_PASSWORD",
	"REFUSED_NOT_AUTHORIZED",
	"REFUSED_UNKNOWN"
};

static const char* mqtt_connect_returncode_to_str(mqtt_connect_returncode_t code)
{
	uint8_t i = code;
	if (i > 6 || i <= 0) i = 0; // ensure within bounds
	return mqtt_connect_returncode_str[i];
}
static const char * const mqtt_packet_qos_str[15] =
{
	"AT_MOST_ONCE",
	"AT_LEAST_ONCE",
	"EXACTLY_ONCE"
};

static const char* mqtt_packet_qos_to_str(mqtt_packet_qos_t qos)
{
	uint8_t i = qos;
	if ((i > 2 || i <= 0)) i = 0; // ensure within bounds
	return mqtt_packet_qos_str[i];
}
#endif

IotHubClient::IotHubClient(IotHubConnectionString *cs, IotHubAuthenticationMethod *auth)
	: connection_string(cs)
	, authentication(auth)
	, on_events_to_process_cb(NULL)
	, on_keep_alive_required_cb(NULL)
	, on_message_received_cb(NULL)
	, on_desired_property_updated_cb(NULL)
	, on_connection_status_changed_cb(NULL)
	, connection_status(IOTHUB_CONNECTION_STATUS_DISCONNECTED)
	, packet_id(0)
	, rid(0)
{
	inner.setup(callback(this, &IotHubClient::inner_transport_setup));
	inner.packet_received(callback(this, &IotHubClient::inner_client_packet_recevied));
	inner.on_events_to_process(callback(this, &IotHubClient::inner_client_on_events_to_process));
	
	// find the amount of space required for c2d topic prefix
	size_t len = snprintf(NULL, 0, IOTHUB_CLIENT_TOPIC_C2D_FORMAT_PREFIX, connection_string->get_device_id());
	len++; // allow for NULL character at the end
	
	// make the c2d topic prefix
	c2b_topic_prefix = (char *)malloc(len);
	len = snprintf(c2b_topic_prefix, len, IOTHUB_CLIENT_TOPIC_C2D_FORMAT_PREFIX, connection_string->get_device_id());
}

IotHubClient::~IotHubClient()
{
	if (c2b_topic_prefix)
	{
		delete[] c2b_topic_prefix;
		c2b_topic_prefix = NULL;
	}
}

iothub_connection_status_t IotHubClient::get_connection_status()
{
	return connection_status;
}

nsapi_error_t IotHubClient::connect(NetworkInterface *net)
{
	nsapi_error_t ret = inner.open(net, connection_string->get_hostname(), IOTHUB_CLIENT_PORT);
	if (ret != NSAPI_ERROR_OK) 
	{
		tr_error("inner.open() failed ret = %d", ret);
		return ret;
	}
	
	// make the username for login purposes and get password from authentication provider
	char *username = make_username();
	char *password = authentication->get_password();
	tr_debug("Username=\"%s\"", username);
	tr_debug("Password=\"%s\"", password);
	
	/*
	 * NOTE ON SESSION PERSISTENCE.
	 * If the device connects with CleanSession flag set to 0, the subscription is persisted across different sessions.
	 * In this case, the next time the device connects with CleanSession 0 it receives any outstanding messages sent to
	 * it while disconnected. If the device uses CleanSession flag set to 1 though, it does not receive any messages
	 * from IoT Hub until it subscribes to its device-endpoint.
	 **/
	// perform protocol connect
	ret = inner.connect(
		/* client_id */connection_string->get_device_id(),
		/* username */username,
		/* password */password,
		/* keep_alive_seconds */MBED_CONF_IOTHUB_CLIENT_KEEPALIVE_TIMEOUT,
		/* clean_session */true);
	if (ret <= 0)
	{
		tr_error("inner.connect() failed ret = %d", ret);
		free(username);
		return ret;
	}
	
	free(username);
	return ret;
}

nsapi_error_t IotHubClient::close()
{
	nsapi_error_t ret = inner.disconnect();
	if (ret != NSAPI_ERROR_OK) 
	{
		tr_error("inner.disconnect() failed ret = %d", ret);
	}
	
	// update connection status and change reason
	set_connection_status(IOTHUB_CONNECTION_STATUS_DISABLED, IOTHUB_CONNECTION_STATUS_CHANGE_REASON_CLIENT_CLOSE);
	
	return ret;
}

nsapi_error_t IotHubClient::send_event(const iothub_message_t* message)
{
	/*
	 * TODO: support encoding of properties in the topic to result in devices/{device_id}/messages/events/{property_bag}
	 * The {property_bag} element enables the device to send messages with additional properties in a url-encoded format. For example:
	 * RFC 2396-encoded(<PropertyName1>)=RFC 2396-encoded(<PropertyValue1>)&RFC 2396-encoded(<PropertyName2>)=RFC 2396-encoded(<PropertyValue2>)…
	 * 
	 * Resulting topic example: devices/{device_id}/messages/events/id=123
	 **/
	
	// determine amount of memory required for the topic
	size_t topic_sz = snprintf(NULL, 0, IOTHUB_CLIENT_TOPIC_D2C_FORMAT, connection_string->get_device_id());
	topic_sz++; // allow for NULL character at the end
	
	// make the topic
	char *topic = (char *)malloc(topic_sz); // TODO: check for NULL
	if(topic == NULL) return NSAPI_ERROR_NO_MEMORY;
	memset(topic, 0, topic_sz);
	topic_sz = snprintf(topic, topic_sz, IOTHUB_CLIENT_TOPIC_D2C_FORMAT, connection_string->get_device_id());

	// send publish packet
	uint16_t pid = get_next_packet_id();
	tr_debug("Publishing D2C on %.*s with Id:%d", topic_sz, topic, pid);
	nsapi_error_t ret = inner.publish(topic, pid, (const uint8_t *)message->body.content, message->body.length);
	if (ret <= 0)
	{
		tr_error("inner.publish() failed ret = %d", ret);
		free(topic);
		return ret;
	}
	
	free(topic);
	return ret;
}

nsapi_error_t IotHubClient::send_events(const iothub_message_t* messages, const size_t count)
{
	nsapi_error_t ret = count;
	for (size_t i = 0;i < count;i++)
	{
		iothub_message_t msg = messages[i];
		ret = send_event(&msg);
		if (ret <= 0) 
		{
			tr_error("send_event() for message at index %d failed ret = %d", i, ret);
			return ret;
		}		
	}
	return ret;
}

nsapi_error_t IotHubClient::send_twin_patch(const iothub_twin_reported_property_update_t *patch)
{
	// determine amount of memory required for the topic
	uint16_t rid = get_next_rid();
	size_t topic_sz = snprintf(NULL, 0, IOTHUB_CLIENT_TOPIC_REPORTED_PROPS_FORMAT, rid);
	topic_sz++; // allow for NULL character at the end
	
	// make the topic
	char *topic = (char *)malloc(topic_sz); // TODO: check for NULL
	if(topic == NULL) return NSAPI_ERROR_NO_MEMORY;
	memset(topic, 0, topic_sz);
	topic_sz = snprintf(topic, topic_sz, IOTHUB_CLIENT_TOPIC_REPORTED_PROPS_FORMAT, rid);

	// send publish packet
	uint16_t pid = get_next_packet_id();
	tr_debug("Publishing Twin patch on %.*s with Id:%d", topic_sz, topic, pid);
	nsapi_error_t ret = inner.publish(topic, pid, (const uint8_t *)patch->content, patch->length);
	if (ret <= 0)
	{
		tr_error("inner.publish() failed ret = %d", ret);
		free(topic);
		return ret;
	}
	
	free(topic);
	return ret;
}

nsapi_error_t IotHubClient::process_events()
{
	mtx_process_events.lock(); // only process events once at a time (to prevent repeated callback invocation)
	
	nsapi_error_t ret = inner.process_events();
	if (ret <= 0) 
	{
		tr_error("inner.process_events() failed ret = %d", ret);
		
		// update connection status and change reason
		set_connection_status(IOTHUB_CONNECTION_STATUS_DISCONNECTED, IOTHUB_CONNECTION_STATUS_CHANGE_REASON_COMMUNICATION_ERROR);
	}
	
	mtx_process_events.unlock(); // release for another thread to use
	
	return ret;
}

void IotHubClient::on_events_to_process(Callback<void(IotHubClient*)> cb)
{ 
	on_events_to_process_cb = cb;
}

nsapi_error_t IotHubClient::keep_alive()
{
	return inner.ping();
}

void IotHubClient::on_keep_alive_required(Callback<void(IotHubClient*)> cb)
{ 
	on_keep_alive_required_cb = cb;
}

void IotHubClient::on_message_received(Callback<void(IotHubClient*, iothub_message_t*)> cb)
{
	on_message_received_cb = cb;
}

void IotHubClient::on_desired_property_updated(Callback<void(IotHubClient*, iothub_twin_desired_property_update_t*)> cb)
{
	on_desired_property_updated_cb = cb;
}

void IotHubClient::on_connection_status_changed(Callback<void(IotHubClient*, iothub_connection_status_t, iothub_connection_status_change_reason_t)> cb)
{
	on_connection_status_changed_cb = cb;
}

nsapi_error_t IotHubClient::inner_transport_setup(TLSSocket *sock)
{
	// set the root certificate authority chain
	nsapi_error_t ret = sock->set_root_ca_cert(iothub_ca_chain_pem, iothub_ca_chain_pem_len);
	if (ret != NSAPI_ERROR_OK) 
	{
		tr_error("inner.transport.set_root_ca_cert() failed ret = %d", ret);
		return ret;
	}
	
	// when authentication is with X509, set the client certificate and key here
	if(authentication->get_type() == IOTHUB_AUTHENTICATION_TYPE_X509_CERT)
	{
		IotHubAuthenticationWithX509Certificate *x509auth = (IotHubAuthenticationWithX509Certificate *)authentication;
		ret = sock->set_client_cert_key(
			x509auth->get_client_cert(),
			x509auth->get_client_private_key());
		
		if (ret != NSAPI_ERROR_OK) 
		{
			tr_error("inner.transport.set_client_cert_key() failed ret = %d", ret);
			return ret;
		}
	}
	
	return NSAPI_ERROR_OK;
}

void IotHubClient::inner_client_packet_recevied(MqttClient *c, mqtt_packet_type_t type, void* packet)
{
	switch (type)
	{
	default:
		break;
	case MQTT_PACKET_TYPE_CONNACK:
		handle_packet_recevied_connack((mqtt_packet_connect_ack_t *)packet);
		break;
	case MQTT_PACKET_TYPE_PUBLISH:
		handle_packet_recevied_publish((mqtt_packet_publish_t *)packet);
		break;
	case MQTT_PACKET_TYPE_PUBREC:
		{
			mqtt_packet_publish_rec_t *p = (mqtt_packet_publish_rec_t *)packet;
			inner.publish_release(p->id);
		}
		break;
	case MQTT_PACKET_TYPE_PUBREL:
		{
			mqtt_packet_publish_rel_t *p = (mqtt_packet_publish_rel_t *)packet;
			inner.publish_complete(p->id);
		}
		break;
	}
}

char* IotHubClient::make_username()
{
	// determine amount of memory required for the username
	size_t username_sz = snprintf(NULL,
		0,
		IOTHUB_CLIENT_USERNAME_FORMAT,
		connection_string->get_hostname(),
		connection_string->get_device_id());
	username_sz++; // allow for NULL character at the end

	// make the username
	char *username = (char *)malloc(username_sz); // TODO: check for NULL
	memset(username, 0, username_sz);
	username_sz = snprintf(username,
		username_sz,
		IOTHUB_CLIENT_USERNAME_FORMAT,
		connection_string->get_hostname(),
		connection_string->get_device_id());
	
	return username;
}

void IotHubClient::inner_client_on_events_to_process(MqttClient *c)
{
	if (on_events_to_process_cb)
	{
		on_events_to_process_cb(this);
	}
}

void IotHubClient::inner_on_keep_alive_required()
{
	if (on_keep_alive_required_cb)
	{
		on_keep_alive_required_cb(this);
	}
}

uint16_t IotHubClient::get_next_packet_id()
{
	// use lock to prevent race condition see https://os.mbed.com/docs/mbed-os/v5.11/apis/criticalsectionlock.html
	CriticalSectionLock  lock;
	return ++packet_id;
}

uint16_t IotHubClient::get_next_rid()
{
	// use lock to prevent race condition see https://os.mbed.com/docs/mbed-os/v5.11/apis/criticalsectionlock.html
	CriticalSectionLock  lock;
	return ++rid;
}

void IotHubClient::handle_packet_recevied_connack(mqtt_packet_connect_ack_t *packet)
{
	if (packet->code != MQTT_PACKET_CONN_ACCEPTED)
	{
		tr_error("Connection failed with %s (%02x) response", mqtt_connect_returncode_to_str(packet->code), packet->code);
		
		// update connection status and change reason
		set_connection_status(IOTHUB_CONNECTION_STATUS_DISCONNECTED, IOTHUB_CONNECTION_STATUS_CHANGE_REASON_BAD_CREDENTIAL);
		
		return;
	}
	
	// at this point, connection succeeded
	tr_info("Connection successful");
				
	// setup ping/keep_alive ticker and callback
	float ping_threshold = IOTHUB_CLIENT_PING_THRESHOLD;
	tr_debug("Setting PING (keep alive) ticker to %.2fsec", ping_threshold);
	keep_alive_ticker.attach(callback(this, &IotHubClient::inner_on_keep_alive_required), ping_threshold);
				
	// subscribe for C2D messages
	size_t sub_topic_sz = sizeof(IOTHUB_CLIENT_TOPIC_C2D_FORMAT_FILTER) + strlen(connection_string->get_device_id());
	char *sub_topic = new(std::nothrow)char[sub_topic_sz];
	snprintf(sub_topic, sub_topic_sz, IOTHUB_CLIENT_TOPIC_C2D_FORMAT_FILTER, connection_string->get_device_id());
	uint16_t pid = get_next_packet_id();
	tr_debug("Subscribing to C2D on %.*s with Id:%d", sub_topic_sz, sub_topic, pid);
	inner.subscribe(sub_topic, pid);
	delete[] sub_topic;
				
	// subscribe for desired property updates
	pid = get_next_packet_id();
	tr_debug("Subscribing to Twin updates on %s with Id:%d", IOTHUB_CLIENT_TOPIC_DESIRED_PROPS_FORMAT_FILTER, pid);
	inner.subscribe(IOTHUB_CLIENT_TOPIC_DESIRED_PROPS_FORMAT_FILTER, pid);
				
	// subscribe for desired property updates
	pid = get_next_packet_id();
	tr_debug("Subscribing to Twin responses on %s with Id:%d", IOTHUB_CLIENT_TOPIC_TWIN_RESPONSE_FORMAT_FILTER, pid);
	inner.subscribe(IOTHUB_CLIENT_TOPIC_TWIN_RESPONSE_FORMAT_FILTER, pid);
				
	// TODO: subscribe to topics for direct methods
	
	// update connection status and change reason
	set_connection_status(IOTHUB_CONNECTION_STATUS_CONNECTED, IOTHUB_CONNECTION_STATUS_CHANGE_REASON_CONNECTION_OK);
}

void IotHubClient::handle_packet_recevied_publish(mqtt_packet_publish_t *packet)
{
	tr_debug("Received publish Id:%d, QoS:%s(%02x)", packet->id, mqtt_packet_qos_to_str(packet->qos), packet->qos);
	tr_debug("Received publish Topic:\'%.*s\'", packet->topic_len, packet->topic);	
	tr_debug("Received publish Payload:\'%.*s\'", packet->payload.length, (char *) packet->payload.content);
	
	// acknowledge the packet depending on QoS
	switch (packet->qos)
	{
	default:
	case MQTT_PACKET_DELIVERY_AT_MOST_ONCE: // no response
		break;
	case MQTT_PACKET_DELIVERY_AT_LEAST_ONCE: // return PUBACK
		inner.publish_ack(packet->id);
		break;
	case MQTT_PACKET_DELIVERY_EXACTLY_ONCE: // return PUBREC
		inner.publish_received(packet->id);
	}
			
	// check if the packet is a C2D
	if(strncmp(packet->topic, c2b_topic_prefix, strlen(c2b_topic_prefix)) == 0 && on_message_received_cb)
	{
		tr_debug("Received event (C2D)");

		iothub_message_t msg;
		memset(&msg, 0, sizeof(iothub_message_t));
		msg.body.content = packet->payload.content;
		msg.body.length = packet->payload.length;
		/*
		 * TODO: parse properties from the topic
		 * Example topic:
		 *	devices/test-dev-0/messages/devicebound/%24.mid=4e6f49cb-feaa-4970-9756-57860c666ba8&%24.to=%2Fdevices%2Ftest-dev-0%2Fmessages%2FdeviceBound&iothub-ack=full
		 * has the following properties
		 *		$.mid=4e6f49cb-feaa-4970-9756-57860c666ba8
		 *		$.to=/devices/test-dev-0/messages/deviceBound
		 *		iothub-ack=full
		 **/
				
		// invoke message received callback
		on_message_received_cb(this, &msg);
	}
	// check if the packet is a desired property update
	else if(strncmp(packet->topic, IOTHUB_CLIENT_TOPIC_DESIRED_PROPS_FORMAT_PREFIX, strlen(IOTHUB_CLIENT_TOPIC_DESIRED_PROPS_FORMAT_PREFIX)) == 0
		&& on_desired_property_updated_cb)
	{
		tr_debug("Received desired property update");

		iothub_twin_desired_property_update_t upd;
		memset(&upd, 0, sizeof(iothub_twin_desired_property_update_t));
		upd.content = packet->payload.content;
		upd.length = packet->payload.length;
		/*
		 * TODO: parse version from topic (i.e. its a property)
		 * Example topic: $iothub/twin/PATCH/properties/desired/?$version=3
		 **/
				
		// invoke desired property updated callback
		on_desired_property_updated_cb(this, &upd);
	}
	// check if the packet is a twin update/get response
	else if(strncmp(packet->topic, IOTHUB_CLIENT_TOPIC_TWIN_RESPONSE_FORMAT_PREFIX, strlen(IOTHUB_CLIENT_TOPIC_TWIN_RESPONSE_FORMAT_PREFIX)) == 0
		&& on_desired_property_updated_cb)
	{
		tr_debug("Received twin update/get response");

		// the payload length is 0 when it s a response to and update in reported properties
		// in this case an example topic is $iothub/twin/res/204/?$rid=1&$version=2
		// the payload length is not zero when it is a response to a GET request, the payload contains the whole twin (reported+desired properties)
	}

	// TODO: check topic for direct method
}

void IotHubClient::set_connection_status(iothub_connection_status_t status, iothub_connection_status_change_reason_t reason)
{
	// if there is not change, then do not proceed
	if (connection_status == status) return;
	
	// update connection status and change reason
	connection_status = status;
	
	// call the connection status changed callback if available
	if(on_connection_status_changed_cb)
	{
		on_connection_status_changed_cb(this, connection_status, reason);
	}	
}
