#ifndef __IOT_HUB_CLIENT_H
#define __IOT_HUB_CLIENT_H

#include "TLSMqttClient.h"
#include "IotHubAuthenticationMethod.h"

class IotHubClient {
public:
	static IotHubClient* create(char *connection_string);
	static IotHubClient* create(char *connection_string, IotHubAuthenticationMethod *auth);
	
	IotHubClient(IotHubConnectionString *cs, IotHubAuthenticationMethod *auth);
	~IotHubClient();
	
	iothub_connection_status_t get_connection_status();

	nsapi_error_t connect(NetworkInterface *net);
	nsapi_error_t close();
	nsapi_error_t send_event(const iothub_message_t *message);
	nsapi_error_t send_events(const iothub_message_t *messages, const size_t count);
	nsapi_error_t send_twin_patch(const iothub_twin_reported_property_update_t *patch);
	
	nsapi_error_t process_events();
	void on_events_to_process(Callback<void(IotHubClient*)> cb);
	
	nsapi_error_t keep_alive();
	void on_keep_alive_required(Callback<void(IotHubClient*)> cb);
	
	void on_message_received(Callback<void(IotHubClient*, iothub_message_t*)> cb);
	void on_desired_property_updated(Callback<void(IotHubClient*, iothub_twin_desired_property_update_t*)> cb);
	
	void on_connection_status_changed(Callback<void(IotHubClient*, iothub_connection_status_t, iothub_connection_status_change_reason_t)> cb);
	
private:
	nsapi_error_t inner_transport_setup(TLSSocket *sock);
	void inner_client_packet_recevied(MqttClient *c, mqtt_packet_type_t type, void* packet);
	void inner_client_on_events_to_process(MqttClient *c);
	char* make_username();
	void inner_on_keep_alive_required();
	uint16_t get_next_packet_id();
	uint16_t get_next_rid();
	void handle_packet_recevied_connack(mqtt_packet_connect_ack_t *packet);
	void handle_packet_recevied_publish(mqtt_packet_publish_t *packet);
	void set_connection_status(iothub_connection_status_t status, iothub_connection_status_change_reason_t reason);

private:
	TLSMqttClient inner;
	IotHubConnectionString *connection_string;
	IotHubAuthenticationMethod *authentication;
	LowPowerTicker keep_alive_ticker;
	Mutex mtx_process_events;
	Callback<void(IotHubClient*)> on_events_to_process_cb;
	Callback<void(IotHubClient*)> on_keep_alive_required_cb;
	Callback<void(IotHubClient*, iothub_message_t*)> on_message_received_cb;
	Callback<void(IotHubClient*, iothub_twin_desired_property_update_t*)> on_desired_property_updated_cb;
	Callback<void(IotHubClient*, iothub_connection_status_t, iothub_connection_status_change_reason_t)> on_connection_status_changed_cb;
	
private:
	iothub_connection_status_t connection_status;
	uint16_t packet_id, rid;
	char *c2b_topic_prefix;
};

#endif /* __IOT_HUB_CLIENT_H */

