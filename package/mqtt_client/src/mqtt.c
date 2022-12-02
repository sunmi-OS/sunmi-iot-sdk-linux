/*
 * This example shows how to write a client that subscribes to a topic and does
 * not do anything other than handle the messages that are received.
 */

#include <mosquitto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "mqtt.h"
#include "link/common.h"

#define RECONNECT_DELAY_MAX 15

static MQTT_CONFIG mqtt_config;                     /* mqtt配置 */
static int mqtt_status = MQTT_STATUS_NOT_CONFIG;    /* mqtt状态 */
static pthread_t mqtt_pid = 0;                           /*  线程pid */
static struct mosquitto *mosq = NULL;               /* mosquitto handle*/
static int run = 1; /* mqtt连接启动标志位，置为0将重启mqtt连接 */

int notify_connect()
{
    int ret = 0;
    struct blob_buf req = {};
    blob_buf_init(&req, 0);
    if (ubus_call("thing_service", "on_connect", &req, NULL, 3000) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call thing_service on_connect failed.");
        ret = -1;
        goto out;
    }

out:
    blob_buf_free(&req);
    return ret;
}

int notify_disconnect()
{
    int ret = 0;
    struct blob_buf req = {};
    blob_buf_init(&req, 0);
    if (ubus_call("thing_service", "on_disconnect", &req, NULL, 3000) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call thing_service on_disconnect failed.");
        ret = -1;
        goto out;
    }

out:
    blob_buf_free(&req);
    return ret;
}

int notify_message(char* topic, char* payload)
{
    int ret = 0;
    struct blob_buf req = {};
    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "topic", topic);
    blobmsg_add_string(&req, "payload", payload);

    if (ubus_call_async("thing_service", "on_message", &req, NULL, NULL) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR,"ubus_call thing_service on_message failed.");
        ret = -1;
        goto out;
    }

out:
    blob_buf_free(&req);
    return ret;
}


/* Callback called when the client receives a CONNACK message from the broker. */
void on_connect(struct mosquitto *mosq, void *obj, int reason_code)
{
	//int rc;
	/* Print out the connection result. mosquitto_connack_string() produces an
	 * appropriate string for MQTT v3.x clients, the equivalent for MQTT v5.0
	 * clients is mosquitto_reason_string().
	 */

	if(reason_code != 0){
		/* If the connection fails for any reason, we don't want to keep on
		 * retrying in this example, so disconnect. Without this, the client
		 * will attempt to reconnect. */
		mosquitto_disconnect(mosq);
        run = 0;
        mqtt_status = MQTT_STATUS_DISCONNECTED;
        SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt on_connect: %s", mosquitto_connack_string(reason_code));
		return;
	}

	mqtt_status = MQTT_STATUS_CONNECTED;
	SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt on_connect: %s", mosquitto_connack_string(reason_code));

#if 0
	/* Making subscriptions in the on_connect() callback means that if the
	 * connection drops and is automatically resumed by the client, then the
	 * subscriptions will be recreated when the client reconnects. */
	rc = mosquitto_subscribe(mosq, NULL, "/helloworld", 1);
	if(rc != MOSQ_ERR_SUCCESS){
		fprintf(stderr, "Error subscribing: %s\n", mosquitto_strerror(rc));
		/* We might as well disconnect if we were unable to subscribe */
		mosquitto_disconnect(mosq);
        mqtt_status = MQTT_STATUS_DISCONNECTED;
	}
#endif
    notify_connect();
}

void on_disconnect(struct mosquitto *mosq, void *obj, int rc)
{
	mqtt_status = MQTT_STATUS_DISCONNECTED;
	SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt on_connect: disconnected");
    notify_disconnect();
}

/* Callback called when the broker sends a SUBACK in response to a SUBSCRIBE. */
void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos)
{
	int i;
	bool have_subscription = false;

	/* In this example we only subscribe to a single topic at once, but a
	 * SUBSCRIBE can contain many topics at once, so this is one way to check
	 * them all. */
	for(i=0; i<qos_count; i++){
        SUNMI_LOG(PRINT_LEVEL_INFO, "on_subscribe: %d:granted qos = %d", i, granted_qos[i]);
		if(granted_qos[i] <= 2){
			have_subscription = true;
		}
	}
	if(have_subscription == false){
		/* The broker rejected all of our subscriptions, we know we only sent
		 * the one SUBSCRIBE, so there is no point remaining connected. */
		fprintf(stderr, "Error: All subscriptions rejected.\n");
		mosquitto_disconnect(mosq);
        run = 0;
        mqtt_status = MQTT_STATUS_DISCONNECTED;
        SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt: disconnected");
	}
}


/* Callback called when the client receives a message. */
void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
	/* This blindly prints the payload, but the payload can be anything so take care. */
	//SUNMI_LOG(PRINT_LEVEL_INFO, "%s %d %s", msg->topic, msg->qos, (char *)msg->payload);
    notify_message(msg->topic, msg->payload);
}

static int mosquitto_loop_forever_ex(struct mosquitto *mosq, int timeout, int max_packets)
{
	int rc = 0;
	unsigned int reconnects = 0;
	unsigned long reconnect_delay = 0;
	unsigned int count = 0;

	if(!mosq) return MOSQ_ERR_INVAL;

    run = 1;
	while(run){
		do{
			rc = mosquitto_loop(mosq, timeout, max_packets);
			if (reconnects !=0 && rc == MOSQ_ERR_SUCCESS){
				reconnects = 0;
			}
		}while (run && rc == MOSQ_ERR_SUCCESS);
        
		SUNMI_LOG(PRINT_LEVEL_ERROR, "cloudproxy: loop error, %s", mosquitto_strerror(rc));

		if (!run) 
		{
			return rc;
		}
        
		/* Quit after fatal errors. */
		switch(rc) {
		case MOSQ_ERR_NOMEM:
		case MOSQ_ERR_PROTOCOL:
		case MOSQ_ERR_INVAL:
		case MOSQ_ERR_NOT_FOUND:
		case MOSQ_ERR_TLS:
		case MOSQ_ERR_PAYLOAD_SIZE:
		case MOSQ_ERR_NOT_SUPPORTED:
		case MOSQ_ERR_AUTH:
		case MOSQ_ERR_ACL_DENIED:
		case MOSQ_ERR_UNKNOWN:
		case MOSQ_ERR_EAI:
		case MOSQ_ERR_PROXY:
			return rc;
		case MOSQ_ERR_ERRNO:
			break;
		}

		if(errno == EPROTO){
			return rc;
		}

		do {
			rc = MOSQ_ERR_SUCCESS;
			reconnect_delay = reconnects*reconnects;
			if (reconnect_delay > RECONNECT_DELAY_MAX){
				reconnect_delay = RECONNECT_DELAY_MAX;
			}else{
				reconnects++;
			}

			while (count++ < reconnect_delay)
            {
				sleep(1);
			}
			count = 0;

			rc = mosquitto_reconnect(mosq);
			SUNMI_LOG(PRINT_LEVEL_INFO, "cloudproxy: reconnect, %s", mosquitto_strerror(rc));
		}while(run && rc != MOSQ_ERR_SUCCESS);
	}

	return rc;
}

static void* mosquitto_routine(void* arg)
{
	int rc;
	int count = 0;
	unsigned int reconnects = 0;
	unsigned long reconnect_delay = 0;
	char will_topic[128] = {0};
	char will_payload[128] = {0};
            
    while (1) 
    {
        /* 没有配置mqtt信息 */
        while (MQTT_STATUS_NOT_CONFIG == mqtt_status) {
            sleep(1);
        }

		reconnect_delay = reconnects*reconnects;
		if (reconnect_delay > RECONNECT_DELAY_MAX){
			reconnect_delay = RECONNECT_DELAY_MAX;
		}else{
			reconnects++;
		}

		while (count++ < reconnect_delay)
        {
			sleep(1);
		}
		count = 0;

        /* Required before calling other mosquitto functions */
    	mosquitto_lib_init();

    	/* Create a new client instance.
    	 * id = NULL -> ask the broker to generate a client id for us
    	 * clean session = true -> the broker should remove old sessions when we connect
    	 * obj = NULL -> we aren't passing any of our private data for callbacks
    	 */
        mosq = mosquitto_new(mqtt_config.client_id, true, NULL);
    	if(mosq == NULL){
    		fprintf(stderr, "Error: Out of memory.\n");
    		continue;
    	}

        mosquitto_username_pw_set(mosq, mqtt_config.username, mqtt_config.password);

    	/* Configure callbacks. This should be done before connecting ideally. */
    	mosquitto_connect_callback_set(mosq, on_connect);
    	mosquitto_disconnect_callback_set(mosq, on_disconnect);
    	mosquitto_subscribe_callback_set(mosq, on_subscribe);
    	mosquitto_message_callback_set(mosq, on_message);

        rc = mosquitto_tls_set(mosq, NULL, "./", NULL, NULL, NULL);
        if(rc){
            if(rc == MOSQ_ERR_INVAL){
                fprintf(stderr, "Error: Problem setting TLS options: File not found.\n");
            }else{
                fprintf(stderr, "Error: Problem setting TLS options: %s.\n", mosquitto_strerror(rc));
            }
        }

        /* 不校验证书 */
        mosquitto_tls_opts_set(mosq,0,NULL,NULL);
        mosquitto_tls_insecure_set(mosq, true);

        /* 配置遗嘱消息 */
        snprintf(will_topic, 128, "smlink/%s/sys/status", mqtt_config.client_id);
        snprintf(will_payload, 128, "deviceid_connercttime+\"@offline");
        mosquitto_will_set(mosq, will_topic, strlen(will_payload), will_payload, 1, true);

    	/* Connect to test.mosquitto.org on port 1883, with a keepalive of 60 seconds.
    	 * This call makes the socket connection only, it does not complete the MQTT
    	 * CONNECT/CONNACK flow, you should use mosquitto_loop_start() or
    	 * mosquitto_loop_forever() for processing net traffic. */
        rc = mosquitto_connect(mosq, mqtt_config.host, mqtt_config.port, 30);
    	if(rc != MOSQ_ERR_SUCCESS){
    		mosquitto_destroy(mosq);
            SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt_client Error: %s", mosquitto_strerror(rc));
    		continue;
    	}else
        {
    		mqtt_status = MQTT_STATUS_CONNECTED;
        }

    	/* Run the network loop in a blocking call. The only thing we do in this
    	 * example is to print incoming messages, so a blocking call here is fine.
    	 *
    	 * This call will continue forever, carrying automatic reconnections if
    	 * necessary, until the user calls mosquitto_disconnect().
    	 */
    #if 0
    	mosquitto_loop_forever(mosq, -1, 1);
    #else
    	mosquitto_loop_forever_ex(mosq, -1, 1);
    #endif
    	mosquitto_lib_cleanup();
        mosq = NULL;
        run = 0;
        mqtt_status = MQTT_STATUS_DISCONNECTED;
        SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt client: disconnected");
    }

    return NULL;
}

/* 设置mqtt配置 */
int mqtt_set_config(char* host, int port, char* username, char* password, char* client_id)
{
    if (!host || strlen(host) >= MQTT_CONFIG_HOST_LEN) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "host is invalid.");
        return -1;
    }

    if (port <=0 ) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "port is invalid.");
        return -1;
    }
    
    if (!username || strlen(username) >= MQTT_CONFIG_USERNAME_LEN) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "username is invalid.");
        return -1;
    }

    if (!password || strlen(password) >= MQTT_CONFIG_PASSWORD_LEN) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "password is invalid.");
        return -1;
    }

    if (!client_id || strlen(client_id) >= MQTT_CONFIG_CLIENT_ID_LEN) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "client_id is invalid.");
        return -1;
    }
    
    strncpy(mqtt_config.host, host, MQTT_CONFIG_HOST_LEN - 1);
    mqtt_config.port = port;
    strncpy(mqtt_config.username, username, MQTT_CONFIG_USERNAME_LEN - 1);
    strncpy(mqtt_config.password, password, MQTT_CONFIG_PASSWORD_LEN - 1);
    strncpy(mqtt_config.client_id, client_id, MQTT_CONFIG_CLIENT_ID_LEN - 1);

    if (MQTT_STATUS_NOT_CONFIG == mqtt_status) 
    {
        mqtt_status = MQTT_STATUS_DISCONNECTED;
    }else if(MQTT_STATUS_CONNECTED == mqtt_status)
    {
        mosquitto_disconnect(mosq);
        run = 0;
        mqtt_status = MQTT_STATUS_DISCONNECTED;
        SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt client: disconnected");        
    }
    return 0;
}

/* 获取mqtt配置 */
int mqtt_get_config(MQTT_CONFIG* config)
{
    if (!config) 
    {
        return -1;
    }

    *config = mqtt_config;
    return 0;
}

/* 获取mqtt状态 */
int mqtt_get_status(int* status)
{
    if (!status) 
    {
        return -1;
    }

    *status = mqtt_status;
    return 0;
}

/* 连接emq */
int mqtt_proc()
{
    /* 创建处理线程 */
    if (pthread_create(&mqtt_pid, NULL, mosquitto_routine, NULL) < 0) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "create pthread failed.");
        return -1;
    }
    pthread_detach(mqtt_pid);

    return 0;
}

/* 订阅topic */
int mqtt_subscribe(char* topic)
{
    int rc = 0;

    if (!topic) 
    {
        return -1;
    }

    if (MQTT_STATUS_CONNECTED != mqtt_status) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt is not connected.");
        return -1;
    }
    
	rc = mosquitto_subscribe(mosq, NULL, topic, 2);
	if(rc != MOSQ_ERR_SUCCESS){
		fprintf(stderr, "Error subscribing: %s\n", mosquitto_strerror(rc));
		/* We might as well disconnect if we were unable to subscribe */
		mosquitto_disconnect(mosq);
        run = 0;
        mqtt_status = MQTT_STATUS_DISCONNECTED;
        SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt client: disconnected");
	}

    return 0;
}

/* 推送数据 */
int mqtt_publish(char* topic, char* payload, int qos)
{
    int rc = 0;
    if (!topic || !payload) 
    {
        return -1;
    }

    if (MQTT_STATUS_CONNECTED != mqtt_status) 
    {
        SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt is not connected.");
        return -1;
    }

	rc = mosquitto_publish(mosq, NULL, topic, strlen(payload), payload, qos, 0);
	if(rc) {
		SUNMI_LOG(PRINT_LEVEL_ERROR, "mqtt client: MQTT send message error %s",mosquitto_strerror(rc));
		if (rc == MOSQ_ERR_NO_CONN)
        {
            mosquitto_disconnect(mosq);
            run = 0;
            mqtt_status = MQTT_STATUS_DISCONNECTED;
            SUNMI_LOG(PRINT_LEVEL_INFO, "mqtt client: disconnected");
        }
	}

    return 0;
}

int mqtt_reconnect()
{
    if (MQTT_STATUS_CONNECTED == mqtt_status) 
    {
        mosquitto_disconnect(mosq);
        run = 0;
        mqtt_status = MQTT_STATUS_DISCONNECTED;
    }
    return 0;
}
