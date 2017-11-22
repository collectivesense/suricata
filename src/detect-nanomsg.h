#pragma once

#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>
#include <assert.h>
#include <pthread.h>

typedef struct NanomsgHandler_ {
    int sock;
    char debug;
    char* url;
    void* buf;
    uint32_t buf_size;
    size_t inc;
    size_t max_it;
} NanomsgHandler;

extern char disable_nanomsg;

inline void SetIp_NET32_TO_HOST64(const uint32_t* ip_N32, uint64_t* ip_H64)
{
    if(ip_N32[2] == 0 && ip_N32[3] == 0) {
        ip_H64[0] = (uint64_t)ntohl(ip_N32[0]);
        ip_H64[1] = 0;
    } else {
        ip_H64[0] = (uint64_t)ntohl(ip_N32[0]) << 32 | (uint64_t)ntohl(ip_N32[1]);
        ip_H64[1] = (uint64_t)ntohl(ip_N32[2]) << 32 | (uint64_t)ntohl(ip_N32[3]);
    }
}

inline uint32_t NanomsgGetEnvDebug()
{
    uint32_t env_debug = 0;
    if (getenv("ENV_DEBUG") != NULL) {
        if (atoi(getenv("ENV_DEBUG")) <= 0)
            env_debug = 0;
        else
            env_debug = 1;
    }

    printf("ENV_DEBUG: %d\n", env_debug);

    return env_debug;
}

inline uint32_t NanomsgGetEnvMQBuffer()
{
    uint32_t env_mq_buffer= 0;
    if (getenv("ENV_MQ_BUFFER") != NULL) {
        if (atoi(getenv("ENV_MQ_BUFFER")) <= 0)
            env_mq_buffer = 0;
        else
            env_mq_buffer = atoi(getenv("ENV_MQ_BUFFER"));
    }

    printf("ENV_MQ_BUFFER: %d\n", env_mq_buffer);

    return env_mq_buffer;
}

inline void NanomsgInit(NanomsgHandler* nn_handler, char* url, uint32_t buffer_size)
{
    nn_handler->inc = 0;
    nn_handler->max_it = 0;
    nn_handler->buf = NULL;
    nn_handler->url = url;

    nn_handler->debug = NanomsgGetEnvDebug();
    nn_handler->buf_size = NanomsgGetEnvMQBuffer();

    //just in case
    if (nn_handler->buf_size <= 0)
        nn_handler->buf_size = buffer_size;

    assert (nn_handler->buf_size > 0);

    nn_handler->sock = nn_socket (AF_SP, NN_PUSH);
    assert (nn_handler->sock >= 0);
    assert (nn_connect (nn_handler->sock, nn_handler->url) >= 0);
    printf("Nanomsg socket connected - buffer size: %d, url: %s\n", nn_handler->buf_size, nn_handler->url);
}

inline void NanomsgReturnBufferElement(NanomsgHandler* nn_handler)
{
    --nn_handler->inc;
}

inline void* NanomsgGetNextBufferElement(NanomsgHandler* nn_handler, uint32_t message_size)
{
    if (nn_handler == NULL) {
        printf("ERROR nn_allocmsg - nn_handler == NULL\n");
        return 0;
    } else if (nn_handler->inc == 0) {
        nn_handler->inc = 1;

        if (nn_handler->debug)
            printf("nn_allocmsg - nn_handler->buf_size: %u, message_size: %d\n", nn_handler->buf_size, message_size);

        nn_handler->buf = nn_allocmsg(nn_handler->buf_size, 0);
        assert(nn_handler->buf != NULL);

        nn_handler->max_it = nn_handler->buf_size / message_size;

        return nn_handler->buf;
    } else {
        if (nn_handler->debug)
            printf("NanomsgGetNextBufferElement message_size: %u, inc: %p, inc: %zu, threadID: %lu\n", message_size, &nn_handler->inc, nn_handler->inc, pthread_self());

        assert(nn_handler->inc <= nn_handler->max_it);

        return nn_handler->buf + nn_handler->inc++ * message_size;
    }
}

inline void NanomsgSendBufferIfNeeded(NanomsgHandler* nn_handler)
{
    if (nn_handler->buf == NULL) {
        printf("ERROR NanomsgSendBufferIfNeeded nn_handler->buf == NULL !!!!\n");
        return;
    }

    if(nn_handler->inc == nn_handler->max_it) {
        if (nn_handler->debug)
            printf("Nanomsg starts sending to: %s, inc: %p, inc: %zu, threadID: %lu\n", nn_handler->url, &nn_handler->inc, nn_handler->inc, pthread_self());

        if (unlikely(TRUE == disable_nanomsg)) {
            nn_freemsg(nn_handler->buf); // to work without mq-broker
        } else {
            nn_send(nn_handler->sock, &nn_handler->buf, NN_MSG, 0);
        }

        // We forget about the buffer, it is someone else's problem now.
        nn_handler->buf = NULL;

        if (nn_handler->debug)
            printf("Nanomsg finished sending to: %s inc: %p, inc: %zu, threadID: %lu\n", nn_handler->url, &nn_handler->inc, nn_handler->inc, pthread_self());

        nn_handler->inc = 0;
    } else if (nn_handler->debug) {
        printf("Some data to log..., inc: %p, inc: %zu, threadID: %lu\n", &nn_handler->inc, nn_handler->inc, pthread_self());
        assert(nn_handler->inc <= nn_handler->max_it);
    }
}

extern char nanomsg_url_td[];
extern char nanomsg_url_ph[];
extern char nanomsg_url_sig[];
extern char nanomsg_url_dns[];
extern char nanomsg_url_tls[];
extern char nanomsg_url_http[];
extern char nanomsg_url_rtcp[];
