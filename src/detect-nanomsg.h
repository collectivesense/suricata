#pragma once

#include <nanomsg/nn.h>
#include <nanomsg/pipeline.h>
#include <assert.h>
#include <pthread.h>
#include <cs/cscommon.h>
#include <cs/csnanomsg.h>

typedef struct NanomsgHandler_ {
    int sock;
    char debug;
    const char* url;
    char disable_nanomsg;
    CsAdaptiveBuffer* buffer;
} NanomsgHandler;

extern char nanomsg_disable;

static inline void SetIp_NET32_TO_HOST64(const uint32_t* ip_N32, uint64_t* ip_H64)
{
    if(ip_N32[2] == 0 && ip_N32[3] == 0) {
        ip_H64[0] = (uint64_t)ntohl(ip_N32[0]);
        ip_H64[1] = 0;
    } else {
        ip_H64[0] = (uint64_t)ntohl(ip_N32[0]) << 32 | (uint64_t)ntohl(ip_N32[1]);
        ip_H64[1] = (uint64_t)ntohl(ip_N32[2]) << 32 | (uint64_t)ntohl(ip_N32[3]);
    }
}

static inline uint32_t NanomsgGetEnvMQBuffer(void)
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

#define VA_ARGS(...) , ##__VA_ARGS__

#define NANOMSG_DEBUG(nn_handler, fmt, ...) \
do { \
    if((nn_handler)->debug) { \
        printf("debug [0x%08lx] nanomsg : " fmt, pthread_self() VA_ARGS(__VA_ARGS__)); \
    } \
 \
} while(0)

#define NANOMSG_WARN(nn_handler, fmt, ...) \
do { \
        printf("WARNING [0x%08lx] nanomsg : " fmt, pthread_self() VA_ARGS(__VA_ARGS__)); \
 \
} while(0)

static inline void NanomsgInit(NanomsgHandler* nn_handler, const char* url, uint32_t item_size, Source queue_kind) {
    assert(nn_handler != NULL);
    assert(url != NULL);
    NANOMSG_DEBUG(nn_handler, "Initializing nanomsg handler 0x%p", nn_handler);
    nn_handler->url = url;
    nn_handler->disable_nanomsg = FALSE;
    nn_handler->debug = get_env_debug_level();
    // nn_handler->max_buf_size = NanomsgGetEnvMQBuffer(); TODO: upper limit from env?
    nn_handler->buffer = cs_adaptive_buffer_create(item_size, time(NULL), queue_kind);

    if (nn_handler->url[0] == 0 || nanomsg_disable)
        nn_handler->disable_nanomsg = TRUE;

    if (!nn_handler->disable_nanomsg)
    {
        nn_handler->sock = nn_socket(AF_SP, NN_PUSH);
        assert(nn_handler->sock >= 0);
        assert(nn_connect(nn_handler->sock, nn_handler->url) >= 0);
        NANOMSG_DEBUG(nn_handler, "socket connected - url: %s, socket id: %d\n", nn_handler->url, nn_handler->sock);
    } else {
        NANOMSG_WARN(nn_handler, "nanomsg disabled\n");
    }
}

static inline void NanomsgReturnBufferElement(NanomsgHandler* nn_handler) {
    cs_adaptive_buffer_release_slot(nn_handler->buffer);
}

static inline void* NanomsgGetNextBufferElement(NanomsgHandler* nn_handler) {
    if (nn_handler == NULL) {
        NANOMSG_DEBUG(nn_handler, "ERROR NanomsgGetNextBufferElement - nn_handler == NULL\n");
        return 0;
    }
    return cs_adaptive_buffer_get_slot(nn_handler->buffer, time(NULL));
}

static inline void NanomsgSendBufferIfNeeded(NanomsgHandler* nn_handler)
{
    if(likely(!nn_handler->disable_nanomsg)) {
         cs_adaptive_buffer_send_if_needed(nn_handler->buffer, nn_handler->sock, time(NULL));
    }
    if(unlikely(nn_handler->debug)) {
        NANOMSG_DEBUG(nn_handler, "finished sending to: %s\n", nn_handler->url);
    }
}

extern char nanomsg_url_td[];
extern char nanomsg_url_ph[];
extern char nanomsg_url_sig[];
extern char nanomsg_url_dns[];
extern char nanomsg_url_tls[];
extern char nanomsg_url_http[];
extern char nanomsg_url_rtcp[];
