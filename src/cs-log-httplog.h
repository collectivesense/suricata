#ifndef __CS_LOG_HTTPLOG_H__
#define __CS_LOG_HTTPLOG_H__

#include "detect-timedelta-utils.h"
#include <cs/cscommon.h>
#include "detect-nanomsg.h"
#define BUF_SIZE_HTTP sizeof(HTTPData) * 1
static __thread NanomsgHandler nn_handler_http;
static __thread char nn_init_http = 0;

extern char http_log_write_to_file;

static void FillAndSendHTTPData(const Packet *p, LogHttpFileCtx *httplog_ctx, htp_tx_t *tx, uint64_t tx_id)
{
    if ( nn_init_http == 0 ) {
        nn_init_http = 1;
        NanomsgInit(&nn_handler_http, nanomsg_url_http, sizeof(HTTPData), HTTP_RECORDS);
    }

    HTTPData* http = (HTTPData*)NanomsgGetNextBufferElement(&nn_handler_http);
    memset(http, 0, sizeof(HTTPData));

    http->timestamp = GetTimestampInMicroSec(p->ts);
    http->tx_id = tx_id;

    //IPs & ports
    http->src_port = p->sp;
    http->dst_port = p->dp;
    SetIp_NET32_TO_HOST64(GET_IPV4_SRC_ADDR_PTR(p), http->src_ip);
    SetIp_NET32_TO_HOST64(GET_IPV4_DST_ADDR_PTR(p), http->dst_ip);

    uint32_t i = 0;
    uint32_t temp = 0;
    uint32_t datalen = 0;

    uint8_t *cvalue = NULL;
    uint32_t cvalue_len = 0;

    htp_header_t *h_response_hdr = NULL;
    htp_header_t *h_request_hdr = NULL;

    http->resp_msg_len = (uint32_t)tx->response_message_len;
    http->req_msg_len = (uint32_t)tx->request_message_len;
    http->resp_status = (uint16_t)tx->response_status_number;

    if ((tx->response_status_number >= 300) && ((tx->response_status_number) < 400)) {
        htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
        if (h_location != NULL) {
            PrintRawUriBuf((char *)http->redirect_location, &temp, sizeof(http->redirect_location),
                (uint8_t *)bstr_ptr(h_location->value), bstr_len(h_location->value)
            );
        }
    }

    temp = 0;
    if (tx->request_hostname != NULL) {
        PrintRawUriBuf((char *)http->hostname, &temp, sizeof(http->hostname),
                (uint8_t *)bstr_ptr(tx->request_hostname), bstr_len(tx->request_hostname)
        );
    }

    temp = 0;
    if (tx->request_method != NULL) {
        PrintRawUriBuf((char *)http->method, &temp, sizeof(http->method),
                (uint8_t *)bstr_ptr(tx->request_method), bstr_len(tx->request_method)
        );
    }

    temp = 0;
    if (tx->request_protocol != NULL) {
        PrintRawUriBuf((char *)http->protocol, &temp, sizeof(http->protocol),
                (uint8_t *)bstr_ptr(tx->request_protocol), bstr_len(tx->request_protocol)
        );
    }

    temp = 0;
    if (tx->request_uri != NULL) {
        PrintRawUriBuf((char *)http->uri, &temp, sizeof(http->uri),
                (uint8_t *)bstr_ptr(tx->request_uri), bstr_len(tx->request_uri));
    }

    temp = 0;
    htp_header_t *h_referer = NULL;
    if (tx->request_headers != NULL) {
        h_referer = htp_table_get_c(tx->request_headers, "referer");
    }
    if (h_referer != NULL) {
        PrintRawUriBuf((char *)http->referer, &temp, sizeof(http->referer),
                (uint8_t *)bstr_ptr(h_referer->value), bstr_len(h_referer->value));
    }

    temp = 0;
    htp_header_t *h_user_agent = NULL;
    if (tx->request_headers != NULL) {
        h_user_agent = htp_table_get_c(tx->request_headers, "user-agent");
    }
    if (h_user_agent != NULL) {
        PrintRawUriBuf((char *)http->user_agent, &temp, sizeof(http->user_agent),
                (uint8_t *)bstr_ptr(h_user_agent->value), bstr_len(h_user_agent->value));
    }

    if (httplog_ctx->cf != NULL)
    for (i = 0; i < httplog_ctx->cf->cf_n; i++) {
        temp = 0;
        datalen = 0;
        h_request_hdr = NULL;
        h_response_hdr = NULL;

        LogCustomFormatNode* node = httplog_ctx->cf->cf_nodes[i];
        if (! node) //Should never happen
            continue;

        cvalue = NULL;
        cvalue_len = 0;

        switch (node->type) {
            case LOG_HTTP_CF_REQUEST_HEADER:
                // REQUEST HEADER
                if (tx->request_headers != NULL) {
                    h_request_hdr = htp_table_get_c(tx->request_headers, node->data);
                }
                if (h_request_hdr != NULL) {
                    datalen = node->maxlen;
                    if (datalen == 0 || datalen > bstr_len(h_request_hdr->value)) {
                        datalen = bstr_len(h_request_hdr->value);
                    }
                    PrintRawUriBuf((char *)http->req_header, &temp, sizeof(http->req_header),
                                (uint8_t *)bstr_ptr(h_request_hdr->value), datalen
                    );
                }
                break;
            case LOG_HTTP_CF_RESPONSE_HEADER:
                // RESPONSE HEADER
                if (tx->response_headers != NULL) {
                    h_response_hdr = htp_table_get_c(tx->response_headers, node->data);
                }
                if (h_response_hdr != NULL) {
                    datalen = node->maxlen;
                    if (datalen == 0 || datalen > bstr_len(h_response_hdr->value)) {
                        datalen = bstr_len(h_response_hdr->value);
                    }
                    PrintRawUriBuf((char *)http->resp_header, &temp, sizeof(http->resp_header),
                                (uint8_t *)bstr_ptr(h_response_hdr->value), datalen
                    );
                }
                break;
            case LOG_HTTP_CF_REQUEST_COOKIE:
                //REQUEST COOKIE
                if (tx->request_headers != NULL) {
                    h_request_hdr = htp_table_get_c(tx->request_headers, "Cookie");
                    if (h_request_hdr != NULL) {
                        cvalue_len = GetCookieValue((uint8_t *) bstr_ptr(h_request_hdr->value),
                                    bstr_len(h_request_hdr->value), (char *) node->data,
                                    &cvalue);
                    }
                }
                if (cvalue_len > 0 && cvalue != NULL) {
                    datalen = node->maxlen;
                    if (datalen == 0 || datalen > cvalue_len) {
                        datalen = cvalue_len;
                    }
                    PrintRawUriBuf((char *)http->req_cookie, &temp, sizeof(http->req_cookie),
                                cvalue, datalen
                    );
                }
                break;
        }
    }

    if (p->flow != NULL)
        http->flow_id = p->flow->flowInfo.flow_id;
    else
        http->flow_id = 0;

    // printf("HTTP RECORD:\n");
    // printf("http->timestamp: %lu\n", http->timestamp);
    // printf("http->tx_id: %lu\n", http->tx_id);
    // printf("http->dst_ip: %lu\n", http->dst_ip[0]);
    // printf("http->src_ip: %lu\n", http->src_ip[0]);
    // printf("http->src_port: %d\n", http->src_port);
    // printf("http->dst_port: %d\n", http->dst_port);
    // printf("http->method: %s\n", http->method);
    // printf("http->uri: %s\n", http->uri);
    // printf("http->hostname: %s\n", http->hostname);
    // printf("http->referer: %s\n", http->referer);
    // printf("http->protocol: %s\n", http->protocol);
    // printf("http->req_header: %s\n", http->req_header);
    // printf("http->req_msg_len: %d\n", http->req_msg_len);
    // printf("http->resp_header: %s\n", http->resp_header);
    // printf("http->resp_msg_len: %d\n", http->resp_msg_len);
    // printf("http->user_agent: %s\n", http->user_agent);
    // printf("http->resp_status: %d\n", http->resp_status);
    // printf("http->req_cookie: %s\n", http->req_cookie);

    NanomsgSendBufferIfNeeded(&nn_handler_http);
}

#endif //__CS_LOG_HTTPLOG_H__
