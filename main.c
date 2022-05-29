#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "mongoose.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define HTTP_SRV    "www.google.com"
const char * HTTP_SERVER = "http_server";
const char * HTTP_CLIENT = "http_client";
int loop = 1;

struct mg_mgr mgr;
struct mg_http_serve_opts dir_opts = {.root_dir = "/home/"};
struct mg_tls_opts tls_opts = {.cert = "cert.pem", .certkey = "key.pem"};
struct mg_tls_opts tls_srv_opts = {};

void fn_http (struct mg_connection *c, int ev, void *ev_data, void *fn_data)
{
    char time_str[30];
    if (ev != MG_EV_POLL)
    {
        time_t t = time(0);
        struct tm * time_info = localtime(&t);
        strftime(time_str, sizeof time_str, "%Y/%m/%d %H:%M:%S", time_info);
        printf(KRED"[%s.%d] ev: %s\n"KNRM, time_str, t % 1000, mg_ev_str[ev]);
    }

    if (ev == MG_EV_CONNECT && strcmp(fn_data, HTTP_CLIENT) == 0)
    {
        mg_tls_init(c, &tls_srv_opts);

        mg_printf(c, "GET / HTTP/1.1\r\n");
        mg_printf(c, "Host: "HTTP_SRV"\r\n");
        mg_printf(c, "Connection: close\r\n");
        mg_printf(c, "\r\n");
    }
    if (ev == MG_EV_ACCEPT && strcmp(fn_data, HTTP_SERVER) == 0)
    {
        mg_tls_init(c, &tls_opts);
    }
    if (ev == MG_EV_HTTP_CHUNK)
    {
        struct mg_http_message * http_msg = (struct mg_http_message *) ev_data;
        struct mg_http_header * hdr = http_msg->headers;

        printf("%.*s %.*s %.*s\n", http_msg->method.len, http_msg->method.ptr,
               http_msg->uri.len, http_msg->uri.ptr,
               http_msg->proto.len, http_msg->proto.ptr);
        struct mg_http_message * hm = (struct mg_http_message *) ev_data;
//        printf("[chunk] %.*s\n", hm->chunk.len, hm->chunk.ptr);
        printf("[chunk] %d\n", hm->chunk.len);
        mg_http_delete_chunk(c, hm);
    }
    if (ev == MG_EV_HTTP_MSG)
    {
        struct mg_http_message * http_msg = (struct mg_http_message *) ev_data;
        struct mg_http_header * hdr = http_msg->headers;

        printf("%.*s %.*s %.*s\n", http_msg->method.len, http_msg->method.ptr,
               http_msg->uri.len, http_msg->uri.ptr,
               http_msg->proto.len, http_msg->proto.ptr);

        while (hdr->name.len)
        {
            printf("<%.*s> [%.*s]\n", hdr->name.len, hdr->name.ptr, hdr->value.len, hdr->value.ptr);
            hdr++;
        }

        if (strcmp(fn_data, HTTP_CLIENT) == 0)
        {
            printf("[body] %.*s\n", http_msg->body.len, http_msg->body.ptr);
        }
        else if (strcmp(fn_data, HTTP_SERVER) == 0)
        {
//            struct mg_str cap_test[2]; int res;
//            printf("[PTR] %X\n", http_msg->uri.ptr);
//            res = mg_match(http_msg->uri, mg_str("/home#"), cap_test);   printf("[match] %d %d |%.*s| %X\n", res, cap_test[0].len, cap_test[0].len, cap_test[0].ptr, cap_test[0].ptr);
//            res = mg_match(http_msg->uri, mg_str("/home*"), cap_test);   printf("[match] %d %d |%.*s| %X\n", res, cap_test[0].len, cap_test[0].len, cap_test[0].ptr, cap_test[0].ptr);
//            res = mg_match(http_msg->uri, mg_str("/home/*"), cap_test);  printf("[match] %d %d |%.*s| %X\n", res, cap_test[0].len, cap_test[0].len, cap_test[0].ptr, cap_test[0].ptr);
//            res = mg_match(http_msg->uri, mg_str("/home*/*"), cap_test); printf("[match] %d %d |%.*s| %X\n", res, cap_test[0].len, cap_test[0].len, cap_test[0].ptr, cap_test[0].ptr);
//            res = mg_match(http_msg->uri, mg_str("/home#/*"), cap_test); printf("[match] %d %d |%.*s| %X\n", res, cap_test[0].len, cap_test[0].len, cap_test[0].ptr, cap_test[0].ptr);

            struct mg_str cap;
            if (mg_http_match_uri(http_msg, "/api#"))
            {
                mg_printf(c, "HTTP/1.1 200 OK\r\n");
                mg_printf(c, "Transfer-Encoding: chunked\r\n");
                mg_printf(c, "Content-Type: application/json\r\n");
                mg_printf(c, "\r\n");
                mg_http_printf_chunk(c, "{\"tag\": \"no tag\", \"server_time\": \"%s\"}", time_str);
                mg_http_printf_chunk(c, "");
            }
            else if (mg_match(http_msg->uri, mg_str("/dir#"), &cap))
            {
                http_msg->uri.len = cap.len;
                http_msg->uri.ptr = cap.ptr;
                mg_http_serve_dir(c, ev_data, &dir_opts);
            }
            else
            {
                mg_http_reply(c, 404, "Connection: close\r\n", "");
                c->is_draining = 1;
                loop = 0;
            }
        }
    }
}

//void cb(struct mg_connection *c, int ev, void *ev_data, void *fn_data)
//{
//    if (ev == MG_EV_READ)
//    {
//        mg_send(c, c->recv.buf, c->recv.len);
//        mg_iobuf_del(&c->recv, 0, c->recv.len);
//    }
//}

int main()
{
    mg_log_set("0");
    mg_mgr_init(&mgr);

    mg_http_connect(&mgr, HTTP_SRV":443", fn_http, HTTP_CLIENT);
    mg_http_listen(&mgr, "https://127.0.0.1:8443", fn_http, HTTP_SERVER);
//    mg_listen(&mgr, "tcp://0.0.0.0:1234", cb, NULL);

    while (loop)
    {
        mg_mgr_poll(&mgr, 1000);
    }

    mg_mgr_free(&mgr);

    return 0;
}
