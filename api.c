//
// Created by hooman on 5/30/22.
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mongoose.h"
#include "cJSON.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"

static int api_server_loop = 1;
static char password[100] = {0};
static struct mg_mgr mgr;
static struct mg_http_serve_opts dir_opts = {.root_dir = "/home/hooman"};

static int simple_handler (struct mg_connection *c, struct mg_http_message * http_msg, struct mg_str * caps, cJSON * body)
{
    mg_printf(c, "HTTP/1.1 200 OK\r\n");
    mg_printf(c, "Transfer-Encoding: chunked\r\n");
    mg_printf(c, "Content-Type: application/json\r\n");
    mg_printf(c, "\r\n");
    char temp[100];
//    snprintf(temp, sizeof temp, "{\"tag\": \"no tag\", \"server_time\": \"%*.*s\"}", cap.len, cap.len, cap.ptr);
    mg_http_printf_chunk(c, "{\"tag\": \"no tag\", \"server_time\": \"%.*s\"}", (int) caps->len, caps->ptr);
    mg_http_printf_chunk(c, "");
    return 0;
}

static int directory_handler (struct mg_connection *c, struct mg_http_message * http_msg, struct mg_str * caps, cJSON * body)
{
    http_msg->uri.len = caps->len;
    http_msg->uri.ptr = caps->ptr;
    mg_http_serve_dir(c, http_msg, &dir_opts);
    return 0;
}

typedef int (* request_handler) (struct mg_connection *c, struct mg_http_message * http_msg, struct mg_str * caps, cJSON * body);
struct api_handlers
{
    const char * pattern;
    request_handler handler;
    int auth_required;
} api_handlers [] = {
        {"/api/v1/", simple_handler, 0},
        {"/dir#", directory_handler, 1},
        {0, 0, 0},
};

static void fn_api (struct mg_connection *c, int ev, void *ev_data, void *fn_data)
{
    static char user[100] = {0};
    static char pass[100] = {0};

    char time_str[30];
    if (ev != MG_EV_POLL)
    {
        time_t t = time(0);
        struct tm * time_info = localtime(&t);
        strftime(time_str, sizeof time_str, "%Y/%m/%d %H:%M:%S", time_info);
        printf(KRED"[%s.%d] ev: %s\n"KNRM, time_str, t % 1000, mg_ev_str[ev]);
    }

    if (ev == MG_EV_HTTP_MSG)
    {
        struct mg_http_message *http_msg = (struct mg_http_message *) ev_data;
        struct mg_http_header *hdr = http_msg->headers;

        printf("%.*s %.*s %.*s\n", http_msg->method.len, http_msg->method.ptr,
               http_msg->uri.len, http_msg->uri.ptr,
               http_msg->proto.len, http_msg->proto.ptr);

        while (hdr->name.len)
        {
            printf("<%.*s> [%.*s]\n", hdr->name.len, hdr->name.ptr, hdr->value.len, hdr->value.ptr);
            hdr++;
        }

        struct mg_str caps[1];
        struct api_handlers * ptr = api_handlers;
        int request_handled = 0;

        while (ptr->pattern)
        {
            if (mg_match(http_msg->uri, mg_str(ptr->pattern), caps))
            {
                if (ptr->auth_required)
                {
                    mg_http_creds(http_msg, user, sizeof(user), pass, sizeof(pass));
                    if (user[0] == NULL || strcmp(user, password) != 0 || pass[0] == NULL || strcmp(pass, password) != 0)
                    {
                        mg_http_reply(c, 401, "WWW-Authenticate: Basic realm=\"POS API Endpoint\"\r\nConnection: close\r\n", "");
                        c->is_draining = 1;
                        request_handled = 1;
                    }
                }

                cJSON * json = NULL;

                if (request_handled == 0)
                {
                    struct mg_str * content_type = mg_http_get_header(http_msg, "Content-Type");
                    if (content_type && mg_strcmp(*content_type, mg_str("application/json")))
                    {
                        if (http_msg->body.len == 0)
                        {
                            mg_http_reply(c, 400, "Connection: close\r\n", "empty body");
                            c->is_draining = 1;
                            request_handled = 1;
                        }
                        else
                        {
                            json = cJSON_ParseWithLength(http_msg->body.ptr, http_msg->body.len);
                            if (json == NULL)
                            {
                                mg_http_reply(c, 400, "Connection: close\r\n", "body is not json");
                                c->is_draining = 1;
                                request_handled = 1;
                            }
                        }
                    }
                }

                if (request_handled == 0)
                {
                    int request_result = ptr->handler(c, http_msg, caps, json);
                    if (request_result != 0)
                    {
                        mg_http_reply(c, request_result, "Connection: close\r\n", "Error");
                    }
                }

                if (json)
                {
                    cJSON_Delete(json);
                }

                break;
            }

            ++ptr;
        }

        if (request_handled == 0)
        {
            mg_http_reply(c, 404, "Connection: close\r\n", "Wrong");
            c->is_draining = 1;
        }
    }
}

void api_server()
{
    unsigned char md5[16];
    mg_md5_ctx ctx;
    mg_md5_init(&ctx);
    mg_md5_update(&ctx, "hooman", 6);
    mg_md5_final(&ctx, md5);
    mg_hex(md5, 16, password);

    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "http://0.0.0.0:8080", fn_api, NULL);
    while (api_server_loop) mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);
}

int main()
{
    api_server();
    return 0;
}
