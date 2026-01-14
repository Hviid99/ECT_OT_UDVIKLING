#include "esp_br_web.h"
#include "udp_br_func.h"
#include "esp_https_server.h"
#include "esp_check.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_openthread.h"
#include "esp_openthread_border_router.h"
#include "esp_vfs.h"
#include "sdkconfig.h"
#include "cJSON.h"
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>


#define SERVER_IPV4_LEN 16
#define FILE_CHUNK_SIZE 1024
#define WEB_TAG "obtr_web"

/*-----------------------------------------------------
 Note：Authentication
-----------------------------------------------------*/
#define AUTH_STRING "Basic YWRtaW46dGVzdDEyMw=="   // "admin:test123" base64
static const char *AUTH_TAG = "auth";

static esp_err_t check_auth(httpd_req_t *req)
{
    char auth_value[128];
    size_t auth_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;

    if (auth_len <= 1) {
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Secure\"");
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        ESP_LOGW(AUTH_TAG, "Access denied: no credentials");
        return ESP_FAIL;
    }

    httpd_req_get_hdr_value_str(req, "Authorization", auth_value, sizeof(auth_value));

    if (strcmp(auth_value, AUTH_STRING) != 0) {
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Secure\"");
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        ESP_LOGW(AUTH_TAG, "Access denied: wrong credentials");
        return ESP_FAIL;
    }

    ESP_LOGI(AUTH_TAG, "Access granted");
    return ESP_OK;
}


/*-----------------------------------------------------
 Note：Https Server
-----------------------------------------------------*/
typedef struct https_server_data {
    char base_path[ESP_VFS_PATH_MAX + 1]; /* the storaged file path */
} https_server_data_t;

typedef struct http_server {
    httpd_handle_t handle;    /* server handle, unique */
    https_server_data_t data;  /* data */
    char ip[SERVER_IPV4_LEN]; /* ip */
    uint16_t port;            /* port */
} http_server_t;

static http_server_t s_server = {0};

#define PROTLOCOL_MAX_SIZE 12
#define FILENAME_MAX_SIZE 64
#define FILEPATH_MAX_SIZE (FILENAME_MAX_SIZE + ESP_VFS_PATH_MAX)
typedef struct request_url {
    char protocol[PROTLOCOL_MAX_SIZE];
    uint16_t port;
    char file_name[FILENAME_MAX_SIZE];
    char file_path[FILEPATH_MAX_SIZE];
} reqeust_url_t;

/*-----------------------------------------------------
 Note：Tidlig deklaration
-----------------------------------------------------*/
static esp_err_t battery_request_handler(httpd_req_t *req);
static esp_err_t hush_alarm_handler(httpd_req_t *req);
static esp_err_t led_test_handler(httpd_req_t *req);
static esp_err_t battery_status_handler(httpd_req_t *req);
static esp_err_t device_handler(httpd_req_t *req);


static httpd_uri_t s_resource_handlers[] = {
    {
    .uri = "/battery_request",
    .method = HTTP_GET,
    .handler = battery_request_handler,
    .user_ctx = NULL,
    },
    {
    .uri = "/battery_status",
    .method = HTTP_GET,
    .handler = battery_status_handler,
    .user_ctx = NULL,
    },
    {
    .uri = "/api/device",
    .method = HTTP_GET,
    .handler = device_handler,
    .user_ctx = NULL,
    },
    {
    .uri = "/hush_alarm",
    .method = HTTP_GET,
    .handler = hush_alarm_handler,
    .user_ctx = NULL,
    },
    {
    .uri = "/led_test",
    .method = HTTP_GET,
    .handler = led_test_handler,
    .user_ctx = NULL,
    },
};

/*-----------------------------------------------------
 Note：Egne funktioner 
-----------------------------------------------------*/
static esp_err_t battery_request_handler(httpd_req_t *req)
{
    otInstance *instance = esp_openthread_get_instance();
    if (!instance) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No OpenThread instance");
        return ESP_FAIL;
    }

     send_udp_to_all_seds_with_payload(instance, "BREQ", "Battery request");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"message\": \"Battery request sent\"}");
    return ESP_OK;
}

static esp_err_t hush_alarm_handler(httpd_req_t *req)
{
    otInstance *instance = esp_openthread_get_instance();
    if (!instance) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No OpenThread instance");
        return ESP_FAIL;
    }

    send_udp_to_all_seds_with_payload(instance, "HUSH", "HUSH request");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"message\": \"Hush request sent\"}");
    return ESP_OK;
}

static esp_err_t led_test_handler(httpd_req_t *req)
{
    otInstance *instance = esp_openthread_get_instance();
    if (!instance) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No OpenThread instance");
        return ESP_FAIL;
    }

    send_udp_to_all_seds_with_payload(instance, "ALARMTEST", "LED request");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"message\": \"LED ON request sent\"}");
    return ESP_OK;
}

static esp_err_t battery_status_handler(httpd_req_t *req)
{
    char json[1024];
    udp_get_all_status(json, sizeof(json));   // bygger JSON direkte

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    return ESP_OK;
}

static esp_err_t device_handler(httpd_req_t *req)
{
    char param[32];
    if (httpd_req_get_url_query_str(req, param, sizeof(param)) == ESP_OK) {
        char sedParam[16];
        if (httpd_query_key_value(param, "sed", sedParam, sizeof(sedParam)) == ESP_OK) {
            if (strncmp(sedParam, "SED", 3) == 0) {
                int idx = atoi(sedParam + 3) - 1;

                const sed_status_t *st = udp_get_status(idx);
                if (!st) {
                    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "SED not found");
                    return ESP_FAIL;
                }

                sed_status_t sed_copy = *st;
                otInstance *instance = esp_openthread_get_instance();
                if (instance) {
                    update_sed_thread_info(&sed_copy, instance);
                }

                // Konverter last_seen til streng
                char timebuf[32] = "---";
                if (sed_copy.last_seen > 0) {
                    struct tm tm_info;
                    localtime_r(&sed_copy.last_seen, &tm_info);
                    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_info);
                }

                // Byg JSON med cJSON
                cJSON *root = cJSON_CreateObject();
                cJSON_AddStringToObject(root, "id", sedParam);
                cJSON_AddNumberToObject(root, "voltage", sed_copy.voltage);
                cJSON_AddStringToObject(root, "status", sed_copy.status);

                cJSON_AddStringToObject(root, "alarm", "");
                cJSON_AddStringToObject(root, "last_seen", timebuf);
                cJSON_AddStringToObject(root, "location", "");

                // Thread sub-objekt
                cJSON *thread = cJSON_CreateObject();
                cJSON_AddStringToObject(thread, "device_type", "SED");
                cJSON_AddStringToObject(thread, "mleid", sed_copy.mleid);

                char rloc16_str[16];
                snprintf(rloc16_str, sizeof(rloc16_str), "0x%04x", sed_copy.rloc16);
                cJSON_AddStringToObject(thread, "rloc16", rloc16_str);

                cJSON_AddStringToObject(thread, "parent_id", "");
                cJSON_AddStringToObject(thread, "partition_id", "");

                cJSON_AddItemToObject(root, "thread", thread);

                // Send svaret
                char *json_str = cJSON_PrintUnformatted(root);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_sendstr(req, json_str);

                // Free hukommelse
                cJSON_Delete(root);
                free(json_str);

                return ESP_OK;
            }
        }
    }

    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request");
    return ESP_FAIL;
}





static esp_err_t favicon_get_handler(httpd_req_t *req)
{
    extern const unsigned char favicon_ico_start[] asm("_binary_favicon_ico_start");
    extern const unsigned char favicon_ico_end[] asm("_binary_favicon_ico_end");
    const size_t favicon_ico_size = (favicon_ico_end - favicon_ico_start);

    ESP_RETURN_ON_ERROR(httpd_resp_set_type(req, "image/x-icon"), WEB_TAG, "Failed to set http respond type");
    ESP_RETURN_ON_ERROR(httpd_resp_send(req, (const char *)favicon_ico_start, favicon_ico_size), WEB_TAG,
                        "Failed to send http respond");
    return ESP_OK;
}

static esp_err_t httpd_resp_send_spiffs_file(httpd_req_t *req, char *path)
{
    ESP_LOGI(WEB_TAG, "-------------------------------------------");
    ESP_LOGI(WEB_TAG, "Reading %s", path);

    FILE *fp = fopen(path, "r"); // Open and read file

    ESP_RETURN_ON_FALSE(fp, ESP_FAIL, WEB_TAG, "Failed to open %s file", path);

    char buf[FILE_CHUNK_SIZE]; // the size of chunk
    while (!feof(fp) && !ferror(fp)) {
        fread(buf, FILE_CHUNK_SIZE - 1, 1, fp);
        buf[FILE_CHUNK_SIZE - 1] = '\0';
        httpd_resp_sendstr_chunk(req, buf);
        memset(buf, 0, sizeof(buf));
    };
    return fclose(fp) == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t index_html_get_handler(httpd_req_t *req, char *path)
{
    // Tjek først, om brugeren har korrekt login (Basic Auth)
    if (check_auth(req) != ESP_OK) {
        // Hvis auth fejler, returneres ESP_FAIL
        // og klienten får automatisk en 401 Unauthorized
        return ESP_FAIL;
    }

    // Hvis auth er godkendt, send HTML-siden
    ESP_RETURN_ON_ERROR(httpd_resp_set_type(req, "text/html"), WEB_TAG, "Failed to set http text/html type");
    ESP_RETURN_ON_ERROR(httpd_resp_send_spiffs_file(req, path), WEB_TAG, "Failed to send index html file");
    ESP_RETURN_ON_ERROR(httpd_resp_sendstr_chunk(req, NULL), WEB_TAG, "Failed to send http string chunk");
    return ESP_OK;
}


static esp_err_t style_css_get_handler(httpd_req_t *req, char *path)
{
    // send content-type："text/css" in http-header
    ESP_RETURN_ON_ERROR(httpd_resp_set_type(req, "text/css"), WEB_TAG, "Failed to set http text/css type");
    ESP_RETURN_ON_ERROR(httpd_resp_send_spiffs_file(req, path), WEB_TAG, "Failed to send css file");
    ESP_RETURN_ON_ERROR(httpd_resp_sendstr_chunk(req, NULL), WEB_TAG, "Failed to send http string chunk");
    return ESP_OK;
}

static esp_err_t script_js_get_handler(httpd_req_t *req, char *path)
{
    // send content-type："application/javascript" in http-header
    ESP_RETURN_ON_ERROR(httpd_resp_set_type(req, "application/javascript"), WEB_TAG,
                        "Failed to set http application/javascript type");
    ESP_RETURN_ON_ERROR(httpd_resp_send_spiffs_file(req, path), WEB_TAG, "Failed to send js file");
    ESP_RETURN_ON_ERROR(httpd_resp_sendstr_chunk(req, NULL), WEB_TAG, "Failed to send http string chunk");
    return ESP_OK;
}

static reqeust_url_t parse_request_url_information(const char *uri, const struct http_parser_url *parse_url,
                                                   const char *base_path)
{
    reqeust_url_t ret = {
        .protocol = "http",
        .port = 80,
        .file_name = "",
        .file_path = "",
    };
    ret.port = parse_url->port;
    if ((parse_url->field_set & (1 << UF_SCHEMA)) != 0 && PROTLOCOL_MAX_SIZE > parse_url->field_data[UF_SCHEMA].len) {
        memcpy(ret.protocol, uri + parse_url->field_data[UF_SCHEMA].off, parse_url->field_data[UF_SCHEMA].len);
        ret.protocol[parse_url->field_data[UF_SCHEMA].len] = '\0';
    }

    if ((parse_url->field_set & (1 << UF_PATH)) != 0 && FILENAME_MAX_SIZE > parse_url->field_data[UF_PATH].len) {
        memcpy(ret.file_name, uri + parse_url->field_data[UF_PATH].off, parse_url->field_data[UF_PATH].len);
        ret.file_name[parse_url->field_data[UF_PATH].len] = '\0';
        memcpy(ret.file_path, base_path, strlen(base_path));
        strcat(ret.file_path, ret.file_name);
    }
    return ret;
}

static esp_err_t default_urls_get_handler(httpd_req_t *req)
{
    struct http_parser_url url;
    ESP_RETURN_ON_ERROR(http_parser_parse_url(req->uri, strlen(req->uri), 0, &url), WEB_TAG, "Failed to parse url");
    reqeust_url_t info =
        parse_request_url_information(req->uri, &url, ((https_server_data_t *)req->user_ctx)->base_path);

    ESP_LOGI(WEB_TAG, "-------------------------------------------");
    ESP_LOGI(WEB_TAG, "%s", info.file_name);
    if (!strcmp(info.file_name, "")) // check the filename.
    {
        ESP_LOGE(WEB_TAG, "Filename is too long or url error"); /* Respond with 500 Internal Server Error */
        ESP_RETURN_ON_ERROR(
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename is too long or url error"), WEB_TAG,
            "Failed to send error code");
        return ESP_FAIL;
    }
    if (strcmp(info.file_name, "/") == 0) {
        return index_html_get_handler(req, info.file_path);

    } else if (strcmp(info.file_name, "/index.html") == 0) {
        return index_html_get_handler(req, info.file_path);

    } else if (strcmp(info.file_name, "/device.html") == 0) {
        return index_html_get_handler(req, info.file_path);

    } else if (strcmp(info.file_name, "/static/style.css") == 0) {
        return style_css_get_handler(req, info.file_path);

    } else if (strcmp(info.file_name, "/static/restful.js") == 0) {
        return script_js_get_handler(req, info.file_path);

    } else if (strcmp(info.file_name, "/static/bootstrap.min.css") == 0) {
        return script_js_get_handler(req, info.file_path);

    // --- Favicon tilføjet her ---
    } else if (strcmp(info.file_name, "/static/favicon.ico") == 0) {
        ESP_RETURN_ON_ERROR(httpd_resp_set_type(req, "image/x-icon"), WEB_TAG, "Failed to set favicon type");
        ESP_RETURN_ON_ERROR(httpd_resp_send_spiffs_file(req, info.file_path), WEB_TAG, "Failed to send favicon");
        ESP_RETURN_ON_ERROR(httpd_resp_sendstr_chunk(req, NULL), WEB_TAG, "Failed to send favicon chunk");
        return ESP_OK;

    // --- Hvis ingen af ovenstående matcher ---
    } else {
        ESP_LOGW(WEB_TAG, "File not found: %s", info.file_path);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
        return ESP_FAIL;
    }
}


/*-----------------------------------------------------
 Note：Server Start
-----------------------------------------------------*/
/* ==========================================================
   HTTPS Certificate + Key (Embedded from CMakeLists.txt)
   ========================================================== */

extern const unsigned char servercert_pem_start[] asm("_binary_servercert_pem_start");
extern const unsigned char servercert_pem_end[]   asm("_binary_servercert_pem_end");
extern const unsigned char prvtkey_pem_start[]    asm("_binary_prvtkey_pem_start");
extern const unsigned char prvtkey_pem_end[]      asm("_binary_prvtkey_pem_end");

#define SERVER_CERT      servercert_pem_start
#define SERVER_CERT_LEN  (servercert_pem_end - servercert_pem_start)
#define SERVER_KEY       prvtkey_pem_start
#define SERVER_KEY_LEN   (prvtkey_pem_end - prvtkey_pem_start)

static void list_spiffs_files(const char *base_path)
{
    ESP_LOGI(WEB_TAG, "Listing files in %s:", base_path);

    DIR *dir = opendir(base_path);
    if (!dir) {
        ESP_LOGE(WEB_TAG, "Failed to open directory %s", base_path);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        ESP_LOGI(WEB_TAG, "  %s", entry->d_name);
    }

    closedir(dir);
    ESP_LOGI(WEB_TAG, "Done listing files.");
}

static httpd_handle_t *start_esp_br_https_server(const char *base_path, const char *host_ip)
{
    ESP_RETURN_ON_FALSE(base_path, NULL, WEB_TAG, "Invalid https server path");
    strcpy(s_server.ip, host_ip);
    strlcpy(s_server.data.base_path, base_path, ESP_VFS_PATH_MAX + 1);
    list_spiffs_files(base_path);

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.port_secure = 443;
    conf.servercert    = SERVER_CERT;
    conf.servercert_len = SERVER_CERT_LEN;
    conf.prvtkey_pem   = SERVER_KEY;
    conf.prvtkey_len   = SERVER_KEY_LEN;

    // Allow wildcard URI matching (so "/*" works)
    conf.httpd.uri_match_fn = httpd_uri_match_wildcard;



    // Start HTTPS-server
    esp_err_t ret = httpd_ssl_start(&s_server.handle, &conf);
    if (ret != ESP_OK) {
        ESP_LOGE(WEB_TAG, "Failed to start HTTPS server: %s", esp_err_to_name(ret));
        return NULL;
    }

    // Registrér URI-handlers
    httpd_uri_t default_uris_get = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = default_urls_get_handler,
        .user_ctx = &s_server.data
    };

    for (int i = 0; i < sizeof(s_resource_handlers) / sizeof(httpd_uri_t); i++) {
        httpd_register_uri_handler(s_server.handle, &s_resource_handlers[i]);
    }
    httpd_register_uri_handler(s_server.handle, &default_uris_get);

    // Info i log
    ESP_LOGI(WEB_TAG, "%s\r\n", "<=======================HTTPS server start========================>");
    ESP_LOGI(WEB_TAG, "https://%s:%d/index.html\r\n", s_server.ip, 443);
    ESP_LOGI(WEB_TAG, "%s\r\n", "<=================================================================>");

    return s_server.handle;
}


void connect_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data, const char *base_path)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    ESP_RETURN_ON_FALSE(server, , WEB_TAG, "Http server is invalid, failed to start it");
    ESP_LOGI(WEB_TAG, "Start the web server for Openthread Border Router");
    *server = (httpd_handle_t *)start_esp_br_https_server(base_path, s_server.ip);
}

static bool is_br_web_server_started = false;
static void handler_got_ip_event(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (!is_br_web_server_started) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        char ipv4_address[SERVER_IPV4_LEN];
        sprintf((char *)ipv4_address, IPSTR, IP2STR(&event->ip_info.ip));
        if (start_esp_br_https_server((const char *)arg, (char *)ipv4_address) != NULL) {
            is_br_web_server_started = true;
        } else {
            ESP_LOGE(WEB_TAG, "Fail to start web server");
        }
    } else {
        ESP_LOGW(WEB_TAG, "Web server had already been started");
    }
}

void esp_br_web_start(char *base_path)
{
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &handler_got_ip_event, base_path));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &handler_got_ip_event, base_path));

}
