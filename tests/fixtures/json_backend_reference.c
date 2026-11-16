/* Bounded Linux-only differential DATA. Never copied into production/native-test.
 * This intentionally links the OLD cJSON provider in a separate diagnostic stage.
 * No assertion treats its acceptance behavior as an authorization decision. */
#include <cjson/cJSON.h>
#include <jansson.h>
#include <winpr/json.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int main(void)
{
    struct rlimit cpu = {3, 3}, memory = {256 * 1024 * 1024, 256 * 1024 * 1024};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_AS, &memory)) return 1;
    alarm(5);
    const char* inputs[] = {"{\"k\":1}", "NaN", "Infinity", "{\"k\":NaN}",
        "{/*comment*/\"k\":1}", "{\"k\":1}garbage", "{\"k\":1,\"k\":2}",
        "\"\\uD800\"", "\"\\uDC00\"", "\"\\uD83D\\uDE00\"", "\"\\u0000\"",
        "\"\303\050\"", "[1,]", "{'k':1}", "1e999"};
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++)
    {
        cJSON* old = cJSON_Parse(inputs[i]);
        json_error_t error;
        json_t* raw = json_loads(inputs[i], JSON_DECODE_ANY, &error);
        WINPR_JSON* now = WINPR_JSON_Parse(inputs[i]);
        printf("{\"case\":%zu,\"cjson\":%s,\"jansson_default\":%s,\"winpr_guarded\":%s}\n",
            i, old ? "true" : "false", raw ? "true" : "false", now ? "true" : "false");
        if (i == 6)
        {
            const cJSON* a = cJSON_GetObjectItem(old, "k");
            const WINPR_JSON* b = WINPR_JSON_GetObjectItem(now, "k");
            if (!cJSON_IsNumber(a) || a->valuedouble != 1 ||
                b != NULL) return 1;
        }
        cJSON_Delete(old);
        json_decref(raw);
        WINPR_JSON_Delete(now);
    }
    const char embedded[] = {'{','}',0,'x'};
    cJSON* old = cJSON_ParseWithLength(embedded, sizeof(embedded));
    WINPR_JSON* now = WINPR_JSON_ParseWithLength(embedded, sizeof(embedded));
    printf("{\"case\":\"embedded_NUL\",\"cjson\":%s,\"winpr_guarded\":%s}\n",
        old ? "true" : "false", now ? "true" : "false");
    const int embedded_NUL_rejected = now == NULL;
    cJSON_Delete(old);
    WINPR_JSON_Delete(now);
    if (!embedded_NUL_rejected) return 1;
    char depth[130];
    memset(depth, '[', 64); depth[64] = '0';
    memset(depth + 65, ']', 64); depth[129] = 0;
    old = cJSON_Parse(depth); now = WINPR_JSON_Parse(depth);
    printf("{\"case\":\"depth64\",\"cjson\":%s,\"winpr_guarded\":%s}\n",
        old ? "true" : "false", now ? "true" : "false");
    const int depth64_ok = old != NULL && now != NULL;
    cJSON_Delete(old); WINPR_JSON_Delete(now);
    if (!depth64_ok) return 1;
    char excessive_depth[8194];
    memset(excessive_depth, '[', 4096); excessive_depth[4096] = '0';
    memset(excessive_depth + 4097, ']', 4096); excessive_depth[8193] = 0;
    now = WINPR_JSON_Parse(excessive_depth);
    const int depth4096_rejected = now == NULL;
    WINPR_JSON_Delete(now);
    printf("{\"case\":\"depth4096\",\"winpr_guarded_rejected\":%s}\n",
        depth4096_rejected ? "true" : "false");
    return depth4096_rejected ? 0 : 1;
}
