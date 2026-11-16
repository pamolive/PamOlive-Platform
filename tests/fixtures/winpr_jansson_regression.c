/* Synthetic, offline contract tests for the actual installed WinPR JSON backend.
 * No client, socket, credential, external input or daemon is used. */
#include <winpr/json.h>
#include <freerdp/settings.h>
#include <math.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "JANSSON_CASE_%d\n", __LINE__); return 1; } } while (0)

int main(void)
{
    struct rlimit cpu = { 3, 3 }, memory = { 256 * 1024 * 1024, 256 * 1024 * 1024 };
    CHECK(setrlimit(RLIMIT_CPU, &cpu) == 0);
    CHECK(setrlimit(RLIMIT_AS, &memory) == 0);
    alarm(5);
    char version[64] = { 0 };
    CHECK(WINPR_JSON_version(version, sizeof(version)) == (int)strlen("jansson 2.14"));
    CHECK(strcmp(version, "jansson 2.14") == 0);

    WINPR_JSON* obj = WINPR_JSON_Parse("{\"access_token\":17,\"token_endpoint\":{},\"Text\":\"synthetic\",\"None\":null,\"Flag\":true}");
    CHECK(WINPR_JSON_IsObject(obj));
    CHECK(WINPR_JSON_GetStringValue(WINPR_JSON_GetObjectItem(obj, "access_token")) == NULL);
    CHECK(WINPR_JSON_GetStringValue(WINPR_JSON_GetObjectItem(obj, "token_endpoint")) == NULL);
    CHECK(isnan(WINPR_JSON_GetNumberValue(WINPR_JSON_GetObjectItem(obj, "Text"))));
    CHECK(isnan(WINPR_JSON_GetNumberValue(WINPR_JSON_GetObjectItem(obj, "None"))));
    CHECK(isnan(WINPR_JSON_GetNumberValue(WINPR_JSON_GetObjectItem(obj, "Flag"))));
    CHECK(WINPR_JSON_GetNumberValue(WINPR_JSON_GetObjectItem(obj, "access_token")) == 17.0);
    CHECK(strcmp(WINPR_JSON_GetStringValue(WINPR_JSON_GetObjectItem(obj, "text")), "synthetic") == 0);
    CHECK(WINPR_JSON_HasObjectItem(obj, "None"));
    CHECK(!WINPR_JSON_HasObjectItem(obj, "none"));
    CHECK(!WINPR_JSON_HasObjectItem(obj, "absent"));
    CHECK(!WINPR_JSON_HasObjectItem(NULL, "absent"));
    CHECK(!WINPR_JSON_GetObjectItem(NULL, "absent"));
    CHECK(!WINPR_JSON_GetObjectItemCaseSensitive(obj, "text"));
    CHECK(WINPR_JSON_IsTrue(WINPR_JSON_GetObjectItem(obj, "Flag")));
    CHECK(!WINPR_JSON_IsNull(WINPR_JSON_GetObjectItem(obj, "absent")));
    CHECK(WINPR_JSON_IsNull(WINPR_JSON_GetObjectItem(obj, "None")));
    WINPR_JSON_Delete(obj);
    obj = WINPR_JSON_CreateNull();
    CHECK(obj && WINPR_JSON_IsNull(obj));
    char* null_text = WINPR_JSON_PrintUnformatted(obj);
    CHECK(null_text && strcmp(null_text, "null") == 0);
    free(null_text);
    WINPR_JSON_Delete(obj);

    /* Duplicate rejection is a native vendor-parser flag, including nested objects. */
    CHECK(!WINPR_JSON_Parse("{\"k\":1,\"k\":2}"));
    CHECK(!WINPR_JSON_Parse("{\"x\":{\"k\":1,\"k\":2}}"));
    CHECK(!WINPR_JSON_Parse("{\"k\":NaN,\"k\":1}"));
    CHECK(!WINPR_JSON_Parse("{\"k\":1e999,\"k\":1}"));
    obj = WINPR_JSON_Parse("{\"k\":1,\"K\":3}");
    CHECK(obj && WINPR_JSON_GetNumberValue(WINPR_JSON_GetObjectItem(obj, "K")) == 1.0);
    CHECK(WINPR_JSON_GetNumberValue(WINPR_JSON_GetObjectItemCaseSensitive(obj, "K")) == 3.0);
    WINPR_JSON_Delete(obj);

    obj = WINPR_JSON_CreateArray();
    CHECK(obj && WINPR_JSON_AddItemToArray(obj, WINPR_JSON_CreateNull()));
    WINPR_JSON* str = WINPR_JSON_CreateString("\303\251\360\237\230\200\n\t\"\\");
    CHECK(str && WINPR_JSON_AddItemToArray(obj, str));
    CHECK(WINPR_JSON_GetArraySize(obj) == 2);
    CHECK(WINPR_JSON_IsNull(WINPR_JSON_GetArrayItem(obj, 0)));
    char* encoded = WINPR_JSON_PrintUnformatted(obj);
    CHECK(encoded && strlen(encoded) < 512);
    WINPR_JSON* round = WINPR_JSON_ParseWithLength(encoded, strlen(encoded));
    CHECK(round && WINPR_JSON_GetArraySize(round) == 2);
    CHECK(WINPR_JSON_IsNull(WINPR_JSON_GetArrayItem(round, 0)));
    CHECK(strcmp(WINPR_JSON_GetStringValue(WINPR_JSON_GetArrayItem(round, 1)),
                 "\303\251\360\237\230\200\n\t\"\\") == 0);
    free(encoded);
    WINPR_JSON_Delete(obj);
    WINPR_JSON_Delete(round);
    CHECK(!WINPR_JSON_CreateNumber(NAN));
    CHECK(!WINPR_JSON_CreateNumber(INFINITY));
    obj = WINPR_JSON_CreateObject();
    CHECK(obj && !WINPR_JSON_AddNumberToObject(obj, "bad", NAN));
    CHECK(!WINPR_JSON_HasObjectItem(obj, "bad"));
    WINPR_JSON_Delete(obj);

    /* Integer storage/printing is exact even when the public double getter rounds. */
    obj = WINPR_JSON_CreateObject();
    CHECK(obj && WINPR_JSON_AddIntegerToObject(obj, "n", INT64_C(9007199254740993)));
    encoded = WINPR_JSON_PrintUnformatted(obj);
    CHECK(encoded && strstr(encoded, "9007199254740993"));
    free(encoded);
    WINPR_JSON_Delete(obj);
    CHECK(!WINPR_JSON_Parse("{\"x\":"));
    CHECK(!WINPR_JSON_Parse("{]"));
    const char* refused[] = {
        "NaN", "Infinity", "-Infinity", "{\"n\":NaN}", "{\"n\":1e999}",
        "{/*comment*/\"n\":1}", "{\"n\":1} trailing", "{'n':1}", "[1,]",
        "\"\\uD800\"", "\"\\uDC00\"", "\"\\uD800\\u0041\"", "\"\\uDC00\\uD800\"",
        "\"\303\050\"", "\"\300\257\"", "\"\355\240\200\"", "\"\\u0000\"",
        "{\"k\":1,\"\\u006b\":2}", "{\"k\\u0000x\":1}", "9223372036854775808"
    };
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++)
    {
        CHECK(!WINPR_JSON_Parse(refused[i]));
        CHECK(WINPR_JSON_GetErrorPtr()[0] != 0);
    }
    const char nul[] = { '{', '}', 0, 'x' };
    CHECK(!WINPR_JSON_ParseWithLength(nul, sizeof(nul)));
    CHECK(!WINPR_JSON_ParseWithLength("{}", (size_t)INT_MAX + 1));
    CHECK(!WINPR_JSON_Parse(NULL));
    obj = WINPR_JSON_ParseWithLength("17", 2);
    CHECK(obj && WINPR_JSON_GetNumberValue(obj) == 17.0 && WINPR_JSON_GetErrorPtr()[0] == 0);
    WINPR_JSON_Delete(obj);
    obj = WINPR_JSON_Parse("\"\\uD83D\\uDE00\"");
    CHECK(obj && strcmp(WINPR_JSON_GetStringValue(obj), "\360\237\230\200") == 0);
    WINPR_JSON_Delete(obj);
    obj = WINPR_JSON_Parse("\"\\\\uD800\"");
    CHECK(obj && strcmp(WINPR_JSON_GetStringValue(obj), "\\uD800") == 0);
    WINPR_JSON_Delete(obj);
    char deep[8194];
    memset(deep, '[', 4096);
    deep[4096] = '0';
    memset(deep + 4097, ']', 4096);
    deep[8193] = 0;
    CHECK(!WINPR_JSON_Parse(deep));

    /* This is real settings serialization, including the early null-pointer path.
     * No fabricated certificate/key is allocated and no network setup is called. */
    rdpSettings* settings = freerdp_settings_new(0);
    CHECK(settings);
    size_t length = 0;
    encoded = freerdp_settings_serialize(settings, FALSE, &length);
    CHECK(encoded && length > 0 && length < 512 * 1024 && strlen(encoded) == length);
    obj = WINPR_JSON_ParseWithLength(encoded, length);
    CHECK(WINPR_JSON_IsObject(obj));
    WINPR_JSON* pointers = WINPR_JSON_GetObjectItemCaseSensitive(obj,
        freerdp_settings_get_type_name_for_type(RDP_SETTINGS_TYPE_POINTER));
    CHECK(WINPR_JSON_IsObject(pointers));
    const FreeRDP_Settings_Keys_Pointer keys[] = {
        FreeRDP_RedirectionTargetCertificate, FreeRDP_RdpServerCertificate, FreeRDP_RdpServerRsaKey
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
    {
        CHECK(!freerdp_settings_get_pointer(settings, keys[i]));
        WINPR_JSON* array = WINPR_JSON_GetObjectItemCaseSensitive(pointers,
            freerdp_settings_get_name_for_key(keys[i]));
        CHECK(WINPR_JSON_IsArray(array) && WINPR_JSON_GetArraySize(array) == 0);
    }
    WINPR_JSON_Delete(obj);
    free(encoded);
    freerdp_settings_free(settings);
    puts("{\"schema\":\"pamolive.winpr-jansson-regression.v1\",\"passed\":true,\"backend\":\"jansson 2.14\",\"network\":false}");
    return 0;
}
