/* Actual signed-source hostname helper bodies are supplied by a pinned include.
 * These unsigned in-memory certificate structures test matching, not chain trust.
 */
#include "hostname-helpers.inc"
#include <stdio.h>

static unsigned int cases, passed;

static void check(const char *cn, const char *san, const char *host, int expected)
{
    X509 *cert = X509_new();
    X509_NAME *name;
    X509_EXTENSION *extension;
    int actual;
    cases++;
    if (cert == NULL)
        return;
    name = X509_get_subject_name(cert);
    if (name == NULL || !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                                  (const unsigned char *)cn, -1, -1, 0))
        goto done;
    if (san != NULL) {
        extension = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char *)san);
        if (extension == NULL)
            goto done;
        actual = X509_add_ext(cert, extension, -1);
        X509_EXTENSION_free(extension);
        if (!actual)
            goto done;
    }
    actual = check_cert_name_or_ip(cert, host);
    if (!!actual == !!expected)
        passed++;
done:
    X509_free(cert);
}

int main(void)
{
    check("kdc.example.invalid", NULL, "kdc.example.invalid", 1);
    check("wrong.example.invalid", NULL, "kdc.example.invalid", 0);
    check("*.example.invalid", NULL, "kdc.example.invalid", 1);
    check("*.example.invalid", NULL, "deep.kdc.example.invalid", 0);
    check("kdc*.example.invalid", NULL, "kdc1.example.invalid", 0);
    check("*kdc.example.invalid", NULL, "mykdc.example.invalid", 0);
    check("*.invalid", NULL, "kdc.invalid", 0);
    check("kdc.example.invalid", "DNS:wrong.example.invalid", "kdc.example.invalid", 0);
    check("wrong.example.invalid", "DNS:kdc.example.invalid", "kdc.example.invalid", 1);
    check("wrong.example.invalid", "DNS:kdc*.example.invalid", "kdc1.example.invalid", 0);
    check("wrong", "IP:127.0.0.1", "127.0.0.1", 1);
    check("127.0.0.1", "IP:127.0.0.2", "127.0.0.1", 0);
    printf("{\"cases\":%u,\"passed\":%u,\"certificate_chain_verified\":false}\n", cases, passed);
    return cases == 12 && passed == cases ? 0 : 1;
}
