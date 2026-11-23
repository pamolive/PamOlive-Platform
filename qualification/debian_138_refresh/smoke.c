#define _GNU_SOURCE
#include <gnu/libc-version.h>
#include <gssapi/gssapi.h>
#include <krb5.h>
#include <link.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct mappings {
    const char *paths[6];
    unsigned int seen;
};

static int inspect(struct dl_phdr_info *image, size_t size, void *data)
{
    struct mappings *mapped = data;
    char resolved[PATH_MAX];
    unsigned int i;

    (void)size;
    if (!image->dlpi_name || image->dlpi_name[0] != '/' ||
        !realpath(image->dlpi_name, resolved))
        return 0;
    for (i = 0; i < 6; i++)
        if (strcmp(mapped->paths[i], resolved) == 0)
            mapped->seen |= 1U << i;
    return 0;
}

int main(int argc, char **argv)
{
    krb5_context context = NULL;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    OM_uint32 minor;
    struct mappings mapped = { .seen = 0 };
    unsigned int i;

    if (argc != 7 || strcmp(gnu_get_libc_version(), "2.41") != 0)
        return 1;
    for (i = 0; i < 6; i++)
        mapped.paths[i] = argv[i + 1];
    if (krb5_init_context(&context) != 0 || context == NULL)
        return 2;
    krb5_free_context(context);
    if (gss_indicate_mechs(&minor, &mechs) != GSS_S_COMPLETE)
        return 3;
    if (mechs == GSS_C_NO_OID_SET || !mechs->count)
        return 4;
    if (gss_release_oid_set(&minor, &mechs) != GSS_S_COMPLETE)
        return 5;
    if (dl_iterate_phdr(inspect, &mapped) != 0 || mapped.seen != 63U)
        return 6;
    return puts("debian-138-native-ok") < 0;
}
