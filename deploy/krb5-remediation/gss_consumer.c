#define _GNU_SOURCE
#include <dlfcn.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>
#include <stdio.h>
#include <string.h>

/* Only synthetic credentials and the caller's closed loopback krb5.conf. */
int main(int argc, char **argv)
{
    OM_uint32 major, minor;
    gss_name_t name = GSS_C_NO_NAME;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc principal = {24, "synthetic@PAMOLIVE.INVALID"};
    gss_buffer_desc password = {18, "synthetic-password"};
    Dl_info gss_provider, krb_provider;
    int present = 0;
    if (argc != 2 || (strcmp(argv[1], "mechanisms") && strcmp(argv[1], "silent-kdc")))
        return 64;
    if (!dladdr((void *)gss_indicate_mechs, &gss_provider) ||
        !dladdr((void *)krb5_init_context, &krb_provider))
        return 65;
    major = gss_indicate_mechs(&minor, &mechs);
    if (major != GSS_S_COMPLETE || mechs == GSS_C_NO_OID_SET || mechs->count == 0)
        return 66;
    major = gss_test_oid_set_member(&minor, gss_mech_krb5, mechs, &present);
    if (major != GSS_S_COMPLETE || !present)
        return 69;
    gss_release_oid_set(&minor, &mechs);
    printf("{\"gss_provider\":\"%s\",\"krb5_provider\":\"%s\",",
           gss_provider.dli_fname, krb_provider.dli_fname);
    if (!strcmp(argv[1], "mechanisms")) {
        puts("\"mechanisms_enumerated\":true,\"kerberos_mechanism_present\":true}");
        return 0;
    }
    principal.length = strlen(principal.value);
    major = gss_import_name(&minor, &principal, GSS_C_NT_USER_NAME, &name);
    if (major != GSS_S_COMPLETE)
        return 67;
    major = gss_create_empty_oid_set(&minor, &mechs);
    if (major != GSS_S_COMPLETE ||
        gss_add_oid_set_member(&minor, gss_mech_krb5, &mechs) != GSS_S_COMPLETE)
        return 70;
    major = gss_acquire_cred_with_password(&minor, name, &password, 0,
                                         mechs, GSS_C_INITIATE,
                                         &cred, NULL, NULL);
    gss_release_oid_set(&minor, &mechs);
    gss_release_name(&minor, &name);
    if (cred != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&minor, &cred);
    printf("\"synthetic_acquire_failed\":%s}\n", GSS_ERROR(major) ? "true" : "false");
    return GSS_ERROR(major) ? 0 : 68;
}
