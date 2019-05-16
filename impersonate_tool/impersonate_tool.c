#include <stdio.h>
#include <string.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

static void display_error(int type, OM_uint32 code)
{
    OM_uint32 maj, min, ctx = 0;
    gss_buffer_desc status;

    do {
        maj = gss_display_status(
                   &min,
                   code,
                   type,
                   GSS_C_NO_OID,
                   &ctx,
                   &status);
        fprintf(stderr, "%.*s\n", (int)status.length, (char *)status.value);
        gss_release_buffer(&min, &status);
    } while (ctx != 0);
}

static void log_error(const char *fn, uint32_t maj, uint32_t min)
{
    fprintf(stderr, "%s: ", fn);
    display_error(GSS_C_GSS_CODE, maj);
    display_error(GSS_C_MECH_CODE, min);
}

static gss_name_t import_name(const char *name)
{
    OM_uint32 maj, min;
    gss_name_t gss_name;
    gss_name = GSS_C_NO_NAME;
    gss_buffer_desc buff = GSS_C_EMPTY_BUFFER;

    buff.value = (void*)name;
    buff.length = strlen(name);

    maj = gss_import_name(&min, &buff, GSS_C_NT_USER_NAME, &gss_name);
    if (GSS_ERROR(maj)) {
        log_error("gss_import_name()", maj, min);
        return GSS_C_NO_NAME;
    }

    return gss_name;
}

static bool store_creds_into_cache(gss_cred_id_t creds, const char *cache)
{
    OM_uint32 maj, min;
    gss_key_value_element_desc store_elm = { "ccache", cache };
    gss_key_value_set_desc store = { 1, &store_elm };

    maj = gss_store_cred_into(&min, creds, GSS_C_INITIATE, GSS_C_NO_OID,
                              1, 1, &store, NULL, NULL);
    if (maj != GSS_S_COMPLETE) {
        log_error("gss_store_cred_into()", maj, min);
        return false;
    }

    return true;
}

static bool impersonate(const char *name, const char *cache)
{
    OM_uint32 maj, min;
    gss_name_t desired_principal = GSS_C_NO_NAME;
    gss_cred_id_t client_creds = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t service_creds = GSS_C_NO_CREDENTIAL;
    bool success = false;

    desired_principal = import_name(name);
    if (desired_principal== GSS_C_NO_NAME)
        return false;

    maj = gss_acquire_cred(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                           GSS_C_NO_OID_SET, GSS_C_INITIATE,
                           &service_creds, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_acquire_cred_from()", maj, min);
        goto done;
    }

    maj = gss_acquire_cred_impersonate_name(&min, service_creds, desired_principal,
                                            GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                            GSS_C_INITIATE, &client_creds, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_acquire_cred_impersonate_name()", maj, min);
        goto done;
    }

    if (!store_creds_into_cache(client_creds, cache)) {
        fprintf(stderr, "Failed to store credentials in cache\n");
        goto done;
    }

    fprintf(stderr, "Acquired credentials for %s\n", name);

    success = true;

done:

    if (desired_principal != GSS_C_NO_NAME)
        gss_release_name(&min, &desired_principal);

    if (client_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &client_creds);

    if (service_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &client_creds);

    return success;
}


int main (int argc, char* argv[])
{
    if (argc  != 3) {
        fprintf(stderr, "Usage: %s user@realm out_cache\n", argv[0]);
        return 1;
    }

    if (!impersonate(argv[1], argv[2]))
        return 1;

    return 0;
}
