#include <ctype.h>
#include <stdio.h>

void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}
//#include <stdio.h>
#include <string.h>
//#include <gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#include <string>
#include <vector>
#include <iostream>

#include "cc_store.h"

cc_store::cc_store(const std::string& ccache,
                   const std::string& principal,
                   const std::string& password,
                   const std::string& impersonate_kt) :
                         m_ccache(ccache),
                         m_principal(principal),
                         m_password(password),
                         m_impersonate_kt(impersonate_kt) {}

bool cc_store::init_creds(const std::string& ccache,
                                 const std::string& principal,
                                 const std::string& password,
                                 const std::string& target)
{
    cc_store store(ccache, principal, password, "");
    if (!target.empty())
        return store.init() && store.verify(target);
    return store.init();
}

bool cc_store::impersonate_creds(const std::string& ccache,
                                     const std::string& principal,
                                     const std::string& impersonate_kt,
                                     const std::string& target)
{
    cc_store store(ccache, principal, "", impersonate_kt);
    if (!target.empty())
        return store.init() && store.verify(target);
    return store.init();
}

/* Helper functions */

static void display_error(int type, OM_uint32 code) {
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

/* The below structs are designed to get the size and
 * location of each data type, not to represent the
 * details of the inner data structures
 */

typedef struct _kerb_validation_info_header
{
  unsigned char rpc_headeaders[20];
} kerb_validation_info_header;

typedef struct _rpc_unicode_string_header
{
  unsigned char length[8];
  unsigned char element[4];
} rpc_unicode_string_header;

typedef struct _kerb_validation_info
{
  unsigned char logon_time[8];
  unsigned char logon_off_time[8];
  unsigned char kick_off_time[8];
  unsigned char password_last_set[8];
  unsigned char password_can_change[8];
  unsigned char password_must_change[8];
  unsigned char p_effective_name[8];
  unsigned char p_full_name[8];
  unsigned char p_logon_script[8];
  unsigned char p_profile_path[8];
  unsigned char p_home_directory[8];
  unsigned char p_home_directory_drive[8];
  unsigned char logon_count[2];
  unsigned char bad_password_count[2];
  unsigned char user_id[4];
  unsigned char primary_group_id[4];
  unsigned char group_count[4];
  unsigned char p_group_ids[4];
  unsigned char user_flags[4];
  unsigned char user_session_key[16];
  unsigned char p_logon_server[8];
  unsigned char p_logon_domain_name[8];
  unsigned char p_logon_domain_id[4];
  unsigned char reserved1[8];
  unsigned char user_account_control[4];
  unsigned char reserved2[28];
  unsigned char sid_count[4];
  unsigned char p_extra_sids[4];
  unsigned char p_resource_group_domain_sid[4];
  unsigned char resource_group_count[4];
  unsigned char p_resource_group_ids[4];
} kerb_validation_info;

/* data length of various SID components */
#define SID_REVISION_STR_LEN      3
#define SID_ID_AUTH_STR_LEN       3
#define SID_SUB_AUTH_STR_LEN      10
#define SID_REVISION_LEN          1
#define SID_ID_AUTH_LEN           1
#define SID_SUB_AUTH_LEN          4
#define SID_SUB_AUTH_NUM_LEN      6
#define RELATIVE_SID_TOTAL_LEN    8
#define RELATIVE_SID_LEN          4
#define LOGON_DOMAIN_SID_AUTH_LEN 4
#define EXTRA_SID_HEADER_LEN      4
#define EXTRA_SID_STRUCT_LEN      8
#define EXTRA_SID_AUTH_LEN        4

/* RPC String and other data length */
#define RPC_STRING_LEN            4
#define RPC_STRING_MAX_LEN        8
#define PROFILE_STRING_NUM        6
#define LOGON_STRING_NUM          2
#define GROUP_LEN                 4
#define BIT_NUM_IN_BYTE           8

static unsigned int get_decimal(unsigned int pos,
                                unsigned int len,
                                unsigned char *validation_data)
{
    unsigned int i, j;

    for (i = 0, j = 0; i < len; i++) {
        j += (unsigned int) validation_data[pos + i] << (BIT_NUM_IN_BYTE * i);
    }

    return j;
}

static unsigned int get_rpc_string_buffer_size(int pos, unsigned char *validation_data)
{
    unsigned int ret, actual_elems;

    ret = get_decimal(pos + RPC_STRING_MAX_LEN, RPC_STRING_LEN, validation_data);
    actual_elems = (ret % 2) ? ret + 1 : ret;

    return RPC_STRING_MAX_LEN + RPC_STRING_LEN + actual_elems * 2;
}

static char *get_string_sid(unsigned int pos,
                            unsigned int *sid_pos,
                            unsigned char *validation_data)
{
    unsigned int next_pos;
    unsigned int sub_auth_num;
    unsigned int revision;
    unsigned int identifier_auth;
    unsigned int sub_auth;
    unsigned int i;
    unsigned int len;
    char *sid, *p_sid;
    char sid_header[] = "S-";

    revision = get_decimal(pos, SID_REVISION_LEN, validation_data);
    next_pos = pos + SID_REVISION_LEN;

    sub_auth_num = get_decimal(next_pos, SID_SUB_AUTH_NUM_LEN, validation_data);
    next_pos += SID_SUB_AUTH_NUM_LEN;

    identifier_auth = get_decimal(next_pos, SID_ID_AUTH_LEN, validation_data);
    next_pos += SID_ID_AUTH_LEN;

    len = strlen(sid_header) + SID_REVISION_STR_LEN + strlen("-") +
          SID_ID_AUTH_STR_LEN + strlen("-") +
          SID_SUB_AUTH_STR_LEN * (sub_auth_num + 1) +
          strlen("-") * sub_auth_num + 1;

    sid = new char[len];
    p_sid = sid;

    /* sid is large enough to hold SID components */
    sprintf(p_sid, "%s%u-%u-", sid_header, revision, identifier_auth);
    p_sid = sid + strlen (sid);

    for (i = 0; i < sub_auth_num; i++) {
        sub_auth = get_decimal(next_pos, SID_SUB_AUTH_LEN, validation_data);

        if (i == sub_auth_num - 1)
            sprintf (p_sid, "%u", sub_auth);
        else
            sprintf (p_sid, "%u-", sub_auth);

        p_sid = sid + strlen (sid);
        next_pos += SID_SUB_AUTH_LEN;
    }

    *sid_pos = next_pos;

    return sid;
}

static bool extractSids(gss_buffer_t logonInfo, std::vector<std::string>& userSids)
{
    unsigned int i, j;
    unsigned int group_count;
    unsigned int group_count_pos;
    unsigned int group_pos;
    unsigned int logon_domain_id_pos;
    unsigned int extra_sid_count;
    unsigned int extra_sid_pos;
    unsigned int extra_sid_data_pos;
    unsigned int domain_sid_str_len;
    unsigned int logon_string_pos;
    char *sid;

    kerb_validation_info kerb_info;

    unsigned char *validation_data = (unsigned char*) logonInfo->value;

    group_count_pos = sizeof(kerb_validation_info_header) +
                      &kerb_info.group_count[0] -
                      &kerb_info.logon_time[0];

    group_count = get_decimal(group_count_pos,
                              sizeof(kerb_info.group_count),
                              validation_data);

    extra_sid_count = get_decimal(sizeof(kerb_validation_info_header) +
                                  &kerb_info.sid_count[0] -
                                  &kerb_info.logon_time[0],
                                  sizeof(kerb_info.sid_count),
                                  validation_data);

    for (i = 0, j = 0; i < PROFILE_STRING_NUM; i++)
        j += get_rpc_string_buffer_size(sizeof(kerb_validation_info_header) +
                                        sizeof(kerb_validation_info) + j,
                                        validation_data);

    group_pos = sizeof(kerb_validation_info_header) +
                sizeof(kerb_validation_info) + j;

    for (i = 0, j = group_pos + GROUP_LEN; i < group_count; i++)
        j += RELATIVE_SID_TOTAL_LEN;

    logon_string_pos = j;

    for (i = 0, j = 0; i < LOGON_STRING_NUM; i++)
        j += get_rpc_string_buffer_size(logon_string_pos + j, validation_data);

    logon_domain_id_pos = logon_string_pos + j + LOGON_DOMAIN_SID_AUTH_LEN;

    sid = get_string_sid(logon_domain_id_pos, &extra_sid_pos, validation_data);
    domain_sid_str_len = strlen(sid);

    for (i = 0, j = group_pos + GROUP_LEN; i < group_count; i++) {
        sprintf(sid + domain_sid_str_len, "-%u",
                get_decimal (j, RELATIVE_SID_LEN, validation_data));

        j += RELATIVE_SID_TOTAL_LEN;

        userSids.push_back(std::string(sid));
    }

    if (extra_sid_count) {
        unsigned int next_sid_pos = 0;
        extra_sid_data_pos = extra_sid_pos + EXTRA_SID_HEADER_LEN +
                             EXTRA_SID_STRUCT_LEN * extra_sid_count;

        for (i = 0, j = extra_sid_data_pos + EXTRA_SID_AUTH_LEN; i < extra_sid_count; i++)
        {
            char *str_sid = get_string_sid(j, &next_sid_pos, validation_data);

            j = next_sid_pos + EXTRA_SID_AUTH_LEN;

            userSids.push_back(std::string(str_sid));
        }
    }

    return true;
}

static void display_name(gss_name_t name) {
    OM_uint32 maj, min;
    int name_is_MN;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    gss_buffer_desc output_buffer_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_buffer_oid = GSS_C_EMPTY_BUFFER;
    gss_OID output_oid = GSS_C_NO_OID;

    maj = gss_display_name(&min, name, &output_buffer_name, &output_oid);
    if (GSS_ERROR(maj)) {
        log_error("gss_display_name()", maj, min);
        return;
    }

    std::cerr << "Display name: " << std::string((char *) output_buffer_name.value,
                                     (int) output_buffer_name.length) << std::endl;

    maj = gss_oid_to_str(&min, output_oid, &output_buffer_oid);
    if (GSS_ERROR(maj)) {
        log_error("gss_oid_to_str()", maj, min);
        return;
    }

    std::cerr << "OID string: " << std::string((char *) output_buffer_oid.value,
                                   (int) output_buffer_oid.length) << std::endl;

    maj = gss_inquire_name(&min, name, &name_is_MN, NULL, &attrs);
    if (GSS_ERROR(maj)) {
        log_error("gss_inquire_name()", maj, min);
        return;
    }

    std::cerr << "name_is_MN: " << name_is_MN << std::endl;
    if(attrs == GSS_C_NO_BUFFER_SET) {
        std::cerr << "attrs is null" << std::endl;
        return;
    }

    std::cerr << "attrs->count: " << (int) attrs->count << std::endl;

    if (!attrs->count) {
        std::cerr << "No attributes ... bye" << std::endl;
        return;
    }

    /* display all attributes urns */
    for (int i=0; i < attrs->count; ++i) {
        std::string attr_name((char *) attrs->elements[i].value, (int)  attrs->elements[i].length);
        std::cerr << "attr[" << i << "]: " << attr_name << std::endl;
    }

    /* that's nice and all, but we already know which one we want */
    char urn[] = "urn:mspac:";
    gss_buffer_desc logon_info = { .length = sizeof(urn) -1, .value = urn };

    gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc dvalue = GSS_C_EMPTY_BUFFER;
    int authenticated = 0;
    int complete = 0;
    int more = -1;

    maj = gss_get_name_attribute(&min, name, &logon_info, &authenticated,
                                 &complete, &value, &dvalue, &more);
    if (GSS_ERROR(maj)) {
        log_error("gss_get_name_attribute()", maj, min);
        return;
    }

    std::cerr << "get-attr: authed(" << authenticated << "), complete(" <<
              complete << "), more(" << more << ")" << std::endl;
    /* According to MS-PAC doc, we expect only one buffer here (todo - recheck) */
    if (more || !complete || !authenticated || !value.length) {
        std::cerr << "Something went wrong, plz contact technical support ..." << std::endl;
        return;
    }

    std::cerr << "Logon-info field (len:" << value.length << "):" << std::endl;
    hexdump(value.value, value.length);

    std::vector<std::string> sids;
    if (!extractSids(&value, sids)) {
        std::cerr << "Failed to extract user's SIDs" << std::endl;
        return;
    }

    for (int i = 0; i < sids.size(); ++i)
        std::cerr << "User SIDs [" << i << "]: " << sids[i] << std::endl;

    std::cerr << "End display name" << std::endl;
}

static gss_name_t import_name(const std::string& name) {
    OM_uint32 maj, min;
    gss_name_t gss_name;
    gss_name = GSS_C_NO_NAME;
    gss_buffer_desc buff = GSS_C_EMPTY_BUFFER;

    buff.value = (void*)name.c_str();
    buff.length = name.length();

    // GSS_KRB5_NT_PRINCIPAL_NAME   GSS_C_NT_ENTERPRISE_NAME
    maj = gss_import_name(&min, &buff, GSS_C_NT_USER_NAME, &gss_name);
    if (GSS_ERROR(maj)) {
        log_error("gss_import_name()", maj, min);
        return GSS_C_NO_NAME;
    }

    display_name(gss_name);

    return gss_name;
}

static bool compare_name(gss_name_t desired_name, gss_name_t name) {
    OM_uint32 maj, min;
    int equal = 0;

    maj = gss_compare_name(&min, desired_name, name, &equal);
    if (maj != GSS_S_COMPLETE || !equal) {
        fprintf(stderr, "Names don't match\n");
        return false;
    }

    return equal;
}

static bool inquire_creds_for_name(gss_cred_id_t creds, gss_name_t desired_name)
{

}

static gss_cred_id_t acquire_accept_cred_from_kt(const std::string& kt)
{
    OM_uint32 maj, min;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    gss_key_value_element_desc store_elm = { "keytab", kt.c_str() };
    gss_key_value_set_desc store = { 1, &store_elm };

    maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET, GSS_C_ACCEPT, &store,
                                &creds, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_acquire_cred_from()", maj, min);
        return GSS_C_NO_CREDENTIAL;
    }

    return creds;
}

static gss_cred_id_t acquire_impersonator_cred(const std::string& kt)
{
    OM_uint32 maj, min;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    gss_key_value_element_desc elms[3];
    gss_key_value_set_desc store = { 3, elms };

    elms[0] = { "ccache", "MEMORY:impersonator" };
    elms[1] = { "keytab", kt.c_str() };
    elms[2] = { "client_keytab", kt.c_str() };

    maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET, GSS_C_BOTH, &store,
                                &creds, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_acquire_cred_from()", maj, min);
        return GSS_C_NO_CREDENTIAL;
    }

    return creds;
}

static gss_cred_id_t acquire_cred_from_cache(const std::string& cache)
{
    OM_uint32 maj, min;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    gss_key_value_element_desc store_elm = { "ccache", cache.c_str() };
    gss_key_value_set_desc store = { 1, &store_elm };

    maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                GSS_C_NO_OID_SET, GSS_C_INITIATE, &store,
                                &creds, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_acquire_cred_from()", maj, min);
        return GSS_C_NO_CREDENTIAL;
    }

    return creds;
}

static bool store_creds_into_cache(gss_cred_id_t creds, const std::string& cache)
{
    OM_uint32 maj, min;
    gss_key_value_element_desc store_elm = { "ccache", cache.c_str() };
    gss_key_value_set_desc store = { 1, &store_elm };

    maj = gss_store_cred_into(&min, creds, GSS_C_INITIATE, GSS_C_NO_OID,
                              1, 1, &store, NULL, NULL);
    if (maj != GSS_S_COMPLETE) {
        log_error("gss_store_cred_into()", maj, min);
        return false;
    }

    return true;
}

static gss_cred_id_t acquire_cred_with_password(gss_name_t name, const std::string& pwd)
{
    OM_uint32 maj, min;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc buff = GSS_C_EMPTY_BUFFER;

    buff.value = (void*)pwd.c_str();
    buff.length = pwd.length();

    maj = gss_acquire_cred_with_password(&min, name, &buff, GSS_C_INDEFINITE,
                                         GSS_C_NO_OID_SET, GSS_C_INITIATE,
                                         &creds, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_acquire_cred_with_password()", maj, min);
        return GSS_C_NO_CREDENTIAL;
    }

    return creds;
}

static bool accept_impersonation(const std::string& kt, gss_buffer_t input)
{
    OM_uint32 maj, min;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t client = GSS_C_NO_NAME;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;

    cred = acquire_impersonator_cred(kt);
    if (cred == GSS_C_NO_CREDENTIAL)
        return false;

    maj = gss_accept_sec_context(&min, &ctx, cred, input,
                                 GSS_C_NO_CHANNEL_BINDINGS,
                                 &client, NULL, &output, NULL, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_accept_sec_context()", maj, min);
        return false;
    }

    if (client == GSS_C_NO_NAME) {
        fprintf(stderr, "accept_impersonation() failed to get client name");
        return false;
    }

    display_name(client);

    return true;
}


/* End of helper functions */

bool cc_store::init()
{
    OM_uint32 maj, min, lifetime = 0;
    gss_name_t desired_principal = GSS_C_NO_NAME;
    gss_name_t cache_principal = GSS_C_NO_NAME;
    gss_cred_id_t client_creds = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t impersonator_creds = GSS_C_NO_CREDENTIAL;
    bool success = false;

    desired_principal = import_name(m_principal);
    if (desired_principal == GSS_C_NO_NAME)  {
        fprintf(stderr, "Failed to import principal name\n");
        goto done;  // cannot continue from here
    }
    else {
        fprintf(stderr, "Imported principal name\n");
    }

    /* Try to acquire principal credentials from cache */
    client_creds = acquire_cred_from_cache(m_ccache);
    if (client_creds != GSS_C_NO_CREDENTIAL) {
        fprintf(stderr, "Acquired credentials from cache\n");

        maj = gss_inquire_cred(&min, client_creds, &cache_principal, &lifetime, NULL, NULL);
        if (GSS_ERROR(maj)) {
            log_error("gss_inquire_cred()", maj, min);
        }
        else {
            display_name(cache_principal);
            fprintf(stderr, "Credentials lifetime: %d minutes\n", lifetime / 60);

            if (compare_name(desired_principal, cache_principal) && lifetime > 300) {
                /* We are done here */
                success = true;
                goto done;
            }
        }

        fprintf(stderr, "Cache crdentials are unusable\n");
        gss_release_cred(&min, &client_creds);
        client_creds = GSS_C_NO_CREDENTIAL;
    }
    else {
        fprintf(stderr, "Failed to acquire credentials from cache.\n");
    }

    if (!m_password.empty()) {
        /* Save old ccache to be restored after acquiring credentials (threadsafe) */
        const char *orig_ccache = NULL;
        maj = gss_krb5_ccache_name(&min, m_ccache.c_str(), &orig_ccache);
        if (GSS_ERROR(maj)) {
            fprintf(stderr, "Failed to set client credential cache\n");
            goto done;
        }

        /* Try to acquire credentials with principal's password */
        client_creds = acquire_cred_with_password(desired_principal, m_password);

        /* First, restore old default cache  */
        maj = gss_krb5_ccache_name(&min, orig_ccache, NULL);
        if (GSS_ERROR(maj)) {
            fprintf(stderr, "Failed to restore client credential cache\n");
            goto done;
        }

        if (client_creds == GSS_C_NO_CREDENTIAL) {
            fprintf(stderr, "Failed to acquire credentials with password\n");
            goto done;
        }

        maj = gss_inquire_cred(&min, client_creds, &cache_principal, &lifetime, NULL, NULL);
        if (GSS_ERROR(maj)) {
            log_error("gss_inquire_cred()", maj, min);
        }
        else {
            fprintf(stderr, "Name from inquired creds:\n");
            display_name(cache_principal);
        }

        /* This is necessary for KRB >= 14 as its stores the creds in memory ccache */
        if (!store_creds_into_cache(client_creds, m_ccache)) {
            fprintf(stderr, "Failed to store credentials in cache\n");
            goto done;
        }

        fprintf(stderr, "Acquired credentials with password\n");
    }
    else if (!m_impersonate_kt.empty()) {
        /* Try to acquire credentials via impersonation */
        impersonator_creds = acquire_impersonator_cred(m_impersonate_kt);
        if (impersonator_creds == GSS_C_NO_CREDENTIAL) {
            fprintf(stderr, "Failed to acquire impersonator credentials.\n");
            goto done;
        }

        display_name(desired_principal);

        maj = gss_acquire_cred_impersonate_name(&min, impersonator_creds, desired_principal,
                                                GSS_C_INDEFINITE, GSS_C_NO_OID_SET,
                                                GSS_C_INITIATE, &client_creds, NULL, NULL);
        if (GSS_ERROR(maj)) {
            log_error("gss_acquire_cred_impersonate_name()", maj, min);
            goto done;
        }

        if (!store_creds_into_cache(client_creds, m_ccache)) {
            fprintf(stderr, "Failed to store credentials in cache\n");
            goto done;
        }

        fprintf(stderr, "Acquired credentials via impersonation\n");
    }
    else {
        fprintf(stderr, "Cannot acquire credentials - no password and no impersonator\n");
        goto done;
    }

    fprintf(stderr, "Successfully acquired credentials and stored in cache\n");
    success = true;

done:

    if (desired_principal != GSS_C_NO_NAME)
        gss_release_name(&min, &desired_principal);

    if (cache_principal != GSS_C_NO_NAME)
        gss_release_name(&min, &cache_principal);

    if (client_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &client_creds);

    if (impersonator_creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &impersonator_creds);

    return success;
}

bool cc_store::verify(const std::string& target)
{
    OM_uint32 maj, min;
    gss_name_t service_name = GSS_C_NO_NAME;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    bool success = false;
    gss_buffer_desc buff = GSS_C_EMPTY_BUFFER;

    buff.value = (void*)target.c_str();
    buff.length = target.length();

    maj = gss_import_name(&min, &buff, /*GSS_C_NT_HOSTBASED_SERVICE - TEMP*/
                          GSS_C_NT_USER_NAME, &service_name);
    if (GSS_ERROR(maj)) {
        log_error("gss_import_name()", maj, min);
        return false;
    }

    creds = acquire_cred_from_cache(m_ccache);
    if (creds == GSS_C_NO_CREDENTIAL) {
        fprintf(stderr, "Failed to acquire credentials from cache\n");
        goto done;
    }

    maj = gss_init_sec_context(&min, creds, &context, service_name, GSS_C_NO_OID,
                               GSS_C_REPLAY_FLAG, 0, GSS_C_NO_CHANNEL_BINDINGS,
                               GSS_C_NO_BUFFER, NULL, &output_token, NULL, NULL);
    if (GSS_ERROR(maj)) {
        log_error("gss_init_sec_context", maj, min);
        goto done;
    }

    if (maj != GSS_S_COMPLETE) {
        fprintf(stderr, "gss_init_sec_context did not complete %d", maj);
        goto done;
    }

    fprintf(stderr, "Security context successfully initiated to %s\n", target.c_str());

    if (accept_impersonation(m_impersonate_kt, &output_token))
        fprintf(stderr, "Initial creds were accepted by the service\n");

    success = true;

done:

    if (service_name != GSS_C_NO_NAME)
        gss_release_name(&min, &service_name);

    if (creds != GSS_C_NO_CREDENTIAL)
        gss_release_cred(&min, &creds);

    if (context != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&min, &context, GSS_C_NO_BUFFER);

    if (output_token.value && output_token.length)
        gss_release_buffer(&min, &output_token);

    return success;
}
