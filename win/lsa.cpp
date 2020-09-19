/*
 * Copyright (c) 2019 Isaac Boukris <iboukris@gmail.com>
 * See LICENSE file.
 *
 * To build with mingw:
 * $ i686-w64-mingw32-g++ lsa.cpp -static -lsecur32 -o lsa.exe
 */

#define _WIN32_WINNT 0x0600

#include <fstream>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <ntsecapi.h>

#define wcbytes( x ) (wcslen( x )*sizeof(wchar_t))

void usage_exit()
{
    printf("Windows client logon with Kerberos package. usage:\n"
           "lsa -u <user> -p <password> [-d <domain>]     // user-password\n"
           "lsa -u <user> [-d <domain>]                   // S4U2Self\n"
           "lsa -c <certfile> [-u <user>] [-d <domain>]   // S4U2Self certfificate\n");
    exit(0);
}

void lsa_error_exit(const char *lsafn, NTSTATUS status)
{
    ULONG err = LsaNtStatusToWinError(status);
    LPVOID lpMsgBuf;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err,
		  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpMsgBuf,
                  0, NULL );
    printf("%s failed: %s\n", lsafn, lpMsgBuf);
    exit(err);
}

void InitUnicodeString(UNICODE_STRING& str, const wchar_t* src,
                       BYTE* buffer, size_t& offset)
{
    size_t size = wcbytes(src);
    str.Length = str.MaximumLength = (USHORT)size;
    str.Buffer = str.Length == 0 ? NULL : (PWSTR)(buffer + offset);
    memcpy(str.Buffer, src, size);
    offset += size;
}

BYTE* InteractiveAuthInfo(ULONG &authInfoSize, const wchar_t *domain,
                          const wchar_t *user, const wchar_t *password)
{
    authInfoSize = sizeof(KERB_INTERACTIVE_LOGON) + wcbytes(domain)
	                     + wcbytes(user) + wcbytes(password);
    BYTE* authInfoBuf = new BYTE[authInfoSize];
    KERB_INTERACTIVE_LOGON* authInfo = (KERB_INTERACTIVE_LOGON*)authInfoBuf;
    authInfo->MessageType = KerbInteractiveLogon;
    size_t offset = sizeof(KERB_INTERACTIVE_LOGON);
    InitUnicodeString(authInfo->LogonDomainName, domain, authInfoBuf, offset);
    InitUnicodeString(authInfo->UserName, user, authInfoBuf, offset);
    InitUnicodeString(authInfo->Password, password, authInfoBuf, offset);

    return authInfoBuf;
}

BYTE* S4UAuthInfo(ULONG &authInfoSize, const wchar_t *domain, const wchar_t *user)
{
    authInfoSize = sizeof(KERB_S4U_LOGON) + wcbytes(user) + wcbytes(domain);
    BYTE* authInfoBuf = new BYTE[authInfoSize];
    KERB_S4U_LOGON* authInfo = (KERB_S4U_LOGON*)authInfoBuf;
    authInfo->MessageType = KerbS4ULogon;
    authInfo->Flags = 0;
    size_t offset = sizeof(KERB_S4U_LOGON);
    InitUnicodeString(authInfo->ClientUpn, user, authInfoBuf, offset);
    InitUnicodeString(authInfo->ClientRealm, domain, authInfoBuf, offset);

    return authInfoBuf;
}

/* mingw lacks below prototype */
typedef struct _KERB_CERTIFICATE_S4U_LOGON
{
    KERB_LOGON_SUBMIT_TYPE MessageType;
    ULONG                  Flags;
    UNICODE_STRING         UserPrincipalName;
    UNICODE_STRING         DomainName;
    ULONG                  CertificateLength;
    PUCHAR                 Certificate;
}   KERB_CERTIFICATE_S4U_LOGON, *PKERB_CERTIFICATE_S4U_LOGON;

BYTE* CertificateAuthInfo(ULONG &authInfoSize, const wchar_t *domain,
	                  const wchar_t *user, const char *certfile)
{
    std::ifstream ifs(certfile, std::ios::binary|std::ios::ate);
    std::streampos cert_size;
    ifs.seekg(0, std::ios::end);
    cert_size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    authInfoSize = sizeof(KERB_CERTIFICATE_S4U_LOGON) + wcbytes(user) +
	                  wcbytes(domain) + (ULONG) cert_size;
    BYTE* authInfoBuf = new BYTE[authInfoSize];
    KERB_CERTIFICATE_S4U_LOGON* authInfo = (KERB_CERTIFICATE_S4U_LOGON*)authInfoBuf;
    authInfo->MessageType = KerbCertificateS4ULogon;
    authInfo->Flags = 0;
    size_t offset = sizeof(KERB_CERTIFICATE_S4U_LOGON);
    InitUnicodeString(authInfo->UserPrincipalName, user, authInfoBuf, offset);
    InitUnicodeString(authInfo->DomainName, domain, authInfoBuf, offset);

    authInfo->CertificateLength = (ULONG) cert_size;
    authInfo->Certificate = authInfoBuf + offset;
    ifs.read((char*) authInfo->Certificate, cert_size);

    return authInfoBuf;
}

int main(int argc, char* argv[])
{
    const wchar_t* user = L"";
    const wchar_t* password = L"";
    const wchar_t* domain = L"";
    const char* certfile = "";

    LPWSTR *szArglist;
    int nArgs;
    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if( NULL == szArglist ) {
        wprintf(L"CommandLineToArgvW failed\n");
        return 1;
    }

    int i = 1;
    while (i < argc - 1) {
        if (i + 1 >= argc || strlen(argv[i]) != 2 || argv[i][0] != '-')
           usage_exit();

	switch (argv[i][1]) {
            case 'u':
                user = szArglist[i+1];
                break;
            case 'p':
                password  = szArglist[i+1];
                break;
            case 'd':
                domain  = szArglist[i+1];
                break;
            case 'c':
                certfile  = argv[i+1];
                break;
            default:
                usage_exit();
	}
	i += 2;
    }

    ULONG authInfoSize;
    BYTE *authInfo;
    SECURITY_LOGON_TYPE LogonType = Network;

    if (*password && *certfile) {
        usage_exit();
    }
    else if (*user && *password) {
        printf("calling LsaLogonUser with user-password\n");
	authInfo = InteractiveAuthInfo(authInfoSize, domain, user, password);
	LogonType = Interactive;
    }
    else if (*certfile) {
        printf("calling LsaLogonUser with S4U-certificate\n");
	authInfo = CertificateAuthInfo(authInfoSize, domain, user, certfile);
    }
    else if (*user){
        printf("calling LsaLogonUser with S4U\n");
	authInfo = S4UAuthInfo(authInfoSize, domain, user);
    }
    else {
        usage_exit();
    }

    NTSTATUS status;

    // connect to the LSA
    HANDLE lsa;
    status = LsaConnectUntrusted(&lsa);
    if (status != ERROR_SUCCESS)
        lsa_error_exit("LsaConnectUntrusted", status);

    // Kerberos security package
    char packageNameRaw[] = MICROSOFT_KERBEROS_NAME_A;
    LSA_STRING packageName;
    packageName.Buffer = packageNameRaw;
    packageName.Length = packageName.MaximumLength = (USHORT)strlen(packageName.Buffer);
    ULONG packageId;
    status = LsaLookupAuthenticationPackage(lsa, &packageName, &packageId);
    if (status != ERROR_SUCCESS)
        lsa_error_exit("LsaLookupAuthenticationPackage", status);

    // origin and token source
    LSA_STRING origin = {};
    origin.Buffer = _strdup("lsa_origin");
    origin.Length = (USHORT)strlen(origin.Buffer);
    origin.MaximumLength = origin.Length;
    TOKEN_SOURCE source = {};
    strcpy(source.SourceName, "lsa_source");
    if (AllocateLocallyUniqueId(&source.SourceIdentifier) == 0) {
        ULONG err = GetLastError();
        printf("AllocateLocallyUniqueId failed: %x\n", err);
	return (err);
    }

    // LsaLogonUser
    void* profileBuffer;
    DWORD profileBufLen;
    LUID luid;
    HANDLE token;
    QUOTA_LIMITS qlimits;
    NTSTATUS subStatus;
    status = LsaLogonUser(lsa, &origin, LogonType, packageId, authInfo,
                          authInfoSize, 0, &source, &profileBuffer,
                          &profileBufLen, &luid, &token, &qlimits,
                          &subStatus);
    if (status != ERROR_SUCCESS)
        lsa_error_exit("LsaLogonUser", status);

    printf("LsaLogonUser succeeded\n");
    return 0;
}

