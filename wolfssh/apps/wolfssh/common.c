/* common.c
 *
 * Copyright (C) 2014-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#define WOLFSSH_TEST_CLIENT

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/port.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/coding.h>
#include "apps/wolfssh/common.h"
#ifndef USE_WINDOWS_API
    #include <termios.h>
#endif

#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/asn.h>
    #include <wolfssl/wolfcrypt/asn_public.h>
#endif

static byte userPublicKeyBuf[512];
static byte* userPublicKey = userPublicKeyBuf;
static const byte* userPublicKeyType = NULL;
static byte userPassword[256];
static const byte* userPrivateKeyType = NULL;
static byte userPublicKeyAlloc = 0;
static word32 userPublicKeySz = 0;
static byte pubKeyLoaded = 0; /* was a public key loaded */
static byte userPrivateKeyBuf[1191];
static byte* userPrivateKey = userPrivateKeyBuf;
static byte userPrivateKeyAlloc = 0;
static word32 userPublicKeyTypeSz = 0;
static word32 userPrivateKeySz = sizeof(userPrivateKeyBuf);
static word32 userPrivateKeyTypeSz = 0;
static byte isPrivate = 0;


#ifdef WOLFSSH_CERTS
#if 0
/* compiled in for using RSA certificates instead of ECC certificate */
static const byte publicKeyType[] = "x509v3-ssh-rsa";
static const byte privateKeyType[] = "ssh-rsa";
#else
static const byte publicKeyType[] = "x509v3-ecdsa-sha2-nistp256";
#endif
#endif


static inline void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}

const char* ClientGetHomeDir(void)
{
    const char* home = NULL;

#ifdef USE_WINDOWS_API
    home = getenv("USERPROFILE");
    if (home == NULL)
        home = getenv("HOME");
#else
    home = getenv("HOME");
#endif

    return home;
}


static int ClientEnsureParentDir(const char* fileName)
{
    char* dirName = NULL;
    char* lastSlash;
    size_t fileNameSz;

    if (fileName == NULL)
        return -1;

    fileNameSz = WSTRLEN(fileName);
    dirName = (char*)WMALLOC(fileNameSz + 1, NULL, 0);
    if (dirName == NULL)
        return -1;

    WSTRCPY(dirName, fileName);
    lastSlash = strrchr(dirName, '/');
#ifdef USE_WINDOWS_API
    {
        char* lastBackSlash = strrchr(dirName, '\\');

        if (lastBackSlash != NULL &&
                (lastSlash == NULL || lastBackSlash > lastSlash)) {
            lastSlash = lastBackSlash;
        }
    }
#endif

    if (lastSlash != NULL) {
        *lastSlash = '\0';
        if (dirName[0] != '\0')
            (void)WMKDIR(NULL, dirName, 0700);
    }

    WFREE(dirName, NULL, 0);
    return 0;
}


static void ClientTrimTrailingCR(char* text)
{
    size_t len;

    if (text == NULL)
        return;

    len = WSTRLEN(text);
    if (len > 0 && text[len - 1] == '\r')
        text[len - 1] = '\0';
}


static int load_der_file(const char* filename, byte** out, word32* outSz)
{
    WFILE* file;
    byte* in;
    long inSz;
    int ret;

    if (filename == NULL || out == NULL || outSz == NULL)
        return -1;

    ret = WFOPEN(NULL, &file, filename, "rb");
    if (ret != 0 || file == WBADFILE)
        return -1;

    if (WFSEEK(NULL, file, 0, WSEEK_END) != 0) {
        WFCLOSE(NULL, file);
        return -1;
    }
    inSz = WFTELL(NULL, file);
    WREWIND(NULL, file);

    if (inSz <= 0) {
        WFCLOSE(NULL, file);
        return -1;
    }

    in = (byte*)WMALLOC(inSz, NULL, 0);
    if (in == NULL) {
        WFCLOSE(NULL, file);
        return -1;
    }

    ret = (int)WFREAD(NULL, in, 1, inSz, file);
    if (ret <= 0 || ret != inSz) {
        ret = -1;
        WFREE(in, NULL, 0);
        in = 0;
        inSz = 0;
    }
    else
        ret = 0;

    *out = in;
    *outSz = (word32)inSz;

    WFCLOSE(NULL, file);

    return ret;
}


#if defined(WOLFSSH_CERTS)

#if (defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME))
/* when set as true then ignore miss matching IP addresses */
static int IPOverride = 0;

static int ParseRFC6187(const byte* in, word32 inSz, byte** leafOut,
    word32* leafOutSz)
{
    int ret = WS_SUCCESS;
    word32 l = 0, m = 0;

    if (inSz < sizeof(word32)) {
        printf("inSz %d too small for holding cert name\n", inSz);
        return WS_BUFFER_E;
    }

    /* Skip the name */
    ato32(in, &l);
    m += l + sizeof(word32);

    /* Get the cert count */
    if (ret == WS_SUCCESS) {
        word32 count;

        if (inSz - m < sizeof(word32))
            return WS_BUFFER_E;

        ato32(in + m, &count);
        m += sizeof(word32);
        if (ret == WS_SUCCESS && count == 0)
            ret = WS_FATAL_ERROR; /* need at least one cert */
    }

    if (ret == WS_SUCCESS) {
        word32 certSz = 0;

        if (inSz - m < sizeof(word32))
            return WS_BUFFER_E;

        ato32(in + m, &certSz);
        m += sizeof(word32);
        if (ret == WS_SUCCESS) {
            /* store leaf cert size to present to user callback */
            *leafOutSz = certSz;
            *leafOut   = (byte*)in + m;
        }

        if (inSz - m < certSz)
            return WS_BUFFER_E;

   }

    return ret;
}

void ClientIPOverride(int flag)
{
    IPOverride = flag;
}
#endif /* OPENSSL_ALL || WOLFSSL_IP_ALT_NAME */
#endif /* WOLFSSH_CERTS */


static int AppendKeyToFile(const char* filename, const char* name,
        const char* type, const char* key)
{
    WFILE *f;
    int ret;

    ret = WFOPEN(NULL, &f, filename, "a");
    if (ret == 0 && f != WBADFILE) {
        fprintf(f, "%s %s %s\n", name, type, key);
        WFCLOSE(NULL, f);
    }

    return ret;
}


static int FingerprintKey(const byte* pubKey, word32 pubKeySz, char* out)
{
    wc_Sha256 sha;
    byte digest[WC_SHA256_DIGEST_SIZE];
    char fp[48] = { 0 };
    word32 fpSz = sizeof(fp);
    int ret;

    ret = wc_InitSha256(&sha);
    if (ret == 0) {
        ret = wc_Sha256Update(&sha, pubKey, pubKeySz);
        if (ret == 0)
            ret = wc_Sha256Final(&sha, digest);
        wc_Sha256Free(&sha);
    }

    if (ret == 0)
        ret = Base64_Encode_NoNl(digest, sizeof(digest), (byte*)fp, &fpSz);

    if (ret == 0) {
        if (fp[fpSz] == '=') {
            fp[fpSz] = 0;
        }

        WSTRCAT(out, "SHA256:");
        WSTRCAT(out, fp);
    }

    return ret;
}


static int GetConfirmation(void)
{
    int c, confirmed = 0;

    printf("Y/n: ");
    c = getchar();

    if (c == 'Y') {
        confirmed = 1;
    }

    return confirmed;
}


#define WOLFSSH_CLIENT_ENCKEY_SIZE_ESTIMATE 1200
#define WOLFSSH_CLIENT_PUBKEYTYPE_SIZE_ESTIMATE 54
#define WOLFSSH_CLIENT_FINGERPRINT_SIZE_ESTIMATE 56

int ClientPublicKeyCheck(const byte* pubKey, word32 pubKeySz, void* ctx)
{
    char *cursor;
    char *line;
    const char *targetName = (const char*)ctx;
    char *name;
    char *keyType;
    char *key;
    char *knownHosts = NULL;
    char *knownHostsName = NULL;
    char *encodedKey = NULL;
    char *pubKeyType = NULL;
    char *fp = NULL;
    int ret = 0, found = 0, badMatch = 0, otherMatch = 0;
    word32 sz, lineCount = 0;

    {
        const char *defaultName = "/.ssh/known_hosts";
        const char *env;

        env = ClientGetHomeDir();
        if (env != NULL) {
            sz = (word32)(WSTRLEN(env) + WSTRLEN(defaultName) + 1);
            knownHostsName = (char*)WMALLOC(sz, NULL, 0);
            if (knownHostsName != NULL) {
                WSTRCPY(knownHostsName, env);
                WSTRCAT(knownHostsName, defaultName);
                (void)ClientEnsureParentDir(knownHostsName);
            }
        }
        else
            ret = -1;
    }

    if (ret == 0) {
        sz = 0;
        ret = load_der_file(knownHostsName, (byte**)&knownHosts, &sz);
    }

    if (ret == 0) {
        if (sz < sizeof(word32)) {
            /* This file is too small. There must be at least a word32
             * length size. */
            ret = -1;
        }
    }

    if (ret == 0) {
        /* load_der_file() loads exactly what's in the file. Since it is
         * NL terminated lines of known host data, and the last line ends
         * in a NL, overwrite that with a nul to terminate the new string. */
        knownHosts[sz - 1] = 0;

        encodedKey = (char*)WMALLOC(WOLFSSH_CLIENT_ENCKEY_SIZE_ESTIMATE
                + WOLFSSH_CLIENT_PUBKEYTYPE_SIZE_ESTIMATE
                + WOLFSSH_CLIENT_FINGERPRINT_SIZE_ESTIMATE, NULL, 0);
        if (encodedKey == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        pubKeyType = encodedKey + WOLFSSH_CLIENT_ENCKEY_SIZE_ESTIMATE;
        fp = pubKeyType + WOLFSSH_CLIENT_PUBKEYTYPE_SIZE_ESTIMATE;

        encodedKey[0] = 0;
        pubKeyType[0] = 0;
        fp[0] = 0;

        /* Get the key type out of the key. */
        ato32(pubKey, &sz);
        if ((sz > pubKeySz - sizeof(word32))
                    || (sz > WOLFSSH_CLIENT_PUBKEYTYPE_SIZE_ESTIMATE - 1)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        WMEMCPY(pubKeyType, pubKey + LENGTH_SZ, sz);
        pubKeyType[sz] = 0;

        sz = WOLFSSH_CLIENT_ENCKEY_SIZE_ESTIMATE;
        ret = Base64_Encode_NoNl(pubKey, pubKeySz, (byte*)encodedKey, &sz);
    }

    if (ret == 0)
        ret = FingerprintKey(pubKey, pubKeySz, fp);

    cursor = (ret == 0) ? knownHosts : NULL;

    {
        char* lineContext = NULL;

        while ((line = WSTRTOK(cursor, "\n", &lineContext)) != NULL) {
            cursor = NULL; /* subsequent calls pass NULL */
            lineCount++;
            if (*line == '\0')
                continue;

            ClientTrimTrailingCR(line);

            {
                char* fieldContext = NULL;
                name = WSTRTOK(line, " ", &fieldContext);
                keyType = WSTRTOK(NULL, " ", &fieldContext);
                key = WSTRTOK(NULL, " ", &fieldContext);
                if (name && keyType && key) {
                    ClientTrimTrailingCR(name);
                    ClientTrimTrailingCR(keyType);
                    ClientTrimTrailingCR(key);

                    int nameMatch, keyTypeMatch, keyMatch;

                    nameMatch = WSTRCMP(targetName , name) == 0;
                    keyTypeMatch = WSTRCMP(pubKeyType, keyType) == 0;
                    keyMatch = WSTRCMP(encodedKey, key) == 0;

                    if (nameMatch) {
                        if (keyTypeMatch) {
                            if (keyMatch) {
                                found = 1;
                            }
                            else {
                                badMatch = 1;
                                break;
                            }
                        }
                    }
                    else if (!found) {
                        if (keyTypeMatch && keyMatch) {
                            /* report key used on different address */
                            if (!otherMatch) {
                                otherMatch = 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if (ret == 0) {
        if (badMatch) {
            printf("That server is known, but that key is not.\n");
            printf("Rejecting connection and closing.\n");
            ret = -1;
        }
        else if (otherMatch) {
            if (!found) {
                printf("The key is unknown but matches other servers.\n");
                printf("Fingerprint: %s\n", fp);
                printf("Shall I add it to the known hosts?\n");
                /* Query. */
                if (GetConfirmation()) {
                    ret = AppendKeyToFile(knownHostsName,
                            targetName, pubKeyType, encodedKey);
                }
                else {
                    ret = -1;
                }
            }
            /* found && otherMatch: target host known and key matches, silent */
        }
        else if (!found) {
            printf("The server is unknown and the key is unknown.\n");
            printf("Fingerprint: %s\n", fp);
            printf("Shall I add it to the known hosts?\n");
            /* Query. */
            if (GetConfirmation()) {
                ret = AppendKeyToFile(knownHostsName,
                        targetName, pubKeyType, encodedKey);
            }
        }
    }

#ifdef WOLFSSH_CERTS
#if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
    /* try to parse the certificate and check it's IP address */
    if (pubKeySz > 0) {
        DecodedCert dCert;
        byte*  der   = NULL;
        word32 derSz = 0;

        if (ParseRFC6187(pubKey, pubKeySz, &der, &derSz) == WS_SUCCESS) {
            wc_InitDecodedCert(&dCert, der,  derSz, NULL);
            if (wc_ParseCert(&dCert, CERT_TYPE, NO_VERIFY, NULL) != 0) {
                WLOG(WS_LOG_DEBUG, "public key not a cert");
            }
            else {
                int ipMatch = 0;
                DNS_entry* current = dCert.altNames;

                if (ctx == NULL) {
                    WLOG(WS_LOG_ERROR, "No host IP set to check against!");
                    ret = -1;
                }

                if (ret == 0) {
                    while (current != NULL) {
                        if (current->type == ASN_IP_TYPE) {
                            WLOG(WS_LOG_DEBUG, "host cert alt. name IP : %s",
                                current->ipString);
                            WLOG(WS_LOG_DEBUG,
                                "\texpecting host IP : %s", (char*)ctx);
                            if (XSTRCMP((const char*)ctx,
                                        current->ipString) == 0) {
                                WLOG(WS_LOG_DEBUG, "\tmatched!");
                                ipMatch = 1;
                            }
                        }
                        current = current->next;
                    }
                }

                if (ipMatch == 0) {
                    printf("IP did not match expected IP");
                    if (!IPOverride) {
                        printf("\n");
                        ret = -1;
                    }
                    else {
                        ret = 0;
                        printf("..overriding\n");
                    }
                }
            }
            wc_FreeDecodedCert(&dCert);
        }
    }
#else
    WLOG(WS_LOG_DEBUG, "wolfSSL not built with OPENSSL_ALL or WOLFSSL_IP_ALT_NAME");
    WLOG(WS_LOG_DEBUG, "\tnot checking IP address from peer's cert");
#endif
#endif

    if (encodedKey)
        WFREE(encodedKey, NULL, 0);
    if (knownHosts)
        WFREE(knownHosts, NULL, 0);
    if (knownHostsName)
        WFREE(knownHostsName, NULL, 0);

    return ret;
}


int ClientUserAuth(byte authType,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    int ret = WOLFSSH_USERAUTH_SUCCESS;

    WOLFSSH_UNUSED(ctx);

#ifdef DEBUG_WOLFSSH
    /* inspect supported types from server */
    printf("Server supports:\n");
    if (authData->type & WOLFSSH_USERAUTH_PASSWORD) {
        printf(" - password\n");
    }
    if (authData->type & WOLFSSH_USERAUTH_PUBLICKEY) {
        printf(" - publickey\n");
    }
    printf("wolfSSH requesting to use type %d\n", authType);
#endif

    /* Wait for request of public key on names known to have one */
    if ((authData->type & WOLFSSH_USERAUTH_PUBLICKEY) &&
            authData->username != NULL &&
            authData->usernameSz > 0) {

        /* in the case that the user passed in a public key file,
         * use public key auth */
        if (pubKeyLoaded == 1) {
            if (authType == WOLFSSH_USERAUTH_PASSWORD) {
                return WOLFSSH_USERAUTH_FAILURE;
            }
        }
    }

    if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        WS_UserAuthData_PublicKey* pk = &authData->sf.publicKey;

        pk->publicKeyType = userPublicKeyType;
        pk->publicKeyTypeSz = userPublicKeyTypeSz;
        pk->publicKey = userPublicKey;
        pk->publicKeySz = userPublicKeySz;
        pk->privateKey = userPrivateKey;
        pk->privateKeySz = userPrivateKeySz;

        ret = WOLFSSH_USERAUTH_SUCCESS;
    }
    else if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        printf("Password: ");
        fflush(stdout);
        ClientSetEcho(0);
        if (fgets((char*)userPassword, sizeof(userPassword), stdin) == NULL) {
            fprintf(stderr, "Getting password failed.\n");
            ret = WOLFSSH_USERAUTH_FAILURE;
        }
        else {
            char* c = strpbrk((char*)userPassword, "\r\n");
            if (c != NULL)
                *c = '\0';
        }
        ClientSetEcho(1);
        #ifdef USE_WINDOWS_API
            printf("\r\n");
        #endif
        fflush(stdout);

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            authData->sf.password.password = userPassword;
            authData->sf.password.passwordSz =
                (word32)strlen((const char*)userPassword);
        }
    }

    return ret;
}


/* type = 2 : shell / execute command settings
 * type = 0 : password
 * type = 1 : restore default
 * return 0 on success */
int ClientSetEcho(int type)
{
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    static int echoInit = 0;
    static struct termios originalTerm;

    if (!echoInit) {
        if (tcgetattr(STDIN_FILENO, &originalTerm) != 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (type == 1) {
        if (tcsetattr(STDIN_FILENO, TCSANOW, &originalTerm) != 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else {
        struct termios newTerm;
        memcpy(&newTerm, &originalTerm, sizeof(struct termios));

        newTerm.c_lflag &= ~ECHO;
        if (type == 2) {
            newTerm.c_lflag &= ~(ICANON | ECHOE | ECHOK | ECHONL | ISIG);
        }
        else {
            newTerm.c_lflag |= ICANON;
        }

        if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#else
    static int echoInit = 0;
    static DWORD originalTerm;
    static CONSOLE_SCREEN_BUFFER_INFO screenOrig;
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (!echoInit) {
        if (GetConsoleMode(stdinHandle, &originalTerm) == 0) {
            printf("Couldn't get the original terminal settings.\n");
            return -1;
        }
        echoInit = 1;
    }
    if (type == 1) {
        if (SetConsoleMode(stdinHandle, originalTerm) == 0) {
            printf("Couldn't restore the terminal settings.\n");
            return -1;
        }
    }
    else if (type == 2) {
        DWORD newTerm = originalTerm;

        newTerm &= ~ENABLE_PROCESSED_INPUT;
        newTerm &= ~ENABLE_PROCESSED_OUTPUT;
        newTerm &= ~ENABLE_LINE_INPUT;
        newTerm &= ~ENABLE_ECHO_INPUT;
        newTerm &= ~(ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE);

        if (SetConsoleMode(stdinHandle, newTerm) == 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
    else {
        DWORD newTerm = originalTerm;

        newTerm &= ~ENABLE_ECHO_INPUT;

        if (SetConsoleMode(stdinHandle, newTerm) == 0) {
            printf("Couldn't turn off echo.\n");
            return -1;
        }
    }
#endif

    return 0;
}


/* Set certificate to use and public key.
 * Supports both DER and PEM format (including cert chains in PEM).
 * returns 0 on success */
int ClientUseCert(const char* certName)
{
    int ret = 0;

    if (certName != NULL) {
    #ifdef WOLFSSH_CERTS
        byte* raw = NULL;
        word32 rawSz = 0;

        ret = load_der_file(certName, &raw, &rawSz);
        if (ret == 0) {
            const char* pemHeader = "-----BEGIN CERTIFICATE-----";
            int beginLen = (int)WSTRLEN(pemHeader);

            if (rawSz > (word32)beginLen &&
                WSTRNSTR((const char*)raw, pemHeader, rawSz) != NULL) {
                /* PEM format: convert each cert block to DER and
                 * concatenate into a single buffer */
                byte* combined = NULL;
                word32 combinedSz = 0;
                word32 certCount = 0;
                const char* p = (const char*)raw;
                const char* end = (const char*)raw + rawSz;

                while (p < end) {
                    const char* begin = WSTRNSTR(p, pemHeader, (word32)(end - p));
                    if (begin == NULL)
                        break;

                    /* Find the end marker */
                    const char* endMarker = "-----END CERTIFICATE-----";
                    const char* blockEnd = WSTRNSTR(begin, endMarker,
                                                    (word32)(end - begin));
                    if (blockEnd == NULL)
                        break;
                    blockEnd += WSTRLEN(endMarker);
                    /* skip newline after end marker */
                    while (blockEnd < end &&
                           (*blockEnd == '\r' || *blockEnd == '\n'))
                        blockEnd++;

                    int pemBlockSz = (int)(blockEnd - begin);
                    byte derBuf[4096];
                    int derSz = wc_CertPemToDer(
                        (const unsigned char*)begin, pemBlockSz,
                        derBuf, (int)sizeof(derBuf), CERT_TYPE);

                    if (derSz > 0) {
                        byte* tmp = (byte*)WMALLOC(combinedSz + derSz, NULL, 0);
                        if (tmp == NULL) {
                            ret = -1;
                            break;
                        }
                        if (combined != NULL) {
                            WMEMCPY(tmp, combined, combinedSz);
                            WFREE(combined, NULL, 0);
                        }
                        WMEMCPY(tmp + combinedSz, derBuf, derSz);
                        combined = tmp;
                        combinedSz += derSz;
                        certCount++;
                    }

                    p = blockEnd;
                }

                WFREE(raw, NULL, 0);

                if (ret == 0 && certCount > 0 && combined != NULL) {
                    userPublicKey = combined;
                    userPublicKeySz = combinedSz;
                    userPublicKeyType = publicKeyType;
                    userPublicKeyTypeSz =
                        (word32)WSTRLEN((const char*)publicKeyType);
                    pubKeyLoaded = 1;
                    userPublicKeyAlloc = 1;
                }
                else {
                    if (combined != NULL)
                        WFREE(combined, NULL, 0);
                    userPublicKey = userPublicKeyBuf;
                    userPublicKeySz = 0;
                    userPublicKeyType = NULL;
                    userPublicKeyAlloc = 0;
                    if (ret == 0) ret = -1;
                }
            }
            else {
                /* DER format: use as-is (original behavior) */
                userPublicKey = raw;
                userPublicKeySz = rawSz;
                userPublicKeyType = publicKeyType;
                userPublicKeyTypeSz =
                    (word32)WSTRLEN((const char*)publicKeyType);
                pubKeyLoaded = 1;
                userPublicKeyAlloc = 1;
            }
        }
        else {
            userPublicKey = userPublicKeyBuf;
            userPublicKeySz = 0;
            userPublicKeyType = NULL;
            userPublicKeyAlloc = 0;
        }
    #else
        fprintf(stderr, "Certificate support not compiled in");
        ret = WS_NOT_COMPILED;
    #endif
    }

    return ret;
}


/* Reads the private key to use from file name privKeyName.
 * returns 0 on success */
int ClientSetPrivateKey(const char* privKeyName)
{
    int ret;

    userPrivateKeyAlloc = 0;
    userPrivateKey = NULL; /* create new buffer based on parsed input */
    ret = wolfSSH_ReadKey_file(privKeyName,
            (byte**)&userPrivateKey, &userPrivateKeySz,
            (const byte**)&userPrivateKeyType, &userPrivateKeyTypeSz,
            &isPrivate, NULL);

    if (ret == 0) {
        userPrivateKeyAlloc = 1;
    }
    else {
        userPrivateKey = userPrivateKeyBuf;
        userPrivateKeySz = sizeof(userPrivateKeyBuf);
        userPrivateKeyType = NULL;
    }

    return ret;
}


/* Extract certificate(s) from a composite PEM file that contains both
 * a private key and certificate(s). Used when -i points to a PEM file
 * with embedded certificates.
 * returns 0 on success, -1 if no certificate found */
int ClientUseCertFromKeyFile(const char* keyFileName)
{
    int ret = -1;

#ifdef WOLFSSH_CERTS
    if (keyFileName != NULL && pubKeyLoaded == 0) {
        byte* raw = NULL;
        word32 rawSz = 0;

        if (load_der_file(keyFileName, &raw, &rawSz) == 0) {
            if (rawSz > 27 &&
                WSTRNSTR((const char*)raw, "-----BEGIN CERTIFICATE-----",
                         rawSz) != NULL) {
                ret = ClientUseCert(keyFileName);
            }
            WFREE(raw, NULL, 0);
        }
    }
#else
    (void)keyFileName;
#endif

    return ret;
}


/* Simple ~/.ssh/config parser: look up IdentityFile for a given host.
 * Only supports exact Host matching (no wildcards).
 * returns 0 on success with identityFile filled, -1 if not found */
int ClientLookupConfigIdentity(const char* configPath, const char* host,
        char* identityFile, int identityFileSz)
{
#if !defined(NO_FILESYSTEM)
    WFILE* fp = NULL;
    char line[512];
    int inMatchingHost = 0;
    int found = 0;
    int ret;

    if (configPath == NULL || host == NULL ||
            identityFile == NULL || identityFileSz <= 0)
        return -1;

    ret = WFOPEN(NULL, &fp, configPath, "r");
    if (ret != 0 || fp == WBADFILE)
        return -1;

    while (fgets(line, (int)sizeof(line), (FILE*)fp) != NULL) {
        char* p = line;
        char* val;

        /* skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;
        /* skip comments and empty lines */
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;

        /* strip trailing whitespace/newline */
        {
            int len = (int)WSTRLEN(p);
            while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r' ||
                               p[len-1] == ' '  || p[len-1] == '\t'))
                p[--len] = '\0';
        }

        if (WSTRNCASECMP(p, "Host ", 5) == 0 ||
            WSTRNCASECMP(p, "Host\t", 5) == 0) {
            val = p + 5;
            while (*val == ' ' || *val == '\t') val++;
            inMatchingHost = (strcmp(val, host) == 0) ? 1 : 0;
        }
        else if (inMatchingHost &&
                 (WSTRNCASECMP(p, "IdentityFile ", 13) == 0 ||
                  WSTRNCASECMP(p, "IdentityFile\t", 13) == 0)) {
            val = p + 13;
            while (*val == ' ' || *val == '\t') val++;
            /* Expand ~ to HOME */
            if (val[0] == '~' && val[1] == '/') {
                const char* home = ClientGetHomeDir();
                if (home != NULL) {
                    snprintf(identityFile, identityFileSz, "%s%s",
                             home, val + 1);
                }
                else {
                    snprintf(identityFile, identityFileSz, "%s", val);
                }
            }
            else {
                snprintf(identityFile, identityFileSz, "%s", val);
            }
            found = 1;
            break;
        }
    }

    WFCLOSE(NULL, fp);
    return found ? 0 : -1;
#else
    (void)configPath;
    (void)host;
    (void)identityFile;
    (void)identityFileSz;
    return -1;
#endif
}


/* Set public key to use
 * returns 0 on success */
int ClientUsePubKey(const char* pubKeyName)
{
    int ret;

    userPublicKeyAlloc = 0;
    userPublicKey = NULL; /* create new buffer based on parsed input */
    ret = wolfSSH_ReadKey_file(pubKeyName,
            &userPublicKey, &userPublicKeySz,
            (const byte**)&userPublicKeyType, &userPublicKeyTypeSz,
            &isPrivate, NULL);

    if (ret == 0) {
        pubKeyLoaded = 1;
        userPublicKeyAlloc = 1;
    }
    else {
        userPublicKey = userPublicKeyBuf;
        userPublicKeySz = 0;
    }

    return ret;
}

int ClientLoadCA(WOLFSSH_CTX* ctx, const char* caCert)
{
    int ret = 0;

    /* CA certificate to verify host cert with */
    if (caCert) {
    #ifdef WOLFSSH_CERTS
        byte* der = NULL;
        word32 derSz;

        ret = load_der_file(caCert, &der, &derSz);
        if (ret == 0) {
            if (wolfSSH_CTX_AddRootCert_buffer(ctx, der, derSz,
                WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
                fprintf(stderr, "Couldn't parse in CA certificate.");
                ret = WS_PARSE_E;
            }
            WFREE(der, NULL, 0);
        }
    #else
        WOLFSSH_UNUSED(ctx);
        fprintf(stderr, "Support for certificates not compiled in.");
        ret = WS_NOT_COMPILED;
    #endif
    }
    return ret;
}


void ClientFreeBuffers(void)
{
    if (userPublicKeyAlloc && userPublicKey != NULL) {
        WFREE(userPublicKey, NULL, DYNTYPE_PRIVKEY);
        userPublicKey = userPublicKeyBuf;
        userPublicKeySz = 0;
        userPublicKeyAlloc = 0;
    }

    if (userPrivateKeyAlloc && userPrivateKey != NULL) {
        WFREE(userPrivateKey, NULL, DYNTYPE_PRIVKEY);
        userPrivateKey = userPrivateKeyBuf;
        userPrivateKeySz = sizeof(userPrivateKeyBuf);
        userPrivateKeyAlloc = 0;
    }
}


/* Simple ~/.ssh/config parser: look up User for a given host.
 * Only supports exact Host matching (no wildcards).
 * returns 0 on success with user filled, -1 if not found */
int ClientLookupConfigUser(const char* configPath, const char* host,
        char* user, int userSz)
{
#if !defined(NO_FILESYSTEM)
    WFILE* fp = NULL;
    char line[512];
    int inMatchingHost = 0;
    int found = 0;
    int ret;

    if (configPath == NULL || host == NULL || user == NULL || userSz <= 0)
        return -1;

    ret = WFOPEN(NULL, &fp, configPath, "r");
    if (ret != 0 || fp == WBADFILE)
        return -1;

    while (fgets(line, (int)sizeof(line), (FILE*)fp) != NULL) {
        char* p = line;
        char* val;

        /* skip leading whitespace */
        while (*p == ' ' || *p == '\t') p++;
        /* skip comments and empty lines */
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;

        /* strip trailing whitespace/newline */
        {
            int len = (int)WSTRLEN(p);
            while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r' ||
                               p[len-1] == ' '  || p[len-1] == '\t'))
                p[--len] = '\0';
        }

        if (WSTRNCASECMP(p, "Host ", 5) == 0 ||
            WSTRNCASECMP(p, "Host\t", 5) == 0) {
            val = p + 5;
            while (*val == ' ' || *val == '\t') val++;
            inMatchingHost = (strcmp(val, host) == 0) ? 1 : 0;
        }
        else if (inMatchingHost &&
                 (WSTRNCASECMP(p, "User ", 5) == 0 ||
                  WSTRNCASECMP(p, "User\t", 5) == 0)) {
            val = p + 5;
            while (*val == ' ' || *val == '\t') val++;
            snprintf(user, userSz, "%s", val);
            found = 1;
            break;
        }
    }

    WFCLOSE(NULL, fp);
    return found ? 0 : -1;
#else
    (void)configPath;
    (void)host;
    (void)user;
    (void)userSz;
    return -1;
#endif
}
