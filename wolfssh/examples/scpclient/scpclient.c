/* scpclient.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <stdio.h>
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32) && \
    !defined(WOLFSSH_ZEPHYR)
    #include <termios.h>
#endif
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/wolfscp.h>
#include <wolfssh/test.h>
#include <wolfssh/port.h>

#ifndef NO_WOLFSSH_CLIENT
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#include "examples/scpclient/scpclient.h"
#include "examples/client/common.h"

#ifndef USE_WINDOWS_API
    #include <pwd.h>
#endif

static void ShowUsage(void)
{
    printf("wolfscp %s linked with wolfSSL %s\n", LIBWOLFSSH_VERSION_STRING,
        LIBWOLFSSL_VERSION_STRING);
    printf("usage: wolfscp [-P port] [-i keyfile] [-l user] "
           "source target\n");
    printf("       wolfscp localfile [user@]host:remotefile\n");
    printf("       wolfscp [user@]host:remotefile localfile\n");
    printf("\n");
    printf("  -P <port>      port to connect on, default 22\n");
    printf("  -i <keyfile>   identity file (private key)\n");
    printf("  -l <user>      login name\n");
    printf("  -p <password>  password for authentication\n");
#ifdef WOLFSSH_CERTS
    printf("  -J <certfile>  certificate file (DER format)\n");
    printf("  -A <cafile>    CA certificate to verify host\n");
    printf("  -X             ignore IP checks on peer certificate\n");
#endif
    printf("  -h             display this help and exit\n");
}


/* Parse [user@]host:path, returns 0 on success.
 * Sets *userOut, *hostOut, *pathOut. userOut may be NULL if no user@. */
static int parseScpArg(const char* arg, char** userOut, char** hostOut,
        char** pathOut)
{
    char* at;
    char* colon;
    static char userBuf[256];
    static char hostBuf[256];

    *userOut = NULL;
    *hostOut = NULL;
    *pathOut = NULL;

    colon = strchr(arg, ':');
#ifdef USE_WINDOWS_API
    /* Skip Windows drive letter prefix (e.g., C:\, D:/) */
    if (colon != NULL && colon == arg + 1 &&
        ((arg[0] >= 'A' && arg[0] <= 'Z') || (arg[0] >= 'a' && arg[0] <= 'z'))) {
        colon = strchr(colon + 1, ':');
    }
#endif
    if (colon == NULL)
        return -1; /* not a remote path */

    at = strchr(arg, '@');
    if (at != NULL && at < colon) {
        int uLen = (int)(at - arg);
        if (uLen <= 0 || uLen >= (int)sizeof(userBuf))
            return -1;
        memcpy(userBuf, arg, uLen);
        userBuf[uLen] = '\0';
        *userOut = userBuf;
        arg = at + 1;
    }

    {
        int hLen = (int)(colon - arg);
        if (hLen <= 0 || hLen >= (int)sizeof(hostBuf))
            return -1;
        memcpy(hostBuf, arg, hLen);
        hostBuf[hLen] = '\0';
        *hostOut = hostBuf;
    }

    *pathOut = (char*)(colon + 1);
    if (strlen(*pathOut) == 0)
        return -1;

    return 0;
}


enum copyDir {copyNone, copyToSrv, copyFromSrv};


THREAD_RETURN WOLFSSH_THREAD scp_client(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
#ifdef TEST_IPV6
    struct sockaddr_in6 clientAddr6;
    socklen_t clientAddrSz6 = sizeof(clientAddr6);
#endif
    int argc = ((func_args*)args)->argc;
    int ret = 0;
    char** argv = ((func_args*)args)->argv;
    const char* username = NULL;
    const char* password = NULL;
    char* host = NULL;
    char* localPath = NULL;
    char* remotePath = NULL;
    word16 port = 22;
    byte nonBlock = 0;
    enum copyDir dir = copyNone;
    int ch;
    char* privKeyName = NULL;
    char* certName = NULL;
    char* caCert   = NULL;

    ((func_args*)args)->return_code = 0;

    while ((ch = mygetopt(argc, argv, "P:p:i:l:J:A:XhN")) != -1) {
        switch (ch) {
            case 'P':
                if (myoptarg == NULL)
                    err_sys("null argument found");
                port = (word16)atoi(myoptarg);
                #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                    if (port == 0)
                        err_sys("port number cannot be 0");
                #endif
                break;

            case 'p':
                password = myoptarg;
                break;

            case 'i':
                privKeyName = myoptarg;
                break;

            case 'l':
                username = myoptarg;
                break;

            case 'N':
                nonBlock = 1;
                break;

        #ifdef WOLFSSH_CERTS
            case 'J':
                certName = myoptarg;
                break;

            case 'A':
                caCert = myoptarg;
                break;

            #if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
            case 'X':
                ClientIPOverride(1);
                break;
            #endif
        #endif

            case 'h':
                ShowUsage();
                exit(EXIT_SUCCESS);

            default:
                ShowUsage();
                exit(MY_EX_USAGE);
                break;
        }
    }

    /* Parse positional arguments: source target
     * One of them must be [user@]host:path (remote), the other is local */
    if (myoptind + 2 != argc) {
        ShowUsage();
        err_sys("Requires exactly two positional arguments: source and target");
    }

    {
        char* remoteUser = NULL;
        char* remoteHost = NULL;
        char* remoteFile = NULL;

        /* Try first arg as remote */
        if (parseScpArg(argv[myoptind], &remoteUser, &remoteHost,
                    &remoteFile) == 0) {
            dir = copyFromSrv;
            host = remoteHost;
            remotePath = remoteFile;
            localPath = argv[myoptind + 1];
            if (remoteUser != NULL && username == NULL)
                username = remoteUser;
        }
        /* Try second arg as remote */
        else if (parseScpArg(argv[myoptind + 1], &remoteUser, &remoteHost,
                    &remoteFile) == 0) {
            dir = copyToSrv;
            host = remoteHost;
            remotePath = remoteFile;
            localPath = argv[myoptind];
            if (remoteUser != NULL && username == NULL)
                username = remoteUser;
        }
        else {
            ShowUsage();
            err_sys("One argument must be [user@]host:path");
        }
    }

    myoptind = 0;      /* reset for test cases */

    if (host == NULL)
        err_sys("missing remote host");

    /* Resolve identity key and username from SSH config if not specified:
     *   1. ~/.ssh/config IdentityFile/User for matching Host
     *   2. Default: ~/.ssh/id_ecdsa */
    if ((privKeyName == NULL || username == NULL) && host != NULL) {
        char* env = getenv("HOME");
#ifdef USE_WINDOWS_API
        if (env == NULL)
            env = getenv("USERPROFILE");
#endif
        if (env != NULL) {
            char configPath[256];

            snprintf(configPath, sizeof(configPath), "%s/.ssh/config", env);

            /* Read username from config if not specified */
            if (username == NULL) {
                static char scpConfigUser[64];
                if (ClientLookupConfigUser(configPath, host,
                        scpConfigUser, sizeof(scpConfigUser)) == 0
                        && scpConfigUser[0] != '\0') {
                    username = scpConfigUser;
                }
            }

            /* Read identity file from config if not specified */
            if (privKeyName == NULL) {
                static char scpIdentity[256];
                scpIdentity[0] = '\0';
                if (ClientLookupConfigIdentity(configPath, host,
                        scpIdentity, sizeof(scpIdentity)) == 0
                        && scpIdentity[0] != '\0') {
                    privKeyName = scpIdentity;
                }
                else {
                    static char scpDefaultKey[256];
                    snprintf(scpDefaultKey, sizeof(scpDefaultKey),
                             "%s/.ssh/id_ecdsa", env);
                    privKeyName = scpDefaultKey;
                }
            }
        }
    }

    /* System user fallback if no username specified */
    if (username == NULL) {
#ifdef USE_WINDOWS_API
        static char sysUserBuf[256 + 1];
        DWORD sysUserSz = sizeof(sysUserBuf);
        if (GetUserNameA(sysUserBuf, &sysUserSz))
            username = sysUserBuf;
#else
        struct passwd* pw = getpwuid(getuid());
        if (pw != NULL && pw->pw_name != NULL)
            username = pw->pw_name;
#endif
    }

    if (username == NULL)
        err_sys("client requires a username (-l user or user@host:path)");

    ret = ClientSetPrivateKey(privKeyName, 0, NULL, NULL);
    if (ret != 0) {
        err_sys("Error setting private key");
    }

#ifdef WOLFSSH_CERTS
    /* passed in certificate to use */
    if (certName) {
        ret = ClientUseCert(certName, NULL);
    }
    else if (ClientUseCertFromKeyFile(privKeyName, NULL) == 0) {
        /* Auto-detected certificate in composite PEM key file */
        certName = privKeyName;
    }
    else
#endif
    {
        ret = ClientUsePubKey(NULL, 0, NULL);
    }
    if (ret != 0) {
        err_sys("Error setting public key");
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    if (((func_args*)args)->user_auth == NULL)
        wolfSSH_SetUserAuth(ctx, ClientUserAuth);
    else
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);

#ifdef WOLFSSH_CERTS
    ClientLoadCA(ctx, caCert);
#else
    (void)caCert;
    (void)certName;
#endif /* WOLFSSH_CERTS */

    wolfSSH_CTX_SetPublicKeyCheck(ctx, ClientPublicKeyCheck);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

#ifdef WOLFSSH_CERTS
    if (certName != NULL) {
        wolfSSH_SetAlgoListKey(ssh,
            "x509v3-ecdsa-sha2-nistp256,"
            "x509v3-ecdsa-sha2-nistp384,"
            "x509v3-ecdsa-sha2-nistp521,"
            "x509v3-ssh-rsa,"
            "ecdsa-sha2-nistp256,"
            "rsa-sha2-256,"
            "ssh-rsa");
    }
#endif

    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)host);

    if (password != NULL)
        wolfSSH_SetUserAuthCtx(ssh, (void*)password);

    WSTARTTCP();

    ret = wolfSSH_SetUsername(ssh, username);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

#ifdef TEST_IPV6
    /* If it is an IPV6 address */
    if (WSTRCHR(host, ':')) {
        printf("IPV6 address\n");
        build_addr_ipv6(&clientAddr6, host, port);
        sockFd = socket(AF_INET6, SOCK_STREAM, 0);
        ret = connect(sockFd, (const struct sockaddr *)&clientAddr6,
                      clientAddrSz6);
    }
    else
#endif
    {
        build_addr(&clientAddr, host, port);
        tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);
        ret = connect(sockFd, (const struct sockaddr *)&clientAddr,
                      clientAddrSz);
    }

    if (ret != 0)
        err_sys("Couldn't connect to server.");

    if (nonBlock)
        tcp_set_nonblocking(&sockFd);

    ret = wolfSSH_set_fd(ssh, (int)sockFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the channel type.");

    do {
        if (dir == copyFromSrv)
            ret = wolfSSH_SCP_from(ssh, remotePath, localPath);
        else if (dir == copyToSrv)
            ret = wolfSSH_SCP_to(ssh, localPath, remotePath);
        if (ret != WS_SUCCESS && ret == WS_FATAL_ERROR) {
            ret = wolfSSH_get_error(ssh);
        }
    } while (ret == WS_WANT_READ || ret == WS_WANT_WRITE ||
                    ret == WS_CHAN_RXD || ret == WS_REKEYING);
    if (ret != WS_SUCCESS) {
        int sshErr = wolfSSH_get_error(ssh);
        const char* errName = wolfSSH_get_error_name(ssh);
        fprintf(stderr, "Couldn't copy the file. ret=%d, sshErr=%d (%s)\n",
                ret, sshErr, errName ? errName : "null");
        ((func_args*)args)->return_code = 1;
    }

    ret = wolfSSH_shutdown(ssh);
    /* do not continue on with shutdown process if peer already disconnected */
    if (ret != WS_CHANNEL_CLOSED && ret != WS_SOCKET_ERROR_E &&
            wolfSSH_get_error(ssh) != WS_SOCKET_ERROR_E &&
            wolfSSH_get_error(ssh) != WS_CHANNEL_CLOSED) {
        if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "Sending the shutdown messages failed.");
        }
        else {
            ret = wolfSSH_worker(ssh, NULL);
            if (ret != WS_SUCCESS && ret != WS_CHANNEL_CLOSED) {
                WLOG(WS_LOG_DEBUG,
                    "Failed to listen for close messages from the peer.");
            }
        }
    }
    WCLOSESOCKET(sockFd);
    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if (ret != WS_SUCCESS && ret != WS_SOCKET_ERROR_E &&
            ret != WS_CHANNEL_CLOSED) {
        WLOG(WS_LOG_DEBUG,
        "Closing scp stream failed. Connection could have been closed by peer");
    }

    ClientFreeBuffers(NULL, privKeyName, NULL);
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    if ((ret != WS_SUCCESS) && (ret != WS_CHANNEL_CLOSED))
        ((func_args*)args)->return_code = 1;
    return 0;
}


#ifndef NO_MAIN_DRIVER

int main(int argc, char* argv[])
{
    func_args args;

    args.argc = argc;
    args.argv = argv;
    args.return_code = 0;
    args.user_auth = NULL;

    #ifdef DEBUG_WOLFSSH
        wolfSSH_Debugging_ON();
    #endif

    wolfSSH_Init();

    scp_client(&args);

    wolfSSH_Cleanup();

    return args.return_code;
}


int myoptind = 0;
char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */
#else
int main()
{
    printf("wolfSSH built with NO_WOLFSSH_CLIENT\n");
    printf("SCP client unavailable\n");
    return -1;
}
#endif /* NO_WOLFSSH_CLIENT */

