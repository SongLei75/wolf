/* wolfssh.c
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

#ifdef WOLFSSH_FWD
    /* tcp_listen/build_addr from test.h require WOLFSSH_TEST_SERVER */
    #ifndef WOLFSSH_TEST_SERVER
        #define WOLFSSH_TEST_SERVER
    #endif
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/version.h>
#include <wolfssl/version.h>
#include <wolfssh/test.h>
#ifdef WOLFSSH_AGENT
    #include <wolfssh/agent.h>
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include "examples/client/client.h"
#include "apps/wolfssh/common.h"
#if !defined(USE_WINDOWS_API) && !defined(MICROCHIP_PIC32)
    #include <termios.h>
#endif

#include <sys/param.h>
#include <libgen.h>

#ifndef USE_WINDOWS_API
    #include <pwd.h>
#endif

#ifdef WOLFSSH_SHELL
    #ifdef HAVE_PTY_H
        #include <pty.h>
    #endif
    #ifdef HAVE_UTIL_H
        #include <util.h>
    #endif
    #ifdef HAVE_TERMIOS_H
        #include <termios.h>
    #endif
#endif /* WOLFSSH_SHELL */

#ifdef WOLFSSH_AGENT
    #include <errno.h>
    #include <stddef.h>
    #include <sys/socket.h>
    #include <sys/un.h>
#endif /* WOLFSSH_AGENT */

#ifdef HAVE_SYS_SELECT_H
    #include <sys/select.h>
#endif

#ifdef WOLFSSH_FWD
    #ifndef USE_WINDOWS_API
        #include <fcntl.h>
        #include <signal.h>
    #endif
#endif

#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/asn.h>
#endif


int myoptind = 0;
char* myoptarg = NULL;


static void ShowUsage(char* appPath)
{
    const char* appName;

    appName = basename(appPath);
    /* Attempt to use the actual program name from the caller. Otherwise,
     * default to "wolfssh". */
    if (appName == NULL) {
        appName = "wolfssh";
    }

    printf("%s v%s linked with wolfSSL %s\n", appName,
        LIBWOLFSSH_VERSION_STRING, LIBWOLFSSL_VERSION_STRING);
    printf("usage: %s [-i identity_file] [-l login_name] [-p port]\n"
           "       %*s [-E logfile] [-G]"
#ifdef WOLFSSH_FWD
           " [-L [bind_addr:]port:host:hostport]"
#endif
           "\n"
           "       %*s [-N] [-t] [-V] [-X]\n"
           "       %*s destination [command]\n",
           appName,
           (int)WSTRLEN(appName), "",
           (int)WSTRLEN(appName), "",
           (int)WSTRLEN(appName), "");
}


#ifdef WOLFSSH_CERTS
static const char* certName = NULL;
static const char* caCert   = NULL;
#endif


static int NonBlockSSH_connect(WOLFSSH* ssh)
{
    int ret;
    int error;
    SOCKET_T sockfd;
    int select_ret = 0;
    ret = wolfSSH_connect(ssh);
    error = wolfSSH_get_error(ssh);
    sockfd = (SOCKET_T)wolfSSH_get_fd(ssh);

    while (ret != WS_SUCCESS &&
            (error == WS_WANT_READ || error == WS_WANT_WRITE))
    {
        select_ret = tcp_select(sockfd, 1);

        /* Continue in want write cases even if did not select on socket
         * because there could be pending data to be written. Added continue
         * on want write for test cases where a forced want read was introduced
         * and the socket will not be receiving more data. */
        if (error == WS_WANT_WRITE || error == WS_WANT_READ ||
            select_ret == WS_SELECT_RECV_READY ||
            select_ret == WS_SELECT_ERROR_READY)
        {
            ret = wolfSSH_connect(ssh);
            error = wolfSSH_get_error(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;
    }

    return ret;
}

#if defined(HAVE_TERMIOS_H) && defined(WOLFSSH_TERM)
WOLFSSH_TERMIOS oldTerm;

static void modes_store(void)
{
    tcgetattr(STDIN_FILENO, &oldTerm);
}

static void modes_clear(void)
{
    WOLFSSH_TERMIOS term = oldTerm;

    term.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO | ECHOE
        | ECHOK | ECHONL | NOFLSH | TOSTOP);

    /* check macros set for some BSD dependent and missing on
     * QNX flags */
#ifdef ECHOPRT
    term.c_lflag &= ~(ECHOPRT);
#endif
#ifdef FLUSHO
    term.c_lflag &= ~(FLUSHO);
#endif
#ifdef PENDIN
    term.c_lflag &= ~(PENDIN);
#endif
#ifdef EXTPROC
    term.c_lflag &= ~(EXTPROC);
#endif

    term.c_iflag &= ~(ISTRIP | INLCR | ICRNL | IGNCR | IXON
        | IXOFF | IXANY | IGNBRK | INPCK | PARMRK);
#ifdef IUCLC
    term.c_iflag &= ~IUCLC;
#endif
    term.c_iflag |= IGNPAR;

    term.c_oflag &= ~(OPOST | ONOCR | ONLRET);
#ifdef OUCLC
    term.c_oflag &= ~OLCUC;
#endif

    term.c_cflag &= ~(CSTOPB | PARENB | PARODD | CLOCAL);
#ifdef CRTSCTS
    term.c_cflag &= ~(CRTSCTS);
#endif
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

static void modes_reset(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldTerm);
}

#define MODES_STORE() modes_store()
#define MODES_CLEAR() modes_clear()
#define MODES_RESET() modes_reset()
#else /* HAVE_TERMIOS_H && WOLFSSH_TERM */
#define MODES_STORE() do {} while(0)
#define MODES_CLEAR() do {} while(0)
#define MODES_RESET() do {} while(0)
#endif /* HAVE_TERMIOS_H && WOLFSSH_TERM */

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)

#if defined(WOLFSSH_AGENT)
static inline void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}
#endif

typedef struct thread_args {
    WOLFSSH* ssh;
    wolfSSL_Mutex lock;
    byte rawMode;
    byte quit;
    int  readError;
} thread_args;

#if defined(_POSIX_THREADS) && !defined(USE_WINDOWS_API)
    #define THREAD_RET void*
    #define THREAD_RET_SUCCESS NULL
#elif defined(USE_WINDOWS_API) || defined(_MSC_VER)
    #define THREAD_RET DWORD WINAPI
    #define THREAD_RET_SUCCESS 0
#else
    #define THREAD_RET int
    #define THREAD_RET_SUCCESS 0
#endif


#ifdef WOLFSSH_TERM
static int sendCurrentWindowSize(thread_args* args)
{
    int ret;
    word32 col = 80, row = 24, xpix = 0, ypix = 0;

    wc_LockMutex(&args->lock);
#if defined(USE_WINDOWS_API) || defined(_MSC_VER)
    {
        CONSOLE_SCREEN_BUFFER_INFO cs;

        if (GetConsoleScreenBufferInfo(
                    GetStdHandle(STD_OUTPUT_HANDLE), &cs) != 0) {
            col = cs.srWindow.Right - cs.srWindow.Left + 1;
            row = cs.srWindow.Bottom - cs.srWindow.Top + 1;
        }
    }
#else
    {
        struct winsize windowSize = { 0,0,0,0 };

        ioctl(STDOUT_FILENO, TIOCGWINSZ, &windowSize);
        col = windowSize.ws_col;
        row = windowSize.ws_row;
        xpix = windowSize.ws_xpixel;
        ypix = windowSize.ws_ypixel;
    }
#endif
    ret = wolfSSH_ChangeTerminalSize(args->ssh, col, row, xpix, ypix);
    wc_UnLockMutex(&args->lock);

    return ret;
}


#ifndef _MSC_VER

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdio.h>
#include <unistd.h>

typedef struct {
    sem_t* s;
    char name[32];
} WOLFSSH_SEMAPHORE;

static inline
int wolfSSH_SEMAPHORE_Init(WOLFSSH_SEMAPHORE* s, unsigned int n)
{
    if (s != NULL) {
        snprintf(s->name, sizeof(s->name), "/wolfssh_winch_%d", (int)getpid());
        s->s = sem_open(s->name, O_CREAT | O_EXCL | O_RDWR, 0600, n);
        if (s->s == SEM_FAILED && errno == EEXIST) {
            /* named semaphore already exists, unlink the name and
             * try to open it one more time. */
            if (sem_unlink(s->name) == 0) {
                s->s = sem_open(s->name, O_CREAT | O_RDWR, 0600, n);
            }
        }
    }
    return (s != NULL && s->s != SEM_FAILED);
}

static inline
void wolfSSH_SEMAPHORE_Release(WOLFSSH_SEMAPHORE* s)
{
    if (s != NULL && s->s != NULL && s->s != SEM_FAILED) {
        sem_close(s->s);
        sem_unlink(s->name);
        s->s = NULL;
    }
}

static inline
int wolfSSH_SEMAPHORE_Wait(WOLFSSH_SEMAPHORE* s)
{
    int ret = -1;
    if (s != NULL && s->s != NULL && s->s != SEM_FAILED) {
        do {
            ret = sem_wait(s->s);
        } while (ret == -1 && errno == EINTR);
    }
    return (ret == 0);
}

static inline
void wolfSSH_SEMAPHORE_Post(WOLFSSH_SEMAPHORE* s)
{
    if (s != NULL && s->s != NULL && s->s != SEM_FAILED) {
        sem_post(s->s);
    }
}

static WOLFSSH_SEMAPHORE windowSem;

/* capture window change signals */
static void WindowChangeSignal(int sig)
{
    wolfSSH_SEMAPHORE_Post(&windowSem);
    (void)sig;
}

/* thread for handling window size adjustments */
static THREAD_RET windowMonitor(void* in)
{
    thread_args* args;
    int ret;

    args = (thread_args*)in;
    do {
        if (!wolfSSH_SEMAPHORE_Wait(&windowSem)) {
            break;
        }
        if (args->quit) {
            break;
        }
        ret = sendCurrentWindowSize(args);
        (void)ret;
    } while (1);

    return THREAD_RET_SUCCESS;
}
#else /* _MSC_VER */
/* no SIGWINCH on Windows, poll current terminal size */
static word32 prevCol, prevRow;

static int windowMonitor(thread_args* args)
{
    word32 row, col;
    int ret = WS_SUCCESS;
    CONSOLE_SCREEN_BUFFER_INFO cs;

    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cs) != 0) {
        col = cs.srWindow.Right - cs.srWindow.Left + 1;
        row = cs.srWindow.Bottom - cs.srWindow.Top + 1;

        if (prevCol != col || prevRow != row) {
            prevCol = col;
            prevRow = row;

            wc_LockMutex(&args->lock);
            ret = wolfSSH_ChangeTerminalSize(args->ssh, col, row, 0, 0);
            wc_UnLockMutex(&args->lock);
        }
    }

    return ret;
}
#endif /* _MSC_VER */
#endif /* WOLFSSH_TERM */


static THREAD_RET readInput(void* in)
{
    byte buf[256];
    int  bufSz = sizeof(buf);
    thread_args* args = (thread_args*)in;
    int ret = 0;
    word32 sz = 0;
#ifdef USE_WINDOWS_API
    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    DWORD  stdinMode;
    int    stdinIsConsole =
        (GetConsoleMode(stdinHandle, &stdinMode) != FALSE);
#endif

    while (ret >= 0) {
        WMEMSET(buf, 0, bufSz);
    #ifdef USE_WINDOWS_API
        if (!stdinIsConsole) {
            /* stdin is redirected/piped — no console input available;
             * exit silently (OpenSSH-compatible behavior). */
            return THREAD_RET_SUCCESS;
        }
        /* Using A version to avoid potential 2 byte chars */
        ret = ReadConsoleA(stdinHandle, (void*)buf, bufSz - 1, (DWORD*)&sz,
                NULL);
        (void)windowMonitor(args);
    #else
        ret = (int)read(STDIN_FILENO, buf, bufSz -1);
        sz  = (word32)ret;
    #endif
        if (ret <= 0) {
        #ifndef USE_WINDOWS_API
            /* In non-interactive mode stdin is not a TTY; EOF (ret==0)
             * is expected behavior — exit silently like OpenSSH. */
            if (!isatty(STDIN_FILENO))
                return THREAD_RET_SUCCESS;
        #endif
            fprintf(stderr, "Error reading stdin\n");
            return THREAD_RET_SUCCESS;
        }
        /* lock SSH structure access */
        wc_LockMutex(&args->lock);
        ret = wolfSSH_stream_send(args->ssh, buf, sz);
        wc_UnLockMutex(&args->lock);
        if (ret <= 0) {
            fprintf(stderr, "Couldn't send data\n");
            return THREAD_RET_SUCCESS;
        }
    }
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif
    return THREAD_RET_SUCCESS;
}


static THREAD_RET readPeer(void* in)
{
    byte buf[256];
    int  bufSz = sizeof(buf);
    thread_args* args = (thread_args*)in;
    int ret = 0;
    int stop = 0;
    int fd = wolfSSH_get_fd(args->ssh);
    word32 bytes;
#ifdef USE_WINDOWS_API
    HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
    fd_set readSet;
    fd_set errSet;

#ifdef USE_WINDOWS_API
    if (args->rawMode == 0) {
        DWORD wrd;

        /* get console mode will fail on handles that are not a console,
         * i.e. if the stdout is being redirected to a file */
        if (GetConsoleMode(stdoutHandle, &wrd) != FALSE) {
            /* depend on the terminal to process VT characters */
        #ifndef _WIN32_WINNT_WIN10
            /* support for virtual terminal processing was introduced in windows 10 */
            #define _WIN32_WINNT_WIN10 0x0A00
        #endif
        #if defined(WINVER) && (WINVER >= _WIN32_WINNT_WIN10)
            wrd |= (ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT);
        #endif
            if (SetConsoleMode(stdoutHandle, wrd) == FALSE) {
                err_sys("Unable to set console mode");
            }
        }
    }

    /* set handle to use for window resize */
    wc_LockMutex(&args->lock);
    wolfSSH_SetTerminalResizeCtx(args->ssh, stdoutHandle);
    wc_UnLockMutex(&args->lock);
#endif

    while (ret >= 0) {
#if defined(WOLFSSH_TERM) && defined(USE_WINDOWS_API)
        (void)windowMonitor(args);
#endif
        FD_ZERO(&readSet);
        FD_ZERO(&errSet);
        FD_SET(fd, &readSet);
        FD_SET(fd, &errSet);

        bytes = select(fd + 1, &readSet, NULL, &errSet, NULL);
        wc_LockMutex(&args->lock);
        while (bytes > 0 && (FD_ISSET(fd, &readSet) || FD_ISSET(fd, &errSet))) {
            /* there is something to read off the wire */
            WMEMSET(buf, 0, bufSz);
            ret = wolfSSH_stream_read(args->ssh, buf, bufSz - 1);
            if (ret == WS_EXTDATA) { /* handle extended data */
                do {
                    WMEMSET(buf, 0, bufSz);
                    ret = wolfSSH_extended_data_read(args->ssh, buf, bufSz - 1);
                    if (ret < 0)
                        err_sys("Extended data read failed.");
                    buf[bufSz - 1] = '\0';
                #ifdef USE_WINDOWS_API
                    fprintf(stderr, "%s", buf);
                #else
                    if (write(STDERR_FILENO, buf, ret) < 0) {
                        perror("Issue with stderr write ");
                    }
                #endif
                } while (ret > 0);
            }
            else if (ret <= 0) {
                int err = (ret == WS_FATAL_ERROR) ?
                    wolfSSH_get_error(args->ssh) : ret;
                if (err == WS_WANT_READ) {
                    bytes = 0;
                }
#ifdef WOLFSSH_AGENT
                else if (err == WS_CHAN_RXD) {
                    byte agentBuf[512];
                    int rxd, txd;
                    word32 channel = 0;

                    wolfSSH_GetLastRxId(args->ssh, &channel);
                        rxd = wolfSSH_ChannelIdRead(args->ssh, channel,
                                agentBuf, sizeof(agentBuf));
                        if (rxd > 4) {
                            word32 msgSz = 0;

                            ato32(agentBuf, &msgSz);
                            if (msgSz > (word32)rxd - 4) {
                                rxd += wolfSSH_ChannelIdRead(args->ssh, channel,
                                        agentBuf + rxd,
                                        sizeof(agentBuf) - rxd);
                            }

                            txd = rxd;
                            rxd = sizeof(agentBuf);
                            ret = wolfSSH_AGENT_Relay(args->ssh,
                                    agentBuf, (word32*)&txd,
                                    agentBuf, (word32*)&rxd);
                            if (ret == WS_SUCCESS) {
                                ret = wolfSSH_ChannelIdSend(args->ssh, channel,
                                        agentBuf, rxd);
                            }
                        }
                        WMEMSET(agentBuf, 0, sizeof(agentBuf));
                        continue;
                    }
#endif /* WOLFSSH_AGENT */
                else if (err == WS_CBIO_ERR_CONN_CLOSE ||
                         err == WS_SOCKET_ERROR_E ||
                         err == WS_MSGID_NOT_ALLOWED_E ||
                         err == WS_CHANNEL_CLOSED) {
                    /* WS_CHANNEL_CLOSED is a normal termination:
                     * the remote command finished and the server
                     * closed the channel. Do NOT treat it as an
                     * error — exit-status has already been stored
                     * in ssh->exitStatus by DoChannelRequest. */
                    args->readError = err;
                    ret = err;
                    stop = 1;
                    bytes = 0;
                }
                else if (err != WS_EOF) {
                    wc_UnLockMutex(&args->lock);
                    err_sys("Stream read failed.");
                }
            }
            else {
            #ifdef USE_WINDOWS_API
                DWORD writtn = 0;
                byte outBuf[256];
                word32 outSz = 0;
                word32 i;

                /* Normalize \r\n to \n: Windows console with
                 * ENABLE_PROCESSED_OUTPUT treats \r and \n as
                 * independent line breaks, so \r\n causes a double
                 * newline. Strip \r that is immediately followed by
                 * \n to get a single line break. */
                for (i = 0; i < (word32)ret && outSz < sizeof(outBuf) - 1;
                     i++) {
                    if (buf[i] == '\r' && (i + 1) < (word32)ret &&
                        buf[i + 1] == '\n') {
                        continue; /* skip \r before \n */
                    }
                    outBuf[outSz++] = buf[i];
                }

                if (outSz > 0) {
                    if (WriteFile(stdoutHandle, outBuf, outSz,
                                  &writtn, NULL) == FALSE) {
                        err_sys("Failed to write to stdout handle");
                    }
                }
            #else
                buf[bufSz - 1] = '\0';
                if (write(STDOUT_FILENO, buf, ret) < 0) {
                    perror("write to stdout error ");
                }
            #endif
            }
            if (!stop) {
                ret = wolfSSH_stream_peek(args->ssh, buf, bufSz);
                if (ret <= 0) {
                    bytes = 0; /* read it all */
                }
            }
        }
        wc_UnLockMutex(&args->lock);
        if (stop)
            break;
    }
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    return THREAD_RET_SUCCESS;
}
#endif /* !SINGLE_THREADED && !WOLFSSL_NUCLEUS */


#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)

static int callbackGlobalReq(WOLFSSH *ssh, void *buf, word32 sz,
        int reply, void *ctx)
{
    char reqStr[] = "SampleRequest";

    if ((WOLFSSH *)ssh != *(WOLFSSH **)ctx) {
        printf("ssh(%p) != ctx(%p)\n", ssh, *(WOLFSSH **)ctx);
        return WS_FATAL_ERROR;
    }

    if (WSTRLEN(reqStr) == sz
            && (WSTRNCMP((char *)buf, reqStr, sz) == 0)
            && reply == 1) {
        printf("Global Request\n");
        return WS_SUCCESS;
    }
    else {
        return WS_FATAL_ERROR;
    }

}
#endif


#ifdef WOLFSSH_AGENT
typedef struct WS_AgentCbActionCtx {
    struct sockaddr_un name;
    int fd;
    int state;
} WS_AgentCbActionCtx;

static const char EnvNameAuthPort[] = "SSH_AUTH_SOCK";

static int wolfSSH_AGENT_DefaultActions(WS_AgentCbAction action, void* vCtx)
{
    WS_AgentCbActionCtx* ctx = (WS_AgentCbActionCtx*)vCtx;
    int ret = WS_AGENT_SUCCESS;

    if (action == WOLFSSH_AGENT_LOCAL_SETUP) {
        const char* sockName;
        struct sockaddr_un* name = &ctx->name;
        size_t size;
        int err;

        sockName = getenv(EnvNameAuthPort);
        if (sockName == NULL)
            ret = WS_AGENT_NOT_AVAILABLE;

        if (ret == WS_AGENT_SUCCESS) {
            WMEMSET(name, 0, sizeof(struct sockaddr_un));
            name->sun_family = AF_LOCAL;
            WSTRNCPY(name->sun_path, sockName, sizeof(name->sun_path) - 1);
            name->sun_path[sizeof(name->sun_path) - 1] = '\0';
            size = WSTRLEN(sockName) +
                    offsetof(struct sockaddr_un, sun_path);

            ctx->fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (ctx->fd == -1) {
                ret = WS_AGENT_SETUP_E;
                err = errno;
                fprintf(stderr, "socket() = %d\n", err);
            }
        }

        if (ret == WS_AGENT_SUCCESS) {
            ret = connect(ctx->fd,
                    (struct sockaddr *)name, (socklen_t)size);
            if (ret < 0) {
                ret = WS_AGENT_SETUP_E;
                err = errno;
                fprintf(stderr, "connect() = %d", err);
            }
        }

        if (ret == WS_AGENT_SUCCESS)
            ctx->state = AGENT_STATE_CONNECTED;
    }
    else if (action == WOLFSSH_AGENT_LOCAL_CLEANUP) {
        int err;

        err = close(ctx->fd);
        if (err != 0) {
            err = errno;
            fprintf(stderr, "close() = %d", err);
            if (ret == 0)
                ret = WS_AGENT_SETUP_E;
        }
    }
    else
        ret = WS_AGENT_INVALID_ACTION;

    return ret;
}


static int wolfSSH_AGENT_IO_Cb(WS_AgentIoCbAction action,
        void* buf, word32 bufSz, void* vCtx)
{
    WS_AgentCbActionCtx* ctx = (WS_AgentCbActionCtx*)vCtx;
    int ret = WS_AGENT_INVALID_ACTION;

    if (action == WOLFSSH_AGENT_IO_WRITE) {
        const byte* wBuf = (const byte*)buf;
        ret = (int)write(ctx->fd, wBuf, bufSz);
        if (ret < 0) {
            ret = WS_CBIO_ERR_GENERAL;
        }
    }
    else if (action == WOLFSSH_AGENT_IO_READ) {
        byte* rBuf = (byte*)buf;
        ret = (int)read(ctx->fd, rBuf, bufSz);
        if (ret < 0) {
            ret = WS_CBIO_ERR_GENERAL;
        }
    }

    return ret;
}


#endif /* WOLFSSH_AGENT */


#ifdef WOLFSSH_FWD
#define MAX_LOCAL_FWD 16

struct fwd_spec {
    char   bindHost[64];
    word16 localPort;
    char   remoteHost[256];
    word16 remotePort;
    char   localSocketPath[256];
    char   remoteSocketPath[256];
    byte   isLocalSocket;
    byte   isRemoteSocket;
};
#endif /* WOLFSSH_FWD */


struct config {
    char* logFile;
    char* user;
    char* hostname;
    char* keyFile;
    char* pubKeyFile;
    char* command;
    word32 printConfig:1;
    word32 noCommand:1;
    word32 forceX509:1;
    word32 forceTty:1;
#ifdef WOLFSSH_FWD
    struct fwd_spec fwdSpecs[MAX_LOCAL_FWD];
    int    fwdCount;
#endif
    word16 port;
};


static int config_init_default(struct config* config)
{
    WMEMSET(config, 0, sizeof(*config));
    config->port = 22;

    /* user defaults to NULL; resolved later by:
     * 1. -l command line option
     * 2. user@host destination
     * 3. ~/.ssh/config User directive
     * 4. system user (getpwuid / GetUserName) */

    return 0;
}


static int config_parse_command_line(struct config* config,
        int argc, char** argv)
{
    int ch;

    while ((ch = mygetopt(argc, argv, "E:Gi:l:L:Np:tVX")) != -1) {
        switch (ch) {
            case 'E':
                config->logFile = myoptarg;
                break;

            case 'G':
                config->printConfig = 1;
                break;

            case 'i':
                if (config->keyFile) {
                    WFREE(config->keyFile, NULL, 0);
                    config->keyFile = NULL;
                }
                if (config->pubKeyFile) {
                    WFREE(config->pubKeyFile, NULL, 0);
                    config->pubKeyFile = NULL;
                }
                {
                    size_t sz = WSTRLEN(myoptarg) + 1;
                    config->keyFile = (char*)WMALLOC(sz, NULL, 0);
                    if (config->keyFile != NULL) {
                        strcpy(config->keyFile, myoptarg);
                    }
                }
                break;

            case 'l':
                if (config->user == NULL) {
                    size_t sz = WSTRLEN(myoptarg) + 1;
                    config->user = (char*)WMALLOC(sz, NULL, 0);
                    if (config->user != NULL)
                        strcpy(config->user, myoptarg);
                }
                break;

#ifdef WOLFSSH_FWD
            case 'L':
            {
                /* Parse -L forwarding specification.
                 * Supported forms (OpenSSH compatible):
                 *   [bind_address:]port:host:hostport    TCP -> TCP
                 *   [bind_address:]port:/remote/socket   TCP -> Unix socket
                 *   /local/socket:host:hostport          Unix socket -> TCP
                 *   /local/socket:/remote/socket         Unix socket -> Unix socket
                 */
                char tmp[512];
                char* colon1;

                if (config->fwdCount >= MAX_LOCAL_FWD) {
                    fprintf(stderr, "Too many -L forwards (max %d)\n",
                            MAX_LOCAL_FWD);
                    exit(EXIT_FAILURE);
                }

                WSTRNCPY(tmp, myoptarg, sizeof(tmp) - 1);
                tmp[sizeof(tmp) - 1] = '\0';

                {
                    struct fwd_spec* spec =
                            &config->fwdSpecs[config->fwdCount];
                    WMEMSET(spec, 0, sizeof(*spec));

                    if (tmp[0] == '/') {
                        /* Local side is a Unix socket path */
                        colon1 = strchr(tmp, ':');
                        if (colon1 == NULL) {
                            fprintf(stderr,
                                "Bad local forwarding spec '%s'\n", myoptarg);
                            exit(EXIT_FAILURE);
                        }
                        *colon1 = '\0';
                        WSTRNCPY(spec->localSocketPath, tmp,
                                sizeof(spec->localSocketPath) - 1);
                        spec->isLocalSocket = 1;

                        /* Remote part after the colon */
                        {
                            char* remote = colon1 + 1;
                            if (remote[0] == '/') {
                                /* /local/socket:/remote/socket */
                                WSTRNCPY(spec->remoteSocketPath, remote,
                                        sizeof(spec->remoteSocketPath) - 1);
                                spec->isRemoteSocket = 1;
                            }
                            else {
                                /* /local/socket:host:hostport */
                                char* colon2 = strchr(remote, ':');
                                long val;
                                if (colon2 == NULL) {
                                    fprintf(stderr,
                                        "Bad local forwarding spec '%s'\n",
                                        myoptarg);
                                    exit(EXIT_FAILURE);
                                }
                                *colon2 = '\0';
                                WSTRNCPY(spec->remoteHost, remote,
                                        sizeof(spec->remoteHost) - 1);
                                val = strtol(colon2 + 1, NULL, 10);
                                if (val <= 0 || val > 65535) {
                                    fprintf(stderr,
                                        "Bad remote port '%s'\n", colon2 + 1);
                                    exit(EXIT_FAILURE);
                                }
                                spec->remotePort = (word16)val;
                            }
                        }
                    }
                    else {
                        /* Local side is TCP. Parse colon-separated parts. */
                        char* p;
                        char* parts[4];
                        int nParts = 0;
                        long val;

                        p = tmp;
                        parts[nParts++] = p;
                        while (*p && nParts < 4) {
                            if (*p == ':') {
                                *p = '\0';
                                parts[nParts++] = p + 1;
                            }
                            p++;
                        }

                        if (nParts == 2) {
                            /* port:/remote/socket */
                            val = strtol(parts[0], NULL, 10);
                            if (val <= 0 || val > 65535) {
                                fprintf(stderr,
                                    "Bad local port '%s'\n", parts[0]);
                                exit(EXIT_FAILURE);
                            }
                            WSTRNCPY(spec->bindHost, "127.0.0.1",
                                    sizeof(spec->bindHost));
                            spec->localPort = (word16)val;
                            if (parts[1][0] == '/') {
                                WSTRNCPY(spec->remoteSocketPath, parts[1],
                                        sizeof(spec->remoteSocketPath) - 1);
                                spec->isRemoteSocket = 1;
                            }
                            else {
                                fprintf(stderr,
                                    "Bad local forwarding spec '%s'\n",
                                    myoptarg);
                                exit(EXIT_FAILURE);
                            }
                        }
                        else if (nParts == 3) {
                            /* port:host:hostport  OR
                             * bind:port:/remote/socket */
                            if (parts[2][0] == '/') {
                                /* bind:port:/remote/socket */
                                WSTRNCPY(spec->bindHost, parts[0],
                                        sizeof(spec->bindHost) - 1);
                                val = strtol(parts[1], NULL, 10);
                                if (val <= 0 || val > 65535) {
                                    fprintf(stderr,
                                        "Bad local port '%s'\n", parts[1]);
                                    exit(EXIT_FAILURE);
                                }
                                spec->localPort = (word16)val;
                                WSTRNCPY(spec->remoteSocketPath, parts[2],
                                        sizeof(spec->remoteSocketPath) - 1);
                                spec->isRemoteSocket = 1;
                            }
                            else {
                                /* port:host:hostport */
                                WSTRNCPY(spec->bindHost, "127.0.0.1",
                                        sizeof(spec->bindHost));
                                val = strtol(parts[0], NULL, 10);
                                if (val <= 0 || val > 65535) {
                                    fprintf(stderr,
                                        "Bad local port '%s'\n", parts[0]);
                                    exit(EXIT_FAILURE);
                                }
                                spec->localPort = (word16)val;
                                WSTRNCPY(spec->remoteHost, parts[1],
                                        sizeof(spec->remoteHost) - 1);
                                spec->remoteHost[
                                    sizeof(spec->remoteHost) - 1] = '\0';
                                val = strtol(parts[2], NULL, 10);
                                if (val <= 0 || val > 65535) {
                                    fprintf(stderr,
                                        "Bad remote port '%s'\n", parts[2]);
                                    exit(EXIT_FAILURE);
                                }
                                spec->remotePort = (word16)val;
                            }
                        }
                        else if (nParts == 4) {
                            /* bind_address:port:host:hostport */
                            WSTRNCPY(spec->bindHost, parts[0],
                                    sizeof(spec->bindHost) - 1);
                            spec->bindHost[sizeof(spec->bindHost) - 1] = '\0';
                            val = strtol(parts[1], NULL, 10);
                            if (val <= 0 || val > 65535) {
                                fprintf(stderr,
                                    "Bad local port '%s'\n", parts[1]);
                                exit(EXIT_FAILURE);
                            }
                            spec->localPort = (word16)val;
                            WSTRNCPY(spec->remoteHost, parts[2],
                                    sizeof(spec->remoteHost) - 1);
                            spec->remoteHost[
                                sizeof(spec->remoteHost) - 1] = '\0';
                            val = strtol(parts[3], NULL, 10);
                            if (val <= 0 || val > 65535) {
                                fprintf(stderr,
                                    "Bad remote port '%s'\n", parts[3]);
                                exit(EXIT_FAILURE);
                            }
                            spec->remotePort = (word16)val;
                        }
                        else {
                            fprintf(stderr,
                                "Bad local forwarding spec '%s'\n", myoptarg);
                            exit(EXIT_FAILURE);
                        }
                    }
                    config->fwdCount++;
                }
                break;
            }
#endif /* WOLFSSH_FWD */

            case 'N':
                config->noCommand = 1;
                break;

            case 'p':
                config->port = (word16)atoi(myoptarg);
                break;

            case 't':
                config->forceTty = 1;
                break;

            case 'V':
                fprintf(stderr, "wolfSSH v%s, wolfSSL v%s\n",
                        LIBWOLFSSH_VERSION_STRING,
                        LIBWOLFSSL_VERSION_STRING);
                exit(EXIT_SUCCESS);

            case 'X':
                config->forceX509 = 1;
                break;

            default:
                ShowUsage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /* Parse the destination. Either:
     *  - [user@]hostname
     *  - ssh://[user@]hostname[:port] */
    if (myoptind < argc) {
        const char* uriPrefix = "ssh://";
        char* dest;
        char* cursor;
        char* found;
        size_t sz;
        int checkPort;

        myoptarg = argv[myoptind];

        sz = WSTRLEN(myoptarg) + 1;
        dest = (char*)WMALLOC(sz, NULL, 0);
        WMEMCPY(dest, myoptarg, sz);
        cursor = dest;

        if (WSTRSTR(cursor, uriPrefix)) {
            checkPort = 1;
            cursor += WSTRLEN(uriPrefix);
        }
        else {
            checkPort = 0;
        }

        found = WSTRCHR(cursor, '@');
        if (found == cursor) {
            fprintf(stderr, "can't start destination with just an @\n");
        }
        if (found != NULL) {
            *found = '\0';
            if (config->user == NULL) {
                sz = WSTRLEN(cursor);
                config->user = (char*)WMALLOC(sz + 1, NULL, 0);
                if (config->user != NULL)
                    strcpy(config->user, cursor);
            }
            cursor = found + 1;
        }

        if (checkPort) {
            found = WSTRCHR(cursor, ':');
            if (found != NULL) {
                *found = '\0';
                sz = WSTRLEN(cursor);
                config->hostname = (char*)WMALLOC(sz + 1, NULL, 0);
                strcpy(config->hostname, cursor);
                cursor = found + 1;
                if (*cursor != 0) {
                    config->port = atoi(cursor);
                }
            }
        }
        else {
            sz = WSTRLEN(cursor);
            config->hostname = (char*)WMALLOC(sz + 1, NULL, 0);
            strcpy(config->hostname, cursor);
        }

        WFREE(dest, NULL, 0);
        myoptind++;
    }

    if (myoptind < argc) {
        int i;
        size_t commandSz;
        char* cursor;
        char* command;

        /* Count the spaces needed. The following will calculate one extra
         * space but that's for the nul termination. */
        commandSz = argc - myoptind;
        for (i = myoptind; i < argc; i++) {
            commandSz += WSTRLEN(argv[i]);
        }

        command = (char*)WMALLOC(commandSz, NULL, 0);
        config->command = command;
        cursor = command;

        for (i = myoptind; i < argc; i++) {
            size_t argLen = WSTRLEN(argv[i]);

            WMEMCPY(cursor, argv[i], argLen);
            cursor += argLen;
            *cursor = ' ';
            cursor++;
        }
        *(--cursor) = '\0';
        myoptind++;
    }

    return 0;
}


static int config_print(struct config* config)
{
    if (config->printConfig) {
        printf("user %s\n", config->user ? config->user : "none");
        printf("hostname %s\n", config->hostname ? config->hostname : "none");
        printf("port %u\n", config->port);
        printf("keyFile %s\n", config->keyFile ? config->keyFile : "none");
        printf("pubKeyFile %s\n",
                config->pubKeyFile ? config->pubKeyFile : "none");
        printf("noCommand %s\n", config->noCommand ? "true" : "false");
        printf("forceX509 %s\n", config->forceX509 ? "true" : "false");
        printf("logfile %s\n", config->logFile ? config->logFile : "default");
        printf("command %s\n", config->command ? config->command : "none");
#ifdef WOLFSSH_FWD
        {
            int i;
            for (i = 0; i < config->fwdCount; i++) {
                struct fwd_spec* s = &config->fwdSpecs[i];
                if (s->isLocalSocket && s->isRemoteSocket) {
                    printf("localForward %s -> %s\n",
                            s->localSocketPath, s->remoteSocketPath);
                }
                else if (s->isLocalSocket) {
                    printf("localForward %s -> %s:%u\n",
                            s->localSocketPath,
                            s->remoteHost, s->remotePort);
                }
                else if (s->isRemoteSocket) {
                    printf("localForward %s:%u -> %s\n",
                            s->bindHost, s->localPort,
                            s->remoteSocketPath);
                }
                else {
                    printf("localForward %s:%u -> %s:%u\n",
                            s->bindHost, s->localPort,
                            s->remoteHost, s->remotePort);
                }
            }
        }
#endif
    }

    return 0;
}


static int config_cleanup(struct config* config)
{
    if (config->user) {
        WFREE(config->user, NULL, 0);
        config->user = NULL;
    }
    if (config->hostname) {
        WFREE(config->hostname, NULL, 0);
        config->hostname = NULL;
    }
    if (config->keyFile) {
        WFREE(config->keyFile, NULL, 0);
        config->keyFile = NULL;
    }
    if (config->pubKeyFile) {
        WFREE(config->pubKeyFile, NULL, 0);
        config->pubKeyFile = NULL;
    }
    if (config->command) {
        WFREE(config->command, NULL, 0);
        config->command = NULL;
    }

    return 0;
}


/* Resolve username with OpenSSH-like priority:
 *   1. -l command line option (already set)
 *   2. user@host destination (already set)
 *   3. ~/.ssh/config User directive for matching Host
 *   4. System user (getpwuid on Unix, GetUserName on Windows) */
static void config_resolve_user(struct config* config)
{
    if (config->user != NULL)
        return;

    /* SSH config User directive */
    if (config->hostname != NULL) {
        const char* home = ClientGetHomeDir();
        if (home != NULL) {
            char configPath[256];
            char userBuf[256];
            snprintf(configPath, sizeof(configPath), "%s/.ssh/config", home);
            userBuf[0] = '\0';
            if (ClientLookupConfigUser(configPath, config->hostname,
                    userBuf, sizeof(userBuf)) == 0 && userBuf[0] != '\0') {
                size_t sz = WSTRLEN(userBuf) + 1;
                config->user = (char*)WMALLOC(sz, NULL, 0);
                if (config->user != NULL)
                    strcpy(config->user, userBuf);
                return;
            }
        }
    }

    /* System user fallback */
#ifdef USE_WINDOWS_API
    {
        char buf[256 + 1];
        DWORD sz = sizeof(buf);
        if (GetUserNameA(buf, &sz)) {
            size_t len = WSTRLEN(buf) + 1;
            config->user = (char*)WMALLOC(len, NULL, 0);
            if (config->user != NULL)
                strcpy(config->user, buf);
        }
    }
#else
    {
        struct passwd* pw = getpwuid(getuid());
        if (pw != NULL && pw->pw_name != NULL) {
            size_t sz = WSTRLEN(pw->pw_name) + 1;
            config->user = (char*)WMALLOC(sz, NULL, 0);
            if (config->user != NULL)
                strcpy(config->user, pw->pw_name);
        }
    }
#endif
}


/* Resolve identity key file with OpenSSH-like priority:
 *   1. -i command line option (already set in config->keyFile)
 *   2. ~/.ssh/config IdentityFile for matching Host
 *   3. Default: ~/.ssh/id_ecdsa
 * Also sets pubKeyFile if not using x509. */
static void config_resolve_key(struct config* config)
{
    char* env;

    if (config->keyFile != NULL) {
        /* Already set by -i option */
        return;
    }

    /* Try ~/.ssh/config lookup */
    if (config->hostname != NULL) {
        env = getenv("HOME");
#ifdef USE_WINDOWS_API
        if (env == NULL)
            env = getenv("USERPROFILE");
#endif
        if (env != NULL) {
            char configPath[256];
            static char identity[256];

            snprintf(configPath, sizeof(configPath), "%s/.ssh/config", env);
            identity[0] = '\0';
            if (ClientLookupConfigIdentity(configPath, config->hostname,
                    identity, sizeof(identity)) == 0 && identity[0] != '\0') {
                size_t sz = WSTRLEN(identity) + 1;
                config->keyFile = (char*)WMALLOC(sz, NULL, 0);
                if (config->keyFile != NULL) {
                    strcpy(config->keyFile, identity);
                }
                return;
            }
        }
    }

    /* Fall back to default ~/.ssh/id_ecdsa */
    env = getenv("HOME");
#ifdef USE_WINDOWS_API
    if (env == NULL)
        env = getenv("USERPROFILE");
#endif
    if (env != NULL) {
        const char* defaultName = "/.ssh/id_ecdsa";
        const char* pubSuffix = ".pub";
        size_t sz;

        sz = WSTRLEN(env) + WSTRLEN(defaultName) + 1;
        config->keyFile = (char*)WMALLOC(sz, NULL, 0);
        if (config->keyFile != NULL) {
            strcpy(config->keyFile, env);
            strcat(config->keyFile, defaultName);
        }

        sz += WSTRLEN(pubSuffix);
        config->pubKeyFile = (char*)WMALLOC(sz, NULL, 0);
        if (config->pubKeyFile != NULL) {
            strcpy(config->pubKeyFile, env);
            strcat(config->pubKeyFile, defaultName);
            strcat(config->pubKeyFile, pubSuffix);
        }
    }
}


#ifdef WOLFSSH_FWD
#ifndef FWD_BUFFER_SZ
    #define FWD_BUFFER_SZ 4096
#endif
#ifndef MAX_FWD_CLIENTS
    #define MAX_FWD_CLIENTS 64
#endif

struct fwd_client {
    SOCKET_T         appFd;
    WOLFSSH_CHANNEL* channel;
    word32           channelId;
    byte             appBuf[FWD_BUFFER_SZ];
    word32           appBufUsed;
};

static int findMaxFd(int a, int b)
{
    return (a > b) ? a : b;
}

/* Run local port forwarding loop:
 *   For each -L spec, listen on bindHost:localPort or a Unix socket path.
 *   Accept incoming connections, open a direct-tcpip or
 *   direct-streamlocal@openssh.com channel for each, and relay data
 *   bidirectionally. Supports multiple listeners and multiple concurrent
 *   forwarded connections per listener.
 */
static int localForwardLoop(WOLFSSH* ssh, struct config* config)
{
    SOCKET_T listenFds[MAX_LOCAL_FWD];
    int      nListeners = 0;
    struct fwd_client clients[MAX_FWD_CLIENTS];
    int      nClients = 0;
    SOCKET_T sshFd;
    fd_set   rxFds, errFds;
    int      nFds;
    int      ret;
    int      i;
    struct timeval to;
    byte     sshBuf[FWD_BUFFER_SZ];

    sshFd = (SOCKET_T)wolfSSH_get_fd(ssh);

#ifndef USE_WINDOWS_API
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Set up listeners for each -L spec */
    for (i = 0; i < config->fwdCount; i++) {
        SOCKET_T lfd;
        struct fwd_spec* spec = &config->fwdSpecs[i];

#ifdef WOLFSSH_HAVE_UNIX_SOCKET
        if (spec->isLocalSocket) {
            struct sockaddr_un unAddr;

            /* Remove stale socket file if it exists */
#ifdef USE_WINDOWS_API
            DeleteFileA(spec->localSocketPath);
#else
            unlink(spec->localSocketPath);
#endif

            unix_socket(&lfd);
            build_addr_unix(&unAddr, spec->localSocketPath);

            if (bind(lfd, (struct sockaddr*)&unAddr, sizeof(unAddr)) < 0) {
                fprintf(stderr, "Failed to bind Unix socket %s: %s\n",
                        spec->localSocketPath, strerror(errno));
                WCLOSESOCKET(lfd);
                continue;
            }
            if (listen(lfd, 5) < 0) {
                fprintf(stderr, "Failed to listen on Unix socket %s: %s\n",
                        spec->localSocketPath, strerror(errno));
                WCLOSESOCKET(lfd);
#ifdef USE_WINDOWS_API
                DeleteFileA(spec->localSocketPath);
#else
                unlink(spec->localSocketPath);
#endif
                continue;
            }
            listenFds[nListeners] = lfd;
            nListeners++;
            if (spec->isRemoteSocket) {
                fprintf(stderr, "Forwarding %s -> %s\n",
                        spec->localSocketPath, spec->remoteSocketPath);
            }
            else {
                fprintf(stderr, "Forwarding %s -> %s:%u\n",
                        spec->localSocketPath,
                        spec->remoteHost, spec->remotePort);
            }
        }
        else
#endif /* WOLFSSH_HAVE_UNIX_SOCKET */
        {
            SOCKADDR_IN_T bindAddr;
            int on = 1;

            build_addr(&bindAddr, spec->bindHost, spec->localPort);
            tcp_socket(&lfd,
                    ((struct sockaddr_in *)&bindAddr)->sin_family);
            setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

            if (bind(lfd, (struct sockaddr*)&bindAddr,
                        sizeof(bindAddr)) < 0) {
                fprintf(stderr, "Failed to bind %s:%u: %s\n",
                        spec->bindHost, spec->localPort,
                        strerror(errno));
                WCLOSESOCKET(lfd);
                continue;
            }
            if (listen(lfd, 5) < 0) {
                fprintf(stderr, "Failed to listen on %s:%u: %s\n",
                        spec->bindHost, spec->localPort,
                        strerror(errno));
                WCLOSESOCKET(lfd);
                continue;
            }
            listenFds[nListeners] = lfd;
            nListeners++;
            if (spec->isRemoteSocket) {
                fprintf(stderr, "Forwarding %s:%u -> %s\n",
                        spec->bindHost, spec->localPort,
                        spec->remoteSocketPath);
            }
            else {
                fprintf(stderr, "Forwarding %s:%u -> %s:%u\n",
                        spec->bindHost, spec->localPort,
                        spec->remoteHost, spec->remotePort);
            }
        }
    }

    if (nListeners == 0) {
        fprintf(stderr, "No forwarding listeners could be established\n");
        return -1;
    }

    for (;;) {
        FD_ZERO(&rxFds);
        FD_ZERO(&errFds);

        FD_SET(sshFd, &rxFds);
        FD_SET(sshFd, &errFds);
        nFds = (int)sshFd + 1;

        for (i = 0; i < nListeners; i++) {
            FD_SET(listenFds[i], &rxFds);
            nFds = findMaxFd(nFds, (int)listenFds[i] + 1);
        }

        for (i = 0; i < nClients; i++) {
            FD_SET(clients[i].appFd, &rxFds);
            FD_SET(clients[i].appFd, &errFds);
            nFds = findMaxFd(nFds, (int)clients[i].appFd + 1);
        }

        to.tv_sec = 1;
        to.tv_usec = 0;
        ret = select(nFds, &rxFds, NULL, &errFds, &to);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }
        if (ret == 0) {
            /* Timeout: still flush any pending client buffers */
            for (i = 0; i < nClients; i++) {
                if (clients[i].appBufUsed > 0 && clients[i].channel != NULL) {
                    int sr = wolfSSH_ChannelSend(clients[i].channel,
                            clients[i].appBuf, clients[i].appBufUsed);
                    if (sr > 0) {
                        if ((word32)sr < clients[i].appBufUsed)
                            WMEMMOVE(clients[i].appBuf,
                                    clients[i].appBuf + sr,
                                    clients[i].appBufUsed - sr);
                        clients[i].appBufUsed -= sr;
                    }
                }
            }
            continue;
        }

        /* Check for SSH connection errors */
        if (FD_ISSET(sshFd, &errFds)) {
            fprintf(stderr, "SSH connection error\n");
            break;
        }

        /* Accept new local connections from any listener */
        for (i = 0; i < nListeners; i++) {
            if (FD_ISSET(listenFds[i], &rxFds)) {
                SOCKADDR_IN_T peerAddr;
                socklen_t peerAddrSz = sizeof(peerAddr);
                SOCKET_T newFd;

                newFd = accept(listenFds[i],
                        (struct sockaddr*)&peerAddr, &peerAddrSz);
                if (newFd < 0) {
                    perror("accept");
                    continue;
                }
                if (nClients >= MAX_FWD_CLIENTS) {
                    fprintf(stderr,
                        "Max forwarded connections reached, rejecting\n");
                    WCLOSESOCKET(newFd);
                    continue;
                }

                {
                    WOLFSSH_CHANNEL* ch;
                    struct fwd_spec* spec = &config->fwdSpecs[i];

                    if (spec->isRemoteSocket) {
                        ch = wolfSSH_ChannelFwdNewStreamLocal(ssh,
                                spec->remoteSocketPath);
                    }
                    else {
                        ch = wolfSSH_ChannelFwdNewLocal(ssh,
                                spec->remoteHost, spec->remotePort,
                                spec->bindHost, spec->localPort);
                    }
                    if (ch == NULL) {
                        if (spec->isRemoteSocket) {
                            fprintf(stderr,
                                "Failed to open streamlocal channel to %s"
                                " (err=%d)\n",
                                spec->remoteSocketPath,
                                wolfSSH_get_error(ssh));
                        }
                        else {
                            fprintf(stderr,
                                "Failed to open forwarding channel to %s:%u"
                                " (err=%d)\n",
                                spec->remoteHost, spec->remotePort,
                                wolfSSH_get_error(ssh));
                        }
                        WCLOSESOCKET(newFd);
                        continue;
                    }

                    WMEMSET(&clients[nClients], 0, sizeof(clients[0]));
                    clients[nClients].appFd = newFd;
                    clients[nClients].channel = ch;
                    wolfSSH_ChannelGetId(ch,
                            &clients[nClients].channelId,
                            WS_CHANNEL_ID_SELF);
                    nClients++;
                }
            }
        }

        /* Read from local app clients → SSH channels */
        for (i = 0; i < nClients; i++) {
            if (FD_ISSET(clients[i].appFd, &errFds)) {
                /* Client socket error — mark for removal */
                goto remove_client;
            }
            if (FD_ISSET(clients[i].appFd, &rxFds)) {
                int rxd = (int)recv(clients[i].appFd,
                        clients[i].appBuf + clients[i].appBufUsed,
                        FWD_BUFFER_SZ - clients[i].appBufUsed, 0);
                if (rxd <= 0) {
                    /* Client disconnected */
                    goto remove_client;
                }
                clients[i].appBufUsed += rxd;
            }

            /* Flush pending data to SSH channel */
            if (clients[i].appBufUsed > 0 && clients[i].channel != NULL) {
                ret = wolfSSH_ChannelSend(clients[i].channel,
                        clients[i].appBuf, clients[i].appBufUsed);
                if (ret > 0) {
                    if ((word32)ret < clients[i].appBufUsed) {
                        WMEMMOVE(clients[i].appBuf,
                                clients[i].appBuf + ret,
                                clients[i].appBufUsed - ret);
                    }
                    clients[i].appBufUsed -= ret;
                }
                else if (ret != WS_CHANNEL_NOT_CONF &&
                         ret != WS_CHAN_RXD &&
                         ret != WS_WANT_WRITE &&
                         ret != WS_WANT_READ) {
                    goto remove_client;
                }
            }
            continue;

        remove_client:
            WCLOSESOCKET(clients[i].appFd);
            if (clients[i].channel != NULL)
                wolfSSH_ChannelExit(clients[i].channel);
            /* Shift remaining clients down */
            if (i < nClients - 1) {
                WMEMMOVE(&clients[i], &clients[i + 1],
                        sizeof(struct fwd_client) * (nClients - 1 - i));
            }
            nClients--;
            i--; /* Re-check this index */
        }

        /* Read from SSH → distribute to local clients */
        if (FD_ISSET(sshFd, &rxFds)) {
            word32 channelId = 0;

            ret = wolfSSH_worker(ssh, &channelId);
            if (ret == WS_CHAN_RXD) {
                WOLFSSH_CHANNEL* readCh;
                int readRet;

                readCh = wolfSSH_ChannelFind(ssh,
                        channelId, WS_CHANNEL_ID_SELF);
                if (readCh != NULL) {
                    readRet = wolfSSH_ChannelRead(readCh,
                            sshBuf, FWD_BUFFER_SZ);
                    if (readRet > 0) {
                        /* Find the client for this channel */
                        for (i = 0; i < nClients; i++) {
                            if (clients[i].channelId == channelId) {
                                send(clients[i].appFd,
                                        sshBuf, readRet, 0);
                                break;
                            }
                        }
                    }
                }
            }
            else if (ret == WS_CHANNEL_CLOSED) {
                /* A channel closed — find and remove client */
                for (i = 0; i < nClients; i++) {
                    if (clients[i].channelId == channelId) {
                        WCLOSESOCKET(clients[i].appFd);
                        if (i < nClients - 1) {
                            WMEMMOVE(&clients[i], &clients[i + 1],
                                sizeof(struct fwd_client) *
                                    (nClients - 1 - i));
                        }
                        nClients--;
                        break;
                    }
                }
                /* Check if SSH itself is dead */
                if (wolfSSH_get_error(ssh) == WS_SOCKET_ERROR_E ||
                    wolfSSH_get_error(ssh) == WS_CBIO_ERR_CONN_CLOSE) {
                    fprintf(stderr, "SSH connection lost\n");
                    break;
                }
            }
            else if (ret == WS_EOF || ret == WS_FATAL_ERROR) {
                int err = wolfSSH_get_error(ssh);
                if (err == WS_SOCKET_ERROR_E ||
                    err == WS_CBIO_ERR_CONN_CLOSE) {
                    fprintf(stderr, "SSH connection closed\n");
                    break;
                }
            }
        }
    }

    /* Cleanup */
    for (i = 0; i < nClients; i++)
        WCLOSESOCKET(clients[i].appFd);
    for (i = 0; i < nListeners; i++)
        WCLOSESOCKET(listenFds[i]);
#ifdef WOLFSSH_HAVE_UNIX_SOCKET
    /* Remove local Unix socket files */
    for (i = 0; i < config->fwdCount; i++) {
        if (config->fwdSpecs[i].isLocalSocket) {
#ifdef USE_WINDOWS_API
            DeleteFileA(config->fwdSpecs[i].localSocketPath);
#else
            unlink(config->fwdSpecs[i].localSocketPath);
#endif
        }
    }
#endif

    return 0;
}
#endif /* WOLFSSH_FWD */


static THREAD_RETURN WOLFSSH_THREAD wolfSSH_Client(void* args)
{
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH* ssh = NULL;
    SOCKET_T sockFd = WOLFSSH_SOCKET_INVALID;
    SOCKADDR_IN_T clientAddr;
    socklen_t clientAddrSz = sizeof(clientAddr);
    int ret = 0;
    int ioErr = 0;
    byte keepOpen = 0;
    byte stdinIsTty = isatty(STDIN_FILENO) ? 1 : 0;
#ifdef USE_WINDOWS_API
    byte rawMode = 0;
#endif
#ifdef WOLFSSH_AGENT
    byte useAgent = 0;
    WS_AgentCbActionCtx agentCbCtx;
#endif
    struct config config;

    if (stdinIsTty)
        MODES_STORE();

    ((func_args*)args)->return_code = 0;

    config_init_default(&config);
    config_parse_command_line(&config,
            ((func_args*)args)->argc, ((func_args*)args)->argv);
    config_resolve_user(&config);
    config_resolve_key(&config);
    config_print(&config);

    if (config.printConfig) {
        config_cleanup(&config);
        ((func_args*)args)->return_code = 0;
        return 0;
    }

    if (config.user == NULL)
        err_sys("client requires a username parameter.");

    if (config.hostname == NULL)
        err_sys("client requires a hostname parameter.");

    /* If no command and not -N, default to an interactive shell when stdin
     * is a terminal. -t explicitly requests the terminal channel. */
    if ((config.command == NULL && !config.noCommand) || config.forceTty) {
#ifdef WOLFSSH_FWD
        if (config.fwdCount > 0) {
            /* Forwarding mode: keep session alive without PTY */
            config.noCommand = 1;
        }
        else
#endif
        if (config.forceTty || stdinIsTty)
            keepOpen = 1;
        else
            config.noCommand = 1; /* no tty, no command → nothing to do */
    }

#ifdef SINGLE_THREADED
    if (keepOpen)
        err_sys("Threading needed for terminal session\n");
#endif

    if (config.keyFile) {
        ret = ClientSetPrivateKey(config.keyFile);
        if (ret == 0) {
        #ifdef WOLFSSH_CERTS
            /* Try to extract certificate from composite key file first */
            ret = ClientUseCertFromKeyFile(config.keyFile);
            if (ret == 0) {
                /* Certificate found in key file, x509 mode auto-enabled */
                config.forceX509 = 1;
            }
            else if (certName) {
                /* Explicit certificate provided */
                (void)ClientUseCert(certName);
            }
            else
        #endif
            if (config.pubKeyFile) {
                (void)ClientUsePubKey(config.pubKeyFile);
            }
        }
    }

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        err_sys("Couldn't create wolfSSH client context.");

    wolfSSH_SetUserAuth(ctx, ClientUserAuth);

#ifdef WOLFSSH_AGENT
    if (useAgent) {
        wolfSSH_CTX_set_agent_cb(ctx,
                wolfSSH_AGENT_DefaultActions, wolfSSH_AGENT_IO_Cb);
        wolfSSH_CTX_AGENT_enable(ctx, 1);
    }
#endif

#ifdef WOLFSSH_CERTS
    ClientLoadCA(ctx, caCert);
#endif /* WOLFSSH_CERTS */

    wolfSSH_CTX_SetPublicKeyCheck(ctx, ClientPublicKeyCheck);

    ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        err_sys("Couldn't create wolfSSH session.");

#ifdef WOLFSSH_CERTS
    if (config.forceX509) {
        /* Set x509 public key algo list to prioritize cert-based auth */
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

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    wolfSSH_SetGlobalReq(ctx, callbackGlobalReq);
    wolfSSH_SetGlobalReqCtx(ssh, &ssh); /* dummy ctx */
#endif

#ifdef WOLFSSH_AGENT
    if (useAgent) {
        WMEMSET(&agentCbCtx, 0, sizeof(agentCbCtx));
        agentCbCtx.state = AGENT_STATE_INIT;
        wolfSSH_set_agent_cb_ctx(ssh, &agentCbCtx);
    }
#endif

    wolfSSH_SetPublicKeyCheckCtx(ssh, (void*)config.hostname);

    ret = wolfSSH_SetUsername(ssh, config.user);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the username.");

    build_addr(&clientAddr, config.hostname, config.port);
    tcp_socket(&sockFd, ((struct sockaddr_in *)&clientAddr)->sin_family);

    ret = connect(sockFd, (const struct sockaddr *)&clientAddr, clientAddrSz);
    if (ret != 0)
        err_sys("Couldn't connect to server.");

    tcp_set_nonblocking(&sockFd);

    ret = wolfSSH_set_fd(ssh, (int)sockFd);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't set the session's socket.");

#ifdef WOLFSSH_FWD
    if (config.fwdCount > 0 && config.command == NULL) {
        /* For forwarding-only mode (-L without command), run a long sleep
         * to keep the session channel alive on the server side */
        static const char fwdKeepCmd[] = "sleep 86400";
        ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_EXEC,
                            (byte*)fwdKeepCmd,
                            (word32)WSTRLEN(fwdKeepCmd));
        if (ret != WS_SUCCESS)
            err_sys("Couldn't set the channel type for forwarding.");
    }
#endif

    if (config.command != NULL) {
        ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_EXEC,
                            (byte*)config.command,
                            (word32)WSTRLEN((char*)config.command));
        if (ret != WS_SUCCESS)
            err_sys("Couldn't set the channel type.");
    }

#ifdef WOLFSSH_TERM
    if (keepOpen) {
        ret = wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_TERMINAL, NULL, 0);
        if (ret != WS_SUCCESS)
            err_sys("Couldn't set the terminal channel type.");
    }
#endif

    ret = NonBlockSSH_connect(ssh);
    if (ret != WS_SUCCESS)
        err_sys("Couldn't connect SSH stream.");

#ifdef WOLFSSH_FWD
    if (config.fwdCount > 0) {
        /* Switch SSH socket back to blocking for select() loop */
#ifndef USE_WINDOWS_API
        {
            int flags = fcntl(sockFd, F_GETFL, 0);
            if (flags >= 0)
                fcntl(sockFd, F_SETFL, flags & ~O_NONBLOCK);
        }
#endif
        localForwardLoop(ssh, &config);
        goto fwd_cleanup;
    }
#endif /* WOLFSSH_FWD */

    if (keepOpen && stdinIsTty)
        MODES_CLEAR();

#ifdef USE_WINDOWS_API
    if (keepOpen && stdinIsTty) {
        /* Disable console local echo in PTY mode.
         * The remote PTY handles echo; local echo would cause
         * double line breaks (CMD echo + server echo). */
        ClientSetEcho(2);
    }
#endif

#if !defined(SINGLE_THREADED) && !defined(WOLFSSL_NUCLEUS)
#if 0
    if (keepOpen) /* set up for pseudo-terminal */
        ClientSetEcho(2);
#endif

    if (config.command != NULL || keepOpen == 1) {
    #if defined(_POSIX_THREADS) && !defined(USE_WINDOWS_API)
        thread_args arg;
        pthread_t   thread[3];

        wc_InitMutex(&arg.lock);
        arg.ssh = ssh;
        arg.readError = 0;
#ifdef WOLFSSH_TERM
        arg.quit = 0;
        if (!wolfSSH_SEMAPHORE_Init(&windowSem, 0)) {
            err_sys("Couldn't initialize window semaphore.");
        }

        if (config.command) {
            int err;

            /* exec command does not contain initial terminal size,
             * unlike pty-req. Send an initial terminal size for receiving
             * the results of the command */
            err = sendCurrentWindowSize(&arg);
            if (err != WS_SUCCESS) {
                fprintf(stderr, "Issue sending exec initial terminal size\n\r");
            }
        }

        signal(SIGWINCH, WindowChangeSignal);
        pthread_create(&thread[0], NULL, windowMonitor, (void*)&arg);
#endif /* WOLFSSH_TERM */
        pthread_create(&thread[1], NULL, readInput, (void*)&arg);
        pthread_create(&thread[2], NULL, readPeer, (void*)&arg);
        pthread_join(thread[2], NULL);
#ifdef WOLFSSH_TERM
        /* Wake the windowMonitor thread so it can exit. */
        arg.quit = 1;
        signal(SIGWINCH, SIG_DFL);
        wolfSSH_SEMAPHORE_Post(&windowSem);
        pthread_join(thread[0], NULL);
#endif /* WOLFSSH_TERM */
        pthread_cancel(thread[1]);
        pthread_join(thread[1], NULL);
#ifdef WOLFSSH_TERM
        wolfSSH_SEMAPHORE_Release(&windowSem);
#endif /* WOLFSSH_TERM */
        ioErr = arg.readError;
    #elif defined(USE_WINDOWS_API) || defined(_MSC_VER)
        thread_args arg;
        HANDLE thread[2];

        arg.ssh     = ssh;
        arg.rawMode = rawMode;
        arg.readError = 0;
        wc_InitMutex(&arg.lock);

        if (config.command) {
            int err;

            /* exec command does not contain initial terminal size,
             * unlike pty-req. Send an initial terminal size for receiving
             * the results of the command */
            err = sendCurrentWindowSize(&arg);
            if (err != WS_SUCCESS) {
                fprintf(stderr, "Issue sending exec initial terminal size\n\r");
            }
        }

        thread[0] = CreateThread(NULL, 0, readInput, (void*)&arg, 0, 0);
        thread[1] = CreateThread(NULL, 0, readPeer, (void*)&arg, 0, 0);
        WaitForSingleObject(thread[1], INFINITE);
        CloseHandle(thread[0]);
        CloseHandle(thread[1]);
        ioErr = arg.readError;
    #else
        err_sys("No threading to use");
    #endif
        if (keepOpen && stdinIsTty)
            ClientSetEcho(1);
    }
#endif

#ifdef WOLFSSH_FWD
fwd_cleanup:
#endif
    ret = wolfSSH_shutdown(ssh);
    /* do not continue on with shutdown process if peer already disconnected */
    if (ret != WS_SOCKET_ERROR_E
            && wolfSSH_get_error(ssh) != WS_SOCKET_ERROR_E) {
        if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG, "Sending the shutdown messages failed.");
        }
        else {
            ret = wolfSSH_worker(ssh, NULL);
        }
        if (ret == WS_CHANNEL_CLOSED) {
            /* Shutting down, channel closing isn't a fail. */
            ret = WS_SUCCESS;
        }
        else if (ret != WS_SUCCESS) {
            WLOG(WS_LOG_DEBUG,
                "Failed to listen for close messages from the peer.");
        }
    }
    WCLOSESOCKET(sockFd);

#if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
    ((func_args*)args)->return_code = wolfSSH_GetExitStatus(ssh);
#endif
    /* Only override exit status for real I/O errors, not for
     * normal channel close (WS_CHANNEL_CLOSED) which happens
     * when the remote command finishes and the server closes
     * the channel. */
    if (ioErr != 0 && ioErr != WS_CHANNEL_CLOSED &&
        ((func_args*)args)->return_code == 0) {
        ((func_args*)args)->return_code = 1;
    }

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);
    if ((ret != WS_SUCCESS && ret != WS_SOCKET_ERROR_E) ||
        (ioErr != 0 && ioErr != WS_CHANNEL_CLOSED)) {
        WLOG(WS_LOG_DEBUG, "Closing client stream failed");
    #if defined(WOLFSSH_TERM) || defined(WOLFSSH_SHELL)
        /* override return value, do not want to return success if connection
         * close failed */
        ((func_args*)args)->return_code = 1;
    #endif
    }

    ClientFreeBuffers();
#if !defined(WOLFSSH_NO_ECC) && defined(FP_ECC) && defined(HAVE_THREAD_LS)
    wc_ecc_fp_free();  /* free per thread cache */
#endif

    config_cleanup(&config);
    if (stdinIsTty)
        MODES_RESET();

    return 0;
}


int main(int argc, char** argv)
{
    func_args args;

    args.argc = argc;
    args.argv = argv;
    args.return_code = 0;
    args.user_auth = NULL;

    WSTARTTCP();

    #ifdef DEBUG_WOLFSSH
        wolfSSH_Debugging_ON();
    #endif

    wolfSSH_Init();

    wolfSSH_Client(&args);

    wolfSSH_Cleanup();

    return args.return_code;
}
