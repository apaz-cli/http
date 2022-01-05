#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "llhttp/build/llhttp.h"

/* Edit these to configure the server. */
/* An SSL key and certificate are required only to use SSL. */
#define ROOT "/home/apaz/Downloads"
#define PORT 8080
#define SSL_KEY_FILE ""
#define SSL_CERT_FILE ""

/* Create different kinds of servers. */
#define SOCKTYPE_OFFSET 0
#define STREAMTYPE_OFFSET 1
#define USE_TCP (0 << SOCKTYPE_OFFSET)
#define USE_UDP (1 << SOCKTYPE_OFFSET)
#define USE_RAW_CONN (0 << STREAMTYPE_OFFSET)
#define USE_SSL_TLS (1 << STREAMTYPE_OFFSET)
#define USE_HTTP_SERVER (USE_TCP | USE_RAW_CONN)
#define USE_HTTPS_SERVER (USE_TCP | USE_SSL_TLS)

#define PRINT_START_MESSAGE 1
#define MAX_MSG_LEN 99999
#define MAX_REQUEST_PATH_LEN 2048
#define MAX_QUEUED_CONNECTIONS 1000
#define ARENA_SIZE (4096 * 10)
#define RESPONSE_BUFFER_SIZE (4096 * 10)

#ifdef __GNUC__
#define LIKELY(expr) __builtin_expect(!!(expr), 1)
#define UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#else /* !__GNUC__ */
#define LIKELY(expr) expr
#define UNLIKELY(expr) expr
#endif /* __GNUC__ */

/* API typedefs */
typedef int ServerConfig;
typedef int fd_t;
typedef char ConnectionBuffer;
typedef char ResponseBuffer;

/* Creating the server */
static inline fd_t startServer(int port, ServerConfig config);
static inline void serverStartListening(fd_t sock_fd, ServerConfig config);
static inline void* handleConnection(void* cli_fd);
static inline SSL_CTX* create_ssl_context(void);

/* Classes */
struct Arena;
typedef struct Arena Arena;
#define ARENA_BUF_SIZE (ARENA_SIZE - (sizeof(Arena*) + sizeof(size_t)))
struct Arena {
    Arena* next;
    size_t size;
    char buf[ARENA_BUF_SIZE];
};
static inline Arena* Arena_create(Arena* prev);
static inline void Arena_destroy(Arena* to_free);
static inline void* Arena_alloc(Arena* on, size_t size);

typedef struct {
    fd_t cli_fd;
    ServerConfig config;
    char request_url[MAX_REQUEST_PATH_LEN];
    llhttp_method_t method;

    struct {
        size_t* name_offsets;
        size_t* value_offsets;
        size_t map_size;
        int last_added_key;
    } request_headers;

    size_t response_size;
    ResponseBuffer response[RESPONSE_BUFFER_SIZE];

    Arena arena;
} HTTPRequest;
static inline void HTTPRequest_create(HTTPRequest* req);
static inline void HTTPRequest_destroy(HTTPRequest* req);

/* Handling requests */
/* You can use your own request handlers, or use these ones. */
typedef void (*requestHandler)(HTTPRequest* request);
static inline void translateTLSBuffer(ConnectionBuffer* buf, SSL_CTX* ctx);
static inline void handleHTTPBuffer(ConnectionBuffer* buf, HTTPRequest* req);
static inline void handleGET(HTTPRequest* request);
static inline void handleHEAD(HTTPRequest* request);
static inline void handlePOST(HTTPRequest* request);
static inline void handlePUT(HTTPRequest* request);
static inline void handleDELETE(HTTPRequest* request);
static inline void handleCONNECT(HTTPRequest* request);
static inline void handleOPTIONS(HTTPRequest* request);
static inline void handleTRACE(HTTPRequest* request);
static inline void handlePATCH(HTTPRequest* request);

static inline void handleBadRequest(void);
static inline void handleUnimplementedMethod(HTTPRequest* request);

/* Building responses */
static inline int bufferWouldOverflow(size_t current_size, size_t max_size,
                                      size_t to_append);
static inline void flushResponseBuffer(ResponseBuffer* buf, size_t size);
static inline void appendToResponse(ResponseBuffer* buf, char* to_append,
                                    size_t len);
static inline void appendLineToResponse(ResponseBuffer* buf, char* line,
                                        size_t len);
static inline void appendToResponseFmt(ResponseBuffer* buf, char* fmt, ...);

/********/
/* MAIN */
/********/

int
main(void) {
    fd_t listenfd;
    ServerConfig config;

    config = USE_HTTP_SERVER;

    listenfd = startServer(PORT, config);

    serverStartListening(listenfd, config);

    return 0;
}

/***********************/
/* Starting the Server */
/***********************/

static inline fd_t
startServer(int port, ServerConfig config) {
    ServerConfig using_udp; /* 1 for UDP, 0 for TCP*/
    struct sockaddr_in addr;
    fd_t sock_fd;

    using_udp = (config >> 0) & 0x1;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* Open and start listening to socket */
    sock_fd = socket(AF_INET, using_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket() error");
        exit(1);
    }
    if (bind(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind() error");
        exit(1);
    }
    if (listen(sock_fd, MAX_QUEUED_CONNECTIONS)) {
        perror("listen() error");
        exit(1);
    }

    if (PRINT_START_MESSAGE) {
        printf(
            "\x1b[33mHTTP server started.\033[0m\n"
            "\x1b[35mPORT\033[0m: \033[92m%i\033[0m\n"
            "\x1b[35mROOT\033[0m: \033[92m%s\033[0m\n",
            PORT, ROOT);
    }

    return sock_fd;
}

static inline void
serverStartListening(fd_t sock_fd, ServerConfig config) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    pthread_t unused_thid;
    fd_t cli_fd;
    ServerConfig using_tls;
    intptr_t packed_arg;

    /* Assert that argument packing will work. */
    assert((sizeof(void*) == (sizeof(fd_t) + sizeof(ServerConfig))));
    assert((sizeof(uintptr_t) == (sizeof(fd_t) + sizeof(ServerConfig))));
    /* Assert that time will work past the year 2038 while we're at it. */
    assert((sizeof(time_t) > ((32 / CHAR_BIT) + (32 % CHAR_BIT != 0))));

    using_tls = (config >> 1) & 0x1;
    addrlen = sizeof(socklen_t);

    for (;;) {
        cli_fd = accept(sock_fd, (struct sockaddr*)&clientaddr, &addrlen);
        if (cli_fd < 0) {
            perror("accept() error.");
            exit(1);
        }

        packed_arg = ((((intptr_t)cli_fd) << 0) | (((uintptr_t)config) << 32));
        pthread_create(&unused_thid, NULL, handleConnection, (void*)packed_arg);
    }
}

static inline SSL_CTX*
create_ssl_context(void) {
    SSL_CTX* ctx;

    /* Create SSL TLS context */
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, SSL_CERT_FILE, SSL_FILETYPE_PEM) <=
        0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, SSL_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    return ctx;
}

static inline int
print_callback(llhttp_t* parser, const char* at, size_t length) {
    (void)parser;
    (void)length;
    puts(at);
    fflush(stdout);
    return 0;
}

/************************************/
/* Functions for building responses */
/************************************/

const char* days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

static inline void
http_response_date_now(char* buf) {
    struct tm tm;
    time_t now;

    now = time(NULL);
    if (now == -1) pthread_exit(NULL);

    if (!gmtime_r(&now, &tm)) pthread_exit(NULL);

    appendToResponseFmt(buf, "%s, %d %s %d %02d:%02d:%02d GMT",
                        days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon],
                        tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static inline int
bufferWouldOverflow(size_t current_size, size_t max_size, size_t to_append) {
    return (current_size + to_append) >= max_size;
}
static inline void
flushResponseBuffer(ResponseBuffer* buf, size_t size) {}
static inline void
appendToResponse(ResponseBuffer* buf, char* headers, size_t len) {}
static inline void
appendLineToResponse(ResponseBuffer* buf, char* content, size_t len) {}
static inline void
appendToResponseFmt(ResponseBuffer* buf, char* fmt, ...) {}

/* Respond */

static inline void*
handleConnection(void* conv) {
    ssize_t rcvd;
    char mesg[MAX_MSG_LEN + 1];
    char path[MAX_REQUEST_PATH_LEN + 1] = ROOT;
    int bytes_read;
    ServerConfig config;
    fd_t cli_fd;
    size_t resp_len;

    cli_fd = (fd_t)((intptr_t)conv >> 0);
    config = (ServerConfig)((intptr_t)conv >> 32);
    pthread_detach(pthread_self());

    rcvd = recv(cli_fd, mesg, MAX_MSG_LEN, 0);
    if (rcvd < 0) {
        fprintf(stderr, ("recv() error\n"));
        goto cleanup;
    } else if (rcvd == 0) {
        fprintf(stderr, "Client disconnected upexpectedly.\n");
        goto cleanup;
    }
    mesg[rcvd] = '\0';  // Null terminate it.

    printf("MESSAGE:\n");
    printf("%s", mesg);

    llhttp_t parser;
    llhttp_settings_t settings;
    /* Initialize user callbacks and settings */
    llhttp_settings_init(&settings);

    settings.on_url = print_callback;
    settings.on_header_field = print_callback;
    settings.on_header_value = print_callback;
    settings.on_status = print_callback;
    settings.on_body = print_callback;
    settings.on_url = print_callback;

    llhttp_init(&parser, HTTP_REQUEST, &settings);

    enum llhttp_errno err = llhttp_execute(&parser, mesg, rcvd);
    if (err != HPE_OK) {
        fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err),
                parser.reason);
        write(cli_fd, "HTTP/1.0 400 Bad Request\n", 25);
        goto cleanup;
    }
    llhttp_finish(&parser);

    write(cli_fd, "HTTP/1.0 200 OK\r\n\r\n", 19);
    write(cli_fd, "This is a test.", 15);

cleanup:;
    write(cli_fd, "\r\n", 2);     // Write end of stream
    shutdown(cli_fd, SHUT_RDWR);  // Close the socket
    close(cli_fd);                // Free the file descriptor
    return NULL;                  // Kill the thread (detached)
}

static inline void
handleGET(HTTPRequest* request) {}
static inline void
handleHEAD(HTTPRequest* request) {}
static inline void
handlePOST(HTTPRequest* request) {}
static inline void
handlePUT(HTTPRequest* request) {}
static inline void
handleDELETE(HTTPRequest* request) {}
static inline void
handleCONNECT(HTTPRequest* request) {}
static inline void
handleOPTIONS(HTTPRequest* request) {}
static inline void
handleTRACE(HTTPRequest* request) {}
static inline void
handlePATCH(HTTPRequest* request) {}

/* Arena */
static inline Arena*
Arena_create(Arena* prev) {
    Arena* new_arena;
    new_arena = (Arena*)malloc(ARENA_SIZE);
    new_arena->next = NULL;
    new_arena->size = 0;

    assert(sizeof(Arena) == ARENA_SIZE);
    if (prev) prev->next = new_arena;

    return new_arena;
}
static inline void
Arena_destroy(Arena* to_free) {
    if (to_free) {
        Arena* next = to_free->next;
        free(to_free);
        Arena_destroy(next);
    }
}

static inline void*
Arena_alloc(Arena* on, size_t size) {
    char* ret;
    if (bufferWouldOverflow(on->size, ARENA_BUF_SIZE, size))
        on = Arena_create(on);

    ret = on->buf + on->size;
    on->size += size;
    return (void*)ret;
}