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
#define NUM_THREADS 8

/* Create different kinds of servers. */
#define SOCKTYPE_OFFSET 0
#define STREAMTYPE_OFFSET 1
#define HANDLE_OFFSET 2

#define GET_USING_UDP(config) ((config >> SOCKTYPE_OFFSET) & 1)
#define GET_USING_TLS(config) ((config >> STREAMTYPE_OFFSET) & 1)
#define GET_USING_HTTP(config) ((config >> HANDLE_OFFSET) & 1)

#define CONFIG_TCP (0 << SOCKTYPE_OFFSET)
#define CONFIG_UDP (1 << SOCKTYPE_OFFSET)
#define CONFIG_UNENCRYPTED (0 << STREAMTYPE_OFFSET)
#define CONFIG_SSL_TLS (1 << STREAMTYPE_OFFSET)
#define CONFIG_RAW_CONN (0 << HANDLE_OFFSET)
#define CONFIG_HTTP_CONN (1 << HANDLE_OFFSET)

#define HTTP_SERVER_CONFIG (CONFIG_TCP | CONFIG_UNENCRYPTED | CONFIG_HTTP_CONN)
#define HTTPS_SERVER_CONFIG (CONFIG_TCP | CONFIG_SSL_TLS | CONFIG_HTTP_CONN)
#define TLS_SERVER_CONFIG (CONFIG_TCP | CONFIG_SSL_TLS | CONFIG_RAW_CONN)
#define UDP_SERVER_CONFIG (CONFIG_UDP | CONFIG_UNENCRYPTED | CONFIG_RAW_CONN)

#define PRINT_START_MESSAGE 1
#define MAX_MSG_LEN 99999
#define MAX_QUEUED_CONNECTIONS 10000
#define PAGE_SIZE 4096
#define HTTP_VERSION_SIZE 16
#define MAX_REQUEST_PATH_LEN (PAGE_SIZE / 2)
#define ARENA_SIZE (PAGE_SIZE * 10)
#define ARENA_BUF_SIZE (ARENA_SIZE - (sizeof(void*) + sizeof(size_t)))
#define RESPONSE_BUFFER_SIZE (PAGE_SIZE * 10)
#define RAW_REQUEST_INITIAL_SIZE (PAGE_SIZE * 3)

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
typedef struct {
    char* buf;
    size_t size;
    size_t cap;
} BufferHandle;
typedef struct {
    char* buf;
    size_t size;
    size_t cap;
    ServerConfig config;
    SSL* ssl;
} ResponseBufferHandle;

/* Objects to write code to handle */
struct Arena;
typedef struct Arena Arena;
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
} RawRequest;
typedef struct {
    fd_t cli_fd;
    ServerConfig config;

    char version[HTTP_VERSION_SIZE];
    char request_url[MAX_REQUEST_PATH_LEN];

    llhttp_method_t method;
    struct {
        size_t* name_offsets;
        size_t* value_offsets;
        size_t map_size;
        int last_added_key;
    } request_headers;

    size_t response_size;
    ResponseBuffer* response_buffer;

    Arena arena;
} HTTPRequest;
static inline void HTTPRequest_create(HTTPRequest* req);
static inline void HTTPRequest_destroy(HTTPRequest* req);

/* Assert that argument packing a void* will work. Also assert
   that time will work past the year 2038 and Arena size is right. */
_Static_assert((sizeof(void*) == (sizeof(fd_t) + sizeof(ServerConfig))), "Packing a void* will not work.");
_Static_assert((sizeof(uintptr_t) == (sizeof(fd_t) + sizeof(ServerConfig))), "Packing a void* will not work.");
_Static_assert((sizeof(time_t) > ((32 / CHAR_BIT) + (32 % CHAR_BIT != 0))), "Time will not work past the year 2038.");
_Static_assert(sizeof(Arena) == ARENA_SIZE, "sizeof(void*) != sizeof(Arena*)? Odd padding issues?");

/* Main API */
/* Creating the server */
static inline fd_t startServer(int port, ServerConfig config);
static inline void serverStartListening(fd_t sock_fd, ServerConfig config);
static inline void* handleConnection(void* cli_fd);
static inline SSL_CTX* create_ssl_context(const char* key_file, const char* cert_file);

/* Handle requests */
/* You define a handler. Implement handleHTTPRequest() if you're using
   HTTP/HTTPS, or handleRawRequest() if using a raw connection. */
typedef void (*requestHandler)(void* request);
static inline void handleHTTPRequest(HTTPRequest* request);
static inline void handleRawRequest(RawRequest* request);

/* Build a response */
static inline int wouldOverflow(size_t into_size, size_t into_cap, size_t from_size);
static inline int bufferWouldOverflow(BufferHandle into, BufferHandle from);
static inline void flushResponseBuffer(ResponseBufferHandle h, ServerConfig config, SSL* ssl);
static inline void appendToResponse(ResponseBufferHandle to, BufferHandle from);
static inline void appendLineToResponse(ResponseBufferHandle to, BufferHandle from);
static inline void appendToResponseFmt(ResponseBufferHandle buf, char* fmt, ...);

/********/
/* MAIN */
/********/

SSL_CTX* ctx;

int
main(void) {
    fd_t sock_fd;
    ServerConfig config = HTTP_SERVER_CONFIG;

    if (GET_USING_TLS(config)) {
        ctx = create_ssl_context(SSL_KEY_FILE, SSL_CERT_FILE);
    }

    sock_fd = startServer(PORT, config);

    serverStartListening(sock_fd, config);

    return 0;
}

/***********************/
/* Starting the Server */
/***********************/

static inline fd_t
startServer(int port, ServerConfig config) {
    ServerConfig using_udp;
    struct sockaddr_in addr;
    fd_t sock_fd;

    using_udp = GET_USING_UDP(config);
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
            "\x1b[33m%s server started.\033[0m\n"
            "\x1b[35mPORT\033[0m: \033[92m%i\033[0m\n"
            "\x1b[35mROOT\033[0m: \033[92m%s\033[0m\n",
            GET_USING_HTTP(config) ? (GET_USING_TLS(config) ? "HTTPS" : "HTTP")
                                   : (GET_USING_TLS(config) ? "TLS" : (GET_USING_UDP(config) ? "UDP" : "TCP")),
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

    using_tls = GET_USING_TLS(config);
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
create_ssl_context(const char* key_file, const char* cert_file) {
    SSL_CTX* ssl_ctx;

    /* Create SSL TLS context */
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ssl_ctx, SSL_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, SSL_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    return ssl_ctx;
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
const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

static inline void
http_response_date_now(ResponseBufferHandle response) {
    struct tm tm;
    time_t now;

    now = time(NULL);
    if (now == -1) pthread_exit(NULL);

    if (!gmtime_r(&now, &tm)) pthread_exit(NULL);

#define TIME_TMP_BUF_SIZE 256
    char timespace[TIME_TMP_BUF_SIZE];
    int space = sprintf(timespace, "%s, %d %s %d %02d:%02d:%02d GMT", days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon],
                        tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);

    BufferHandle handle = {timespace, (size_t)space, TIME_TMP_BUF_SIZE};
    appendLineToResponse(response, handle);
}

static inline int
wouldOverflow(size_t into_size, size_t into_cap, size_t from_size) {
    return (into_size + from_size) > into_cap;
}
static inline int
bufferWouldOverflow(BufferHandle into, BufferHandle from) {
    return wouldOverflow(into.size, into.cap, from.size);
}
static inline void
flushResponseBuffer(ResponseBufferHandle h, ServerConfig config, SSL* ssl) {}
static inline void
appendToResponse(ResponseBufferHandle to, BufferHandle from) {}
static inline void
appendLineToResponse(ResponseBufferHandle to, BufferHandle from) {}
static inline void
appendToResponseFmt(ResponseBufferHandle buf, char* fmt, ...) {}

/* Respond */

static inline void*
handleConnection(void* conv) {
    ConnectionBuffer mesg[MAX_MSG_LEN + 1];
    ssize_t rcvd;
    int bytes_read;
    ServerConfig config;
    fd_t cli_fd;
    size_t resp_len;
    int using_tls, using_http;

    llhttp_t parser;
    llhttp_settings_t settings;
    enum llhttp_errno err;
    SSL* ssl;

    // outputs
    HTTPRequest request;
    char* raw_request;
    size_t raw_request_size;

    cli_fd = (fd_t)((intptr_t)conv >> 0);
    config = (ServerConfig)((intptr_t)conv >> 32);
    using_tls = GET_USING_TLS(config);
    using_http = GET_USING_HTTP(config);

    pthread_detach(pthread_self());

    /* If this connection uses TLS (SSL), create an SSL object using the global
     * context. */
    if (using_tls) {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cli_fd);
    }

    /* If this is an HTTP server, initialize the parser. */
    if (using_http) {
        settings.on_url = print_callback;
        settings.on_header_field = print_callback;
        settings.on_header_value = print_callback;
        settings.on_status = print_callback;
        settings.on_body = print_callback;

        llhttp_settings_init(&settings);
        llhttp_init(&parser, HTTP_REQUEST, &settings);
    }

    /* Initialize a buffer to copy the raw data from the client into. This is
     * decoded first if using ssl/tls. It will be incorporated into the
     * HTTPRequest object, or handled directly if a raw connection. */
    raw_request_size = RAW_REQUEST_INITIAL_SIZE;
    raw_request = malloc(RAW_REQUEST_INITIAL_SIZE);
    if (using_http) {
        HTTPRequest_create(&request);
    }

    do {
        /* Read from the connection into the buffer. */
        rcvd = using_tls ? SSL_read(ssl, mesg, MAX_MSG_LEN) : recv(cli_fd, mesg, MAX_MSG_LEN, 0);
        if (rcvd < 0) {
            fprintf(stderr, "Error reading from the connection.\n");
            goto cleanup;
        }

        /* Run it through the http parser. */
        if (using_http) {
            err = llhttp_execute(&parser, mesg, rcvd);
            if (err != HPE_OK) {
                fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), parser.reason);
                write(cli_fd, "HTTP/1.0 400 Bad Request\n", 25);
                goto cleanup;
            }
        }

        /* Append it to the buffer. */
        

    } while (rcvd);

    llhttp_finish(&parser);

    write(cli_fd, "HTTP/1.0 200 OK\r\n\r\n", 19);
    write(cli_fd, "This is a test.", 15);

cleanup:;
    shutdown(cli_fd, SHUT_RDWR);  // Close the socket
    close(cli_fd);                // Free the file descriptor
    return NULL;                  // Kill the thread (detached)
}

/* Arena */
static inline Arena*
Arena_create(Arena* prev) {
    Arena* new_arena;
    new_arena = (Arena*)malloc(ARENA_SIZE);
    if (!new_arena) return NULL;
    new_arena->next = NULL;
    new_arena->size = 0;
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
    BufferHandle into, from;

    into.cap = ARENA_BUF_SIZE;
    into.size = on->size;
    from.size = size;

    if (bufferWouldOverflow(into, from)) {
        on = Arena_create(on);
    }

    ret = on->buf + on->size;
    on->size += size;
    return (void*)ret;
}
