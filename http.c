#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <llhttp.h>
#include <netdb.h>
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

#define ROOT "/home/apaz/Downloads"
#define PORT "8080"
#define PRINT_START_MESSAGE 1
#define MAX_MSG_LEN 99999
#define MAX_PATH_LEN 2048
#define MAX_QUEUED_CONNECTIONS 1000

#define NUM_HEADERS

typedef struct {

} HTTPRequest;
void HTTPRequest_destroy(HTTPRequest *req);

static inline int startServer(void);
static inline void serverStartListening(int listenfd);

static inline void appendHeaders(char *buf, char *header, size_t len);
static inline void appendContent(char *buf, char *content, size_t len);

typedef void (*requestHandler)(HTTPRequest *request);

static inline void *handleConnection(void *cli_fd);

static inline void handleGET(HTTPRequest *request) {}
static inline void handleHEAD(HTTPRequest *request) {}
static inline void handlePOST(HTTPRequest *request) {}
static inline void handlePUT(HTTPRequest *request) {}
static inline void handleDELETE(HTTPRequest *request) {}
static inline void handleCONNECT(HTTPRequest *request) {}
static inline void handleOPTIONS(HTTPRequest *request) {}
static inline void handleTRACE(HTTPRequest *request) {}
static inline void handlePATCH(HTTPRequest *request) {}

int main(void) {
  int listenfd;

  listenfd = startServer();

  serverStartListening(listenfd);

  return 0;
}

static inline int startServer(void) {
  struct addrinfo hints, *res, *p;
  int listenfd;

  // Get address info for host
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, PORT, &hints, &res) != 0) {
    perror("getaddrinfo() error");
    exit(1);
  }

  // Create sockets and bind our address to them.
  for (p = res; p != NULL; p = p->ai_next) {
    listenfd = socket(p->ai_family, p->ai_socktype, 0);
    if (listenfd == -1)
      continue;
    if (!bind(listenfd, p->ai_addr, p->ai_addrlen))
      break;
  }
  if (p == NULL) {
    perror("socket() or bind() error");
    exit(1);
  }

  freeaddrinfo(res);

  // listen for incoming connections
  if (listen(listenfd, MAX_QUEUED_CONNECTIONS)) {
    perror("listen() error");
    exit(1);
  }

  if (PRINT_START_MESSAGE) {
    printf("\x1b[33mHTTP server started.\033[0m\n"
           "\x1b[35mPORT\033[0m: \033[92m%s\033[0m\n"
           "\x1b[35mROOT\033[0m: \033[92m%s\033[0m\n",
           PORT, ROOT);
  }

  return listenfd;
}

static inline void serverStartListening(int listenfd) {
  struct sockaddr_in clientaddr;
  socklen_t addrlen = sizeof(socklen_t);
  pthread_t unused_thid;
  int cli_fd;

  while (1) {
    cli_fd = accept(listenfd, (struct sockaddr *)&clientaddr, &addrlen);

    if (cli_fd < 0)
      fprintf(stderr, "accept() error.");
    else {
      pthread_create(&unused_thid, NULL, handleConnection,
                     (void *)(intptr_t)cli_fd);
    }
  }
}

static inline int print_callback(llhttp_t *parser, const char *at,
                                 size_t length) {
  (void)parser;
  (void)length;
  puts(at);
  fflush(stdout);
  return 0;
}

/************************************/
/* Functions for building responses */
/************************************/

static inline int http_response_date_now(char *buf, size_t buf_len) {
  const char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

  time_t now = time(NULL);
  if (now == -1)
    return -1;

  struct tm *tm = gmtime(&now);
  if (tm == NULL)
    return -1;

  return snprintf(buf, buf_len, "%s, %d %s %d %02d:%02d:%02d GMT",
                  days[tm->tm_wday], tm->tm_mday, months[tm->tm_mon],
                  tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec);
}

// to be used by handlers
static inline void appendHeaders(char *header_buffer, char *headers,
                                 size_t len) {}
static inline void appendContent(char *content_buffer, char *content,
                                 size_t len) {}

/* Respond */

static inline void *handleConnection(void *conv) {
  ssize_t rcvd;
  char mesg[MAX_MSG_LEN + 1];
  char path[MAX_PATH_LEN + 1] = ROOT;
  int fd, bytes_read, cli_fd;
  size_t resp_len;

  cli_fd = (int)(intptr_t)(conv);
  pthread_detach(pthread_self());

  rcvd = recv(cli_fd, mesg, MAX_MSG_LEN, 0);
  if (rcvd < 0) {
    fprintf(stderr, ("recv() error\n"));
    goto cleanup;
  } else if (rcvd == 0) {
    fprintf(stderr, "Client disconnected upexpectedly.\n");
    goto cleanup;
  }
  mesg[rcvd] = '\0'; // Null terminate it.

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
  write(cli_fd, "\r\n", 2);    // Write end of stream
  shutdown(cli_fd, SHUT_RDWR); // Close the socket
  close(cli_fd);               // Free the file descriptor
  return NULL;                 // Kill the thread (detached)
}
