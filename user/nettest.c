/* TCP client smoke test for xiande-os M8.
 *
 * Connects to 10.0.2.2:5555 (QEMU user-net host), sends a tiny HTTP
 * request, prints whatever the host sends back, exits.
 *
 * Run before booting:
 *   $ printf 'HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello' | nc -l -p 5555
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(5555);
    sa.sin_addr.s_addr = inet_addr("10.0.2.2");

    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("connect"); return 2;
    }

    const char *req = "GET / HTTP/1.0\r\n\r\n";
    if (send(fd, req, strlen(req), 0) < 0) { perror("send"); return 3; }

    char buf[4096];
    ssize_t total = 0;
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = 0;
        fputs(buf, stdout);
        fflush(stdout);
        total += n;
        if (total > (ssize_t)sizeof(buf) * 8) break;
    }
    printf("\n[nettest] read %zd bytes\n", total);
    close(fd);
    return 0;
}
