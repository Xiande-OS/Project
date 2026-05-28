/* UDP DNS test: query 10.0.2.3:53 for example.com A. Prints hex of reply.
 * Exits non-zero on failure. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static unsigned char query[] = {
    /* header: ID, flags=0x0100 (std query, RD=1), qd=1 */
    0x12, 0x34,  0x01, 0x00,  0x00, 0x01,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00,
    /* qname: 7 example 3 com 0 */
    7,'e','x','a','m','p','l','e', 3,'c','o','m', 0,
    /* qtype=A (1), qclass=IN (1) */
    0, 1,  0, 1,
};

int main(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(53);
    sa.sin_addr.s_addr = inet_addr("10.0.2.3");

    if (sendto(fd, query, sizeof(query), 0,
               (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto"); return 2;
    }

    unsigned char reply[1024];
    struct sockaddr_in from = {0};
    socklen_t fl = sizeof(from);
    ssize_t n = recvfrom(fd, reply, sizeof(reply), 0,
                        (struct sockaddr*)&from, &fl);
    if (n < 0) { perror("recvfrom"); return 3; }

    printf("[dnstest] %zd bytes from %s:%d\n",
           n, inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    int qname_found = 0;
    /* check QNAME bytes appear somewhere in the reply */
    for (ssize_t i = 0; i + 13 < n; i++) {
        if (reply[i] == 7 && memcmp(&reply[i+1], "example", 7) == 0
            && reply[i+8] == 3 && memcmp(&reply[i+9], "com", 3) == 0) {
            qname_found = 1; break;
        }
    }
    printf("[dnstest] qname echoed: %s\n", qname_found ? "yes" : "no");

    /* dump first 64 bytes of reply as hex */
    int dump = n < 64 ? (int)n : 64;
    for (int i = 0; i < dump; i++) {
        printf("%02x", reply[i]);
        if (i % 16 == 15) printf("\n");
        else printf(" ");
    }
    if (dump % 16) printf("\n");

    close(fd);
    return qname_found ? 0 : 4;
}
