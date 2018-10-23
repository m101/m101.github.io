// @author  m_101
// @year    2011
// @desc    GCHQ level 3 reversed
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <sys/socket.h>
#include <netdb.h>

#include <crypt.h>

#define SERVER_PORT 80

static const char crypted_password[] = "hqDTK7b8K2rvw";

int server_connect(char *hostname, uint32_t keys[]) {
    int retcode;
    char buffer[256] = {0};
    // socket stuffs
    int sockfd;
    struct hostent *host;
    struct sockaddr_in addr;
    // recv stuffs
    int recvBytes = 0;

    host = gethostbyname(hostname);
    if (host == 0) {
        printf("error: gethostbyname() failed\n");
        return -1;
    }

    // set up sockaddr
    memcpy(&(addr.sin_addr), host->h_addr_list[0], host->h_length);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);

    // open socket
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // connect to target
    retcode = connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    if (retcode != 0) {
        printf("error: connect(\"%s\") failed\n", hostname);
        return -1;
    }

    // construct GET request
    sprintf(buffer, "GET /%s/%x/%x/%x/key.txt HTTP/1.0\r\n\r\n", crypted_password, keys[0], keys[1], keys[2]);
    printf("request:\n\n%s", buffer);

    // send request
    retcode = send(sockfd, buffer, strlen(buffer), 0);
    if (retcode <= 0) {
        printf("error: send() failed\n");
        return -1;
    }

    // get response
    printf("response:\n\n");

    do {
        memset(buffer, 0, sizeof(buffer));
        recvBytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (recvBytes > 0)
            printf("%s", buffer);
    } while (recvBytes > 0);
    printf("\n");

    return recvBytes;
}

int main (int argc, char *argv[]) {
    FILE *fp;
    char buffer[24] = {0};
    uint32_t *ptr = (uint32_t *) buffer;
    // license stuffs
    int hasLicense;
    char *crypted;
    uint32_t keys[3] = {0};

    hasLicense = 0;
    printf("\nkeygen.exe\n\n");

    // check args
    if (argc != 2) {
        printf("usage: keygen.exe hostname\n");
        return -1;
    }

    // open license file
    fp = fopen("license.txt", "r");
    if (!fp) {
        printf("error: license.txt not found\n");
        return -1;
    }

    memset(buffer, 0, 24);
    fscanf(fp, "%s", buffer);
    fclose(fp);

    // if buffer does not begin with gchq
    // then bye
    if (*ptr != 0x71686367) {
        printf("error: license.txt invalid\n");
        return -1;
    }

    // check for password
    crypted = crypt(buffer + 4, crypted_password);
    if (strcmp(crypted, crypted_password) == 0)
        hasLicense = 1;

    printf("loading stage1 license key(s)...\n");
    keys[0] = *((uint32_t *)(buffer + 12));
    printf("loading stage2 license key(s)...\n\n");
    keys[1] = *((uint32_t *)(buffer + 16));
    keys[2] = *((uint32_t *)(buffer + 20));
    // if we don't have license
    // then bye
    if (hasLicense == 0) {
        printf("error: license.txt invalid\n");
        return -1;
    }

    return server_connect(argv[1], keys);
}

