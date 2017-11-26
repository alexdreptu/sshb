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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void log_printf(const char *file, char *fmt, ...) {
    FILE *fptr;
    va_list ap;
    int r;

    fptr = fopen(file, "a+t");
    if (!fptr) return;

    va_start(ap, fmt);
    r = vfprintf(fptr, fmt, ap);
    va_end(ap);
    if (r == -1) fprintf(stderr, "log_printf: vfprintf error.");

    fflush(fptr);
    fclose(fptr);
}

// print progress
void log_stat(char *fmt, ...) {
    FILE *fptr_stat;
    va_list ap;
    char stat_file[512];
    int r;

    sprintf(stat_file, ".pid_stat/%d", getpid());
    fptr_stat = fopen(stat_file, "w+t");
    if (!fptr_stat) {
        fprintf(stderr, "Pid file cannot be created, continuing...\n");
        return;
    }

    // fseek(fptr_stat, 0L, SEEK_SET);

    va_start(ap, fmt);
    r = vfprintf(fptr_stat, fmt, ap);
    va_end(ap);
    if (r == -1) fprintf(stderr, "log_stat: vfprintf error.");

    fflush(fptr_stat);
    fclose(fptr_stat);
}
