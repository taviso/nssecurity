// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// Logging routines.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "npapi.h"
#include "npfunctions.h"
#include "config.h"
#include "log.h"

void l_message_(const char *function, const char *format, ...)
{
    va_list ap;

    fprintf(stderr, "%s:%s(): ", NSSECURITY_TAG, function);
    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
    return;
}

void l_warning_(const char *function, const char *format, ...)
{
    va_list ap;

    fprintf(stderr, "%s:%s(): ", NSSECURITY_TAG, function);
    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
    return;
}

void l_error_(const char *function, const char *format, ...)
{
    va_list ap;

    fprintf(stderr, "%s:%s(): ", NSSECURITY_TAG, function);
    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
    return;
}

void l_debug_(const char *function, const char *format, ...)
{
    va_list ap;

    fprintf(stderr, "%s:%s(): ", NSSECURITY_TAG, function);
    va_start(ap, format);
        vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
    return;
}
