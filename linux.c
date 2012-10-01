// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// Platform specific code for managing plugins on Linux.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#include "log.h"
#include "npapi.h"
#include "npfunctions.h"
#include "config.h"
#include "util.h"
#include "log.h"
#include "platform.h"

char * platform_getmimedescription(struct plugin *plugin)
{
    char *result;
    char *(*get_mime_description)(void);

    // Make sure we have a handle to this plugin.
    if (!plugin->handle) {
        l_warning("BUG: no open handle to plugin %s for %s",
                  plugin->section,
                  plugin->plugin);
        return NULL;
    }

    // Resolve the required export.
    get_mime_description = platform_dlsym(plugin->handle, "NP_GetMIMEDescription");

    // Verify that worked.
    if (!get_mime_description) {
        l_warning("unable to find NP_GetMIMEDescription in %s for %s, %s",
                  plugin->plugin,
                  plugin->section,
                  dlerror());
        return NULL;
    }

    // Call the exported function to retrieve the MIME types supported.
    result = get_mime_description();

    // Make sure we return a string even if that fails.
    return result ? strdup(result) : strdup("");
}

// We can actually use real dlopen() suite on Linux, so just pass everything
// straight through.
void * platform_dlopen(const char *plugin)
{
    return dlopen(plugin, RTLD_LAZY);
}

void * platform_dlsym(void *handle, const char *symbol)
{
    return dlsym(handle, symbol);
}

// I'm not sure if dlclose() handles NULL like free, or like fclose(). To be
// safe, I'll check.
void platform_dlclose(void *handle)
{
    if (handle) dlclose(handle);
}

