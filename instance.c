// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// Mapping instances (opaque pointers) to owner plugins.
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
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "log.h"
#include "npfunctions.h"
#include "npapi.h"
#include "config.h"
#include "instance.h"

struct instance {
    void *instance;
    void *plugin;
};

static struct instance *global_instance_table;
static size_t           global_instance_count;

static int instance_compare(const void *key, const void *value);
static void netscape_instance_list_dump(void);

// The maximum number of plugin instances we will manage simultaneously before
// retuning error when adding new instances.
static const size_t kMaxInstances = 0x1000;

// Netscape anticipates that you might want one plugin to handle multiple MIME
// types, and so uses instance pointers which uniquely identify every instance
// of a plugin.
//
// On subsequent interactions with the plugin, you receive the same instance
// pointer, so you can map it to the appropriate action. We can't look inside
// the structure (because it's an opaque pointer), but we can trust that it's
// unique, and store a map of instance pointers to owner plugins.
//

// Return the plugin structure that owns this instance.
bool netscape_instance_resolve(NPP instance, struct plugin **result)
{
    struct instance *match, key = {
        .instance = instance,
        .plugin   = NULL,
    };

    // Find the requested instance.
    match = bsearch(&key,
                    global_instance_table,
                    global_instance_count,
                    sizeof key,
                    instance_compare);

    // Pass pointer back to caller.
    *result = match ? match->plugin : NULL;

    // Return result.
    return !! *result;
}

// Record a new instance -> plugin relationship.
bool netscape_instance_map(NPP instance, struct plugin *plugin)
{
    // Verify this is sane.
    if (global_instance_count >= kMaxInstances)
        return false;

    // Realloc list with new size.
    global_instance_table = realloc(global_instance_table,
                                    global_instance_count
                                        * sizeof(struct instance)
                                        + sizeof(struct instance));
    // Insert the new relationship.
    global_instance_table[global_instance_count].instance = instance;
    global_instance_table[global_instance_count].plugin = plugin;

    // Increment list size
    global_instance_count++;

    // Sort the array so we can use bsearch.
    qsort(global_instance_table,
          global_instance_count,
          sizeof(struct instance),
          instance_compare);

    // Looks good.
    return true;
}

// When netscape calls NPP_Destroy() on a specific instance, it promises never
// to interact with it again, so we can remove our reference to it.
bool netscape_instance_destroy(NPP instance)
{
    struct instance *match, key = {
        .instance = instance,
        .plugin   = NULL,
    };

    // Find the requested instance.
    match = bsearch(&key,
                    global_instance_table,
                    global_instance_count,
                    sizeof key,
                    instance_compare);

    // Remove from array, no sort required.
    if (match) {
        memmove(&match[0],
                &match[1],
                (&global_instance_table[global_instance_count]
                    - &match[1])
                    * sizeof key);

        // Decrement number of instances.
        global_instance_count--;

        // I could realloc global_instance_table here to clear the pointer, I
        // don't see the point, it's resized correctly in map() anyway.
    }

    return !! match;
}

// Destroy the entire list, we're in NP_Shutdown.
bool netscape_instance_list_destroy(void)
{
    // Destroy the entire table.
    free(global_instance_table);

    // Reset the count.
    global_instance_count = 0;

    // Done.
    return true;
}

// Compare routine for bsearch and qsort.
static int instance_compare(const void *key, const void *value)
{
    const struct instance *x = key, *y = value;

    if (x->instance < y->instance)
        return -1;

    if (x->instance > y->instance)
        return  1;

    return 0;
}

// Debugging routine.
static void __unused netscape_instance_list_dump(void)
{
    unsigned i;

    l_debug("Dumping %u member instance list...", global_instance_count);

    for (i = 0; i < global_instance_count; i++) {
        l_debug("%u\t%p => %p",
                i,
                global_instance_table[i].instance,
                global_instance_table[i].plugin);
    }
}

#if defined(ENABLE_RUNTIME_TESTS)

static void __constructor test_instance_maps(void)
{
    struct plugin data1, data2, data3;
    struct plugin *result1, *result2, *result3;

    void *key1 = &key1;
    void *key2 = &key2;
    void *key3 = &key3;

    assert(netscape_instance_map(key1, &data1) == true);
    assert(netscape_instance_map(key2, &data2) == true);
    assert(netscape_instance_map(key3, &data3) == true);

    assert(netscape_instance_resolve(key1, &result1) == true);
    assert(netscape_instance_resolve(key2, &result2) == true);
    assert(netscape_instance_resolve(key3, &result3) == true);

    netscape_instance_list_dump();

    assert(result1 == &data1);
    assert(result2 == &data2);
    assert(result3 == &data3);

    assert(netscape_instance_destroy(key1) == true);
    assert(netscape_instance_destroy(key1) == false);
    assert(netscape_instance_resolve(key1, &result1) == false);
    assert(netscape_instance_resolve(key2, &result2) == true);
    assert(netscape_instance_resolve(key3, &result3) == true);

    assert(result2 == &data2);
    assert(result3 == &data3);

    netscape_instance_list_dump();

    assert(netscape_instance_destroy(key2) == true);
    assert(netscape_instance_destroy(key2) == false);
    assert(netscape_instance_resolve(key1, &result1) == false);
    assert(netscape_instance_resolve(key2, &result2) == false);
    assert(netscape_instance_resolve(key3, &result3) == true);

    assert(result3 == &data3);

    netscape_instance_list_dump();

    assert(netscape_instance_destroy(key3) == true);
    assert(netscape_instance_destroy(key3) == false);
    assert(netscape_instance_resolve(key1, &result1) == false);
    assert(netscape_instance_resolve(key2, &result2) == false);
    assert(netscape_instance_resolve(key3, &result3) == false);

    assert(netscape_instance_map(key1, &data1) == true);
    assert(netscape_instance_map(key2, &data2) == true);
    assert(netscape_instance_map(key3, &data3) == true);

    assert(netscape_instance_destroy(key2) == true);

    assert(netscape_instance_resolve(key1, &result1) == true);
    assert(netscape_instance_resolve(key2, &result2) == false);
    assert(netscape_instance_resolve(key3, &result3) == true);

    assert(result1 == &data1);
    assert(result3 == &data3);

    netscape_instance_list_dump();

    assert(netscape_instance_destroy(key1) == true);
    assert(netscape_instance_destroy(key3) == true);
    assert(netscape_instance_destroy(key2) == false);
}

#endif
