// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// Main NPP (non exported plugin-side APIs) implementations.
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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <dlfcn.h>
#include <strings.h>

#include "log.h"
#include "npapi.h"
#include "nptypes.h"
#include "npfunctions.h"
#include "config.h"
#include "export.h"
#include "netscape.h"
#include "instance.h"
#include "policy.h"
#include "util.h"

// The set of characters allowed in a MIME type.
static const char kMimeCharacterSet[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMOPQRSTUVWXYZ@0123456789.,- ;+=/:_";

// The maximum realistic length of a MIME type.
static const size_t kMaxMimeLength = 128;

// Maximum number of sites per plugin for NPP_GetSitesWithData.
static const unsigned kMaxSitesWithData = 1024;

// Deletes a specific instance of a plug-in.
NPError netscape_plugin_destroy(NPP instance, NPSavedData **save)
{
    struct plugin *plugin;

    // We need to lookup who owns this instance.
    if (!netscape_instance_resolve(instance, &plugin)) {
        // This can happen when we denied a plugin from loading. My
        // interpretation of the specification is that if dont return
        // NPERR_NO_ERROR from newp, then this should not be called, but
        // apparently not all browsers agree.
        l_debug("failed to resolve instance %p, probably harmless", instance);
        return NPERR_GENERIC_ERROR;
    }

    // We can remove this instance now, as the browser promises not to use it
    // again.
    if (!netscape_instance_destroy(instance)) {
        l_warning("resolved instance to %s, but failed to destroy instance %p",
                  plugin->section,
                  instance);
        return NPERR_GENERIC_ERROR;
    }

    // Verify it's implemented (it should always be, but who knows).
    if (!plugin->plugin_funcs->destroy) {
        return NPERR_GENERIC_ERROR;
    }

    // And finally pass through the call to the plugin.
    return plugin->plugin_funcs->destroy(instance, save);
}

// Allows the browser to query the plug-in for information.
NPError netscape_plugin_getvalue(NPP instance,
                                 NPPVariable variable,
                                 void *value)
{
    // These interfaces are similar enough that they can be reused.
    return NP_GetValue(instance, variable, value);
}

// Creates a new instance of a plug-in.
//
// In this routine the parameter pluginType, and the contents of argn and argv
// are *UNTRUSTED*, as they're controlled by the hosted potentially malicious
// page. It's possible the browser sanitised them, but we can't rely on that.
//
// I'm currently not interested in the contents of argn and argv, and just pass
// them through to the plugin, but I do need to examime pluginType.
//
NPError netscape_plugin_new(NPMIMEType pluginType,
                            NPP instance,
                            uint16_t mode,
                            int16_t argc,
                            char *argn[],
                            char *argv[],
                            NPSavedData *saved)
{
    char          *pageurl;
    struct plugin *current;

    // First sanity check the untrusted parameter pluginType.
    if (strspn(pluginType, kMimeCharacterSet) != strlen(pluginType)) {
        l_warning("rejected unusual mime type supplied by browser");
        return NPERR_INVALID_PARAM;
    }

    // Verify it's a sane length.
    if (strlen(pluginType) > kMaxMimeLength) {
        l_warning("rejected unusual mime type supplied by browser");
        return NPERR_INVALID_PARAM;
    }

    l_debug("new plugin requested for mimetype %s @%p", pluginType, instance);

    // First we find a plugin that wants to handle this type.
    for (current = registry.plugins; current; current = current->next) {
        char *saveptr;
        char *mimetypes;
        char *field;

        saveptr   = NULL;

        // Verify there is a mime description for this plugin.
        if (!current->mime_description)
            continue;

        // Create a copy we can modify.
        mimetypes = strdupa(current->mime_description);

        // The MIME types supported by this plugin are seperated by ';', any
        // plugin can handle multiple MIME types.
        while ((field = strtok_r(mimetypes, ";", &saveptr))) {
            // Reset the string for strtok.
            mimetypes = NULL;

            // Check the plugin description is well formed.
            if (!strchr(field, ':')) {
                continue;
            }

            // Check if this plugin matches.
            if (strncasecmp(field,
                            pluginType,
                            strchr(field, ':') - field) != 0) {
                continue;
            }

            l_debug("plugin %s would like to handle type %s, instance %p",
                    current->section,
                    pluginType,
                    instance);

            // Fetch the current domain from netscape.
            if (!netscape_plugin_geturl(instance, &pageurl)) {
                l_warning("unknown url for plugin %s", current->section);
                continue;
            }

            // Match that URL against the security policy.
            if (!policy_plugin_allowed_url(current, pageurl)) {
                l_warning("plugin %s not allowed from %s, policy match failed",
                          current->section,
                          pageurl);

                // Possibly display a message to the user.
                netscape_display_message(instance, current->warning
                                                    ? current->warning
                                                    : registry.global->warning);

                // Done.
                free(pageurl);
                continue;
            }

            // We determined this plugin is allowed to be loaded here, and it
            // does want this MIME type, so we have finished.
            free(pageurl);

            // No need to keep searching.
            goto found;
        }
    }

  found:

    // At this point, if current is NULL, we don't want this type.
    if (!current) {
        l_warning("netscape requested %s, but we cant handle it", pluginType);
        return NPERR_INVALID_PARAM;
    }

    // The plugin has been permitted, so we need to register this instance to
    // this plugin before passing control to it.
    if (!netscape_instance_map(instance, current)) {
        l_debug("failed to map new instance %p to plugin %s",
                instance,
                current->section);
        return NPERR_GENERIC_ERROR;
    }

    l_debug("plugin %s permitted, and instance %p registered",
            current->section,
            instance);

    // And finally we can pass through the results.
    return current->plugin_funcs->newp(pluginType,
                                       instance,
                                       mode,
                                       argc,
                                       argn,
                                       argv,
                                       saved);
}

// Tells the plug-in when a window is created, moved, sized, or destroyed.
NPError netscape_plugin_setwindow(NPP instance, NPWindow *window)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return NPERR_INVALID_INSTANCE_ERROR;
    }

    if (!plugin->plugin_funcs->setwindow) {
        return NPERR_GENERIC_ERROR;
    }

    return plugin->plugin_funcs->setwindow(instance, window);
}

// Notifies a plug-in instance of a new data stream.
NPError netscape_plugin_newstream(NPP instance,
                                  NPMIMEType type,
                                  NPStream *stream,
                                  NPBool seekable,
                                  uint16_t *stype)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return NPERR_INVALID_INSTANCE_ERROR;
    }

    if (!plugin->plugin_funcs->newstream) {
        return NPERR_GENERIC_ERROR;
    }

    return plugin->plugin_funcs->newstream(instance,
                                           type,
                                           stream,
                                           seekable,
                                           stype);
}


// Tells the plug-in that a stream is about to be closed or destroyed.
NPError netscape_plugin_destroystream(NPP instance,
                                      NPStream* stream,
                                      NPReason reason)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return NPERR_INVALID_INSTANCE_ERROR;
    }

    if (!plugin->plugin_funcs->destroystream) {
        return NPERR_GENERIC_ERROR;
    }

    return plugin->plugin_funcs->destroystream(instance, stream, reason);
}


// Provides a local file name for the data from a stream.
void netscape_plugin_streamasfile(NPP instance,
                                  NPStream *stream,
                                  const char *fname)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return;
    }

    if (!plugin->plugin_funcs->asfile) {
        return;
    }

    return plugin->plugin_funcs->asfile(instance, stream, fname);
}

// Determines maximum number of bytes that the plug-in can consume.
int32_t netscape_plugin_writeready(NPP instance, NPStream* stream)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return NPERR_INVALID_INSTANCE_ERROR;
    }

    if (!plugin->plugin_funcs->writeready) {
        return NPERR_GENERIC_ERROR;
    }

    return plugin->plugin_funcs->writeready(instance, stream);
}

// Delivers data to a plug-in instance.
int32_t netscape_plugin_write(NPP instance,
                              NPStream *stream,
                              int32_t offset,
                              int32_t len,
                              void *buf)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return NPERR_INVALID_INSTANCE_ERROR;
    }

    if (!plugin->plugin_funcs->write) {
        return NPERR_GENERIC_ERROR;
    }

    return plugin->plugin_funcs->write(instance, stream, offset, len, buf);
}

// Requests a platform-specific print operation for an embedded or full-screen
// plug-in.
void netscape_plugin_print(NPP instance, NPPrint *PrintInfo)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return;
    }

    if (!plugin->plugin_funcs->print) {
        return;
    }

    return plugin->plugin_funcs->print(instance, PrintInfo);
}

// Delivers a platform-specific window event to the instance.
int16_t netscape_plugin_handleevent(NPP instance, void *event)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return NPERR_INVALID_INSTANCE_ERROR;
    }

    if (!plugin->plugin_funcs->event) {
        return NPERR_GENERIC_ERROR;
    }

    return plugin->plugin_funcs->event(instance, event);
}

// Notifies the instance of the completion of a URL request.
void netscape_plugin_urlnotify(NPP instance,
                               const char *url,
                               NPReason reason,
                               void *notifyData)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return;
    }

    if (!plugin->plugin_funcs->urlnotify) {
        return;
    }

    return plugin->plugin_funcs->urlnotify(instance, url, reason, notifyData);
}

// Sets information about the plug-in.
NPError netscape_plugin_setvalue(NPP instance, NPNVariable variable, void *value)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return NPERR_INVALID_INSTANCE_ERROR;
    }

    if (!plugin->plugin_funcs->setvalue) {
        return NPERR_GENERIC_ERROR;
    }

    return plugin->plugin_funcs->setvalue(instance, variable, value);
}

// Called by the browser when the browser intends to focus an instance.
NPBool netscape_plugin_gotfocus(NPP instance, NPFocusDirection direction)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return false;
    }

    if (!plugin->plugin_funcs->gotfocus) {
        return false;
    }

    return plugin->plugin_funcs->gotfocus(instance, direction);
}

// Called by the browser when the browser intends to take focus.
void netscape_plugin_lostfocus(NPP instance)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return;
    }

    if (!plugin->plugin_funcs->lostfocus) {
        return;
    }

    return plugin->plugin_funcs->lostfocus(instance);
}

// The following function can be implemented by plugins to allow for URL
// redirect handling.
void netscape_plugin_urlredirectnotify(NPP instance,
                                       const char* url,
                                       int32_t status,
                                       void* notifyData)
{
    struct plugin *plugin;

    if (!netscape_instance_resolve(instance, &plugin)) {
        return;
    }

    if (!plugin->plugin_funcs->urlredirectnotify) {
        return;
    }

    return plugin->plugin_funcs->urlredirectnotify(instance,
                                                   url,
                                                   status,
                                                   notifyData);
}

// Allows browsers to discover and clear plugin private data. This API was
// designed by people who forgot that NPP routines must take an instance
// pointer. Sigh.
//
// This makes our work harder, because we will have to pass it through to
// everyone who implements it. Not as hard as getsites though, where we have to
// reconstruct an array.
//
// Seriously, why isn't this an NP (as opposed to NPP) api?!
NPError netscape_plugin_clearsitedata(const char* site, uint64_t flags, uint64_t maxAge)
{
    struct plugin *current;

    l_debug("browser requests all plugins clear site data for %s", site);

    for (current = registry.plugins; current; current = current->next) {

        if (!current->plugin_funcs)
            continue;

        if (!current->plugin_funcs->clearsitedata)
            continue;

        // What should I do on error here?
        if (current->plugin_funcs->clearsitedata(site,
                                                 flags,
                                                 maxAge) != NPERR_NO_ERROR) {
            l_warning("plugin %s returned error from ClearSiteData",
                      current->section);
        }
    }

    return NPERR_NO_ERROR;
}

// We don't need to duplicate the strings, but we do need to make a new array.
char **netscape_plugin_getsiteswithdata(void)
{
    struct plugin *current;
    void         **result;
    void          *final;
    unsigned       total;

    // Keep track of total strings we have.
    result = NULL;
    total = 0;

    // Pass the query through to each plugin.
    for (current = registry.plugins; current; current = current->next) {
        char        **sites_data;
        unsigned      count;

        if (!current->plugin_funcs)
            continue;

        if (!current->plugin_funcs->getsiteswithdata)
            continue;

        sites_data = current->plugin_funcs->getsiteswithdata();

        // Verify that returned something useful.
        if (!sites_data) {
            continue;
        }

        // Append the new strings we find.
        for (count = 0; sites_data[count]; count++) {

            // Allocate space for the new string pointers.
            result = realloc(result, total * sizeof(char *)
                                           + sizeof(char *));

            // Verify that worked.
            if (!result) {
                l_warning("memory allocation failure querying sites for %s, %u",
                          current->plugin,
                          count);
                return NULL;
            }

            // Re-use the string we were given.
            result[total++] = sites_data[count];

            // Sanity check. I'll leak the remaining strings returned here, but
            // the plugin is broken and I would prefer not to interact with it.
            // Leaking memory is relatively minor.
            if (count >= kMaxSitesWithData) {
                l_warning("stop querying %s after unusually high count %u",
                          current->plugin,
                          count);
                break;
            }
        }

        l_debug("plugin %s reports %u sites with data",
                current->section,
                count);

        // Free the array, but not the strings.
        registry.netscape_funcs->memfree(sites_data);
    }

    // Translate this insto an NPN buffer.
    final = registry.netscape_funcs->memalloc(total * sizeof(char *)
                                                    + sizeof(char *));

    // Check that worked.
    if (!final) {
        l_warning("memory allocation failed, %u pointer array", total);
        goto finished;
    }

    // Add one pointer for a NULL terminating pointer.
    memset(final, 0, total * sizeof(char *) + sizeof(char *));

    // Copy my array in.
    memcpy(final, result, total * sizeof(char *));

finished:

    // Release the working version.
    free(result);

    return final;
}
