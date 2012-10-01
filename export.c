// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// The main NP (plugin side) exported symbols queried by the browser.
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

#include "npapi.h"
#include "npfunctions.h"
#include "nptypes.h"
#include "config.h"
#include "platform.h"
#include "instance.h"
#include "netscape.h"
#include "util.h"
#include "export.h"
#include "log.h"

// NP_GetMIMEDescription returns a supported MIME Type list for your plugin. It
// works on Unix (Linux) and MacOS.
//
// Each MIME type description should be separated by a semicolon (;).
// Each MIME type description contains the MIME Type, an extensions list and a
// short description.
//
// I have already aggregated the mime types supported, so just hand it along
// here.
__export char * NP_GetMIMEDescription(void)
{
    return registry.mime_description;
}

__export char * NP_GetPluginVersion(void)
{
    return NSSECURITY_VERSION;
}

__export NPError NP_GetValue(NPP instance, NPPVariable variable, void *value)
{
    struct plugin *plugin;
    char         **string = value;

    switch (variable) {
        case NPPVpluginNameString:
            // This is a string displayed to the user in about:plugins
            if (!registry.global || !registry.global->name) {
                return NPERR_GENERIC_ERROR;
            }

            *string = registry.global->name;

            return NPERR_NO_ERROR;
        case NPPVpluginDescriptionString:
            // This is a string displayed to the user in about:plugins
            if (!registry.global || !registry.global->name) {
                return NPERR_GENERIC_ERROR;
            }

            *string = registry.global->description;

            return NPERR_NO_ERROR;
        default:
            // I have no handler for this requested value, so pass it through
            // to the relevant instance if it exists.

            // We need to lookup who owns this instance.
            if (!netscape_instance_resolve(instance, &plugin)) {
                // Instance does not exist, and I don't want to handle it.
                l_warning("failed to resolve instance %p for variable %u",
                          instance,
                          variable);

                return NPERR_INVALID_INSTANCE_ERROR;
            }

            // Pass through the call to the plugin.
            return plugin->plugin_funcs->getvalue(instance, variable, value);
    }

    // Unreachable.
    return NPERR_GENERIC_ERROR;
}

// Provides global initialization for a plug-in.
//
// We need to pass this along to all known plugins. The NetscapeFuncs structure
// is effectively readonly, we can let the plugins see it and use them
// directly. We need to intercept modifications to the PluginFuncs structure,
// and redirect them via us.
__export NPError NP_Initialize(NPNetscapeFuncs *aNPNFuncs,
                               NPPluginFuncs *aNPPFuncs __unused)
{
    struct plugin *current = registry.plugins;

    // This is useful to log for compatability issues.
    l_debug("NPNetscapeFuncs version %u, size %u",
            aNPNFuncs->version,
            aNPNFuncs->size);

    // Record the netscape functions for future use.
    registry.netscape_funcs = aNPNFuncs;

    // We need to pass the call through to all plugins.
    while (current) {
        NPError         *(*np_initialize)(void *, void *);
        NPError         *(*np_getentrypoints)(void *);
        NPPluginFuncs     *np_funcs;

        // Verify the plugin has been dlopened.
        if (!current->handle) {
            l_debug("plugin %s does not have open handle", current->section);
            goto next;
        }

        // Resolve this exported routine.
        np_initialize = platform_dlsym(current->handle, "NP_Initialize");
        np_getentrypoints = platform_dlsym(current->handle, "NP_GetEntryPoints");

        if (!np_initialize) {
            l_warning("failed to resolve required symbol from %s, \"%s\"",
                      current->plugin,
                      dlerror());
            goto next;
        }

        // Allocate a function table for this plugin if necessary. We will ask
        // the plugin to populate this table for later use.
        if (current->plugin_funcs == NULL) {
            // Warn about potential incompatabilities.
            if (aNPNFuncs->version > ((NP_VERSION_MAJOR << 8) | NP_VERSION_MINOR)) {
                l_warning("browser supports NPAPI revision %u, but we know %u",
                          aNPNFuncs->version,
                          (NP_VERSION_MAJOR << 8) | NP_VERSION_MINOR);
                goto next;
            }

            np_funcs = calloc(1, sizeof *np_funcs);
            np_funcs->version = aNPNFuncs->version;
            np_funcs->size = sizeof *np_funcs;
            current->plugin_funcs = np_funcs;
        }

        // Now we can initialize it, and populate the plugin function table.
        // On Apple, the second argument is ignored, we need to populate it
        // ourselves via NP_GetEntryPoints.
        if (np_initialize(aNPNFuncs, current->plugin_funcs) != NPERR_NO_ERROR) {
            // Difficult to know what to do here, should I stop passing calls
            // to this plugin?
            l_warning("plugin %s returned error from NP_Initialize",
                      current->section);
            goto next;
        }

        // On Linux, this might be a No-op, but on Apple this is the normal
        // procedure.
        if (np_getentrypoints != NULL) {
            if (np_getentrypoints(current->plugin_funcs) != NPERR_NO_ERROR) {
                // Difficult to know what to do here, should I stop passing
                // calls to this plugin?
                l_warning("plugin %s returned error from NP_GetEntryPoints, %d",
                          current->section,
                          np_getentrypoints(current->plugin_funcs));
                goto next;
            }
        }

      next:

        // Finished initializing this plugin, find the next.
        current = current->next;
    }

#if defined(__linux__)
    // Netscape expects us to populate the plugin function table, but we can't
    // just route these directly to the plugin because we have multiple plugins
    // to manage. Instead, we will insert shims that route the requests
    // appropriately.
    //
    // On Apple, the browser is expected to call this routine, on Linux, I'll
    // pass it through manually.
    if (NP_GetEntryPoints(aNPPFuncs) != NPERR_NO_ERROR) {
        l_warning("NP_GetEntryPoints failed.");
        return NPERR_GENERIC_ERROR;
    }
#endif

    // At this point, everything looks good.
    l_debug("NP_Initialize completed");

    // Return success.
    return NPERR_NO_ERROR;
}

// The browser is about to delete us, we can safely destroy everything. The
// browser promises not to call us again when this routine returns. However,
// browsers do this inconsistently, so I would rather do nothing here and use
// destructors.
__export NPError NP_Shutdown(void)
{
    return NPERR_NO_ERROR;
}

// This is required on OSX, but unused on other Systems.
__export NPError NP_GetEntryPoints(NPPluginFuncs *pFuncs)
{
    l_debug("NPPluginFuncs version %u, sizeof %u",
            pFuncs->version,
            pFuncs->size);

    if (pFuncs->size < sizeof(NPPluginFuncs)) {
        l_warning("browser requested unrecognized function table size %u",
                  pFuncs->size);
        return NPERR_INVALID_FUNCTABLE_ERROR;
    }

    pFuncs->newp = netscape_plugin_new;
    pFuncs->destroy = netscape_plugin_destroy;
    pFuncs->setwindow = netscape_plugin_setwindow;
    pFuncs->newstream = netscape_plugin_newstream;
    pFuncs->destroystream = netscape_plugin_destroystream;
    pFuncs->asfile = netscape_plugin_streamasfile;
    pFuncs->writeready = netscape_plugin_writeready;
    pFuncs->write = netscape_plugin_write;
    pFuncs->print = netscape_plugin_print;
    pFuncs->event = netscape_plugin_handleevent;
    pFuncs->urlnotify = netscape_plugin_urlnotify;
    pFuncs->getvalue = netscape_plugin_getvalue;
    pFuncs->setvalue = netscape_plugin_setvalue;
    pFuncs->gotfocus = netscape_plugin_gotfocus;
    pFuncs->lostfocus = netscape_plugin_lostfocus;
    pFuncs->urlredirectnotify = netscape_plugin_urlredirectnotify;
    pFuncs->clearsitedata = netscape_plugin_clearsitedata;
    pFuncs->getsiteswithdata = netscape_plugin_getsiteswithdata;

    // Not supported.
    pFuncs->javaClass = NULL;

    return NPERR_NO_ERROR;
}

