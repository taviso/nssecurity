// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// Parse the configuration file and prepare all the plugins discovered.
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

#include <assert.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>

#include "npapi.h"
#include "npfunctions.h"
#include "config.h"
#include "platform.h"
#include "instance.h"
#include "log.h"
#include "ini.h"

// The global registry of known plugins.
struct registry registry;

// Find the matching plugin structure for the section name `section`. If no
// such section exists, a new one is allocated and returned. If the section
// name matches the special name "Global", it is added to the appropriate list.
//
// Returns true on success, false on failure.
static bool find_plugin_section(struct registry *registry,
                                const char *section,
                                struct plugin **plugin)
{
    struct plugin *current;

    // Check if this is the special "Global" section used to specify default
    // parameters and other special values.
    if (strcmp(section, "Global") == 0) {

        // If this is the first value from the Global section, we need to
        // create it.
        if (registry->global == NULL) {

            // Allocate a new structure.
            if ((*plugin = calloc(1, sizeof(**plugin))) == NULL) {
                l_error("memory allocation failure");
                return false;
            }

            // Install as the global plugin.
            registry->global            = *plugin;
            registry->global->section   = strdup(section);
        }

        // Return pointer to parent.
        *plugin = registry->global;

        // Success.
        return !! registry->global->section;
    } else {
        // This is not the Global section, a regular plugin section.
        current = registry->plugins;

        for (current = registry->plugins; current; current = current->next) {
            // Search to see if we already recognise this section.
            if (strcmp(current->section, section) == 0) {
                // Match found.
                *plugin = current;

                return true;
            }
        }
    }

    // This is the first time we've seen this section, we have to set it up.
    l_debug("new plugin section %s discovered", section);

    // Allocate a new structure.
    if ((*plugin = calloc(1, sizeof(**plugin))) == NULL) {
        l_error("memory allocation failure");
        return false;
    }

    // Check if we have any other plugins registered.
    if (registry->plugins != NULL) {

        // Find the tail of the plugin registry.
        for (current = registry->plugins; current->next; current = current->next)
            ;

        // Add to the list.
        current->next = *plugin;
        current = current->next;
        current->section = strdup(section);
    } else {
        // This is the first plugin structure we've seen, create the list head.
        registry->plugins = *plugin;
        registry->plugins->section = strdup(section);
        current = registry->plugins;
    }

    // Success.
    return !! current->section;
}


// This is a callback for parsing the ini files.
static int config_ini_handler(struct registry *registry,
                              const char *section,
                              const char *name,
                              const char *value)
{
    struct plugin *plugin;

    // Lookup this section in our configuration registry to see if we've seen
    // it before. If we havn't, this routine will create it.
    if (find_plugin_section(registry, section, &plugin) == false) {
        l_warning("failed to create plugin %s while trying to set %s",
                  section,
                  name);
        return false;
    } else if (strcmp(name, "AllowedDomains") == 0) {
        // AllowedDomains is a whitelist of domains allowed to load the
        // specified plugin. It is passed to fnmatch(), so shell-style globbing
        // is permitted.
        //  AllowedDomains=*.corp.google.com
        plugin->allow_domains = strdup(value);
    } else if (strcmp(name, "AllowInsecure") == 0) {
        // AllowInsecure disables mandatory https pages for AllowedDomains.
        // This is not recommended, but can be used if absolutely necessary.
        //  AllowInsecure=1
        plugin->allow_insecure = strdup(value);
    } else if (strcmp(name, "FriendlyWarning") == 0) {
        // FriendlyWarning is a message displayed to users when a plugin load
        // is denied. It is intended to give users a clue about why their page
        // isn't working, and how to ask for help.
        plugin->warning = strdup(value);
    } else if (strcmp(name, "PluginDescription") == 0) {
        // A description shown to users in their about:plugins page, make it
        // something descriptive and explain how to get help.
        plugin->description = strdup(value);
    } else if (strcmp(name, "PluginName") == 0) {
        // The name displayed to users in their about:plugins page.
        plugin->name = strdup(value);
    } else if (strcmp(name, "AllowPort") == 0) {
        // If a domain contains a port specification, allow it to match.
        //
        // This has some security implications with AllowInsecure=1, and so is
        // not recommended.
        plugin->allow_port = strdup(value);
    } else if (strcmp(name, "AllowAuth") == 0) {
        // If a domain appears to contain HTTP authentication credentials,
        // allow it to match.
        //
        // This is not recommended due to some ambiguities parsing URLs it
        // introduces.
        plugin->allow_auth = strdup(value);
    } else if (strcmp(name, "LoadPlugin") == 0) {
        // The path to a plugin you want managed by this security wrapper.

        // This one is interesting, we've been told about a new plugin binary
        // we can try to load. Let's load it now, and keep a reference around
        // to it.
        plugin->plugin = strdup(value);
        plugin->handle = platform_dlopen(value);

        // We can do one more piece of housekeeping, we can generate the global
        // MIME description list by appending this new plugins MIME types to
        // the types we already know.

        // Call the exported function to retrieve the MIME types supported.
        plugin->mime_description = platform_getmimedescription(plugin);

        // If that worked, we need to parse it.
        if (plugin->mime_description) {
            if (registry->mime_description) {
                char *trailing_delimiter;
                size_t new_length;

                // This is not the first description we have, we need to append a
                // ';' and realloc enough space to store the new one, the 2 is
                // for the ';' and the terminating '\0'.
                new_length = strlen(registry->mime_description)
                                + strlen(plugin->mime_description)
                                + 2;

                registry->mime_description = realloc(registry->mime_description,
                                                     new_length);

                // Some plugins already have a semicolon, check for that.
                trailing_delimiter = strrchr(registry->mime_description, ';');

                // If there is no delimiter, or the last delimiter is *not* the
                // last character, we need to append our own.
                if (trailing_delimiter == NULL || *++trailing_delimiter != '\0') {
                    // But is there an empty string in there (Firefox).
                    if (strlen(registry->mime_description)) {
                        // Okay, String is non-empty and there is no semi
                        // colon, or not at the end. We need to add one.
                        strcat(registry->mime_description, ";");
                    }
                }

                // Now we can append the new type.
                strcat(registry->mime_description, plugin->mime_description);
            } else {
                // This is the first description we've seen, just strdup it.
                registry->mime_description = strdup(plugin->mime_description);
            }
        }
    } else {
        l_warning("unrecognised directive %s found in section %s",
                  name,
                  section);
        return false;
    }

    return true;
}

// This is the initial constructor used to parse the configuration files.
static void __constructor init_parse_config(void)
{
    struct passwd *passwd_entry;
    char *home_directory;
    char *user_path;

    // Find this users passwd entry.
    passwd_entry = getpwuid(getuid());

    // Parse the system configuration.
    if (ini_parse(NSSECURITY_PATH, (void *)(config_ini_handler), &registry)) {
        l_warning("failed to parse the global configuration file");
    }

    // If permitted, parse the user configuration.
    if (registry.global && registry.global->allow_override) {
        home_directory = passwd_entry->pw_dir;
        user_path      = alloca(strlen(home_directory)
                                    + strlen(NSSECURITY_USER_PATH)
                                    + 1
                                    + 1);

        // Generate full path.
        sprintf(user_path, "%s/%s", home_directory, NSSECURITY_USER_PATH);

        // Parse the file.
        if (ini_parse(user_path, (void *)(config_ini_handler), &registry)) {
            l_warning("failed to parse the user configuration file");
        }
    }

    return;
}

bool netscape_plugin_list_destroy(void)
{
    struct plugin *current;

    while (registry.plugins) {
        // Find the current head of the plugins list.
        current = registry.plugins;

        // Unlink this node from the list.
        registry.plugins = current->next;

      freecurrent:

        // Unused elements are NULL, so we don't have to test.
        free(current->allow_insecure);
        free(current->allow_domains);
        free(current->allow_override);
        free(current->allow_port);
        free(current->allow_auth);
        free(current->warning);
        free(current->plugin);
        free(current->section);
        free(current->name);
        free(current->mime_description);

        // Close any open handles.
        platform_dlclose(current->handle);

        // Free the node itself.
        free(current);
    }

    // Test if we also need to free the global plugin structure.
    if (registry.global) {
        current = registry.global;

        // Set to NULL so we don't free twice.
        registry.global = NULL;

        // Re-use the plugin code above.
        goto freecurrent;
    }

    return true;
}

static void __destructor fini_clear_plugins(void)
{
    netscape_instance_list_destroy();
    netscape_plugin_list_destroy();
    free(registry.mime_description);
    return;
}

#if defined(ENABLE_RUNTIME_TESTS)

static void __constructor test_parse_config(void)
{
}

#endif
