// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// Platform specific code for managing plugins on Mac OS X.
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

#include <stdint.h>
#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>

#include "npapi.h"
#include "npfunctions.h"
#include "config.h"
#include "platform.h"
#include "util.h"
#include "log.h"

// For some reason this prototype is private, I would rather use
// CFCopySearchPathForDirectoriesInDomains but it's too complex to rely on
// without support.
CFURLRef CFCopyHomeDirectoryURLForUser(CFStringRef uName);

static void merge_dictionary_applier(const void *key,
                                     const void *value,
                                     void *context);
static void extension_array_applier(const void *value, void *context);
static void mimetype_dictionary_applier(const void *key,
                                        const void *value,
                                        void *context);

// The primary problem we need to resolve for OSX portability is that Apple
// only permit you to define static MIME types in the property list for
// plugins bundles, because we need to generate these dynamically.
//
// Luckily, Apple also want to generate MIME types dynamically for QuickTime,
// so they provide a (bizarre) API to do so.
//
// The solution is to set WebPluginMIMETypesFilename to an invalid filename,
// and then implement the dynamic symbol BP_CreatePluginMIMETypesPreferences.
// When the path is found to be invalid by the loader, our callback will be
// invoked and we can generate a new plist.
//
// Once our callback returns, the loader then attempts to load the missing
// filename again, and then parses it for the MIME types.
//
// In order to keep this file fresh, we should unlink() it on NP_Initialize().
//
// This is an example of the data we need:
//
//    <key>WebPluginMIMETypes</key>
//    <dict>
//        <key>application/pdf</key>
//        <dict>
//            <key>WebPluginExtensions</key>
//            <array>
//                <string>pdf</string>
//            </array>
//            <key>WebPluginTypeDescription</key>
//            <string>PDF Image</string>
//            <key>WebPluginTypeEnabled</key>
//            <false/>
//        </dict>
//    </dict>
//
// This is the dynamic symbol used by the loader to resolve the missing MIME list.
void __export BP_CreatePluginMIMETypesPreferences(void)
{
    CFMutableDictionaryRef  cf_root;
    CFMutableDictionaryRef  cf_mimetypes;
    CFDictionaryRef         cf_pluginmimetypes;
    struct plugin          *current;

    // We need to create a new preferences dictionary, so this will be the root
    // of the new property list.
    cf_root = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                        0,
                                        &kCFTypeDictionaryKeyCallBacks,
                                        &kCFTypeDictionaryValueCallBacks);
    // A WebPluginMIMETypes Dictionary.
    cf_mimetypes = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                             0,
                                             &kCFTypeDictionaryKeyCallBacks,
                                             &kCFTypeDictionaryValueCallBacks);

    // Every plugin should have a handle should have a CFBundle handle open,
    // which we can query for it's WebPluginMIMETypes CFDictionary, which we
    // simply merge with ours.
    for (current = registry.plugins; current; current = current->next) {
        // Verify this handle exists, it can be NULL when LoadPlugin fails.
        if (current->handle) {
            // This should be a CFDictionary of all the MIME types supported by the plugin.
            cf_pluginmimetypes = CFBundleGetValueForInfoDictionaryKey(current->handle,
                                                                      CFSTR("WebPluginMIMETypes"));

            // Check that key exists in the Proerty Info.
            if (cf_pluginmimetypes) {
                // Merge this dictionary with ours.
                CFDictionaryApplyFunction(cf_pluginmimetypes,
                                          merge_dictionary_applier,
                                          cf_mimetypes);
            } else {
                // FIXME: If a plugin does not have a WebPluginMIMETypes key,
                //        it is either invalid, or uses dynamic MIME type
                //        generation. QuickTime is the only major plugin that
                //        does this.
                //
                //        I can implement it on request, but see no reason to
                //        implement now.
                l_warning("unable to handle plugin %s, from %s",
                          current->section,
                          current->plugin);
            }
        }
    }

    // Add the types to my plist root.
    CFDictionarySetValue(cf_root, CFSTR("WebPluginMIMETypes"), cf_mimetypes);

    // Create the missing plist file.
    CFPreferencesSetMultiple(cf_root,
                             NULL,
                             CFSTR("com.google.netscapesecurity"),
                             kCFPreferencesCurrentUser,
                             kCFPreferencesAnyHost);

    // Save changes to disk.
    CFPreferencesAppSynchronize(CFSTR("com.google.netscapesecurity"));

    // Clean up.
    CFRelease(cf_mimetypes);
    CFRelease(cf_root);
    return;
}

// On Linux, it's convenient to use dlfcn handles, as plugins are entirely self
// contained. On Apple, CFBundles are the preferred format. They implement
// (roughly) similar functionality, but at a higher level of abstraction.
//
// So we will use CFBundleRef pointers instead when requested to dlopen().
void * platform_dlopen(const char *plugin)
{
    CFURLRef    cf_pluginurl;
    CFStringRef cf_pluginpath;
    CFBundleRef cf_bundle;

    // Create a CFString from that pathname.
    cf_pluginpath = CFStringCreateWithCString(kCFAllocatorDefault,
                                              plugin,
                                              kCFStringEncodingUTF8);

    // Create a URL from the file system path to the plugin bundle.
    cf_pluginurl = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                 cf_pluginpath,
                                                 kCFURLPOSIXPathStyle,
                                                 true);

    // Fetch a CFBundle Reference, note that this may return NULL.
    cf_bundle = CFBundleCreate(kCFAllocatorDefault, cf_pluginurl);

    // Clean up
    CFRelease(cf_pluginurl);
    CFRelease(cf_pluginpath);
    return cf_bundle;
}

// Apple don't use a simple callback to NP_GetMIMEDescription, as on Linux, but
// we still need to implement it as we can dynamically open other plugins.
//
// XXX: For the initial release, I'm not going to support external MIME types. I
//      will add it on request.
char * platform_getmimedescription(struct plugin *plugin)
{
    CFDictionaryRef     cf_pluginplist   = NULL;
    CFDictionaryRef     cf_mimetypes     = NULL;
    CFBundleRef         cf_plugin        = plugin->handle;
    char               *mime_description = strdup("");

    // If we don't have a valid handle, we return an empty MIME description.
    // This is jsut for convenience so that I don't have to special case
    // invalid plugins on shutdown.
    if (plugin->handle == NULL) {
        goto finished;
    }

    // We should already have a CFBundleRef in plugin->handle.
    cf_pluginplist = CFBundleGetInfoDictionary(cf_plugin);

    // Find the WebPluginMIMETypes key.
    if (CFDictionaryGetValueIfPresent(cf_pluginplist,
                                      CFSTR("WebPluginMIMETypes"),
                                      (const void **) &cf_mimetypes) == false) {
        // The plugin is invalid, malformed, or using external MIME Types. This
        // is not currently supported, so return an empty string.
        goto finished;
    }

    if (CFGetTypeID(cf_mimetypes) != CFDictionaryGetTypeID()) {
        goto finished;
    }

    l_debug("found %u keys in WebPluginMIMETypes dictionary from plugin %s",
            CFDictionaryGetCount(cf_mimetypes),
            plugin->section);

    // Enumerate each key in the dictionary, adding them to the description.
    CFDictionaryApplyFunction(cf_mimetypes,
                              mimetype_dictionary_applier,
                              &mime_description);

finished:
    // Return the final string.
    return mime_description;
}

// A version of dlsym() that handles CFBundle references instead of dlfcn
// handles.
void * platform_dlsym(void *handle, const char *symbol)
{
    CFStringRef cf_symbol;
    void       *result;

    // Convert symbol name into CFString.
    cf_symbol = CFStringCreateWithCString(kCFAllocatorDefault,
                                          symbol,
                                          kCFStringEncodingUTF8);

    // Locate symbol in CFBundle handle.
    result = CFBundleGetFunctionPointerForName(handle, cf_symbol);

    // Clean up.
    CFRelease(cf_symbol);

    // Finished.
    return result;
}

// Helper applier to merge two CFDictionaries.
//  key     void * key
//  value   void * value
//  context CFMutableDictionaryRef to insert the key/value pair.
static void merge_dictionary_applier(const void *key, const void *value, void *context)
{
    return CFDictionaryAddValue(context, key, value);
}

// This is the helper function to extract the strings from WebPluginExtensions
// in mimetype_dictionary_applier.
//  value   CFString containing a single file extension
//  context char ** of the current extension list.
static void extension_array_applier(const void *value, void *context)
{
    CFIndex     ext_length;
    char      **extension_list;

    extension_list  = context;
    ext_length      = CFStringGetMaximumSizeForEncoding(CFStringGetLength(value),
                                                        kCFStringEncodingUTF8);
    *extension_list = realloc(*extension_list, strlen(*extension_list)
                                + ext_length
                                + 1
                                + 1);

    // If I'm not the first extension, append a comma delimiter.
    if (strlen(*extension_list)) {
        strcat(*extension_list, ",");
    }

    // Append this string to the list.
    CFStringGetCString(value,
                       *extension_list + strlen(*extension_list),
                       ext_length + 1,
                       kCFStringEncodingUTF8);

    return;
}

// Helper function to construct strings for CFDictionaryApplyFunction in
// platform_getmimedescription()
//  key     CFString containing a MIME type.
//  value   CFDictionary containing descriptions and extensions.
//  context char * where we want our NP_GetMIMETypeDescription compatible output.
static void mimetype_dictionary_applier(const void *key,
                                        const void *value,
                                        void *context)
{
    CFDictionaryRef cf_mimetype_dict    = value;
    CFStringRef     cf_mimetype         = key;
    CFIndex         cf_length;
    CFArrayRef      cf_extensions;
    CFStringRef     cf_description;
    CFBooleanRef    cf_enabled;
    char           *mimetype            = strdupa("");
    char           *description         = strdupa("");
    char           *extensions          = strdup("");
    char          **result              = context;

    // Here is an example of the output we want:
    //
    // "application/example:ext1,ext2:Example MIME Type"
    //

    // Verify that we received a CFDictionary object.
    if (CFGetTypeID(cf_mimetype_dict) != CFDictionaryGetTypeID()) {
        goto finished;
    }

    // Verify that the key is a CFString.
    if (CFGetTypeID(cf_mimetype) != CFStringGetTypeID()) {
        goto finished;
    }

    // Find the length of the MIME Type, and allocate stack space for it.
    cf_length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(cf_mimetype),
                                                  kCFStringEncodingUTF8);
    mimetype = alloca(cf_length + 1);

    // Extract the string.
    if (CFStringGetCString(cf_mimetype,
                           mimetype,
                           cf_length + 1,
                           kCFStringEncodingUTF8) != true) {
        goto finished;
    }

    // First we need to check if this type is disabled via WebPluginTypeEnabled.
    if (CFDictionaryGetValueIfPresent(cf_mimetype_dict,
                                      CFSTR("WebPluginTypeEnabled"),
                                      (const void **) &cf_enabled)) {
        // Verify that is a CFBoolean
        if (CFGetTypeID(cf_enabled) != CFBooleanGetTypeID()) {
            goto finished;
        }

        // Test value.
        if (CFBooleanGetValue(cf_enabled) == false) {
            goto finished;
        }
    }


    // Verify we have an empty string.
    if (!extensions) {
        goto finished;
    }

    // Now we need to lookup the extensions requested by the plugin.
    if (CFDictionaryGetValueIfPresent(cf_mimetype_dict,
                                      CFSTR("WebPluginExtensions"),
                                      (const void **) &cf_extensions)) {
        if (CFGetTypeID(cf_extensions) != CFArrayGetTypeID()) {
            goto finished;
        }

        l_debug("discovered %u extensions defined for mimetype %s",
                CFArrayGetCount(cf_extensions),
                mimetype);

        // Apply a function to every extension listed to concatenate them.
        CFArrayApplyFunction(cf_extensions,
                             CFRangeMake(0, CFArrayGetCount(cf_extensions)),
                             extension_array_applier,
                             &extensions);
    }

    // Now we need the description which is a CFString
    if (CFDictionaryGetValueIfPresent(cf_mimetype_dict,
                                      CFSTR("WebPluginTypeDescription"),
                                      (const void **) &cf_description)) {
        if (CFGetTypeID(cf_description) != CFStringGetTypeID()) {
            goto finished;
        }

        // Find the length of the MIME Type, and allocate stack space for it.
        cf_length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(cf_description),
                                                      kCFStringEncodingUTF8);
        description = alloca(cf_length + 1);

        // Extract the string.
        if (CFStringGetCString(cf_description,
                               description,
                               cf_length + 1,
                               kCFStringEncodingUTF8) != true) {
            goto finished;
        }
    }

    // So now we need to assemble the final string.
    *result = realloc(*result,
                      (*result ? strlen(*result) : 0)
                        + strlen(mimetype) + 1
                        + strlen(description) + 1
                        + strlen(extensions) + 1
                        + 1
                        + 1);

    // Verify that worked.
    if (!*result) {
        goto finished;
    }

    // Create the final string.
    sprintf(*result, "%s%s%s:%s:%s",
            *result,
            strlen(*result) ? ";" : "",
            mimetype,
            extensions,
            description);

    l_debug("successfully processed mimetype %s", mimetype);

finished:
    free(extensions);
    return;
}

// Try to remove the dynamic MIME file used for dynamic content-type generation.
// You cannot rely on registry being sane at this point, as we can't guarantee
// the order destructors are called, so please don't access it here.
void __destructor fini_remove_dynamic_plist(void)
{
    CFURLRef    home_directory = NULL;
    CFURLRef    pref_directory = NULL;
    CFURLRef    mime_file      = NULL;
    CFURLRef    mime_file_lock = NULL;
    SInt32      error_code     = -1;

    // Resolve the home directory.
    home_directory = CFCopyHomeDirectoryURLForUser(NULL);

    if (home_directory == NULL) {
        goto finished;
    }

    // Resolve Preferences directory (this is how CoreFoundation does it), I
    // don't want to have to rely on this, but they don't make it easy.
    pref_directory = CFURLCreateWithFileSystemPathRelativeToBase(kCFAllocatorDefault,
                                                                 CFSTR("Library/Preferences/"),
                                                                 kCFURLPOSIXPathStyle,
                                                                 true,
                                                                 home_directory);

    if (pref_directory == NULL) {
        goto finished;
    }

    // Append the name of my cache file.
    mime_file  = CFURLCreateWithFileSystemPathRelativeToBase(kCFAllocatorDefault,
                                                             CFSTR("com.google.netscapesecurity.plist"),
                                                             kCFURLPOSIXPathStyle,
                                                             false,
                                                             pref_directory);
    mime_file_lock = CFURLCreateWithFileSystemPathRelativeToBase(kCFAllocatorDefault,
                                                                 CFSTR("com.google.netscapesecurity.plist.lockfile"),
                                                                 kCFURLPOSIXPathStyle,
                                                                 false,
                                                                 pref_directory);

    if (!mime_file || !mime_file_lock) {
        goto finished;
    }

    // Delete the file, and possibly stale lockfile, I don't care if it fails.
    CFURLDestroyResource(mime_file, &error_code);
    CFURLDestroyResource(mime_file_lock, &error_code);

finished:
    CFRelease(home_directory);
    CFRelease(pref_directory);
    CFRelease(mime_file);
    CFRelease(mime_file_lock);

    return;
}

// On Apple, we use a CFBundleRef instead of a dlfcn handle.
void platform_dlclose(void *handle)
{
    if (handle) CFRelease(handle);
}

void __export DynamicRegistrationFunction(void)
{
    // I don't need to do anything here, I just want to make sure I'm loaded so
    // that my constructors and destructors are exercised.
    l_message("Netscape Security Wrapper Initialized %s %s",
              NSSECURITY_VERSION,
              NSSECURITY_REVISON);
}
