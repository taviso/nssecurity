// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// Miscellaneous utility routines.
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

#include <stdbool.h>
#include <stdlib.h>
#include <fnmatch.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "log.h"
#include "npapi.h"
#include "npfunctions.h"
#include "ini.h"
#include "config.h"
#include "log.h"
#include "npapi.h"
#include "npruntime.h"
#include "config.h"
#include "util.h"

// Format string to encode a messsage to pass to the browser.
static const char kJSDisplayEncodedMessageFormat[] =
    "try {                                              "
    "   window.hasOwnProperty('__nssecurity_warning')   "
    "       ? false                                     "
    "       : alert(unescape('%s'));                    "
    "   window.__nssecurity_warning=true;               "
    "} catch (e) {};";

// Maximum length string I'll accept from browser.
static const size_t kNetscapeStringMax = 2048;
static const size_t kMessageLengthMax = 2048;

static bool encode_javascript_string(const char *message, char **output);

// We use this simple function for translating strings from the browser into
// cstrings. These strings can be untrusted, so verify them carefully.
bool netscape_string_convert(NPString *string, char **output)
{
    // Sanity check the string length.
    if (string->UTF8Length > kNetscapeStringMax) {
        l_debug("refusing to convert very long string, length %u",
                string->UTF8Length);
        return false;
    }

    // Does it contain nuls or other indicators of encoding issues?
    if (strnlen(string->UTF8Characters, string->UTF8Length) != string->UTF8Length) {
        l_debug("refusing to convert weird encoding, %u != %u, %s",
                strnlen(string->UTF8Characters, string->UTF8Length),
                string->UTF8Length,
                string->UTF8Characters);
        return false;
    }

    // Okay, it seems sane. Copy the output.
    return !! (*output = strndup(string->UTF8Characters, string->UTF8Length));
}

// We may want to display a message to the user, but don't want to have to
// create our own windows. We can ask the browser to display it instead, but
// have to be careful about what we send.
bool netscape_display_message(NPP instance, const char *message)
{
    void     *element;
    char     *encoded;
    NPError   result;
    NPString  script;
    NPVariant output;

    // Verify the parameters are sane,
    if (!message || !instance) {
        l_debug("invalid instance or message received, cannot display");
        return false;
    }

    // No need to actually display the empty message
    if (!strlen(message)) {
        return true;
    }

    // Retrieve the plugin object.
    if (registry.netscape_funcs->getvalue(instance,
                                          NPNVPluginElementNPObject,
                                          &element) != NPERR_NO_ERROR) {
        l_debug("unable to retrieve element object to display message");
        return false;
    }

    // We cannot display a message this way in Firefox due to a bug.
    if (strstr(registry.netscape_funcs->uagent(instance), "Firefox")) {
        l_warning("FIXME: unable to display messages in FireFox due to a bug");
        return false;
    }

    // Percent encode the required string.
    if (!encode_javascript_string(message, &encoded)) {
        l_debug("unable to construct javascript safe string, failed");
        return false;
    }

    // To produce the final message, we need to allow for the code to alert and
    // unescape the message as well.
    script.UTF8Characters = alloca(strlen(encoded)
                                 + strlen(kJSDisplayEncodedMessageFormat));

    // Produce the NPString, which doesn't want the terminating nul. Luckily,
    // that's what sprintf returns.
    script.UTF8Length = sprintf((char *) script.UTF8Characters,
                                kJSDisplayEncodedMessageFormat,
                                encoded);

    // This should evaluate the script NPString in the context of the plugin
    // object.
    result = registry.netscape_funcs->evaluate(instance,
                                               element,
                                               &script,
                                               &output);


    // Print debugging message if that failed.
    if (result != NPERR_NO_ERROR) {
        l_debug("netscape returned error displaying message %s", encoded);
    }

    // Clean up.
    registry.netscape_funcs->releasevariantvalue(&output);
    free(encoded);

    return result == NPERR_NO_ERROR;
}

bool netscape_plugin_geturl(NPP instance, char **url)
{
    void          *window;
    NPIdentifier  *locationid;
    NPIdentifier  *hrefid;
    NPVariant      location;
    NPVariant      href;

    // We need often need to query the url hosting the current instance to
    // apply our policy logic. This routine handles that.
    //
    // We do this by querying window.location.href, while this may seem
    // fragile, it's actually the officially supported method of retrieving the
    // URL. Being able to fool it would break most popular plugins, so we can
    // rely on browser vendors maintaining it.
    if (registry.netscape_funcs->getvalue(instance,
                                          NPNVWindowNPObject,
                                          &window) != NPERR_NO_ERROR) {
        l_debug("failed to fetch window object for instance %p", instance);
        return false;
    }

    // Create required identifiers to query the objects.
    //
    // Why not use location.hostname?
    //
    // > location.__defineGetter__("hostname", function () { return "arbitrary"; })
    // > undefined
    // > location.hostname
    // > "arbitrary"
    //
    // In fact the browser guarantees nothing except window.location.href.
    locationid = registry.netscape_funcs->getstringidentifier("location");
    hrefid = registry.netscape_funcs->getstringidentifier("href");

    // Get the Location object.
    if (!registry.netscape_funcs->getproperty(instance,
                                              window,
                                              locationid,
                                              &location)
            || !NPVARIANT_IS_OBJECT(location)) {
        l_debug("failed to fetch location object for instance %p", instance);
        return false;
    }

    // Get the URL from the Location object via href.
    if (!registry.netscape_funcs->getproperty(instance,
                                              location.value.objectValue,
                                              hrefid,
                                              &href)
            || !NPVARIANT_IS_STRING(href)) {
        l_warning("failed to fetch href string for instance %p", instance);
        return false;
    }

    // No longer need location object.
    registry.netscape_funcs->releasevariantvalue(&location);

    // Finally, Convert the NPString returned into a C string.
    if (!netscape_string_convert(&NPVARIANT_TO_STRING(href), url)) {
        l_warning("failed to convert NPString to c string for %p", instance);
        return false;
    }

    // Clear the NPString.
    registry.netscape_funcs->releasevariantvalue(&href);

    return true;
}

// Used to percent encode messages so we can ignore sanitisation.
static bool encode_javascript_string(const char *message, char **output)
{
    // Sanity check parameters.
    if (!message || strlen(message) > kMessageLengthMax)
        return false;

    // Allow for triple expansion.
    if (!(*output = malloc(strlen(message) * 3 + 1))) {
        l_debug("memory allocation failure constructing message");
        return false;
    }

    // Safely encode string using percent-encodiung.
    for (**output = 0; *message; message++) {
        sprintf(*output + strlen(*output), "%%%02hx", *message);
    }

    return true;
}

#if defined(ENABLE_RUNTIME_TESTS)
static void __constructor test_encoding_message(void)
{
    char *output;

    assert(encode_javascript_string("test", &output) == true);
    assert(strcmp(output, "%74%65%73%74") == 0);
    free(output);

    assert(encode_javascript_string("", &output) == true);
    assert(strcmp(output, "") == 0);
    free(output);

    assert(encode_javascript_string(NULL, &output) == false);
}
#endif
