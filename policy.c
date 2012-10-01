// Copyright 2012 Google Inc. All Rights Reserved.
//
// Author: taviso@google.com
//
// Policy decision logic for plugin loading.
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

#include "log.h"
#include "npapi.h"
#include "npfunctions.h"
#include "ini.h"
#include "config.h"
#include "npapi.h"
#include "npruntime.h"
#include "util.h"
#include "config.h"
#include "policy.h"

static const char kDomainCharacterSet[] = "abcdefghijklmnopqrstuvwxyz0123456789-._";
static const size_t kDomainMaxLen = 128;
static const char kHttpPrefix[] = "http://";
static const char kHttpsPrefix[] = "https://";

// This is where the policy decision for domains is made. The plugin structure
// includes a list of shell-style globs for permitted domains, separated by
// ',', for example:
//
//      *.corp.google.com,*.yahoo.com,www.microsoft.com,??.wikipedia.org
//
// These strings are matched with fnmatch(), if *any* of the strings specified
// match, then return true. If the policy does not exist, because no
// AllowedDomains were specified, then always return false.
//
// Note that if AllowInsecure is set, it's possible there are some bizarre URL
// tricks you can use to confuse this. I hope forcing https will make it harder
// to get these through.
bool policy_plugin_allowed_domain(struct plugin *plugin, char *url)
{
    char *policy;
    char *domainglob;
    char *saveptr;
    char *hostname;

    l_debug("testing %s against domain policy %s for url %s",
            plugin->section,
            plugin->allow_domains ? plugin->allow_domains : "<None>",
            url);

    // Verify there are some domains.
    if (!plugin->allow_domains) {
        l_debug("plugin %s has no permitted domains, so %s is not permitted",
                plugin->section,
                url);
        return false;
    }

    // Verify the prefix matches the whitelisted set http://, https://,
    // additional sane protocols can be added on request.
    if (strncmp(url, kHttpPrefix, strlen(kHttpPrefix)) == 0) {
        hostname = url + strlen(kHttpPrefix);
    } else if (strncmp(url, kHttpsPrefix, strlen(kHttpsPrefix)) == 0) {
        hostname = url + strlen(kHttpsPrefix);
    } else {
        l_warning("plugin %s loaded from unrecognised protocol at %s",
                  plugin->section,
                  url);
        return false;
    }

    // Take everything between '://' and the first '/', we've already verified
    // that hostname is a sane length, and contains "reasonable" characters for
    // a URL.
    //
    //  http://www.foo.com/blah?blah=blah&blah=blah#blah => www.foo.com
    //
    hostname = strndupa(hostname, strcspn(hostname, "/"));

    // Now we have what should be just the hostname, but let's verify it looks
    // sane.
    if (strspn(hostname, kDomainCharacterSet) != strlen(hostname)) {
        l_debug("discovered non-whitelisted character in hostname %s",
                hostname);
        return false;
    }

    // Check it's a reasonable length
    if (strlen(hostname) > kDomainMaxLen || strlen(hostname) == 0) {
        l_debug("rejecting unrealistic length %u for domain name %s",
                strlen(hostname),
                hostname);
        return false;
    }

    // Create a copy of the policy we can modify with strtok.
    policy  = strdupa(plugin->allow_domains);
    saveptr = NULL;

    // Test each permitted domain.
    while ((domainglob = strtok_r(policy, ",", &saveptr))) {
        // Clear pointer for strtok
        policy = NULL;

        // Check if this glob matches the host domain.
        if (fnmatch(domainglob, hostname, FNM_NOESCAPE) == 0) {
            l_debug("domain %s allowed to load plugin %s, matches %s",
                    hostname,
                    plugin->section,
                    domainglob);
            return true;
        }
    }

    // No matching globs found, the plugin is not allowed.
    l_debug("domain %s is not allowed to load plugin %s",
            hostname,
            plugin->section);

    return false;
}

// By default, plugins with domain whitelists must be loaded over https so that
// we have some confidence about the domain. This can be disabled if required,
// which allows any protocol.
bool policy_plugin_allowed_protocol(struct plugin *plugin, char *url)
{
    // If allow_insecure was set, then I don't care what protocol you use.
    if (plugin->allow_insecure) {
        return true;
    }

    // Plugin has to be loaded from a secure page.
    return !!! strncmp(url, kHttpsPrefix, strlen(kHttpsPrefix));
}

// Convenience wrapper to call all policy routines on a single URL.
bool policy_plugin_allowed_url(struct plugin *plugin, char *url)
{
    return policy_plugin_allowed_protocol(plugin, url)
        && policy_plugin_allowed_domain(plugin, url);
}

#if defined(ENABLE_RUNTIME_TESTS)

// Define some policy tests to run here if this is a debug build.
static void __constructor test_policy_allowed(void)
{
    struct plugin testplugin1 = {
        .section       = "Domain With Wildcard",
        .allow_domains = "*.google.com,google.com,*.safe.com",
    };
    struct plugin testplugin2 = {
        .section       = "Empty Domain Specification",
        .allow_domains = "",
    };

    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.google.com/safepage.html") == true);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://google.com/safepage.html") == true);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://subdomain.google.com/safepage.html") == true);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://subdomain.google.com/") == true);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://subdomain.google.com") == true);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.safe.com/safepage.html") == true);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.safe.com/test/test/") == true);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.safe.com//") == true);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.google.com.evil.com/") == false);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.google.com.evil.com/http://www.google.com/safe") == false);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.google.com@evil.com/") == false);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.google.com:@evil.com/") == false);
    assert(policy_plugin_allowed_domain(&testplugin1, "data://www.google.com/,evil") == false);
    assert(policy_plugin_allowed_domain(&testplugin1, "https://www.google.com:@evil.com") == false);
    assert(policy_plugin_allowed_protocol(&testplugin1, "https://www.google.com/") == true);
    assert(policy_plugin_allowed_protocol(&testplugin1, "ftp://www.google.com/") == false);
    assert(policy_plugin_allowed_domain(&testplugin2, "https://www.google.com/") == false);
    assert(policy_plugin_allowed_url(&testplugin1, "https://www.google.com/safepage.html") == true);
    assert(policy_plugin_allowed_url(&testplugin1, "https://www.google.com.evil.com/") == false);
    return;
}

#endif
