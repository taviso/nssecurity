#ifndef __POLICY_H
#define __POLICY_H

bool policy_plugin_allowed_domain(struct plugin *plugin, char *url);
bool policy_plugin_allowed_protocol(struct plugin *plugin, char *url);
bool policy_plugin_allowed_url(struct plugin *plugin, char *url);

#endif
