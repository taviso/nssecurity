#ifndef __INSTANCE_H
#define __INSTANCE_H

bool netscape_instance_resolve(NPP instance, struct plugin **result);
bool netscape_instance_map(NPP instance, struct plugin *plugin);
bool netscape_instance_destroy(NPP instance);
bool netscape_instance_list_destroy(void);

#endif
