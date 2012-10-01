#ifndef __PLATFORM_H
#define __PLATFORM_H

// Some wrappers to hide the functional differences between Apple and Linux.

char * platform_getmimedescription(struct plugin *plugin);
void * platform_dlopen(const char *plugin);
void * platform_dlsym(void *handle, const char *symbol);
char * platform_getname(void);
char * platform_getdescription(void);
char * platform_getversion(void);
void platform_dlclose(void *handle);

#endif
