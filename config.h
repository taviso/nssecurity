#ifndef __CONFIG_H
#define __CONFIG_H

struct registry;
struct plugin;

struct registry {
    char            *mime_description;
    NPNetscapeFuncs *netscape_funcs;
    struct plugin   *global;
    struct plugin   *plugins;
};

struct plugin {
    char            *allow_insecure;
    char            *allow_domains;
    char            *allow_override;
    char            *allow_port;
    char            *allow_auth;
    char            *warning;
    char            *plugin;
    char            *section;
    char            *description;
    char            *name;
    char            *mime_description;
    void            *handle;
    NPPluginFuncs   *plugin_funcs;
    struct plugin   *next;
};

extern struct registry registry;

bool netscape_plugin_list_destroy(void);

#define NSSECURITY_REVISON      "$DateTime: 2012/02/20 07:36:10 $"
#define NSSECURITY_PATH         "/etc/nssecurity.ini"
#define NSSECURITY_USER_PATH    ".nssecurity.ini"
#define NSSECURITY_TAG          "nssecurity"

#ifndef __export
# define __export        __attribute__((visibility("default")))
#endif

#ifndef __constructor
# define __constructor   __attribute__((constructor))
#endif

#ifndef __unused
# define __unused        __attribute__((unused))
#endif

#ifndef __destructor
# define __destructor    __attribute__((destructor))
#endif

#endif
