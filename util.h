#ifndef __UTIL_H
#define __UTIL_H

// This useful routine is only available for _GNU_SOURCE
#ifndef _GNU_SOURCE
# define strdupa(str) strcpy(alloca(strlen(str) + 1), (str))

// Ugh. I hope this is equivalent to the GNU routine.
# define strndupa(str, len) strncpy(memset(alloca((len) + 1), 0, (len) + 1),    \
                                    (str),                                      \
                                    (len));
#endif

bool netscape_string_convert(NPString *string, char **output);
bool netscape_display_message(NPP instance, const char *message);
bool netscape_plugin_geturl(NPP instance, char **url);

#endif
