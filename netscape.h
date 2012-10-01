#ifndef __NETSCAPE_H
#define __NETSCAPE_H

NPError netscape_plugin_destroy(NPP instance, NPSavedData **save);
NPError netscape_plugin_getvalue(NPP instance,
                                 NPPVariable variable,
                                 void *value);
NPError netscape_plugin_new(NPMIMEType pluginType,
                            NPP instance,
                            uint16_t mode,
                            int16_t argc,
                            char *argn[],
                            char *argv[],
                            NPSavedData *saved);
NPError netscape_plugin_setwindow(NPP instance, NPWindow* window);
NPError netscape_plugin_newstream(NPP instance,
                                  NPMIMEType type,
                                  NPStream *stream,
                                  NPBool seekable,
                                  uint16_t *stype);
NPError netscape_plugin_destroystream(NPP instance,
                                      NPStream *stream,
                                      NPReason reason);
NPError netscape_plugin_setvalue(NPP instance,
                                 NPNVariable variable,
                                 void *value);
void netscape_plugin_streamasfile(NPP instance,
                                  NPStream *stream,
                                  const char *fname);
void netscape_plugin_print(NPP instance, NPPrint *PrintInfo);
void netscape_plugin_urlnotify(NPP instance,
                               const char *url,
                               NPReason reason,
                               void *notifyData);
int16_t netscape_plugin_handleevent(NPP instance, void *event);
int32_t netscape_plugin_writeready(NPP instance, NPStream *stream);
int32_t netscape_plugin_write(NPP instance,
                              NPStream *stream,
                              int32_t offset,
                              int32_t len,
                              void *buf);
NPBool netscape_plugin_gotfocus(NPP instance, NPFocusDirection direction);
void netscape_plugin_lostfocus(NPP instance);
void netscape_plugin_urlredirectnotify(NPP instance,
                                       const char* url,
                                       int32_t status,
                                       void* notifyData);
NPError netscape_plugin_clearsitedata(const char* site,
                                      uint64_t flags,
                                      uint64_t maxAge);
char **netscape_plugin_getsiteswithdata(void);

#endif
