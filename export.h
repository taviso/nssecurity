#ifndef __EXPORT_H
#define __EXPORT_H

NPError NP_GetEntryPoints(NPPluginFuncs *pFuncs);
NPError NP_GetValue(NPP instance, NPPVariable variable, void *value);
NPError NP_Initialize(NPNetscapeFuncs *aNPNFuncs, NPPluginFuncs *aNPPFuncs);
NPError NP_Shutdown(void);
char *  NP_GetMIMEDescription(void);
char *  NP_GetPluginVersion(void);

#endif
