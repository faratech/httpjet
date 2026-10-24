#ifndef ZEND_FALLTHROUGH
#define ZEND_FALLTHROUGH __attribute__((fallthrough))
#endif
#include <dlfcn.h>
#define DL_LOAD(libname) dlopen(libname, RTLD_LAZY | RTLD_GLOBAL)
#define DL_FETCH_SYMBOL dlsym
#define DL_ERROR dlerror
#define DL_UNLOAD dlclose
