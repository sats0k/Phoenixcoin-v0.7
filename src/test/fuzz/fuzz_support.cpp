#include "allocators.h"
#include "util.h"

#include <cstdarg>

LockedPageManager LockedPageManager::instance;

int OutputDebugStringF(const char* /*pszFormat*/, ...)
{
    return 0;
}
