#include <stdio.h>

#define USE_SINGLE_HEADER 0

#if USE_SINGLE_HEADER
#include "single_header/HideImport.hpp"
#else
#include "src/HideImport.hpp"
#endif

int main() {
    printf("Hello World!\n");

    uintptr_t func = HideImport::GetSymbol("libc.so", "malloc");
    int is_hooked = IS_FUNCTION_HOOKED(func);
    uintptr_t a = is_hooked == 1 ? NULL : func;

    HI_FUNCTION_POINTER(my_malloc, void*, size_t size) = HI_GET_SAFE("libc.so", "malloc");

    void *testMemory = my_malloc(20);
    printf("my_malloc test returned: %p\n", testMemory);
    free(testMemory);

    void *testMemory2 = HI_CALL_SAFE("libc.so", malloc, void*, size_t)(15);
    printf("malloc test 2 returned: %p\n", testMemory2);
    free(testMemory2);

    return 0;
}