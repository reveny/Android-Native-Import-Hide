# Android-Native-Import-Hide
A library for hiding and retrieving imports in ELF binaries.

## Features
- [x] Hide and retrieve symbols in ELF binaries
- [x] Support for multiple architectures (x86_64, ARM, ARM64)
- [x] Cache resolved symbols for performance
- [x] Thread-safe symbol resolution
- [x] Detailed logging for debugging purposes
- [x] Check hooking before calling (ARM and ARM64 only)
- [ ] Prevent hooking completely 

## Build and Installation
Compatible Compilers
- GCC or Clang
- Make
- CMake

Clone the repository:
```sh
git clone https://github.com/reveny/Android-Native-Import-Hide.git
cd Android-Native-Import-Hide
```

To include the library in your project, add the following line to your source code:

```cpp
#include "HideImport.hpp"
```
## Usage
Here is a simple example demonstrating how to use the library and make sure to include HideImport.cpp in the source file list:

## Using `HI_GET`
```cpp
#include <stdio.h>
#include "HideImport.hpp"

int main() {
    HI_FUNCTION_POINTER(my_malloc, void*, size_t size) = HI_GET("libc.so", "malloc");

    void *testMemory = my_malloc(20);
    printf("my_malloc test returned: %p\n", testMemory);
    free(testMemory);

    return 0;
}
```

## Using `HI_CALL`
```cpp
#include <stdio.h>
#include "HideImport.hpp"

int main() {
    void *testMemory2 = HI_CALL("libc.so", malloc, void*, size_t)(15);
    printf("malloc test 2 returned: %p\n", testMemory2);
    free(testMemory2);

    return 0;
}
```

## Using `HI_SAFE`
```cpp
#include <stdio.h>
#include "HideImport.hpp"

int main() {
    void *testMemory2 = HI_CALL_SAFE("libc.so", malloc, void*, size_t)(15);
    printf("malloc test 2 returned: %p\n", testMemory2);
    free(testMemory2);

    return 0;
}
```
The SAFE version will check if the function is hooked before calling. If the function happens to be hooked, the call will not be executed and return NULL.

## Single Header Library
A single header version of the library is available for convenience. Simply include single_header/HideImport.hpp in your project.

## Preview
Disassembly without string encryption: <br>
![Preview](https://github.com/reveny/Android-Native-Import-Hide/blob/main/images/preview.png)

Disassembly with string encryption: <br>
![Preview](https://github.com/reveny/Android-Native-Import-Hide/blob/main/images/preview2.png)

## Credits
Special thanks to:
- [ARandomPerson](https://github.com/ARandomPerson7) for doing a lot of the work and the significant contribution and collaboration on this project.
- [Ac3ss0r](https://github.com/ac3ss0r) for some inspiration from [ShellcodeLab](https://github.com/ac3ss0r/ShellcodeLab)
- LSPlt for inspiration from their module listing implementation: [LSPlt](https://github.com/LSPosed/LSPlt)

## Contact
Feel free to reach out via:
- Telegram Group: [Join Group](https://t.me/reveny1)
- Telegram Contact: [Contact](https://t.me/revenyy)

## License
This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.
