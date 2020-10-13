#include <stdio.h>
#include <windows.h>

typedef void(*t_cast128_generate_key)();

int main() {
	HINSTANCE crypto = LoadLibraryA("../target/debug/crypto.dll");
    if (crypto == NULL) {
        printf("LoadLibraryA failed: %d", GetLastError());
        return -1;
    }

	void* cast128_generate_key_ptr = GetProcAddress(crypto, "cast128_generate_key");
    if (cast128_generate_key_ptr == NULL) {
        printf("GetProcAddress failed: %d", GetLastError());
        return -1;
    }

    t_cast128_generate_key cast128_generate_key = (t_cast128_generate_key)(cast128_generate_key_ptr);

	printf("before\n");

    cast128_generate_key();

    printf("after\n");

	return 0;
}
