#ifndef SPECK_DECRYPT_H
#define SPECK_DECRYPT_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

    // Constantes
#define ROUNDS 45
#define BLOCK_BYTES 16

// Variables globales (las mismas que en tu .cpp)
    extern uint64_t roundKeys[ROUNDS];

    // Funciones inline (declaración - implementación en .cpp si no son inline)
    uint64_t rol(uint64_t x, int r);
    uint64_t ror(uint64_t x, int r);

    // Funciones principales
    void parseHexKey(const char* keyStr, uint64_t key[2]);
    void speckKeySchedule(uint64_t key[2]);
    void speckDecrypt(uint64_t* x, uint64_t* y);
    unsigned char* decryptShellcode(const unsigned char* encryptedShellcodeBuffer,
        size_t shellcodeLength,
        const char* keyStr);

#ifdef __cplusplus
}
#endif

#endif // SPECK_DECRYPT_H