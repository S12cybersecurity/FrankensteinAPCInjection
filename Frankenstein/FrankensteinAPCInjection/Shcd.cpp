#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "Shcd.h"

#define ROUNDS 45
#define BLOCK_BYTES 16 // 128 bits

uint64_t roundKeys[ROUNDS];

inline uint64_t rol(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

inline uint64_t ror(uint64_t x, int r) {
    return (x >> r) | (x << (64 - r));
}


inline void parseHexKey(const char* keyStr, uint64_t key[2]) {
    char buffer[17] = { 0 };
    strncpy(buffer, keyStr, 16);
    key[0] = strtoull(buffer, NULL, 16);
    strncpy(buffer, keyStr + 16, 16);
    key[1] = strtoull(buffer, NULL, 16);
}

inline void speckKeySchedule(uint64_t key[2]) {
    roundKeys[0] = key[0];
    uint64_t b = key[1];
    for (int i = 0; i < ROUNDS - 1; i++) {
        b = (ror(b, 8) + roundKeys[i]) ^ i;
        roundKeys[i + 1] = rol(roundKeys[i], 3) ^ b;
    }
}


inline void speckDecrypt(uint64_t* x, uint64_t* y) {
    for (int i = ROUNDS - 1; i >= 0; i--) {
        *y = ror(*y ^ *x, 3);
        *x = rol((*x ^ roundKeys[i]) - *y, 8);
    }
}

unsigned char* decryptShellcode(const unsigned char* encryptedShellcodeBuffer, size_t shellcodeLength, const char* keyStr) {
    size_t paddedLen = (shellcodeLength + BLOCK_BYTES - 1) & ~(BLOCK_BYTES - 1);

    uint64_t key[2];
    parseHexKey(keyStr, key);
    speckKeySchedule(key);

    unsigned char* decryptBuffer = (unsigned char*)malloc(paddedLen);
    if (!decryptBuffer) return NULL;

    const uint64_t* iv = (const uint64_t*)encryptedShellcodeBuffer;

    memcpy(decryptBuffer, encryptedShellcodeBuffer + BLOCK_BYTES, paddedLen);

    uint64_t prevDecrypt[2] = { iv[0], iv[1] };
    for (size_t i = 0; i < paddedLen; i += BLOCK_BYTES) {
        uint64_t* block = (uint64_t*)(decryptBuffer + i);
        uint64_t temp[2] = { block[0], block[1] };

        speckDecrypt(&block[0], &block[1]);

        block[0] ^= prevDecrypt[0];
        block[1] ^= prevDecrypt[1];

        prevDecrypt[0] = temp[0];
        prevDecrypt[1] = temp[1];
    }

    return decryptBuffer;
}

