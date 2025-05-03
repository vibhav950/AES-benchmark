/**
 * @file aes.h
 * @brief Defines for AES-128
 */
#pragma once

#include <immintrin.h>
#include <stdint.h>

#define ALIGN16 __attribute__((aligned(16)))

#define AES_BLOCK_SIZE 16U
#define AES128_KEY_SIZE 16U
#define AES128_ROUNDS 10U

#define Nk 4
#define Nb 4
#define Nr AES128_ROUNDS

/** The AES-128 cipher key */
typedef ALIGN16 struct _aes128_key_st {
  union {
    uint8_t bytes[AES128_KEY_SIZE];
    uint32_t words[AES128_KEY_SIZE / 4];
  };
} aes128_key_t;

/** The AES-128 key schedule */
typedef ALIGN16 struct _aes128_ks_st {
  uint32_t rk[4 * (AES128_ROUNDS + 1)];
} aes128_ks_t;
