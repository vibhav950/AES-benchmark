// #include "aes.cu.h" /*transitive include by key_schedule.c*/

extern "C" {
#include "key_schedule.c"
}

#include "test_values.h"
#include "benchmark.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cuda.h>

// #define WINDOW_SIZE (32 * AES_BLOCK_SIZE)
#define BLOCKS_PER_SM (32) /*set this according to the CUDA compute capability spec*/

#define CUDA_CHECK(stmt)                                                       \
  do {                                                                         \
    cudaError_t err = (stmt);                                                  \
    if ((err) != cudaSuccess) {                                                \
      printf("\x1B[31m[CUDA error, line: %d]:\x1B[0m %s\n", __LINE__, cudaGetErrorString(err));          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define PRINT_ARRAY(arr, len)                                                  \
  do {                                                                         \
    uint8_t *p8 = (uint8_t *)arr;                                              \
    for (int i = 0; i < len; i++)                                              \
      printf("%02x ", p8[i]);                                                  \
    printf("\n");                                                              \
  } while(0)


__device__ __constant__ uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

__device__ __constant__ uint8_t SBOX_INV[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

__device__ __constant__ uint8_t ShiftRowsTable[16] = {
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
};

__device__ __constant__ uint8_t InvShiftRowsTable[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
};

__device__ __constant__ uint8_t KeySchedule[16 * (AES128_ROUNDS + 1)];

__host__ void AES_Init_Key(aes128_key_t *key) {
  aes128_ks_t ks;
  aes128_key_schedule(key, &ks);
  CUDA_CHECK(cudaMemcpyToSymbol(KeySchedule, (uint8_t *)ks.rk, (4*(AES128_ROUNDS + 1)) * sizeof(uint32_t), 0, cudaMemcpyHostToDevice));
}

__device__ __forceinline__ void AddRoundKey(uint8_t state[16], int round) {
  state[threadIdx.x] ^= KeySchedule[round * 16 + threadIdx.x];
}

__device__ __forceinline__ void SubBytes(uint8_t state[16]) {
  state[threadIdx.x] = SBOX[state[threadIdx.x]];
}

__device__ __forceinline__ void InvSubBytes(uint8_t state[16]) {
  state[threadIdx.x] = SBOX_INV[state[threadIdx.x]];
}

__device__ __forceinline__ void ShiftRows(uint8_t instate[16], uint8_t outstate[16]) {
  outstate[threadIdx.x] = instate[ShiftRowsTable[threadIdx.x]];
}

__device__ __forceinline__ void InvShiftRows(uint8_t instate[16], uint8_t outstate[16]) {
  outstate[threadIdx.x] = instate[InvShiftRowsTable[threadIdx.x]];
}

__device__ __forceinline__ uint8_t mul2(uint8_t a) {
    // return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
    return (a << 1) ^ ((a & 0x80) >> 7) * 0x1b;
}

__device__ void MixColumns(uint8_t instate[16], uint8_t outstate[16]) {
    int tid = threadIdx.x;
    int col = tid / 4;
    int row = tid % 4;
    int base = 4 * col;

    uint8_t s0 = instate[base + 0];
    uint8_t s1 = instate[base + 1];
    uint8_t s2 = instate[base + 2];
    uint8_t s3 = instate[base + 3];
    uint8_t t = s0 ^ s1 ^ s2 ^ s3;
    uint8_t r = 0;

    switch (row) {
      case 0:
          r = mul2(s0 ^ s1) ^ s0 ^ t;
          break;
      case 1:
          r = mul2(s1 ^ s2) ^ s1 ^ t;
          break;
      case 2:
          r = mul2(s2 ^ s3) ^ s2 ^ t;
          break;
      case 3:
          r = mul2(s3 ^ s0) ^ s3 ^ t;
          break;
    }
    outstate[tid] = r;
}

__device__ void InvMixColumns(uint8_t instate[16], uint8_t outstate[16]) {
    int tid = threadIdx.x;
    int col = tid / 4;
    int row = tid % 4;
    int base = 4 * col;

    uint8_t s0 = instate[base + 0];
    uint8_t s1 = instate[base + 1];
    uint8_t s2 = instate[base + 2];
    uint8_t s3 = instate[base + 3];
    uint8_t t = s0 ^ s1 ^ s2 ^ s3;
    uint8_t u = mul2(mul2(s0 ^ s2));
    uint8_t v = mul2(mul2(s1 ^ s3));
    uint8_t t2 = mul2(u ^ v);

    uint8_t r = 0;
    switch (row) {
      case 0:
          r = t ^ s0 ^ mul2(s0 ^ s1);
          r ^= t2 ^ u;
          break;
      case 1:
          r = t ^ s1 ^ mul2(s1 ^ s2);
          r ^= t2 ^ v;
          break;
      case 2:
          r = t ^ s2 ^ mul2(s2 ^ s3);
          r ^= t2 ^ u;
          break;
      case 3:
          r = t ^ s3 ^ mul2(s3 ^ s0);
          r ^= t2 ^ v;
          break;
    }
    outstate[tid] = r;
}

/**
 * Encrypt `num_blocks` blocks of plaintext in parallel.
 * 
 * `d_in`, `d_out` reside on device memory.
 * 
 * Note: num_blocks is the number of blocks to be processed in parallel,
 * not to be confused with the total number of blocks in the input file!
 */
__global__ void AES_Encrypt(uint8_t *d_in, uint8_t *d_out, int num_blocks) {
  __shared__ uint8_t state[16];
  __shared__ uint8_t temp[16];

  if (blockIdx.x >= num_blocks)
    return;

  /* Each thread loads a byte */
  state[threadIdx.x] = d_in[blockIdx.x * AES_BLOCK_SIZE + threadIdx.x];

  /* Whitening step; initial AddRoundKey */
  AddRoundKey(state, 0);
  __syncthreads();

  /* Process all rounds */
  for (int round = 1; round <= Nr; round++) {
    SubBytes(state);
    __syncthreads();
    
    ShiftRows(state, temp);
    __syncthreads();

    /* Last round does not have MixColumns */
    if (round < Nr) {
      MixColumns(temp, state);
      __syncthreads();
    } else {
      /* Copy temp to state for the final round */
      state[threadIdx.x] = temp[threadIdx.x];
      __syncthreads();
    }
    
    AddRoundKey(state, round);
    __syncthreads();
  }

  /* Each thread stores a byte */
  d_out[blockIdx.x * AES_BLOCK_SIZE + threadIdx.x] = state[threadIdx.x];
}

__global__ void AES_Decrypt(uint8_t *d_ct, uint8_t *d_pt, int num_blocks) {
    __shared__ uint8_t state[16];
    __shared__ uint8_t temp[16];

    if (blockIdx.x >= num_blocks)
        return;

    state[threadIdx.x] = d_ct[blockIdx.x * AES_BLOCK_SIZE + threadIdx.x];

    AddRoundKey(state, Nr);
    __syncthreads();

    InvShiftRows(state, temp);
    __syncthreads();

    InvSubBytes(temp);
    __syncthreads();

    state[threadIdx.x] = temp[threadIdx.x];
    __syncthreads();

    for (int round = Nr - 1; round > 0; round--) {
        AddRoundKey(state, round);
        __syncthreads();

        InvMixColumns(state, temp);
        __syncthreads();

        InvShiftRows(temp, state);
        __syncthreads();

        InvSubBytes(state);
        __syncthreads();
    }

    AddRoundKey(state, 0);
    __syncthreads();

    d_pt[blockIdx.x * AES_BLOCK_SIZE + threadIdx.x] = state[threadIdx.x];
}

int main(int argc, char *argv[]) {
  FILE *infile, *outfile;
  long filesize;
  aes128_key_t key;
  int deviceId, numSM;
  char *deviceName;
  int windowSize;
  bool is_encrypt;

  if (argc != 4) {
      printf("Usage: %s [encrypt/decrypt] <infile> <outfile>\n", argv[0]);
      return 1;
  }

  if (strcmp(argv[1], "encrypt") && strcmp(argv[1], "decrypt")) {
    printf("Error: Invalid operation, expected encrypt/decrypt\n");
    return 1;
  }

  infile = fopen(argv[2], "rb");
  if (!infile) {
      printf("Error: Cannot open input file %s\n", argv[1]);
      return 1;
  }

  outfile = fopen(argv[3], "wb");
  if (!outfile) {
      printf("Error: Cannot open output file %s\n", argv[2]);
      fclose(infile);
      return 1;
  }

  if (!strcmp(argv[1], "encrypt"))
    is_encrypt = true;
  else
    is_encrypt = false;

  fseek(infile, 0, SEEK_END);
  filesize = ftell(infile);
  fseek(infile, 0, SEEK_SET);

  if (filesize % AES_BLOCK_SIZE != 0) {
      printf("Error: Input file size (%ld bytes) is not a multiple of AES_BLOCK_SIZE (%d bytes)\n", 
              filesize, AES_BLOCK_SIZE);
      fclose(infile);
      fclose(outfile);
      return 1;
  }

  memcpy(key.bytes, TEST_KEY, AES128_KEY_SIZE);
  AES_Init_Key(&key);

  deviceId = 0;
  cudaDeviceProp deviceProp;
  CUDA_CHECK(cudaGetDevice(&deviceId));
  CUDA_CHECK(cudaGetDeviceProperties(&deviceProp, deviceId));
  deviceName = deviceProp.name;
  numSM = deviceProp.multiProcessorCount;
  windowSize = BLOCKS_PER_SM * numSM * AES_BLOCK_SIZE;

  uint8_t *h_window_in = (uint8_t*)malloc(windowSize);
  uint8_t *h_window_out = (uint8_t*)malloc(windowSize);
  if (!h_window_in || !h_window_out) {
      printf("Error: Malloc fail\n");
      free(h_window_in);
      free(h_window_out);
      fclose(infile);
      fclose(outfile);
      return 1;
  }

  uint8_t *d_in, *d_out;
  CUDA_CHECK(cudaMalloc((void**)&d_in, windowSize));
  CUDA_CHECK(cudaMalloc((void**)&d_out, windowSize));

  dim3 blocksz(AES_BLOCK_SIZE);

  /**
   * Read the file using a sliding window technique
   * Read MIN(windowSize, remaining_bytes) bytes at a time, and distribute among CUDA blocks
   */
  long nprocessed = 0;
  timer_reset();
  while (nprocessed < filesize) {
      long ntodo = (filesize - nprocessed < windowSize) ? (filesize - nprocessed) : windowSize;

      size_t nread = fread(h_window_in, 1, ntodo, infile);
      if (nread != ntodo) {
          printf("Error: Failed to read expected bytes from input file\n");
          break;
      }

      int nblocks = ntodo / AES_BLOCK_SIZE;

      CUDA_CHECK(cudaMemcpy(d_in, h_window_in, ntodo, cudaMemcpyHostToDevice));

      dim3 gridsz(nblocks);

      timer_start();

      if (is_encrypt)
        AES_Encrypt<<<gridsz, blocksz>>>(d_in, d_out, nblocks);
      else
        AES_Decrypt<<<gridsz, blocksz>>>(d_in, d_out, nblocks);

      timer_pause_accumulate();

      CUDA_CHECK(cudaGetLastError());
      
      CUDA_CHECK(cudaMemcpy(h_window_out, d_out, ntodo, cudaMemcpyDeviceToHost));
      
      size_t bytes_written = fwrite(h_window_out, 1, ntodo, outfile);
      if (bytes_written != ntodo) {
          printf("Error: Failed to write expected bytes to output file\n");
          break;
      }
      
      nprocessed += ntodo;
  }

  CUDA_CHECK(cudaFree(d_in));
  CUDA_CHECK(cudaFree(d_out));
  free(h_window_in);
  free(h_window_out);
  fclose(infile);
  fclose(outfile);

  printf("\x1B[36m");
  printf("================ SUMMARY ================\n");
  printf("Processed %ld bytes, %ld blocks\n", filesize, filesize / AES_BLOCK_SIZE);
  printf("Time taken: %lf ms\n", timer_get_accumulated());
  printf("CUDA device: %s\n", deviceName);
  printf("Max blocks: %d\n", windowSize / AES_BLOCK_SIZE);
  printf("\x1B[0m");
  
  return 0;
}