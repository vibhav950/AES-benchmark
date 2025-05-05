#include "aes.h"
#include "benchmark.h" // #include <Windows.h>
#include "test.h"
#include "test_values.h"

#include <assert.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_processor_count(void) {
  SYSTEM_LOGICAL_PROCESSOR_INFORMATION *info = NULL;
  DWORD length = 0;
  int physical_cores = 0;

  GetLogicalProcessorInformation(NULL, &length);
  info = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION *)malloc(length);
  if (!info) {
    fprintf(stderr, "Memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  if (!GetLogicalProcessorInformation(info, &length)) {
    fprintf(stderr, "GetLogicalProcessorInformation failed\n");
    free(info);
    exit(EXIT_FAILURE);
  }

  DWORD count = length / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
  for (DWORD i = 0; i < count; ++i) {
    if (info[i].Relationship == RelationProcessorCore) {
      physical_cores++;
    }
  }

  free(info);
  return physical_cores;
}

static inline __m128i __attribute__((always_inline))
KEY_128_ASSIST(__m128i temp1, __m128i temp2) {
  __m128i temp3;
  temp2 = _mm_shuffle_epi32(temp2, 0xff);
  temp3 = _mm_slli_si128(temp1, 0x04);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x04);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp3 = _mm_slli_si128(temp3, 0x04);
  temp1 = _mm_xor_si128(temp1, temp3);
  temp1 = _mm_xor_si128(temp1, temp2);
  return temp1;
}

static void aes128_expand_key(const aes128_key_t *key, aes128_ks_t *ks) {
  const __m128i *k = (const __m128i *)key->bytes;
  __m128i temp1, temp2;
  __m128i *Key_Schedule = (__m128i *)ks->rk;
  temp1 = _mm_loadu_si128(k);
  Key_Schedule[0] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x01);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[1] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x02);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[2] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x04);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[3] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x08);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[4] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[5] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[6] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[7] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[8] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[9] = temp1;
  temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
  temp1 = KEY_128_ASSIST(temp1, temp2);
  Key_Schedule[10] = temp1;
  _mm256_zeroall();
}

void aes128_encrypt_ks(const aes128_key_t *key, aes128_ks_t *ks) {
  assert((key != NULL) && (ks != NULL));
  aes128_expand_key(key, ks);
}

void aes128_decrypt_ks(const aes128_key_t *key, aes128_ks_t *ks) {
  aes128_ks_t temp_ks;
  __m128i *Key_Schedule, *Temp_Key_Schedule;

  assert((key != NULL) && (ks != NULL));

  Key_Schedule = (__m128i *)ks->rk;
  Temp_Key_Schedule = (__m128i *)temp_ks.rk;

  aes128_expand_key(key, &temp_ks);
  Key_Schedule[Nr] = Temp_Key_Schedule[0];
  Key_Schedule[Nr - 1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
  Key_Schedule[Nr - 2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
  Key_Schedule[Nr - 3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
  Key_Schedule[Nr - 4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
  Key_Schedule[Nr - 5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
  Key_Schedule[Nr - 6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
  Key_Schedule[Nr - 7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
  Key_Schedule[Nr - 8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
  Key_Schedule[Nr - 9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
  Key_Schedule[0] = Temp_Key_Schedule[Nr];
  _mm256_zeroall();
}

#define LOAD128(x) _mm_loadu_si128(x)
#define STORE128(x, y) _mm_storeu_si128(x, y)
#define XOR128(x, y) _mm_xor_si128(x, y)
#define ZEROALL256 _mm256_zeroall

#define AESENC(x, y) _mm_aesenc_si128(x, y)
#define AESENCLAST(x, y) _mm_aesenclast_si128(x, y)
#define AESDEC(x, y) _mm_aesdec_si128(x, y)
#define AESDECLAST(x, y) _mm_aesdeclast_si128(x, y)

void aesni_block_encr(uint8_t *in, uint8_t *out, const aes128_ks_t *ks) {
  const __m128i *rk = (const __m128i *)ks->rk;
  __m128i tmp = LOAD128((const __m128i *)in);
  int j;
  tmp = XOR128(tmp, rk[0]);
  for (j = 1; j < Nr; j++) {
    tmp = AESENC(tmp, rk[j]);
  }
  tmp = AESENCLAST(tmp, rk[j]);
  STORE128((__m128i *)out, tmp);
  ZEROALL256();
}

void aesni_block_decr(uint8_t *in, uint8_t *out, const aes128_ks_t *ks) {
  const __m128i *rk = (const __m128i *)ks->rk;
  __m128i tmp = LOAD128((const __m128i *)in);
  int j;
  tmp = XOR128(tmp, rk[0]);
  for (j = 1; j < Nr; j++) {
    tmp = AESDEC(tmp, rk[j]);
  }
  tmp = AESDECLAST(tmp, rk[j]);
  STORE128((__m128i *)out, tmp);
  ZEROALL256();
}

#define WINDOW_SIZE 1024 * 1024 /* 1 MB sliding window buffer */
#define BLOCKS_PER_WINDOW (WINDOW_SIZE / AES_BLOCK_SIZE)

typedef struct {
  aes128_ks_t *ks;
  uint8_t *input;
  uint8_t *output;
  int thread_id;
  int num_threads;
  int total_blocks;
} ThreadData;

typedef unsigned(__stdcall *thread_func_t)(void *);

unsigned __stdcall encrypt_thread(void *param) {
  ThreadData *data = (ThreadData *)param;
  for (int i = data->thread_id; i < data->total_blocks;
       i += data->num_threads) {
    aesni_block_encr(data->input + i * AES_BLOCK_SIZE,
                     data->output + i * AES_BLOCK_SIZE, data->ks);
  }
  _endthreadex(0);
  return 0;
}

unsigned __stdcall decrypt_thread(void *param) {
  ThreadData *data = (ThreadData *)param;
  for (int i = data->thread_id; i < data->total_blocks;
       i += data->num_threads) {
    aesni_block_decr(data->input + i * AES_BLOCK_SIZE,
                     data->output + i * AES_BLOCK_SIZE, data->ks);
  }
  _endthreadex(0);
  return 0;
}

void aesni_do(const char *input_file, const char *output_file,
              aes128_key_t *key, int num_threads, thread_func_t thread_func) {
  FILE *in, *out;
  aes128_ks_t ks;
  HANDLE *threads;
  ThreadData *thread_data;
  long file_size;
  int total_blocks;
  size_t blocks_processed, blocks_to_process, bytes_to_process, bytes_read;

  in = fopen(input_file, "rb");
  if (!in) {
    fprintf(stderr, "Could not open file\n");
    exit(EXIT_FAILURE);
  }

  out = fopen(output_file, "wb");
  if (!out) {
    fprintf(stderr, "Could not open output file\n");
    exit(EXIT_FAILURE);
  }

  fseek(in, 0, SEEK_END);
  file_size = ftell(in);
  fseek(in, 0, SEEK_SET);

  if (file_size % AES_BLOCK_SIZE != 0) {
    fprintf(stderr, "Input file size is not a multiple of AES block size\n");
    exit(EXIT_FAILURE);
  }

  /** Expand AES key */
  if (thread_func == encrypt_thread) {
    aes128_encrypt_ks(key, &ks);
  } else {
    aes128_decrypt_ks(key, &ks);
  }

  total_blocks = file_size / AES_BLOCK_SIZE;
  uint8_t *input_buffer = malloc(WINDOW_SIZE);
  uint8_t *output_buffer = malloc(WINDOW_SIZE);

  if (!input_buffer || !output_buffer) {
    fprintf(stderr, "Malloc failed\n");
    exit(EXIT_FAILURE);
  }

  threads = malloc(num_threads * sizeof(HANDLE));
  thread_data = malloc(num_threads * sizeof(ThreadData));

  if (!threads || !thread_data) {
    fprintf(stderr, "Malloc failed\n");
    exit(EXIT_FAILURE);
  }

  /* Process the file in chunks */
  blocks_processed = 0;
  timer_reset();
  while (blocks_processed < total_blocks) {
    blocks_to_process = (blocks_processed + BLOCKS_PER_WINDOW <= total_blocks)
                            ? BLOCKS_PER_WINDOW
                            : (total_blocks - blocks_processed);
    bytes_to_process = blocks_to_process * AES_BLOCK_SIZE;

    /* Read a chunk from the input file */
    fseek(in, blocks_processed * AES_BLOCK_SIZE, SEEK_SET);
    bytes_read = fread(input_buffer, 1, bytes_to_process, in);

    if (bytes_read != bytes_to_process) {
      fprintf(stderr, "Error reading input file\n");
      break;
    }

    /* Process the chunk with multiple threads */

    timer_start();

    for (int i = 0; i < num_threads; i++) {
      thread_data[i] = (ThreadData){.ks = &ks,
                                    .input = input_buffer,
                                    .output = output_buffer,
                                    .thread_id = i,
                                    .num_threads = num_threads,
                                    .total_blocks = blocks_to_process};
      threads[i] = (HANDLE)_beginthreadex(NULL, 0, thread_func, &thread_data[i],
                                          0, NULL);
    }

    for (int i = 0; i < num_threads; i++) {
      WaitForSingleObject(threads[i], INFINITE);
      CloseHandle(threads[i]);
    }

    timer_pause_accumulate();

    /* Write the processed chunk to the output file */
    fwrite(output_buffer, 1, bytes_to_process, out);

    blocks_processed += blocks_to_process;
  }

  fclose(in);
  fclose(out);

  free(input_buffer);
  free(output_buffer);
  free(threads);
  free(thread_data);

  printf("\x1B[36m");
  printf("================ SUMMARY ================\n");
  printf("Processed %ld bytes, %ld blocks\n", file_size,
         file_size / AES_BLOCK_SIZE);
  printf("Time taken: %lf ms\n", timer_get_accumulated());
  printf("Number of cores: %d\n", num_threads);
  printf("\x1B[0m");
}

int main(int argc, char *argv[]) {
  aes128_key_t key;

  memcpy(key.bytes, TEST_KEY, AES128_KEY_SIZE);

  if (argc != 4) {
    fprintf(stderr, "Usage: %s [encrypt/decrypt] <input_file> <output_file>", argv[0]);
    return 1;
  }

  if (strcmp(argv[1], "encrypt") == 0) {
    aesni_do(argv[2], argv[3], &key, get_processor_count(), encrypt_thread);
  } else if (strcmp(argv[1], "decrypt") == 0) {
    aesni_do(argv[2], argv[3], &key, get_processor_count(), decrypt_thread);
  } else {
    fprintf(stderr, "Invalid operation: %s\n", argv[1]);
    return 1;
  }

  return 0;
}