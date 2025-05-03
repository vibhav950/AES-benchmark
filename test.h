#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void read_hex(const char *hex, uint8_t *buf, const uint32_t len) {
  uint32_t i, value;

  for (i = 0; i < len; ++i) {
    sscanf(hex + 2 * i, "%02x", &value);
    buf[i] = (uint8_t)value;
  }
}

static void print_matrix(const uint8_t *buf, int rows, int cols) {
  int i, j;

  for (i = 0; i < rows; ++i) {
    for (j = 0; j < cols; ++j)
      printf("%02x ", buf[i * cols + j]);
    printf("\n");
  }
  printf("\n");
}