# AES-benchmark

This is a benchmark to test how the x64 AES-NI extension using accelerated hardware compares with an implementation of AES on CUDA. Both these methods exploit block-level parallelism found in two modes of operations - AES-ECB and AES-CTR.

## Instructions

To run the AES-NI benchmarks

```bash
dd if=/dev/zero of=zeros.bin bs=1M count=16
gcc aesni.c -I. -march=native
./a.out
```
