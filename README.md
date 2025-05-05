# AES-benchmark

This is a benchmark to test how the x64 AES-NI extension using accelerated hardware compares with an implementation of AES on CUDA. Both these methods exploit block-level parallelism found in two modes of operations - AES-ECB and AES-CTR.

## Instructions

To run the AES-NI benchmarks

```bash
dd if=/dev/zero of=zeros.bin bs=1M count=16
gcc aesni.c -march=native -O3 -o aesni
./aesni.exe encrypt zeros.bin out.bin
```

To run the AES-CUDA benchmarks

```bash
nvcc aes.cu -o aes_cuda
./aes_cuda encrypt zeros.bin out.bin
```

## Results and Conclusion

I have attached below the results I observed on my humble machine. I would like to prefice this by saying this is not the best way to benchmark; I have simply pasted the results of a singular run on each of the two implementations, and for best results it is recommended to get the average time over a bunch of runs.

Also note that this is not the most accurate way of profiling by any means, but it does the job in proving which of the two hardware devices are faster for parallel AES operations - a dedicated AES accelerator on the CPU or a GPU made for processing hundreds of blocks in parallel, which was the aim of this experiment to begin with.

As a final note, the CUDA implementation _could_ possibly be faster with cleverer memory access patterns and maybe with better ways of implementing Galois Field computations, but I am going to save those improvements for a rainy day.

**Specs:**
- CPU: AMD Ryzen 7 5800HS with Radeon Graphics @ 3.20 GHz
- GPU: NVIDIA GeForce GTX 1650 [CUDA 12.8]

**(1) Input size:** 16 M bytes

```
================ SUMMARY ================
Processed 16777216 bytes, 1048576 blocks
Time taken: 0.016815 ms
Number of cores: 8
```

```
================ SUMMARY ================
Processed 16777216 bytes, 1048576 blocks
Time taken: 0.036708 ms
CUDA device: NVIDIA GeForce GTX 1650
Max blocks: 448
```

**(2) Input size: 1G bytes**

```
================ SUMMARY ================
Processed 1073741824 bytes, 67108864 blocks
Time taken: 1.012455 ms
Number of cores: 8
```

```
================ SUMMARY ================
Processed 1073741824 bytes, 67108864 blocks
Time taken: 2.292581 ms
CUDA device: NVIDIA GeForce GTX 1650
Max blocks: 448
```
