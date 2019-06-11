## wasabi
This is a [WASI](https://github.com/WebAssembly/WASI) binary. It contains 3 sub challenges during the 0CTF/TCTF 2019 Finals.

### Env
Runtime: [wasmtime](https://github.com/CraneStation/wasmtime)

### Build
You should setup wasi env first.

```bash
$ make release
```

For heap debug, you can download a `malloc.c` from wasi-libc, then
```bash
$ make -f Makefile.linux debug
```

### 1. wasabi
The 1st step is a simple Reverse challenge for warmup. It implements a simple compression algorithm. 

> Burrows-Wheeler Transform + Run-Length Encoding.

### 2. wasabi001
The 2nd step is a simple heap Pwnable challenge on [dlmalloc 2.8.6](https://github.com/CraneStation/wasi-libc/blob/master/dlmalloc/src/malloc.c).

With the heap overflow in `Edit Option`. Hackers are able to achieve arbitrary read and write, then bypass SHA512 check in `Get Flag` option and get 2nd flag.

> Arbitrary read will leak encrypted flag on server. But without modifying the Hardcodz SHA512 on linear memory, you may not have a chance to reach next `wasabi002`. There is no rodata in wasm linear memory, at least it is on wasmtime. Without this sense, some hackers may not try `Get Flag` on server again.

### 3. wasabi002
The 3rd step is also a Pwnable challenge, which requires hackers to open a flag file on server and read, write it. 

In the end of `Get Flag` option of 2nd step, wasabi will enter a vm and execute tens of fixed vm instructions, then program exit.

So with the ability of arbitrary write in wasabi001, hackers can modify vtable of VM class, vm registers and vm memory. Then from instruction semantic confusion to finish wasabi series.
