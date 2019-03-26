Here is `Sixology` source code and some related ugly scripts on [0CTF/TCTF 2019 Quals](https://ctf.0ops.sjtu.cn)

This is a vm reversing challenge, but without simulator.

## Build Processor
Tested on 7.0 and 7.2

```bash
$ cd sixology/IDA
$ mkdir build
$ cd build
# for debug
$ cmake -DIDA_SDK_DIR="/path/to/your/idasdk" ..
# for release
$ cmake -DIDA_SDK_DIR="/path/to/your/idasdk" -DCMAKE_BUILD_TYPE=Release ..
```

> If you are told that missing some files, find them in IDASDK.

## Writeup
0. Have some basic knowledge on IDA processor development.
1. Get `LPH` in processor from export table
2. find out `notify` member in `LPH` object
3. locate key functions in `notify` via event_code (ev_ana_insn, ev_emu_insn, etc.)
4. Figure out instruction encoding and decoding from `ana` function
5. Understand vm instructions semantic in all emu analysis handlers, I've try to explain all the instructions in this vm. Follow the emu data flow and other api used at this stage (set_switch_info, add_crefs, get_dword, trace_sp, etc.), you could understand all of them.

> * `HINT` in source code means that here is the hint of one vm instruction.
> * You could find most of enum value and struct definition through IDA official online documents.
> * Be careful about `lexcmp` and `exchange` vm instruction, without `lexcmp`, it's another problem.

6. Understand what's the program doing and optimize the algorithm.
7. Run it and Get flag.


## Thanks
* Thanks for [slipper](https://github.com/5lipper) and [hen](https://github.com/liumuqing) for many useful advice to this challenge.
* Thanks for [nforest](https://github.com/nforest) and [Azure](https://twitter.com/4zure9) for help on IDA.
