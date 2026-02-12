  | Rizin dm command | Makes sense in core dump mode? | oml / GDB equivalent |
  |---|---|---|
  | dm[jqt] | Yes | rz `oml[jqQt]` |
  | dm= | Yes | rz `oml=` |
  | dm. | Yes | rz `oml.` |
  | dmm[j.] | Yes | gdb `info sharedlibrary` |
  | dmi[jqQa.] | Yes | gdb `info symbol <addr>`, `info functions`, `info variables`, require the executable binary file |
  | dmS[?] [<addr\|libname> [<sectname>]] | Yes | gdb `maintenance info sections` |
  | dmd[aw] | Yes | gdb `dump memory <file> <start> <end>` |
  | dm+ <size> | No | |
  | dm- | No |  |
  | dml <file> | No |  |
  | dmp <perms> [<size>] | No |  |
  | dmL <size> | No |  |
  | dmh[?] | TODO |  |
  | dmw[jb?] | No |  |
  | dmx<abce?> | TODO |  |



```
[0x00000000]> dm
is_core=1
 1 fd: 3 +0x00002000 0x56149dfaf000 - 0x56149dfaffff r-- fmap./home/florian/dev/crash/crash-linux-x86_64
 2 fd: 4 +0x00000000 0x56149dfb0000 - 0x56149dfb0fff r-x mmap./home/florian/dev/crash/crash-linux-x86_64
 3 fd: 5 +0x00000000 0x56149dfb1000 - 0x56149dfb1fff r-- mmap./home/florian/dev/crash/crash-linux-x86_64
 4 fd: 3 +0x00003000 0x56149dfb2000 - 0x56149dfb2fff r-- fmap./home/florian/dev/crash/crash-linux-x86_64
 5 fd: 3 +0x00004000 0x56149dfb3000 - 0x56149dfb3fff r-- fmap./home/florian/dev/crash/crash-linux-x86_64
 6 fd: 3 +0x00005000 0x7f582fa2e000 - 0x7f582fa2ffff r-- fmap.LOAD5
 7 fd: 6 +0x00000000 0x7f582fa31000 - 0x7f582fa55fff r-- mmap./usr/lib/libc-2.33.so
 8 fd: 3 +0x00007000 0x7f582fa30000 - 0x7f582fa30fff r-- fmap./usr/lib/libc-2.33.so
 9 fd: 7 +0x00000000 0x7f582fa56000 - 0x7f582fba1fff r-x mmap./usr/lib/libc-2.33.so
10 fd: 8 +0x00000000 0x7f582fba2000 - 0x7f582fbedfff r-- mmap./usr/lib/libc-2.33.so
11 fd: 3 +0x00008000 0x7f582fbee000 - 0x7f582fbf0fff r-- fmap./usr/lib/libc-2.33.so
12 fd: 3 +0x0000b000 0x7f582fbf1000 - 0x7f582fbf3fff r-- fmap./usr/lib/libc-2.33.so
13 fd: 3 +0x0000e000 0x7f582fbf4000 - 0x7f582fbfefff r-- fmap.LOAD11
14 fd: 3 +0x00019000 0x7f582fc4c000 - 0x7f582fc4cfff r-- fmap./usr/lib/ld-2.33.so
15 fd: 9 +0x00000000 0x7f582fc4d000 - 0x7f582fc70fff r-x mmap./usr/lib/ld-2.33.so
16 fd: 10 +0x00000000 0x7f582fc71000 - 0x7f582fc79fff r-- mmap./usr/lib/ld-2.33.so
17 fd: 3 +0x0001a000 0x7f582fc7b000 - 0x7f582fc7cfff r-- fmap./usr/lib/ld-2.33.so
18 fd: 3 +0x0001c000 0x7f582fc7d000 - 0x7f582fc7efff r-- fmap./usr/lib/ld-2.33.so
19 fd: 3 +0x0001e000 0x7ffc8352d000 - 0x7ffc8354dfff r-- fmap.[stack]
20 fd: 3 +0x0003f000 0x7ffc83558000 - 0x7ffc8355bfff r-- fmap.LOAD18
21 fd: 3 +0x00043000 0x7ffc8355c000 - 0x7ffc8355dfff r-x fmap.LOAD19
22 fd: 3 +0x00045000 0xffffffffff600000 - 0xffffffffff600fff r-x fmap.LOAD20
[0x00000000]> s 0x56149dfaf000

[0x56149dfaf000]> obf test/bins/elf/core/crash-linux-arm64
WARNING: Neither hash nor gnu_hash exist. Falling back to heuristics for deducing the number of dynamic symbols...
WARNING: Neither hash nor gnu_hash exist. Falling back to heuristics for deducing the number of dynamic symbols...
WARNING: Neither hash nor gnu_hash exist. Falling back to heuristics for deducing the number of dynamic symbols...
