![PyPI - Python Version](https://img.shields.io/pypi/pyversions/r2analyze)
![PyPI](https://img.shields.io/pypi/v/r2analyze)
# r2analyze - Radare2 integration with Intezer Analyze

Execute the plugin via `#!pipe` and save yourself time while reversing. The plugin helps you focus on the malicious and unique functions.

## How to use

1. Run `pip install r2analyze` to download and install.
2. Add your API key as a shell environment variable `INTEZER_API_KEY`.
3. Upload the sample to [Analyze](https://analyze.intezer.com).
3. Open the file with radare2 and analyze the file with for example `aaa`.
4. Run `#!pipe r2analyze`.
5. Flag starting with `gene_` has been added to all functions with code-reuse.

## Example

After we have submitted the file to Intezer Analyze, we open the file
with radare2:

```
$ r2 7c82689142a415b0a34553478e445988980f48705735939d6d33c17e4e8dac94
 -- *(ut64*)buffer ought to be illegal
[0x004028e3]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
```

When we run `r2analyze`, it will query Analyze for code reuse. Functions
that share code already malware will be marked with a gene `flag`. All
the flags are added to a new flag space called "gene" for easier
filtering.
```
[0x004028e3]> #!pipe r2analyze
Analyzing 7c82689142a415b0a34553478e445988980f48705735939d6d33c17e4e8dac94
Functions found 194.
[0x004028e3]> fs gene 
[0x004028e3]> f
0x00401000 1 gene_malware_ScarCruft_4198400
0x004013e0 1 gene_malware_ScarCruft_4199392
0x00401f20 1 gene_malware_ScarCruft_4202272
0x00402090 1 gene_malware_ScarCruft_4202640
```

Function identified as sharing code with ScarCruft:
```
[0x004028e3]> pdfs @ 4202272
;-- gene_malware_ScarCruft_4202272:
0x00401f4a call dword [sym.imp.KERNEL32.dll_CreateFileA]
0x00401f5f call dword [sym.imp.KERNEL32.dll_GetFileSizeEx]
0x00401f7a call dword [sym.imp.KERNEL32.dll_CloseHandle]
0x00401f98:
0x00401fb0:
0x00401fc7 fcn.00401f20+0xb0 fcn.00401f20+0xb0
0x00401fd0:
0x00401fd3:
0x00401ff0:
0x00401ff5:
0x00402003:
0x0040200c int32_t arg_1ch
0x0040200d int32_t arg_18h
0x0040200e uint32_t arg_14h
0x0040200f int32_t arg_10h
0x00402010 int32_t arg_ch
0x00402014 int32_t arg_8h
0x00402018 call fcn.00402090 fcn.00402090
```