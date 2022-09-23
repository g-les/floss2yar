# floss2yar
Adventures in Awful Python To Find Shared Code

Required installs include:
- `flare-floss`
- `rizin`
- `r2pipe`
- `vivisect`


## Premise
This tooling came out of an attempt to speed up a 'secret-sauce' of my YARA workflow. One of the first things I'd do when facing a new cluster of malware or sample I was tasked with would be to run FLOSS on the file. By happen-stance in 2020 I saw a tweet from Marc Ochsenmeier referencing the '-x' flag (or expert :D) that kindly highlights likely encoding functions from FLOSS's emulation in addition to some other goodies. Example of the old run of FLOSS with -x flag showing function scoring:

```
$ floss Testing/SampleDump//Turla/35f205367e2e5f8a121925bbae6ff07626b526a7 -x

TRUNCATED

Most likely decoding functions in: Testing/SampleDump//Turla/35f205367e2e5f8a121925bbae6ff07626b526a7
address      score
---------  -------
0x402AE2   1.13577
0x4034D8   0.80244
0x403384   0.68577
0x402F78   0.67398
0x4017ED   0.67154
0x402A68   0.50244
0x404247   0.50244
0x40394D   0.48333
0x40379F   0.40488
0x401369   0.30244

FLOSS decoded 1858 strings

Decoding function at 0x40394D (decoded 1788 strings)
Offset      Called At    String
----------  -----------  ----------------------------------------------
[HEAP]      0x401588     02d:%02d:%02d:%03d|\t[%04d|%-48s]\t
[HEAP]      0x401588     csec
[HEAP]      0x401588     02d:%02d:%02d:%03d|\t[%04d|%-48s]\t

TRUNCATED

FLOSS extracted 4 stackstrings
Function    Frame Offset    String
----------  --------------  -----------------------
0x404247    0x21B           kernel32.dll
0x404247    0x110           WriteProcessorPwrScheme
0x404247    0x110           WriteProcessMemory
0x404247    0xFD            =eme
```

Please note that while function scoring is still present in the new version of FLOSS, it does not 'pop' out of the -v flag the way it used to. If you just want function scoring, try a [this script](https://gist.github.com/williballenthin/635329b7bc4dc73805f6cbfb1bef468b) from Willi instead

Floss2Yar uses the new version of FLOSS to gather interesting functions, disassemble them in rizin, mask the bytes that likely would change sample over sample (addresses) and generate a rule for each function. The inclusion of the disassembly with the relevant bytes was intentional so more analyts could trim the rule down to interesting basic blocks. 

## Inspiration:

 - Qutluch's [Steezy](https://github.com/schrodyn/steezy) 
 - Kaspersky and Costin's [KTAE Tooling](https://securelist.com/big-threats-using-code-similarity-part-1/97239/)
 - ArielJT's [VTCodeSimilarity-YaraGen tooling](https://github.com/arieljt/VTCodeSimilarity-YaraGen)
 - c3rb3ru5d3d53c's [binlex](https://github.com/c3rb3ru5d3d53c/binlex)
 - Malpedia's [yara-signator](https://github.com/fxb-cocacoding/yara-signator) thanks @fxb_b and @push_pnx
 - Notareverser's consistent encouragement and slick one off tooling ideas
 - ConnorSecurity's vision to automate all workflows and replace me with a computer
 - jgrosfelts's mad reversing skills
 - xorhex's WILD code and jump and switch table based rules 
 - williballenthin insane smarts and kindness to underpin this whole thing with a script that is much more professional than the rest of this outfit
 - Stvemillertime for making YARA approachable to find evil with weak signals and overall ruling as a human 
 - BitsofBinary's creative YARA rules that expanded my understanding of detection possibilities

## Installation

Install [rizin](https://github.com/rizinorg/rizin/releases/tag/v0.4.0)

Update pip
- `pip install --upgrade pip`

Create Virtual Environment (Clean work space):​
- `python3 -m venv floss2yar_env​`
- `source floss2yar_env/bin/activate​`

Jump into floss2yar directory & install components:
- `pip install ./`



## Usage:

Point the script at a file using -f and get yaras! 

Optional Flags:
- Score: -s flag with a float (0.95, 1.2, whatever) as a minimum threshold for data coming from FLOSS main library
- Name: -n flag to pass a name to the outputted yara rules; otherwise they will be given generic names based on the functions analyzed

Please note - as this can produce many yara rules, users are encouraged to rapidly test the new rules for false positives (ie incidental shared functions that are not malicious) over legitimate Windows components or a set of samples that are likely unrelated. Recommend using this [blog](https://stairwell.com/news/threat-research-detection-research-labeled-malware-corpus-yara-testing/) to start! 

Please also note floss2yar uses some verbose logging from FLOSS - don't assume something broke if information begins to flood your terminal 

```
$ python3 floss2yar/main.py -f ~/Testing/SampleDump/backburner -s 0.98

parsing funcs with minimum score:  0.98
[+] parsing funcs with minimum score:  0.98
finding decoding function features: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████| 150/150 [00:00<00:00, 678.83 functions/s, skipped 0 library functions]
[+] trying to process data

rule floss2yar_fcn_00016c1f {
meta:
	author = "floss2yar"
	date = "2022-08-30"
	version = "1.0"
	hash = "ea2ea2ae0d92e9b186ccb313fb8961cf9d6716a80588a87545f71f2a2b48a63d"

strings: 
	$fcn_00016c1f = {55 8D 6C 24 98 81 EC 8C ?? ?? ?? 8B 4D 7C 53 8B D8 0F B6 81 F2 ?? ?? ?? 85 C0 56 57 89 45 60 0F 84 ?? ?? ?? ?? 8B 75 78 8D 7D DC A5 A5 A5 8D 45 DC 50 A5 E8 ?? ?? ?? ?? EB ?? 83 7D 74 ?? 0F 84 ?? ?? ?? ?? 8B 45 60 8A 44 05 DC 32 03 8B 4D 70 FF 45 70 FF 45 60 43 FF 4D 74 88 01 83 7D 60 10 7C ?? 83 7D 74 ?? 0F 84 ?? ?? ?? ?? 8B 4D 78 FF 01 83 65 60 ?? E9 ?? ?? ?? ?? BE ?? ?? ?? ?? 39 75 74 7E ?? 89 75 5C EB ?? 8B 45 74 89 45 5C 8B 45 5C 29 45 74 C1 F8 04 85 C0 8D 55 DC 89 55 64 7E ?? 8B D0 8B 7D 64 83 ?? ?? ?? 8B F1 A5 A5 A5 A5 FF 01 4A 75 ?? F6 45 5C 0F 74 ?? 8B 7D 64 8B F1 A5 A5 A5 A5 40 C1 E0 04 8B F0 C1 FE 04 A8 ?? 8D 7D DC 75 ?? EB ?? 8B 4D 7C 57 8B C7 4E E8 ?? ?? ?? ?? 83 ?? ?? 85 F6 75 ?? 83 65 64 ?? F6 ?? ?? 8B 4D 70 8D 45 DC 75 ?? F6 ?? ?? 75 ?? 8B D0 F6 ?? ?? 75 ?? 83 7D 5C 10 0F 8C ?? ?? ?? ?? 6A ?? 5E 8D 55 E4 2B F2 8B 13 33 10 6A ?? 89 11 8B 50 04 33 53 04 89 51 04 8B 50 08 33 53 08 89 51 08 8B 50 0C 33 53 0C 89 51 0C 5A 01 55 64 03 C2 03 DA 03 CA 8D 54 06 08 3B 55 5C 7E ?? E9 ?? ?? ?? ?? 83 7D 5C 10 0F 8C ?? ?? ?? ?? 6A ?? 5E 8D 55 DE 2B F2 8A 13 32 10 6A ?? 88 11 8A 50 01 32 53 01 88 51 01 8A 50 02 32 53 02 88 51 02 8A 50 03 32 53 03 88 51 03 8A 50 04 32 53 04 88 51 04 8A 50 05 32 53 05 88 51 05 8A 50 06 32 53 06 88 51 06 8A 50 07 32 53 07 88 51 07 8A 50 08 32 53 08 88 51 08 8A 50 09 32 53 09 88 51 09 8A 50 0A 32 53 0A 88 51 0A 8A 50 0B 32 53 0B 88 51 0B 8A 50 0C 32 53 0C 88 51 0C 8A 50 0D 32 53 0D 88 51 0D 8A 50 0E 32 53 0E 88 51 0E 8A 50 0F 32 53 0F 88 51 0F 5A}
 /* 
            ; CALL XREF from fcn.000134c9 @ 0x1359e
            ; CALL XREF from fcn.000135e1 @ 0x1376a
┌ fcn.00016c1f ();
│           0x00016c1f      55             push  ebp
│           0x00016c20      8d6c2498       lea   ebp, [esp - 0x68]
│           0x00016c24      81ec8c000000   sub   esp, 0x8c
│           0x00016c2a      8b4d7c         mov   ecx, dword [ebp + 0x7c]
│           0x00016c2d      53             push  ebx
│           0x00016c2e      8bd8           mov   ebx, eax
│           0x00016c30      0fb681f20000.  movzx eax, byte [ecx + 0xf2]
│           0x00016c37      85c0           test  eax, eax
│           0x00016c39      56             push  esi
│           0x00016c3a      57             push  edi
│           0x00016c3b      894560         mov   dword [ebp + 0x60], eax
│       ┌─< 0x00016c3e      0f840a020000   je    0x16e4e
│       │   0x00016c44      8b7578         mov   esi, dword [ebp + 0x78]
│       │   0x00016c47      8d7ddc         lea   edi, [ebp - 0x24]
│       │   0x00016c4a      a5             movsd dword es:[edi], dword ptr [esi]
│       │   0x00016c4b      a5             movsd dword es:[edi], dword ptr [esi]
│       │   0x00016c4c      a5             movsd dword es:[edi], dword ptr [esi]
│       │   0x00016c4d      8d45dc         lea   eax, [ebp - 0x24]
│       │   0x00016c50      50             push  eax                   ; int32_t arg_8h
│       │   0x00016c51      a5             movsd dword es:[edi], dword ptr [esi]
│       │   0x00016c52      e81c020000     call  fcn.00016e73
│      ┌──< 0x00016c57      eb22           jmp   0x16c7b
│     ┌───> 0x00016c59      837d7400       cmp   dword [ebp + 0x74], 0
│    ┌────< 0x00016c5d      0f84f8010000   je    0x16e5b
│    │╎││   0x00016c63      8b4560         mov   eax, dword [ebp + 0x60]
│    │╎││   0x00016c66      8a4405dc       mov   al, byte [ebp + eax - 0x24]
│    │╎││   0x00016c6a      3203           xor   al, byte [ebx]
│    │╎││   0x00016c6c      8b4d70         mov   ecx, dword [ebp + 0x70]
│    │╎││   0x00016c6f      ff4570         inc   dword [ebp + 0x70]
│    │╎││   0x00016c72      ff4560         inc   dword [ebp + 0x60]
│    │╎││   0x00016c75      43             inc   ebx
│    │╎││   0x00016c76      ff4d74         dec   dword [ebp + 0x74]
│    │╎││   0x00016c79      8801           mov   byte [ecx], al
│    │╎││   ; CODE XREF from fcn.00016c1f @ 0x16c57
│    │╎└──> 0x00016c7b      837d6010       cmp   dword [ebp + 0x60], 0x10
│    │└───< 0x00016c7f      7cd8           jl    0x16c59
│    │  │   0x00016c81      837d7400       cmp   dword [ebp + 0x74], 0
│    │ ┌──< 0x00016c85      0f84d0010000   je    0x16e5b
│    │ ││   0x00016c8b      8b4d78         mov   ecx, dword [ebp + 0x78]
│    │ ││   0x00016c8e      ff01           inc   dword [ecx]
│    │ ││   0x00016c90      83656000       and   dword [ebp + 0x60], 0
│    │┌───< 0x00016c94      e9b8010000     jmp   0x16e51
│   ┌─────> 0x00016c99      be80000000     mov   esi, 0x80             ; 128
│   ╎││││   0x00016c9e      397574         cmp   dword [ebp + 0x74], esi
│  ┌──────< 0x00016ca1      7e05           jle   0x16ca8
│  │╎││││   0x00016ca3      89755c         mov   dword [ebp + 0x5c], esi
│ ┌───────< 0x00016ca6      eb06           jmp   0x16cae
│ │└──────> 0x00016ca8      8b4574         mov   eax, dword [ebp + 0x74]
│ │ ╎││││   0x00016cab      89455c         mov   dword [ebp + 0x5c], eax
│ │ ╎││││   ; CODE XREF from fcn.00016c1f @ 0x16ca6
│ └───────> 0x00016cae      8b455c         mov   eax, dword [ebp + 0x5c]
│   ╎││││   0x00016cb1      294574         sub   dword [ebp + 0x74], eax
│   ╎││││   0x00016cb4      c1f804         sar   eax, 4
│   ╎││││   0x00016cb7      85c0           test  eax, eax
│   ╎││││   0x00016cb9      8d55dc         lea   edx, [ebp - 0x24]
│   ╎││││   0x00016cbc      895564         mov   dword [ebp + 0x64], edx
│  ┌──────< 0x00016cbf      7e14           jle   0x16cd5
│  │╎││││   0x00016cc1      8bd0           mov   edx, eax
│ ┌───────> 0x00016cc3      8b7d64         mov   edi, dword [ebp + 0x64]
│ ╎│╎││││   0x00016cc6      83456410       add   dword [ebp + 0x64], 0x10 ; [0x10:4]=-1 ; 16
│ ╎│╎││││   0x00016cca      8bf1           mov   esi, ecx
│ ╎│╎││││   0x00016ccc      a5             movsd dword es:[edi], dword ptr [esi]
│ ╎│╎││││   0x00016ccd      a5             movsd dword es:[edi], dword ptr [esi]
│ ╎│╎││││   0x00016cce      a5             movsd dword es:[edi], dword ptr [esi]
│ ╎│╎││││   0x00016ccf      a5             movsd dword es:[edi], dword ptr [esi]
│ ╎│╎││││   0x00016cd0      ff01           inc   dword [ecx]
│ ╎│╎││││   0x00016cd2      4a             dec   edx
│ └───────< 0x00016cd3      75ee           jne   0x16cc3
│  └──────> 0x00016cd5      f6455c0f       test  byte [ebp + 0x5c], 0xf
│  ┌──────< 0x00016cd9      740a           je    0x16ce5
│  │╎││││   0x00016cdb      8b7d64         mov   edi, dword [ebp + 0x64]
│  │╎││││   0x00016cde      8bf1           mov   esi, ecx
│  │╎││││   0x00016ce0      a5             movsd dword es:[edi], dword ptr [esi]
│  │╎││││   0x00016ce1      a5             movsd dword es:[edi], dword ptr [esi]
│  │╎││││   0x00016ce2      a5             movsd dword es:[edi], dword ptr [esi]
│  │╎││││   0x00016ce3      a5             movsd dword es:[edi], dword ptr [esi]
│  │╎││││   0x00016ce4      40             inc   eax
│  └──────> 0x00016ce5      c1e004         shl   eax, 4
│   ╎││││   0x00016ce8      8bf0           mov   esi, eax
│   ╎││││   0x00016cea      c1fe04         sar   esi, 4
│   ╎││││   0x00016ced      a80f           test  al, 0xf               ; 15
│   ╎││││   0x00016cef      8d7ddc         lea   edi, [ebp - 0x24]
│  ┌──────< 0x00016cf2      7515           jne   0x16d09
│ ┌───────< 0x00016cf4      eb0f           jmp   0x16d05
│ ────────> 0x00016cf6      8b4d7c         mov   ecx, dword [ebp + 0x7c]
│ ││╎││││   0x00016cf9      57             push  edi                   ; int32_t arg_8h
│ ││╎││││   0x00016cfa      8bc7           mov   eax, edi
│ ││╎││││   0x00016cfc      4e             dec   esi
│ ││╎││││   0x00016cfd      e871010000     call  fcn.00016e73
│ ││╎││││   0x00016d02      83c710         add   edi, 0x10             ; 16
│ ││╎││││   ; CODE XREF from fcn.00016c1f @ 0x16cf4
│ └───────> 0x00016d05      85f6           test  esi, esi
│ ────────< 0x00016d07      75ed           jne   0x16cf6
│  └──────> 0x00016d09      83656400       and   dword [ebp + 0x64], 0
│   ╎││││   0x00016d0d      f6c303         test  bl, 3                 ; 3
│   ╎││││   0x00016d10      8b4d70         mov   ecx, dword [ebp + 0x70]
│   ╎││││   0x00016d13      8d45dc         lea   eax, [ebp - 0x24]
│  ┌──────< 0x00016d16      7559           jne   0x16d71
│  │╎││││   0x00016d18      f6c103         test  cl, 3                 ; 3
│ ┌───────< 0x00016d1b      7554           jne   0x16d71
│ ││╎││││   0x00016d1d      8bd0           mov   edx, eax
│ ││╎││││   0x00016d1f      f6c203         test  dl, 3                 ; 3
│ ────────< 0x00016d22      754d           jne   0x16d71
│ ││╎││││   0x00016d24      837d5c10       cmp   dword [ebp + 0x5c], 0x10
│ ────────< 0x00016d28      0f8cfe000000   jl    0x16e2c
│ ││╎││││   0x00016d2e      6a10           push  0x10                  ; 16
│ ││╎││││   0x00016d30      5e             pop   esi
│ ││╎││││   0x00016d31      8d55e4         lea   edx, [ebp - 0x1c]
│ ││╎││││   0x00016d34      2bf2           sub   esi, edx
│ ────────> 0x00016d36      8b13           mov   edx, dword [ebx]
│ ││╎││││   0x00016d38      3310           xor   edx, dword [eax]
│ ││╎││││   0x00016d3a      6a10           push  0x10                  ; 16
│ ││╎││││   0x00016d3c      8911           mov   dword [ecx], edx
│ ││╎││││   0x00016d3e      8b5004         mov   edx, dword [eax + 4]
│ ││╎││││   0x00016d41      335304         xor   edx, dword [ebx + 4]
│ ││╎││││   0x00016d44      895104         mov   dword [ecx + 4], edx
│ ││╎││││   0x00016d47      8b5008         mov   edx, dword [eax + 8]
│ ││╎││││   0x00016d4a      335308         xor   edx, dword [ebx + 8]
│ ││╎││││   0x00016d4d      895108         mov   dword [ecx + 8], edx
│ ││╎││││   0x00016d50      8b500c         mov   edx, dword [eax + 0xc]
│ ││╎││││   0x00016d53      33530c         xor   edx, dword [ebx + 0xc]
│ ││╎││││   0x00016d56      89510c         mov   dword [ecx + 0xc], edx
│ ││╎││││   0x00016d59      5a             pop   edx
│ ││╎││││   0x00016d5a      015564         add   dword [ebp + 0x64], edx
│ ││╎││││   0x00016d5d      03c2           add   eax, edx
│ ││╎││││   0x00016d5f      03da           add   ebx, edx
│ ││╎││││   0x00016d61      03ca           add   ecx, edx
│ ││╎││││   0x00016d63      8d540608       lea   edx, [esi + eax + 8]
│ ││╎││││   0x00016d67      3b555c         cmp   edx, dword [ebp + 0x5c]
│ ────────< 0x00016d6a      7eca           jle   0x16d36
│ ────────< 0x00016d6c      e9b8000000     jmp   0x16e29
│ └└──────> 0x00016d71      837d5c10       cmp   dword [ebp + 0x5c], 0x10
│  ┌──────< 0x00016d75      0f8cb1000000   jl    0x16e2c
│  │╎││││   0x00016d7b      6a10           push  0x10                  ; 16
│  │╎││││   0x00016d7d      5e             pop   esi
│  │╎││││   0x00016d7e      8d55de         lea   edx, [ebp - 0x22]
│  │╎││││   0x00016d81      2bf2           sub   esi, edx
│ ┌───────> 0x00016d83      8a13           mov   dl, byte [ebx]
│ ╎│╎││││   0x00016d85      3210           xor   dl, byte [eax]
│ ╎│╎││││   0x00016d87      6a10           push  0x10                  ; 16
│ ╎│╎││││   0x00016d89      8811           mov   byte [ecx], dl
│ ╎│╎││││   0x00016d8b      8a5001         mov   dl, byte [eax + 1]
│ ╎│╎││││   0x00016d8e      325301         xor   dl, byte [ebx + 1]
│ ╎│╎││││   0x00016d91      885101         mov   byte [ecx + 1], dl
│ ╎│╎││││   0x00016d94      8a5002         mov   dl, byte [eax + 2]
│ ╎│╎││││   0x00016d97      325302         xor   dl, byte [ebx + 2]
│ ╎│╎││││   0x00016d9a      885102         mov   byte [ecx + 2], dl
│ ╎│╎││││   0x00016d9d      8a5003         mov   dl, byte [eax + 3]
│ ╎│╎││││   0x00016da0      325303         xor   dl, byte [ebx + 3]
│ ╎│╎││││   0x00016da3      885103         mov   byte [ecx + 3], dl
│ ╎│╎││││   0x00016da6      8a5004         mov   dl, byte [eax + 4]
│ ╎│╎││││   0x00016da9      325304         xor   dl, byte [ebx + 4]
│ ╎│╎││││   0x00016dac      885104         mov   byte [ecx + 4], dl
│ ╎│╎││││   0x00016daf      8a5005         mov   dl, byte [eax + 5]
│ ╎│╎││││   0x00016db2      325305         xor   dl, byte [ebx + 5]
│ ╎│╎││││   0x00016db5      885105         mov   byte [ecx + 5], dl
│ ╎│╎││││   0x00016db8      8a5006         mov   dl, byte [eax + 6]
│ ╎│╎││││   0x00016dbb      325306         xor   dl, byte [ebx + 6]
│ ╎│╎││││   0x00016dbe      885106         mov   byte [ecx + 6], dl
│ ╎│╎││││   0x00016dc1      8a5007         mov   dl, byte [eax + 7]
│ ╎│╎││││   0x00016dc4      325307         xor   dl, byte [ebx + 7]
│ ╎│╎││││   0x00016dc7      885107         mov   byte [ecx + 7], dl
│ ╎│╎││││   0x00016dca      8a5008         mov   dl, byte [eax + 8]
│ ╎│╎││││   0x00016dcd      325308         xor   dl, byte [ebx + 8]
│ ╎│╎││││   0x00016dd0      885108         mov   byte [ecx + 8], dl
│ ╎│╎││││   0x00016dd3      8a5009         mov   dl, byte [eax + 9]
│ ╎│╎││││   0x00016dd6      325309         xor   dl, byte [ebx + 9]
│ ╎│╎││││   0x00016dd9      885109         mov   byte [ecx + 9], dl
│ ╎│╎││││   0x00016ddc      8a500a         mov   dl, byte [eax + 0xa]
│ ╎│╎││││   0x00016ddf      32530a         xor   dl, byte [ebx + 0xa]
│ ╎│╎││││   0x00016de2      88510a         mov   byte [ecx + 0xa], dl
│ ╎│╎││││   0x00016de5      8a500b         mov   dl, byte [eax + 0xb]
│ ╎│╎││││   0x00016de8      32530b         xor   dl, byte [ebx + 0xb]
│ ╎│╎││││   0x00016deb      88510b         mov   byte [ecx + 0xb], dl
│ ╎│╎││││   0x00016dee      8a500c         mov   dl, byte [eax + 0xc]
│ ╎│╎││││   0x00016df1      32530c         xor   dl, byte [ebx + 0xc]
│ ╎│╎││││   0x00016df4      88510c         mov   byte [ecx + 0xc], dl
│ ╎│╎││││   0x00016df7      8a500d         mov   dl, byte [eax + 0xd]
│ ╎│╎││││   0x00016dfa      32530d         xor   dl, byte [ebx + 0xd]
│ ╎│╎││││   0x00016dfd      88510d         mov   byte [ecx + 0xd], dl
│ ╎│╎││││   0x00016e00      8a500e         mov   dl, byte [eax + 0xe]
│ ╎│╎││││   0x00016e03      32530e         xor   dl, byte [ebx + 0xe]
│ ╎│╎││││   0x00016e06      88510e         mov   byte [ecx + 0xe], dl
│ ╎│╎││││   0x00016e09      8a500f         mov   dl, byte [eax + 0xf]
│ ╎│╎││││   0x00016e0c      32530f         xor   dl, byte [ebx + 0xf]
│ ╎│╎││││   0x00016e0f      88510f         mov   byte [ecx + 0xf], dl
│ ╎│╎││││   0x00016e12      5a             pop   edx
│ ╎│╎││││   0x00016e13      015564         add   dword [ebp + 0x64], edx
│ ╎│╎││││   0x00016e16      03c2           add   eax, edx
│ ╎│╎││││   0x00016e18      03da           add   ebx, edx
│ ╎│╎││││   0x00016e1a      03ca           add   ecx, edx
│ ╎│╎││││   0x00016e1c      8d540602       lea   edx, [esi + eax + 2]
│ ╎│╎││││   0x00016e20      3b555c         cmp   edx, dword [ebp + 0x5c]
│ └───────< 0x00016e23      0f8e5affffff   jle   0x16d83
│  │╎││││   ; CODE XREF from fcn.00016c1f @ 0x16d6c
│ ────────> 0x00016e29      894d70         mov   dword [ebp + 0x70], ecx
│ ─└──────> 0x00016e2c      8b555c         mov   edx, dword [ebp + 0x5c]
│   ╎││││   0x00016e2f      395564         cmp   dword [ebp + 0x64], edx
│  ┌──────< 0x00016e32      7d1a           jge   0x16e4e
│  │╎││││   0x00016e34      8bf2           mov   esi, edx
│  │╎││││   0x00016e36      2b7564         sub   esi, dword [ebp + 0x64]
│ ┌───────> 0x00016e39      8b5560         mov   edx, dword [ebp + 0x60]
│ ╎│╎││││   0x00016e3c      8a1410         mov   dl, byte [eax + edx]
│ ╎│╎││││   0x00016e3f      3213           xor   dl, byte [ebx]
│ ╎│╎││││   0x00016e41      8811           mov   byte [ecx], dl
│ ╎│╎││││   0x00016e43      41             inc   ecx
│ ╎│╎││││   0x00016e44      ff4560         inc   dword [ebp + 0x60]
│ ╎│╎││││   0x00016e47      43             inc   ebx
│ ╎│╎││││   0x00016e48      4e             dec   esi
│ └───────< 0x00016e49      75ee           jne   0x16e39
│  │╎││││   0x00016e4b      894d70         mov   dword [ebp + 0x70], ecx
│  └────└─> 0x00016e4e      8b4d78         mov   ecx, dword [ebp + 0x78]
│   ╎│││    ; CODE XREF from fcn.00016c1f @ 0x16c94
│   ╎│└───> 0x00016e51      837d7400       cmp   dword [ebp + 0x74], 0
│   └─────< 0x00016e55      0f853efeffff   jne   0x16c99
│    └─└──> 0x00016e5b      8a4560         mov   al, byte [ebp + 0x60]
│           0x00016e5e      8b4d7c         mov   ecx, dword [ebp + 0x7c]
│           0x00016e61      5f             pop   edi
│           0x00016e62      5e             pop   esi
│           0x00016e63      8881f2000000   mov   byte [ecx + 0xf2], al
│           0x00016e69      33c0           xor   eax, eax
│           0x00016e6b      5b             pop   ebx
│           0x00016e6c      83c568         add   ebp, 0x68             ; 104
│           0x00016e6f      c9             leave
└           0x00016e70      c21000         ret   0x10

 */ 
condition: 
	1 of them 
}


```
