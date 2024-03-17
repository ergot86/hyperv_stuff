# Hyper-V stuff

This repository contains some of the Hyper-V related work I did in the past...


## GHHv6_ch25

My code from the "Inside Hyper-V" of the *Gray Hat Hacking* book (6th edition).
Original repository: https://github.com/GrayHatHacking/GHHv6.git

Includes a framework that can be used to perform hypervisor research/fuzzing and hyper-v specific code (hypercalls, MSRs, VMBus communication).


## windbg_hyperv_script.js

Windbg script that can be used when debugging `hvix64` and provides the following features:
- Dumping VMCS contents.
- Dumping EPT tables.
- GPA -> SPA translation.
- **Conditional breakpoints on VMExit conditions**:
  - Use `!brexit conditions`.
  - Where `conditions` is a in the form `condition1 condition2 .. conditionN`.
  - Each condition consists of 3 parts (in the described order and without space between them):
    1. A VMCS field name (for example `VM_EXIT_REASON`)
    2. A *condition code*: any of `==`, `!=`, `<=`, `>=`, `<`, `>`.
    3. An integer value.


## CVE-2020-0751.c

Proof of concept for Hyper-V stack overflow bug (hvix64).

Advisory: https://labs.bluefrostsecurity.de/advisories/bfs-sa-2020-001/


## CVE-2020-0890.c

Proof of concept for Hyper-V NULL deref bug (hvix64).

Advisory: https://labs.bluefrostsecurity.de/advisories/bfs-sa-2020-002/


## CVE-2020-0904.c

Proof of concept for Hyper-V type confusion bug (hvix64).

Advisory: https://labs.bluefrostsecurity.de/advisories/bfs-sa-2020-003/


## CVE-2021-28476

Proof of concept for Hyper-V arbitrary memory read bug (vmswitch).

Advisory: https://labs.bluefrostsecurity.de/advisories/bfs-sa-2021-001/
Original repo: https://github.com/bluefrostsecurity/CVE-2021-28476

Notes:
 - This bug was classified as RCE, [learn why here](https://www.youtube.com/watch?v=uqWiZXMh8TI).
 - This bug has also been presented by other researchers: https://www.youtube.com/watch?v=ALcm6pmR8ck
 - In the advisory I included other OOB read bugs I found but no CVEs where assigned to them.



