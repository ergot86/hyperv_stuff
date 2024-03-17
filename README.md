# hyper-v stuff

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


