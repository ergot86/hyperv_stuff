// complaints to: daniel.kuehr@tacitosecurity.com

"use strict";

const log = x => host.diagnostics.debugLog(`${x}\n`);
const set_bp = x => host.namespace.Debugger.Utility.Control.SetBreakpointAtOffset(hex(x), 0);
const exec = x => host.namespace.Debugger.Utility.Control.ExecuteCommand(x);
const i64 = x => host.Int64(x);
const max_code_size = 512;
let code_buffer = null;
let breakpoint = null;
let host_rip = null;

function hex(num, padding = 16) {
    return num.toString(16).padStart(padding, "0");
}

function bits(value, offset, size) {
    let mask = i64(1).bitwiseShiftLeft(size).subtract(1);
    return value.bitwiseShiftRight(offset).bitwiseAnd(mask);
}

function* readPhys64(address, blocks) {
    for (let line of exec(`!dq ${hex(address)} L${hex(blocks, 0)}`)) {
        line = line.substring(1).replace(/\s+/g, ' ').trim()
        let tok = line.split(" ");
        //log(line);
        yield host.parseInt64(tok[1], 16);

        if (tok.length > 2) {
            yield host.parseInt64(tok[2], 16);
        }
    }
}

function writeBytes(address, bytes) {
    let bytes_str = bytes.map(b => `0x${hex(b, 2)}`).join(" ");
    let cmd = `eb ${hex(address)} ${bytes_str}`;
    //log(cmd);
    exec(cmd);
}

function findHole(code_base, min_size) {
    let last_addr = null;
    let curr_size = 0;
    let paddings = host.namespace.Debugger.Utility.Code.CreateDisassembler()
        .DisassembleBlocks(code_base)
        .Select(bb => bb.Instructions.Where(i => i.CodeBytes[0] == 0xCC).Select(i => i.Address))
        .SelectMany(x => x);

    for (let addr of paddings) {
        if (last_addr == null) {
            last_addr = addr;
        }
        else {
            if (curr_size >= min_size) {
                return last_addr;
            }

            curr_size = (addr.subtract(last_addr) != i64(1)) ? 0 : curr_size + 1;
            last_addr = addr;
        }
    }

    return null;
}

function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(ReadVmcs, "vmcs"),
        new host.functionAlias(DumpEPT, "ept"),
        new host.functionAlias(ResolveGPA, "spa"),
        new host.functionAlias(BreakOnVmexit, "brexit")
    ];
}

function invokeScript() {
    let hvix = host.currentProcess.Modules.First(m => m.Name == "hvix64.exe");
    let hdr = hvix.Contents.Headers.OptionalHeader;
    let code_base = hdr.ImageBase.add(hdr.BaseOfCode);

    exec(".load kext");
    log(`[i] Searching for holes in ${hvix.Name} (${hex(code_base)})...`);
    code_buffer = findHole(code_base, max_code_size);
    log(`[+] Hole found at ${hex(code_buffer)}`);
    host_rip = ReadVmcs("HOST_RIP");
    log(`[+] VMEXIT handler at ${hex(host_rip)}`);
}

// TODO: PWL5 support
// !ept
function DumpEPT(start_gpa, end_gpa) {
    if (end_gpa == null) {
        end_gpa = start_gpa.add(1);
    }

    new EPT_PML4(ReadVmcs("EPT_POINTER"), start_gpa, end_gpa).dump();
}

// !spa
function ResolveGPA(gpa) {
    return new EPT_PML4(ReadVmcs("EPT_POINTER"), gpa, gpa.add(1)).spa(gpa);
}

class EPT_PML4 {
    constructor(eptp, start_gpa, end_gpa) {
        this.start_index = start_gpa.bitwiseShiftRight(39);
        let end_index = end_gpa.bitwiseShiftRight(39);

        if (bits(end_gpa, 0, 39).asNumber() != 0) {
            end_index = end_index.add(1);
        }

        let num_entries = end_index.subtract(this.start_index);
        let base = eptp.bitwiseAnd(~0xfff).add(this.start_index.bitwiseShiftLeft(3));
        this.entries = Array.from(readPhys64(base, num_entries)).map(
            (x, i) => new EPT_PML4E(x, i64(i).bitwiseShiftLeft(39).add(start_gpa), end_gpa)
        );
    }

    spa(gpa) {
        let index = gpa.bitwiseShiftRight(39);

        if (index > this.start_index) {
            return null;
        }

        let entry = this.entries[index.subtract(this.start_index).asNumber()];

        if (!entry.present()) {
            return null;
        }

        if (entry.hasOwnProperty('table')) {
            return entry.table.spa(gpa);
        }
        else {
            return null;
        }
    }

    dump() {
        for (let [index, entry] of this.entries.entries()) {
            let va = this.start_index.add(index).bitwiseShiftLeft(39);

            log(`PML4E[${hex(this.start_index.add(index), 2)}]: GPA ${hex(va)} => SPA ${entry.toString()}`);

            if (entry.hasOwnProperty('table')) {
                entry.table.dump();
            }
        }
    }
}

class EPT_PML4E {
    constructor(entry, start_gpa, end_gpa) {
        this.Read = bits(entry, 0, 1);
        this.Write = bits(entry, 1, 1);
        this.Execute = bits(entry, 2, 1);
        this.Rsv1 = bits(entry, 3, 5);
        this.Accessed = bits(entry, 8, 1);
        this.Ign1 = bits(entry, 9, 1);
        this.ExecuteForUserMode = bits(entry, 10, 1);
        this.Ign2 = bits(entry, 11, 1);
        this.PFN = bits(entry, 12, 40); // TODO: N-bits support
        this.Ign3 = bits(entry, 52, 12);

        if (this.present()) {
            this.table = new EPT_PDPT(this.PFN.bitwiseShiftLeft(12), start_gpa, end_gpa);
        }
    }

    present() {
        return (this.Read.bitwiseOr(this.Write.bitwiseOr(this.Execute)) != 0);
    }

    toString() {
        return hex(this.PFN.bitwiseShiftLeft(12)) + ' '
            + { 1: 'U', 0: '-' }[this.ExecuteForUserMode.asNumber()]
            + { 1: 'A', 0: '-' }[this.Accessed.asNumber()]
            + { 1: 'X', 0: '-' }[this.Execute.asNumber()]
            + { 1: 'W', 0: '-' }[this.Write.asNumber()]
            + { 1: 'R', 0: '-' }[this.Read.asNumber()];
    }
}

class EPT_PDPT {
    constructor(pdpt, start_gpa, end_gpa) {
        this.start_index = bits(start_gpa, 30, 9);
        let end_index = bits(end_gpa, 30, 9);

        if (bits(end_gpa, 0, 30).asNumber() != 0) {
            end_index = end_index.add(1);
        }

        let num_entries = end_index.subtract(this.start_index);
        let base = pdpt.add(this.start_index.bitwiseShiftLeft(3));
        this.entries = Array.from(readPhys64(base, num_entries)).map(
            (x, i) => new EPT_PDPTE(x, i64(i).bitwiseShiftLeft(30).add(start_gpa), end_gpa)
        );
    }

    spa(gpa) {
        let index = bits(gpa, 30, 9);

        if (index > this.start_index) {
            return null;
        }

        let entry = this.entries[index.subtract(this.start_index).asNumber()];

        if (!entry.present()) {
            return null;
        }

        if (entry.hasOwnProperty('table')) {
            return entry.table.spa(gpa);
        }
        else {
            return entry.PFN.bitwiseShiftLeft(12).add(bits(gpa, 0, 30));
        }
    }

    dump() {
        for (let [index, entry] of this.entries.entries()) {
            let va = this.start_index.add(index).bitwiseShiftLeft(30);

            log(`PDPTE[${hex(this.start_index.add(index), 2)}]: GPA ${hex(va)} => SPA ${entry.toString()}`);

            if (entry.hasOwnProperty('table')) {
                entry.table.dump();
            }
        }
    }
}

class EPT_PDPTE {
    constructor(entry, start_gpa, end_gpa) {
        this.Read = bits(entry, 0, 1);
        this.Write = bits(entry, 1, 1);
        this.Execute = bits(entry, 2, 1);
        this.Rsv1 = bits(entry, 3, 4);
        this.Large = bits(entry, 7, 1);
        this.Accessed = bits(entry, 8, 1);
        this.Ign1 = bits(entry, 9, 1);
        this.ExecuteForUserMode = bits(entry, 10, 1);
        this.Ign2 = bits(entry, 11, 1);
        this.PFN = bits(entry, 12, 40); // TODO: N-bits support

        if (this.Large.asNumber() == 0 && this.present()) {
            this.Ign3 = bits(entry, 52, 12);
            this.table = new EPT_PD(this.PFN.bitwiseShiftLeft(12), start_gpa, end_gpa);
        }
        else {
            this.Ign3 = bits(entry, 52, 11);
            this.SVE = bits(entry, 63, 1);
        }
    }

    present() {
        return (this.Read.bitwiseOr(this.Write.bitwiseOr(this.Execute)) != 0);
    }

    toString() {
        return hex(this.PFN.bitwiseShiftLeft(12)) + ' '
            + { 1: 'U', 0: '-' }[this.ExecuteForUserMode.asNumber()]
            + { 1: 'A', 0: '-' }[this.Accessed.asNumber()]
            + { 1: 'L', 0: '-' }[this.Large.asNumber()]
            + { 1: 'X', 0: '-' }[this.Execute.asNumber()]
            + { 1: 'W', 0: '-' }[this.Write.asNumber()]
            + { 1: 'R', 0: '-' }[this.Read.asNumber()];
    }
}

class EPT_PD {
    constructor(pd, start_gpa, end_gpa) {
        this.start_index = bits(start_gpa, 21, 9);
        let end_index = bits(end_gpa, 21, 9);

        if (bits(end_gpa, 0, 21).asNumber() != 0) {
            end_index = end_index.add(1);
        }

        let num_entries = end_index.subtract(this.start_index);
        let base = pd.add(this.start_index.bitwiseShiftLeft(3));
        this.entries = Array.from(readPhys64(base, num_entries)).map(
            (x, i) => new EPT_PDE(x, i64(i).bitwiseShiftLeft(21).add(start_gpa), end_gpa)
        );
    }

    spa(gpa) {
        let index = bits(gpa, 21, 9);

        if (index > this.start_index) {
            return null;
        }

        let entry = this.entries[index.subtract(this.start_index).asNumber()];

        if (!entry.present()) {
            return null;
        }

        if (entry.hasOwnProperty('table')) {
            return entry.table.spa(gpa);
        }
        else {
            return entry.PFN.bitwiseShiftLeft(12).add(bits(gpa, 0, 21));
        }
    }

    dump() {
        for (let [index, entry] of this.entries.entries()) {
            let va = this.start_index.add(index).bitwiseShiftLeft(21);

            log(`  PDE[${hex(this.start_index.add(index), 2)}]: GPA ${hex(va)} => SPA ${entry.toString()}`);

            if (entry.hasOwnProperty('table')) {
                entry.table.dump();
            }
        }
    }
}

class EPT_PDE {
    constructor(entry, start_gpa, end_gpa) {
        this.Read = bits(entry, 0, 1);
        this.Write = bits(entry, 1, 1);
        this.Execute = bits(entry, 2, 1);
        this.Rsv1 = bits(entry, 3, 4);
        this.Large = bits(entry, 7, 1);
        this.Accessed = bits(entry, 8, 1);
        this.Ign1 = bits(entry, 9, 1);
        this.ExecuteForUserMode = bits(entry, 10, 1);
        this.Ign2 = bits(entry, 11, 1);
        this.PFN = bits(entry, 12, 40); // TODO: N-bits support

        if (this.Large.asNumber() == 0 && this.present()) {
            this.Ign3 = bits(entry, 52, 12);
            this.table = new EPT_PT(this.PFN.bitwiseShiftLeft(12), start_gpa, end_gpa);
        }
        else {
            this.Ign3 = bits(entry, 52, 11);
            this.SVE = bits(entry, 63, 1);
        }
    }

    present() {
        return (this.Read.bitwiseOr(this.Write.bitwiseOr(this.Execute)) != 0);
    }

    toString() {
        return hex(this.PFN.bitwiseShiftLeft(12)) + ' '
            + { 1: 'U', 0: '-' }[this.ExecuteForUserMode.asNumber()]
            + { 1: 'A', 0: '-' }[this.Accessed.asNumber()]
            + { 1: 'L', 0: '-' }[this.Large.asNumber()]
            + { 1: 'X', 0: '-' }[this.Execute.asNumber()]
            + { 1: 'W', 0: '-' }[this.Write.asNumber()]
            + { 1: 'R', 0: '-' }[this.Read.asNumber()];
    }
}

class EPT_PT {
    constructor(pt, start_gpa, end_gpa) {
        this.start_index = bits(start_gpa, 12, 9);
        let end_index = bits(end_gpa, 12, 9);

        if (bits(end_gpa, 0, 12).asNumber() != 0) {
            end_index = end_index.add(1);
        }

        let num_entries = end_index.subtract(this.start_index);
        let base = pt.add(this.start_index.bitwiseShiftLeft(3));
        this.entries = Array.from(readPhys64(base, num_entries)).map(
            (x, i) => new EPT_PTE(x)
        );
    }

    spa(gpa) {
        let index = bits(gpa, 12, 9);

        if (index > this.start_index) {
            return null;
        }

        let entry = this.entries[index.subtract(this.start_index).asNumber()];

        if (!entry.present()) {
            return null;
        }

        return entry.PFN.bitwiseShiftLeft(12).add(bits(gpa, 0, 12));
    }

    dump() {
        for (let [index, entry] of this.entries.entries()) {
            let va = this.start_index.add(index).bitwiseShiftLeft(12);

            log(`  PTE[${hex(this.start_index.add(index), 2)}]: GPA ${hex(va)} => SPA ${entry.toString()}`);
        }
    }
}

class EPT_PTE {
    constructor(entry) {
        this.Read = bits(entry, 0, 1);
        this.Write = bits(entry, 1, 1);
        this.Execute = bits(entry, 2, 1);
        this.EPTMT = bits(entry, 3, 3);
        this.IPAT = bits(entry, 6, 1);
        this.Ign1 = bits(entry, 7, 1);
        this.Accessed = bits(entry, 8, 1);
        this.Dirty = bits(entry, 9, 1);
        this.ExecuteForUserMode = bits(entry, 10, 1);
        this.Ign2 = bits(entry, 11, 1);
        this.PFN = bits(entry, 12, 40); // TODO: N-bits support
        this.Ign3 = bits(entry, 52, 11);
        this.SVE = bits(entry, 63, 1);
    }

    present() {
        return (this.Read.bitwiseOr(this.Write.bitwiseOr(this.Execute)) != 0);
    }

    toString() {
        return hex(this.PFN.bitwiseShiftLeft(12)) + ' '
            + { 1: 'U', 0: '-' }[this.ExecuteForUserMode.asNumber()]
            + { 1: 'D', 0: '-' }[this.Accessed.asNumber()]
            + { 1: 'A', 0: '-' }[this.Accessed.asNumber()]
            + { 1: 'X', 0: '-' }[this.Execute.asNumber()]
            + { 1: 'W', 0: '-' }[this.Write.asNumber()]
            + { 1: 'R', 0: '-' }[this.Read.asNumber()];
    }
}

function stepUntil(ip) {
    while (host.currentThread.Registers.User.rip != ip) {
        for (let l of exec("p")) {
            //log(l);
        }
    }
}

// !vmcs
function ReadVmcs(field) {
    let rax = host.currentThread.Registers.User.rax;
    let rip = host.currentThread.Registers.User.rip;
    let over_bp = host.currentProcess.Debug.Breakpoints.Any(b => b.Address == rip);

    if (typeof field === 'string') {
        field = vmcs_fields[field];
    }

    // we can't be over a bp so step
    while (host.currentProcess.Debug.Breakpoints.Any(b => b.Address == rip) == true) {
        for (let l of exec("p")) {
            //log(l);
        }
        rip = host.currentThread.Registers.User.rip;
    }

    host.currentThread.Registers.User.rax = field;

    if (breakpoint == null) {
        // we don't have a !brexit breakpoint yet
        writeBytes(code_buffer, [0x0F, 0x78, 0xC0]);
        host.currentThread.Registers.User.rip = code_buffer;
        stepUntil(code_buffer.add(3));
    }
    else {
        host.currentThread.Registers.User.rip = breakpoint.Address.add(6);
        stepUntil(breakpoint.Address.add(10));
    }

    let ret = host.currentThread.Registers.User.rax;
    host.currentThread.Registers.User.rax = rax;
    host.currentThread.Registers.User.rip = rip;
    return ret;
}

const dw2b = x => [x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff];

function cond_opcodes(cond, index, total) {
    let cc = {
        "==": 0x85,
        "!=": 0x84,
        "<=": 0x87,
        ">=": 0x82,
        "<": 0x83,
        ">": 0x86
    };
    let block_delta = ((total - index - 1) * 26);
    let data_target = block_delta + (index * 8) + 61;
    let jmp_target = block_delta + 21;
    return [0x48, 0xB8]                          // mov rax, field
        .concat(dw2b(cond.field.getLowPart()))
        .concat(dw2b(cond.field.getHighPart()))
        .concat(
        [
            0x0F, 0x78, 0xC0,                    // vmread rax, rax
            0x48, 0x3B, 0x05])                   // cmp rax, [rel value]
        .concat(dw2b(data_target))
        .concat([0x0F, cc[cond.cond]])           // jcc exit
        .concat(dw2b(jmp_target));
}

function patch_code(conditions) {
    let delta = code_buffer.getLowPart() - (host_rip.getLowPart() + 5);

    if (code_buffer.getHighPart() != host_rip.getHighPart()
        || delta > 0x80000000
        || delta < -0x7fffffff) {
        log("[-] Buffer too far away for jmp");
        return null;
    }

    let total = conditions.length;
    let payload = [0x48, 0x89, 0x44, 0x24, 0x28]; // mov [rsp+0x28], rax

    for (let [index, cond] of conditions.entries()) {
        payload = payload.concat(cond_opcodes(cond, index, total));
    }

    let bp_addr = code_buffer.add(payload.length + 10);
    payload = payload
        .concat(
        [
            0x48, 0x8b, 0x44, 0x24, 0x28,          // mov rax, [rsp+0x28]
            0x0F, 0xC7, 0x7C, 0x24, 0x28,          // vmptrst [rsp+0x28]
            0x90,                                  // nop (bp)
            0x48, 0x89, 0x44, 0x24, 0x28,          // mov [rsp+0x28], rax
            0x0F, 0x78, 0xC0,                      // vmread rax, rax
            0x90, 0x90, 0x90,
            0x48, 0x8b, 0x44, 0x24, 0x28,          // mov rax, [rsp+0x28]
            0xC7, 0x44, 0x24, 0x28])               // mov dword [rsp+0x2c], low
        .concat(dw2b(host_rip.getLowPart() + 5))
        .concat([0xC7, 0x44, 0x24, 0x2C])          // mov dword [rsp+0x28], high
        .concat(dw2b(host_rip.getHighPart()))
        .concat(
        [                                          // original handler instruction
            0xC7, 0x44, 0x24, 0x30, 0x00, 0x00,    // mov dword [rsp+0x30], 0
            0x00, 0x00])
        .concat([0xFF, 0x64, 0x24, 0x28]);         // jmp [rsp+0x28]

    for (let cond of conditions) {
        payload = payload
            .concat(dw2b(cond.value.getLowPart()))
            .concat(dw2b(cond.value.getHighPart()));
    }

    if (payload.length > max_code_size) {
        log(`[-] Payload size ${payload.length} larger than ${max_code_size}`);
        return null;
    }

    //log(payload);
    writeBytes(code_buffer, payload);
    breakpoint = set_bp(bp_addr);
    breakpoint.Command = '.printf "VMPTR: %p\n", poi(rsp+0x28)';

    let jmp = [0xe9].concat(dw2b(delta & 0xffffffff)).concat([0x90, 0x90, 0x90]);
    writeBytes(host_rip, jmp);
}


function BreakOnVmexit(stop_conditions) {
    let conditions = stop_conditions
        .replace(/\s+/g, ' ')
        .trim()
        .split(" ")
        .map(
        cond => {
            for (let cc of ["==", "!=", "<=", ">=", "<", ">"]) {
                if (cond.includes(cc)) {
                    let tok = cond.split(cc);
                    return {
                        cond: cc,
                        field: vmcs_fields[tok[0]],
                        value: host.parseInt64(tok[1], 16)
                    }
                }

            }
        }
        );

    return patch_code(conditions);
}

// taken from Linux kernel sources
let vmcs_fields = {
    VIRTUAL_PROCESSOR_ID: 0x00000000,
    POSTED_INTR_NV: 0x00000002,
    GUEST_ES_SELECTOR: 0x00000800,
    GUEST_CS_SELECTOR: 0x00000802,
    GUEST_SS_SELECTOR: 0x00000804,
    GUEST_DS_SELECTOR: 0x00000806,
    GUEST_FS_SELECTOR: 0x00000808,
    GUEST_GS_SELECTOR: 0x0000080a,
    GUEST_LDTR_SELECTOR: 0x0000080c,
    GUEST_TR_SELECTOR: 0x0000080e,
    GUEST_INTR_STATUS: 0x00000810,
    GUEST_PML_INDEX: 0x00000812,
    HOST_ES_SELECTOR: 0x00000c00,
    HOST_CS_SELECTOR: 0x00000c02,
    HOST_SS_SELECTOR: 0x00000c04,
    HOST_DS_SELECTOR: 0x00000c06,
    HOST_FS_SELECTOR: 0x00000c08,
    HOST_GS_SELECTOR: 0x00000c0a,
    HOST_TR_SELECTOR: 0x00000c0c,
    IO_BITMAP_A: 0x00002000,
    IO_BITMAP_A_HIGH: 0x00002001,
    IO_BITMAP_B: 0x00002002,
    IO_BITMAP_B_HIGH: 0x00002003,
    MSR_BITMAP: 0x00002004,
    MSR_BITMAP_HIGH: 0x00002005,
    VM_EXIT_MSR_STORE_ADDR: 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH: 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR: 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH: 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR: 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH: 0x0000200b,
    PML_ADDRESS: 0x0000200e,
    PML_ADDRESS_HIGH: 0x0000200f,
    TSC_OFFSET: 0x00002010,
    TSC_OFFSET_HIGH: 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR: 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH: 0x00002013,
    APIC_ACCESS_ADDR: 0x00002014,
    APIC_ACCESS_ADDR_HIGH: 0x00002015,
    POSTED_INTR_DESC_ADDR: 0x00002016,
    POSTED_INTR_DESC_ADDR_HIGH: 0x00002017,
    VM_FUNCTION_CONTROL: 0x00002018,
    VM_FUNCTION_CONTROL_HIGH: 0x00002019,
    EPT_POINTER: 0x0000201a,
    EPT_POINTER_HIGH: 0x0000201b,
    EOI_EXIT_BITMAP0: 0x0000201c,
    EOI_EXIT_BITMAP0_HIGH: 0x0000201d,
    EOI_EXIT_BITMAP1: 0x0000201e,
    EOI_EXIT_BITMAP1_HIGH: 0x0000201f,
    EOI_EXIT_BITMAP2: 0x00002020,
    EOI_EXIT_BITMAP2_HIGH: 0x00002021,
    EOI_EXIT_BITMAP3: 0x00002022,
    EOI_EXIT_BITMAP3_HIGH: 0x00002023,
    EPTP_LIST_ADDRESS: 0x00002024,
    EPTP_LIST_ADDRESS_HIGH: 0x00002025,
    VMREAD_BITMAP: 0x00002026,
    VMREAD_BITMAP_HIGH: 0x00002027,
    VMWRITE_BITMAP: 0x00002028,
    VMWRITE_BITMAP_HIGH: 0x00002029,
    XSS_EXIT_BITMAP: 0x0000202C,
    XSS_EXIT_BITMAP_HIGH: 0x0000202D,
    ENCLS_EXITING_BITMAP: 0x0000202E,
    ENCLS_EXITING_BITMAP_HIGH: 0x0000202F,
    TSC_MULTIPLIER: 0x00002032,
    TSC_MULTIPLIER_HIGH: 0x00002033,
    GUEST_PHYSICAL_ADDRESS: 0x00002400,
    GUEST_PHYSICAL_ADDRESS_HIGH: 0x00002401,
    VMCS_LINK_POINTER: 0x00002800,
    VMCS_LINK_POINTER_HIGH: 0x00002801,
    GUEST_IA32_DEBUGCTL: 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH: 0x00002803,
    GUEST_IA32_PAT: 0x00002804,
    GUEST_IA32_PAT_HIGH: 0x00002805,
    GUEST_IA32_EFER: 0x00002806,
    GUEST_IA32_EFER_HIGH: 0x00002807,
    GUEST_IA32_PERF_GLOBAL_CTRL: 0x00002808,
    GUEST_IA32_PERF_GLOBAL_CTRL_HIGH: 0x00002809,
    GUEST_PDPTR0: 0x0000280a,
    GUEST_PDPTR0_HIGH: 0x0000280b,
    GUEST_PDPTR1: 0x0000280c,
    GUEST_PDPTR1_HIGH: 0x0000280d,
    GUEST_PDPTR2: 0x0000280e,
    GUEST_PDPTR2_HIGH: 0x0000280f,
    GUEST_PDPTR3: 0x00002810,
    GUEST_PDPTR3_HIGH: 0x00002811,
    GUEST_BNDCFGS: 0x00002812,
    GUEST_BNDCFGS_HIGH: 0x00002813,
    GUEST_IA32_RTIT_CTL: 0x00002814,
    GUEST_IA32_RTIT_CTL_HIGH: 0x00002815,
    HOST_IA32_PAT: 0x00002c00,
    HOST_IA32_PAT_HIGH: 0x00002c01,
    HOST_IA32_EFER: 0x00002c02,
    HOST_IA32_EFER_HIGH: 0x00002c03,
    HOST_IA32_PERF_GLOBAL_CTRL: 0x00002c04,
    HOST_IA32_PERF_GLOBAL_CTRL_HIGH: 0x00002c05,
    PIN_BASED_VM_EXEC_CONTROL: 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL: 0x00004002,
    EXCEPTION_BITMAP: 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK: 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH: 0x00004008,
    CR3_TARGET_COUNT: 0x0000400a,
    VM_EXIT_CONTROLS: 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT: 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT: 0x00004010,
    VM_ENTRY_CONTROLS: 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT: 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD: 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE: 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN: 0x0000401a,
    TPR_THRESHOLD: 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL: 0x0000401e,
    PLE_GAP: 0x00004020,
    PLE_WINDOW: 0x00004022,
    VM_INSTRUCTION_ERROR: 0x00004400,
    VM_EXIT_REASON: 0x00004402,
    VM_EXIT_INTR_INFO: 0x00004404,
    VM_EXIT_INTR_ERROR_CODE: 0x00004406,
    IDT_VECTORING_INFO_FIELD: 0x00004408,
    IDT_VECTORING_ERROR_CODE: 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN: 0x0000440c,
    VMX_INSTRUCTION_INFO: 0x0000440e,
    GUEST_ES_LIMIT: 0x00004800,
    GUEST_CS_LIMIT: 0x00004802,
    GUEST_SS_LIMIT: 0x00004804,
    GUEST_DS_LIMIT: 0x00004806,
    GUEST_FS_LIMIT: 0x00004808,
    GUEST_GS_LIMIT: 0x0000480a,
    GUEST_LDTR_LIMIT: 0x0000480c,
    GUEST_TR_LIMIT: 0x0000480e,
    GUEST_GDTR_LIMIT: 0x00004810,
    GUEST_IDTR_LIMIT: 0x00004812,
    GUEST_ES_AR_BYTES: 0x00004814,
    GUEST_CS_AR_BYTES: 0x00004816,
    GUEST_SS_AR_BYTES: 0x00004818,
    GUEST_DS_AR_BYTES: 0x0000481a,
    GUEST_FS_AR_BYTES: 0x0000481c,
    GUEST_GS_AR_BYTES: 0x0000481e,
    GUEST_LDTR_AR_BYTES: 0x00004820,
    GUEST_TR_AR_BYTES: 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO: 0x00004824,
    GUEST_ACTIVITY_STATE: 0X00004826,
    GUEST_SYSENTER_CS: 0x0000482A,
    VMX_PREEMPTION_TIMER_VALUE: 0x0000482E,
    HOST_IA32_SYSENTER_CS: 0x00004c00,
    CR0_GUEST_HOST_MASK: 0x00006000,
    CR4_GUEST_HOST_MASK: 0x00006002,
    CR0_READ_SHADOW: 0x00006004,
    CR4_READ_SHADOW: 0x00006006,
    CR3_TARGET_VALUE0: 0x00006008,
    CR3_TARGET_VALUE1: 0x0000600a,
    CR3_TARGET_VALUE2: 0x0000600c,
    CR3_TARGET_VALUE3: 0x0000600e,
    EXIT_QUALIFICATION: 0x00006400,
    GUEST_LINEAR_ADDRESS: 0x0000640a,
    GUEST_CR0: 0x00006800,
    GUEST_CR3: 0x00006802,
    GUEST_CR4: 0x00006804,
    GUEST_ES_BASE: 0x00006806,
    GUEST_CS_BASE: 0x00006808,
    GUEST_SS_BASE: 0x0000680a,
    GUEST_DS_BASE: 0x0000680c,
    GUEST_FS_BASE: 0x0000680e,
    GUEST_GS_BASE: 0x00006810,
    GUEST_LDTR_BASE: 0x00006812,
    GUEST_TR_BASE: 0x00006814,
    GUEST_GDTR_BASE: 0x00006816,
    GUEST_IDTR_BASE: 0x00006818,
    GUEST_DR7: 0x0000681a,
    GUEST_RSP: 0x0000681c,
    GUEST_RIP: 0x0000681e,
    GUEST_RFLAGS: 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS: 0x00006822,
    GUEST_SYSENTER_ESP: 0x00006824,
    GUEST_SYSENTER_EIP: 0x00006826,
    HOST_CR0: 0x00006c00,
    HOST_CR3: 0x00006c02,
    HOST_CR4: 0x00006c04,
    HOST_FS_BASE: 0x00006c06,
    HOST_GS_BASE: 0x00006c08,
    HOST_TR_BASE: 0x00006c0a,
    HOST_GDTR_BASE: 0x00006c0c,
    HOST_IDTR_BASE: 0x00006c0e,
    HOST_IA32_SYSENTER_ESP: 0x00006c10,
    HOST_IA32_SYSENTER_EIP: 0x00006c12,
    HOST_RSP: 0x00006c14,
    HOST_RIP: 0x00006c16,
};
