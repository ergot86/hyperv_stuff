// complaints to: daniel.kuehr@tacitosecurity.com

"use strict";

const log = x => host.diagnostics.debugLog(`${x}\n`);
const exec = x => host.namespace.Debugger.Utility.Control.ExecuteCommand(x);
const i64 = x => host.Int64(x);
const max_code_size = 512;
const context = {
    code_buffer: null,
    host_rip: null,
    breakpoint: null
};

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

function getEntryPoint() {
    let hvix = host.currentProcess.Modules.First(m => m.Name == "hvix64.exe");
    let hdr = hvix.Contents.Headers.OptionalHeader;
    let entry_point = hdr.ImageBase.add(hdr.AddressOfEntryPoint);

    log(`[i] ${hvix.Name} entry point: ${entry_point}`);
    return entry_point;
}

function removeBreakpoint() {
    let ctx = getContext();
    let bp = getBreakpoint();
    let context_area_bp = ctx.code_buffer.subtract(8);

    if (bp != null) {
        host.namespace.Debugger.State.RemoveBreakpoint(bp);
    }

    ctx.breakpoint = null;
    // update information at context area in target
    writeBytes(context_area_bp, [0, 0, 0, 0, 0, 0, 0, 0]);
}

function setBreakPoint(address) {
    let ctx = getContext();
    let context_area_bp = ctx.code_buffer.subtract(8);

    ctx.breakpoint = host.namespace.Debugger.Utility.Control.SetBreakpointAtOffset(hex(address), 0);
    // update information at context area in target
    writeBytes(context_area_bp, dq2b(address));
    return ctx.breakpoint;
}

function range(start, end, step) {
    let arr = [];
    let addr = start;
    let mask = i64(0xfff).bitwis

    while (addr.compareTo(end) < 1) {
        let next_addr = addr.add(step).divide(step).multiply(step);
        let size = next_addr.subtract(addr);

        arr.push([addr, size]);
        addr = next_addr;
    }

    return arr;
}

function findPattern(startAddress, endAddress) {
    for (let block of range(startAddress, endAddress, 0x1000)) {
        let [addr, size] = block;
        let memory = host.memory.readMemoryValues(addr, size);

        for (let i = 0; i+7 < size; i++) {
            if (memory[i] === 0x7
             && memory[i+1] === 0xA
             && memory[i+2] === 0xC
             && memory[i+3] === 0x1
             && memory[i+4] === 0x7
             && memory[i+5] === 0x0
             && memory[i+6] === 0x5
             && memory[i+7] === 0xE) {
                 return addr.add(i);
             }
        }
    }

    log("[-] Can't find context in memory");
    return undefined;
}

function resetContext() {
    log("[i] Context lost, searching it in target...");

    let entry_point = getEntryPoint();
    let context_area = findPattern(entry_point, entry_point.add(0x0402000));
    let [host_rip, bp_address] = host.memory.readMemoryValues(context_area.add(8), 16, 8);

    context.code_buffer = context_area.add(8*3);
    context.host_rip = host_rip;

    if (bp_address.compareTo(i64(0)) != 0) {
        for (let bp of host.currentProcess.Debug.Breakpoints) {
            if (bp.Address == bp_address) {
                context.breakpoint = bp;
                return;
            }
        }

        log(`[-] No breakpoint found for stored address ${bp_address}`);
    } else {
        context.breakpoint = null;
    }
}

function getContext() {
    if (context.code_buffer == null) {
        resetContext();
    };

    return context;
}

function getPatchArea() {
    return getContext().code_buffer;
}

function getBreakpoint() {
    return getContext().breakpoint;
}

function getHostRip() {
    let context = getContext();

    if (context.host_rip == null) {
        log("[i] HOST_RIP not found in context, fetching it from VMCS...");
        context.host_rip = ReadVmcs("HOST_RIP");
    }

    return context.host_rip;
}

function findHole(code_base, min_size) {
    let last_addr = null;
    let curr_size = 0;
    let paddings = host.namespace.Debugger.Utility.Code.CreateDisassembler()
        .DisassembleBlocks(code_base)
        .Select(bb => bb.Instructions.Where(i => i.CodeBytes[0] == 0xcc).Select(i => i.Address))
        .SelectMany(x => x);

    for (let addr of paddings) {
        //log(`found ${addr}`);
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
    exec(".load kext");
    log(`[i] Searching for holes...`);
    let context_area = findHole(getEntryPoint(), max_code_size);
    log(`[+] Hole found at ${context_area}`);
    context.code_buffer = context_area.add(8*3);
    
    let host_rip = getHostRip();
    log(`[+] VMEXIT handler at ${host_rip}`);

    let context_data = [0x7, 0xA, 0xC, 0x1, 0x7, 0x0, 0x5, 0xE] // pattern
        .concat(dq2b(host_rip))
        .concat(dq2b(i64(0))) // bp address;

    writeBytes(context_area, context_data);
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
        this.start_index = bits(start_gpa, 39, 9);
        let end_index = bits(end_gpa, 39, 9);

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
    let current_rip = host.currentThread.Registers.User.rip;

    while (current_rip != ip) {
        for (let l of exec("p")) {
            //log(`stepUntil: ${current_rip} ${l}`);
        }

        current_rip = host.currentThread.Registers.User.rip;
    }
}

// !vmcs
function ReadVmcs(field) {
    let patch_area = getPatchArea();
    let breakpoint = getBreakpoint();
    let rax = host.currentThread.Registers.User.rax;
    let rip = host.currentThread.Registers.User.rip;

    if (typeof field === 'string') {
        field = vmcs_fields[field];
    }

    // we can't be over a bp so step
    while (host.currentProcess.Debug.Breakpoints.Any(b => b.Address == rip) == true) {
        for (let l of exec("p")) {
            log(`over bp: ${l}`);
        }
        rip = host.currentThread.Registers.User.rip;
    }

    if (breakpoint == null) {
        writeBytes(patch_area, [0x0F, 0x78, 0xC0]);
        exec(`r rip=${patch_area}, rax=${field}`);
        stepUntil(patch_area.add(3));
    }
    else {
        // re-use vmread injected by !brexit
        exec(`r rip=${breakpoint.Address.add(6)}, rax=${field}`);
        // go on until after vmread
        stepUntil(breakpoint.Address.add(10));
    }

    let ret = host.currentThread.Registers.User.rax;
    exec(`r rip=${rip}, rax=${rax}`);
    return ret;
}

const dw2b = x => [x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff];
const dq2b = x => dw2b(x.getLowPart()).concat(dw2b(x.getHighPart()));


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
    return [0x48, 0xB8].concat(dq2b(cond.field))                 // mov rax, field
        .concat([0x0F, 0x78, 0xC0,                               // vmread rax, rax
                 0x48, 0x3B, 0x05]).concat(dw2b(data_target))    // cmp rax, [rel value]
        .concat([0x0F, cc[cond.cond]]).concat(dw2b(jmp_target)); // jcc exit
}

function patch_code(conditions) {
    let patch_area = getPatchArea();
    let host_rip = getHostRip();
    let delta = patch_area.getLowPart() - (host_rip.getLowPart() + 5);

    if (patch_area.getHighPart() != host_rip.getHighPart()
        || delta > 0x80000000
        || delta < -0x7fffffff) {
        log("[-] Buffer too far away for jmp");
        return;
    }

    let total = conditions.length;
    let payload = [0x48, 0x89, 0x44, 0x24, 0x28]; // mov [rsp+0x28], rax

    for (let [index, cond] of conditions.entries()) {
        payload = payload.concat(cond_opcodes(cond, index, total));
    }

    let bp_addr = patch_area.add(payload.length + 10);

    payload = payload.concat([
        0x48, 0x8b, 0x44, 0x24, 0x28,          // mov rax, [rsp+0x28]
        0x0F, 0xC7, 0x7C, 0x24, 0x28,          // vmptrst [rsp+0x28]
        0x90,                                  // nop (bp)
        0x48, 0x89, 0x44, 0x24, 0x28,          // mov [rsp+0x28], rax
        0x0F, 0x78, 0xC0,                      // vmread rax, rax
        0x90, 0x90, 0x90,
        0x48, 0x8b, 0x44, 0x24, 0x28,          // mov rax, [rsp+0x28]
                                               // mov dword [rsp+0x28], low
        0xC7, 0x44, 0x24, 0x28]).concat(dw2b(host_rip.getLowPart() + 5))
                                               // mov dword [rsp+0x2c], high
        .concat([0xC7, 0x44, 0x24, 0x2C]).concat(dw2b(host_rip.getHighPart()))
        // original handler instruction:          mov dword [rsp+0x30], 0
        .concat([0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00])
        .concat([0xFF, 0x64, 0x24, 0x28]);     // jmp [rsp+0x28]

    for (let cond of conditions) {
        payload = payload.concat(dq2b(cond.value));
    }

    if (payload.length > max_code_size) {
        log(`[-] Payload size ${payload.length} larger than ${max_code_size}`);
        return;
    }

    //log(payload);
    removeBreakpoint();
    writeBytes(patch_area, payload);
    setBreakPoint(bp_addr)
    .Command = '.printf "===[     VMEXIT BREAK     ]===  VMCS@%p === ", poi(rsp+0x28)';

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
                            field_name: tok[0],
                            value: host.parseInt64(tok[1], 16),
                        }
                    }
                }
            }
        );

    patch_code(conditions);
}

// taken from Linux kernel sources
let vmcs_fields = {
    VIRTUAL_PROCESSOR_ID: i64(0x00000000),
    POSTED_INTR_NV: i64(0x00000002),
    GUEST_ES_SELECTOR: i64(0x00000800),
    GUEST_CS_SELECTOR: i64(0x00000802),
    GUEST_SS_SELECTOR: i64(0x00000804),
    GUEST_DS_SELECTOR: i64(0x00000806),
    GUEST_FS_SELECTOR: i64(0x00000808),
    GUEST_GS_SELECTOR: i64(0x0000080a),
    GUEST_LDTR_SELECTOR: i64(0x0000080c),
    GUEST_TR_SELECTOR: i64(0x0000080e),
    GUEST_INTR_STATUS: i64(0x00000810),
    GUEST_PML_INDEX: i64(0x00000812),
    HOST_ES_SELECTOR: i64(0x00000c00),
    HOST_CS_SELECTOR: i64(0x00000c02),
    HOST_SS_SELECTOR: i64(0x00000c04),
    HOST_DS_SELECTOR: i64(0x00000c06),
    HOST_FS_SELECTOR: i64(0x00000c08),
    HOST_GS_SELECTOR: i64(0x00000c0a),
    HOST_TR_SELECTOR: i64(0x00000c0c),
    IO_BITMAP_A: i64(0x00002000),
    IO_BITMAP_A_HIGH: i64(0x00002001),
    IO_BITMAP_B: i64(0x00002002),
    IO_BITMAP_B_HIGH: i64(0x00002003),
    MSR_BITMAP: i64(0x00002004),
    MSR_BITMAP_HIGH: i64(0x00002005),
    VM_EXIT_MSR_STORE_ADDR: i64(0x00002006),
    VM_EXIT_MSR_STORE_ADDR_HIGH: i64(0x00002007),
    VM_EXIT_MSR_LOAD_ADDR: i64(0x00002008),
    VM_EXIT_MSR_LOAD_ADDR_HIGH: i64(0x00002009),
    VM_ENTRY_MSR_LOAD_ADDR: i64(0x0000200a),
    VM_ENTRY_MSR_LOAD_ADDR_HIGH: i64(0x0000200b),
    PML_ADDRESS: i64(0x0000200e),
    PML_ADDRESS_HIGH: i64(0x0000200f),
    TSC_OFFSET: i64(0x00002010),
    TSC_OFFSET_HIGH: i64(0x00002011),
    VIRTUAL_APIC_PAGE_ADDR: i64(0x00002012),
    VIRTUAL_APIC_PAGE_ADDR_HIGH: i64(0x00002013),
    APIC_ACCESS_ADDR: i64(0x00002014),
    APIC_ACCESS_ADDR_HIGH: i64(0x00002015),
    POSTED_INTR_DESC_ADDR: i64(0x00002016),
    POSTED_INTR_DESC_ADDR_HIGH: i64(0x00002017),
    VM_FUNCTION_CONTROL: i64(0x00002018),
    VM_FUNCTION_CONTROL_HIGH: i64(0x00002019),
    EPT_POINTER: i64(0x0000201a),
    EPT_POINTER_HIGH: i64(0x0000201b),
    EOI_EXIT_BITMAP0: i64(0x0000201c),
    EOI_EXIT_BITMAP0_HIGH: i64(0x0000201d),
    EOI_EXIT_BITMAP1: i64(0x0000201e),
    EOI_EXIT_BITMAP1_HIGH: i64(0x0000201f),
    EOI_EXIT_BITMAP2: i64(0x00002020),
    EOI_EXIT_BITMAP2_HIGH: i64(0x00002021),
    EOI_EXIT_BITMAP3: i64(0x00002022),
    EOI_EXIT_BITMAP3_HIGH: i64(0x00002023),
    EPTP_LIST_ADDRESS: i64(0x00002024),
    EPTP_LIST_ADDRESS_HIGH: i64(0x00002025),
    VMREAD_BITMAP: i64(0x00002026),
    VMREAD_BITMAP_HIGH: i64(0x00002027),
    VMWRITE_BITMAP: i64(0x00002028),
    VMWRITE_BITMAP_HIGH: i64(0x00002029),
    XSS_EXIT_BITMAP: i64(0x0000202C),
    XSS_EXIT_BITMAP_HIGH: i64(0x0000202D),
    ENCLS_EXITING_BITMAP: i64(0x0000202E),
    ENCLS_EXITING_BITMAP_HIGH: i64(0x0000202F),
    TSC_MULTIPLIER: i64(0x00002032),
    TSC_MULTIPLIER_HIGH: i64(0x00002033),
    GUEST_PHYSICAL_ADDRESS: i64(0x00002400),
    GUEST_PHYSICAL_ADDRESS_HIGH: i64(0x00002401),
    VMCS_LINK_POINTER: i64(0x00002800),
    VMCS_LINK_POINTER_HIGH: i64(0x00002801),
    GUEST_IA32_DEBUGCTL: i64(0x00002802),
    GUEST_IA32_DEBUGCTL_HIGH: i64(0x00002803),
    GUEST_IA32_PAT: i64(0x00002804),
    GUEST_IA32_PAT_HIGH: i64(0x00002805),
    GUEST_IA32_EFER: i64(0x00002806),
    GUEST_IA32_EFER_HIGH: i64(0x00002807),
    GUEST_IA32_PERF_GLOBAL_CTRL: i64(0x00002808),
    GUEST_IA32_PERF_GLOBAL_CTRL_HIGH: i64(0x00002809),
    GUEST_PDPTR0: i64(0x0000280a),
    GUEST_PDPTR0_HIGH: i64(0x0000280b),
    GUEST_PDPTR1: i64(0x0000280c),
    GUEST_PDPTR1_HIGH: i64(0x0000280d),
    GUEST_PDPTR2: i64(0x0000280e),
    GUEST_PDPTR2_HIGH: i64(0x0000280f),
    GUEST_PDPTR3: i64(0x00002810),
    GUEST_PDPTR3_HIGH: i64(0x00002811),
    GUEST_BNDCFGS: i64(0x00002812),
    GUEST_BNDCFGS_HIGH: i64(0x00002813),
    GUEST_IA32_RTIT_CTL: i64(0x00002814),
    GUEST_IA32_RTIT_CTL_HIGH: i64(0x00002815),
    HOST_IA32_PAT: i64(0x00002c00),
    HOST_IA32_PAT_HIGH: i64(0x00002c01),
    HOST_IA32_EFER: i64(0x00002c02),
    HOST_IA32_EFER_HIGH: i64(0x00002c03),
    HOST_IA32_PERF_GLOBAL_CTRL: i64(0x00002c04),
    HOST_IA32_PERF_GLOBAL_CTRL_HIGH: i64(0x00002c05),
    PIN_BASED_VM_EXEC_CONTROL: i64(0x00004000),
    CPU_BASED_VM_EXEC_CONTROL: i64(0x00004002),
    EXCEPTION_BITMAP: i64(0x00004004),
    PAGE_FAULT_ERROR_CODE_MASK: i64(0x00004006),
    PAGE_FAULT_ERROR_CODE_MATCH: i64(0x00004008),
    CR3_TARGET_COUNT: i64(0x0000400a),
    VM_EXIT_CONTROLS: i64(0x0000400c),
    VM_EXIT_MSR_STORE_COUNT: i64(0x0000400e),
    VM_EXIT_MSR_LOAD_COUNT: i64(0x00004010),
    VM_ENTRY_CONTROLS: i64(0x00004012),
    VM_ENTRY_MSR_LOAD_COUNT: i64(0x00004014),
    VM_ENTRY_INTR_INFO_FIELD: i64(0x00004016),
    VM_ENTRY_EXCEPTION_ERROR_CODE: i64(0x00004018),
    VM_ENTRY_INSTRUCTION_LEN: i64(0x0000401a),
    TPR_THRESHOLD: i64(0x0000401c),
    SECONDARY_VM_EXEC_CONTROL: i64(0x0000401e),
    PLE_GAP: i64(0x00004020),
    PLE_WINDOW: i64(0x00004022),
    VM_INSTRUCTION_ERROR: i64(0x00004400),
    VM_EXIT_REASON: i64(0x00004402),
    VM_EXIT_INTR_INFO: i64(0x00004404),
    VM_EXIT_INTR_ERROR_CODE: i64(0x00004406),
    IDT_VECTORING_INFO_FIELD: i64(0x00004408),
    IDT_VECTORING_ERROR_CODE: i64(0x0000440a),
    VM_EXIT_INSTRUCTION_LEN: i64(0x0000440c),
    VMX_INSTRUCTION_INFO: i64(0x0000440e),
    GUEST_ES_LIMIT: i64(0x00004800),
    GUEST_CS_LIMIT: i64(0x00004802),
    GUEST_SS_LIMIT: i64(0x00004804),
    GUEST_DS_LIMIT: i64(0x00004806),
    GUEST_FS_LIMIT: i64(0x00004808),
    GUEST_GS_LIMIT: i64(0x0000480a),
    GUEST_LDTR_LIMIT: i64(0x0000480c),
    GUEST_TR_LIMIT: i64(0x0000480e),
    GUEST_GDTR_LIMIT: i64(0x00004810),
    GUEST_IDTR_LIMIT: i64(0x00004812),
    GUEST_ES_AR_BYTES: i64(0x00004814),
    GUEST_CS_AR_BYTES: i64(0x00004816),
    GUEST_SS_AR_BYTES: i64(0x00004818),
    GUEST_DS_AR_BYTES: i64(0x0000481a),
    GUEST_FS_AR_BYTES: i64(0x0000481c),
    GUEST_GS_AR_BYTES: i64(0x0000481e),
    GUEST_LDTR_AR_BYTES: i64(0x00004820),
    GUEST_TR_AR_BYTES: i64(0x00004822),
    GUEST_INTERRUPTIBILITY_INFO: i64(0x00004824),
    GUEST_ACTIVITY_STATE: i64(0x00004826),
    GUEST_SYSENTER_CS: i64(0x0000482A),
    VMX_PREEMPTION_TIMER_VALUE: i64(0x0000482E),
    HOST_IA32_SYSENTER_CS: i64(0x00004c00),
    CR0_GUEST_HOST_MASK: i64(0x00006000),
    CR4_GUEST_HOST_MASK: i64(0x00006002),
    CR0_READ_SHADOW: i64(0x00006004),
    CR4_READ_SHADOW: i64(0x00006006),
    CR3_TARGET_VALUE0: i64(0x00006008),
    CR3_TARGET_VALUE1: i64(0x0000600a),
    CR3_TARGET_VALUE2: i64(0x0000600c),
    CR3_TARGET_VALUE3: i64(0x0000600e),
    EXIT_QUALIFICATION: i64(0x00006400),
    GUEST_LINEAR_ADDRESS: i64(0x0000640a),
    GUEST_CR0: i64(0x00006800),
    GUEST_CR3: i64(0x00006802),
    GUEST_CR4: i64(0x00006804),
    GUEST_ES_BASE: i64(0x00006806),
    GUEST_CS_BASE: i64(0x00006808),
    GUEST_SS_BASE: i64(0x0000680a),
    GUEST_DS_BASE: i64(0x0000680c),
    GUEST_FS_BASE: i64(0x0000680e),
    GUEST_GS_BASE: i64(0x00006810),
    GUEST_LDTR_BASE: i64(0x00006812),
    GUEST_TR_BASE: i64(0x00006814),
    GUEST_GDTR_BASE: i64(0x00006816),
    GUEST_IDTR_BASE: i64(0x00006818),
    GUEST_DR7: i64(0x0000681a),
    GUEST_RSP: i64(0x0000681c),
    GUEST_RIP: i64(0x0000681e),
    GUEST_RFLAGS: i64(0x00006820),
    GUEST_PENDING_DBG_EXCEPTIONS: i64(0x00006822),
    GUEST_SYSENTER_ESP: i64(0x00006824),
    GUEST_SYSENTER_EIP: i64(0x00006826),
    HOST_CR0: i64(0x00006c00),
    HOST_CR3: i64(0x00006c02),
    HOST_CR4: i64(0x00006c04),
    HOST_FS_BASE: i64(0x00006c06),
    HOST_GS_BASE: i64(0x00006c08),
    HOST_TR_BASE: i64(0x00006c0a),
    HOST_GDTR_BASE: i64(0x00006c0c),
    HOST_IDTR_BASE: i64(0x00006c0e),
    HOST_IA32_SYSENTER_ESP: i64(0x00006c10),
    HOST_IA32_SYSENTER_EIP: i64(0x00006c12),
    HOST_RSP: i64(0x00006c14),
    HOST_RIP: i64(0x00006c16),
};
