#pragma once

#include "util/types.hpp"
#include "Emu/Cell/ErrorCodes.h"

// The custom firmware syscalls.
//
// A retail lv2 leaves syscalls 6-11 and 15 unused, and RPCS3 used to answer
// them with ENOSYS.  Cobra (and the CFWs built on it) put its own calls there,
// and tools such as multiMAN and PS3MAPI are written against them:
//
//   6   peek  - read eight bytes of lv2 memory
//   7   poke  - write eight bytes of lv2 memory
//   8   the extended call, an opcode in r3 and arguments in r4-r10
//   9   lv1 poke
//   10  lv1 call
//   11  lv1 peek
//   15  call an lv2 function by address
//
// RPCS3 has no lv1.self to execute, but the hypervisor's entry points are known
// (Emu/Cell/lv1), so calls 9-11 work against the guest memory and the entries
// in that table; an address outside it answers ENOSYS.  Calling lv2 code by
// address is still not possible, and 15 says so.
u64 sys_cfw_peek(u64 addr);
s32 sys_cfw_poke(u64 addr, u64 value);
s64 sys_cfw_syscall8(u64 function, u64 param1, u64 param2, u64 param3, u64 param4, u64 param5, u64 param6, u64 param7);
s32 sys_cfw_lv1_poke(u64 addr, u64 value);
s32 sys_cfw_lv1_call(u64 addr, u64 arg1, u64 arg2);
u64 sys_cfw_lv1_peek(u64 addr);
s32 sys_cfw_lv2_func(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6, u64 arg7, u64 num);
