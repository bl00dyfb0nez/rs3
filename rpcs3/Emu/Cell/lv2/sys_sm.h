#pragma once

#include "Emu/Memory/vm_ptr.h"
#include "Emu/Cell/ErrorCodes.h"

// SysCalls

error_code sys_sm_get_ext_event2(vm::ptr<u64> a1, vm::ptr<u64> a2, vm::ptr<u64> a3, u64 a4);
error_code sys_sm_shutdown(ppu_thread& ppu, u16 op, vm::ptr<void> param, u64 size);
error_code sys_sm_get_params(vm::ptr<u8> a, vm::ptr<u8> b, vm::ptr<u32> c, vm::ptr<u64> d);
error_code sys_sm_set_shop_mode(s32 mode);
error_code sys_sm_control_led(u8 led, u8 action);

// The thermal configuration the console keeps in its SYSCON: a fan curve of
// duty steps with a rising and a falling threshold per step, and the policy
// that decides between the curve, full speed and a pinned duty (docs/fsm.txt
// and the thermal config format).
error_code sys_sm_set_fan_policy(ppu_thread& ppu, u8 setting, u8 unknown, u8 fan_speed);
error_code sys_sm_get_fan_policy(ppu_thread& ppu, u8 setting, vm::ptr<u8> unknown, vm::ptr<u8> fan_speed, vm::ptr<u8> temperature);
error_code sys_sm_ring_buzzer(u64 packet, u64 a1, u64 a2);
constexpr auto sys_sm_ring_buzzer2 = sys_sm_ring_buzzer;
