#include "stdafx.h"
#include "sys_cfw.h"

#include "Emu/Cell/lv1/lv1.h"
#include "Emu/Memory/vm_ptr.h"
#include "util/sysinfo.hpp"

#include <array>
#include <charconv>

LOG_CHANNEL(sys_cfw, "CFW");

namespace
{
	// What stage2 of Cobra 8.5 reports about itself.
	constexpr u8 cobra_version = 0x0F;      // 8.5 in the packed format
	constexpr u16 cobra_version_bcd = 0x0850;

	constexpr u64 opcode_disable_cobra = 0x0000;
	constexpr u64 opcode_enable_cobra = 0x0001;
	constexpr u64 disable_capability = 0x0002;
	constexpr u64 disable_status = 0x0003;
	constexpr u64 disable_ok = 0x5555;

	constexpr u64 opcode_get_version = 0x7000;
	constexpr u64 opcode_get_version2 = 0x7001;
	constexpr u64 opcode_poke_lv2 = 0x7003;
	constexpr u64 opcode_poke8_lv2 = 0x7005;
	constexpr u64 opcode_poke16_lv2 = 0x7007;
	constexpr u64 opcode_poke32_lv2 = 0x7009;

	// Cobra keeps a flag of the same name: 1 while its extended call is off.
	atomic_t<bool> s_cobra_disabled = false;

	// The firmware version as stage2 packs it: 4.93 becomes 0x493.
	u32 firmware_version()
	{
		const std::string installed = utils::get_firmware_version();
		const usz dot = installed.find('.');

		u32 major = 0;
		u32 minor = 0;

		if (dot == umax
			|| std::from_chars(installed.data(), installed.data() + dot, major).ec != std::errc{}
			|| std::from_chars(installed.data() + dot + 1, installed.data() + installed.size(), minor).ec != std::errc{})
		{
			return 0;
		}

		return (major << 8) | minor;
	}

	// A write of 1, 2, 4 or 8 bytes into lv2 memory.
	s32 poke(u64 addr, u64 value, u32 size)
	{
		const u32 address = static_cast<u32>(addr);

		switch (size)
		{
		case 1:
		{
			const u8 data = static_cast<u8>(value);
			return vm::try_access(address, const_cast<u8*>(&data), 1, true) ? CELL_OK : CELL_EINVAL;
		}
		case 2:
		{
			const u16 data = static_cast<u16>(value);
			return vm::try_access(address, const_cast<u16*>(&data), 2, true) ? CELL_OK : CELL_EINVAL;
		}
		case 4:
		{
			const u32 data = static_cast<u32>(value);
			return vm::try_access(address, const_cast<u32*>(&data), 4, true) ? CELL_OK : CELL_EINVAL;
		}
		case 8:
		{
			const u64 data = value;
			return vm::try_access(address, const_cast<u64*>(&data), 8, true) ? CELL_OK : CELL_EINVAL;
		}
		default:
			return CELL_EINVAL;
		}
	}
}

u64 sys_cfw_peek(u64 addr)
{
	const auto [ok, value] = vm::ptr<u64>{vm::cast(addr)}.try_read();

	if (!ok)
	{
		sys_cfw.warning("sys_cfw_peek(0x%x): unreadable address", addr);
		return 0;
	}

	return value;
}

s32 sys_cfw_poke(u64 addr, u64 value)
{
	sys_cfw.trace("sys_cfw_poke(0x%x, 0x%x)", addr, value);
	return poke(addr, value, 8);
}

s64 sys_cfw_syscall8(u64 function, u64 param1, u64 param2, u64 param3, u64 param4, u64 param5, u64 param6, u64 param7)
{
	switch (function)
	{
	case opcode_disable_cobra:
	case opcode_enable_cobra:
	{
		// param1 selects what is asked about: the capability, the status, or
		// the switch itself.
		if (param1 >= disable_capability)
		{
			if (param1 == disable_capability)
			{
				return static_cast<s64>(disable_ok);
			}

			return s_cobra_disabled ? 1 : 0;
		}

		s_cobra_disabled = (function == opcode_disable_cobra && param1 == 1);
		sys_cfw.notice("Cobra %s by the guest", s_cobra_disabled ? "disabled" : "enabled");
		return CELL_OK;
	}
	case opcode_get_version:
	{
		const u32 packed = (cobra_version & 0xFF) | ((firmware_version() & 0xFFFF) << 8) | (1u << 24);

		if (!vm::ptr<u32>{vm::cast(param1)}.try_write(packed))
		{
			return CELL_EINVAL;
		}

		return CELL_OK;
	}
	case opcode_get_version2:
	{
		if (!vm::ptr<u16>{vm::cast(param1)}.try_write(cobra_version_bcd))
		{
			return CELL_EINVAL;
		}

		return CELL_OK;
	}
	case opcode_poke_lv2:
		return poke(param1, param2, 8);
	case opcode_poke8_lv2:
		return poke(param1, param2, 1);
	case opcode_poke16_lv2:
		return poke(param1, param2, 2);
	case opcode_poke32_lv2:
		return poke(param1, param2, 4);
	default:
		break;
	}

	sys_cfw.todo("syscall 8 opcode 0x%x (0x%x, 0x%x, 0x%x)", function, param1, param2, param3);
	return CELL_ENOSYS;
}

s32 sys_cfw_lv1_poke(u64 addr, u64 value)
{
	sys_cfw.trace("sys_cfw_lv1_poke(0x%x, 0x%x)", addr, value);

	// lv1 and lv2 address the same guest memory here, so a hypervisor write is
	// a write like any other; only the log keeps the two callers apart.
	return poke(addr, value, 8);
}

s32 sys_cfw_lv1_call(u64 addr, u64 arg1, u64 arg2)
{
	const lv1::entry* const call = lv1::find(addr);

	if (!call)
	{
		sys_cfw.todo("sys_cfw_lv1_call(0x%x, 0x%x, 0x%x): not an lv1 entry point", addr, arg1, arg2);
		return CELL_ENOSYS;
	}

	sys_cfw.notice("sys_cfw_lv1_call: %s(0x%x, 0x%x)", call->name, arg1, arg2);

	std::array<u64, 8> args{};
	args[0] = arg1;
	args[1] = arg2;

	return static_cast<s32>(lv1::call(addr, args));
}

u64 sys_cfw_lv1_peek(u64 addr)
{
	const auto [ok, value] = vm::ptr<u64>{vm::cast(addr)}.try_read();

	if (!ok)
	{
		sys_cfw.warning("sys_cfw_lv1_peek(0x%x): unreadable address", addr);
		return 0;
	}

	return value;
}

s32 sys_cfw_lv2_func(u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6, u64 arg7, u64 num)
{
	sys_cfw.todo("sys_cfw_lv2_func(0x%x, ...): calling lv2 code by address is not possible here", num);
	return CELL_ENOSYS;
}
