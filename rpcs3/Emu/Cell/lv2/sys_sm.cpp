#include "stdafx.h"
#include "Emu/System.h"
#include "Emu/system_config.h"

#include "Emu/Cell/ErrorCodes.h"
#include "Emu/Cell/PPUThread.h"
#include "Emu/Cell/lv2/sys_process.h"

#include "sys_sm.h"

#include <algorithm>
#include <span>

LOG_CHANNEL(sys_sm);

error_code sys_sm_get_params(vm::ptr<u8> a, vm::ptr<u8> b, vm::ptr<u32> c, vm::ptr<u64> d)
{
	sys_sm.todo("sys_sm_get_params(a=*0x%x, b=*0x%x, c=*0x%x, d=*0x%x)", a, b, c, d);

	if (a) *a = 0; else return CELL_EFAULT;
	if (b) *b = 0; else return CELL_EFAULT;
	if (c) *c = 0x200; else return CELL_EFAULT;
	if (d) *d = 7; else return CELL_EFAULT;

	return CELL_OK;
}

error_code sys_sm_get_ext_event2(vm::ptr<u64> a1, vm::ptr<u64> a2, vm::ptr<u64> a3, u64 a4)
{
	sys_sm.trace("sys_sm_get_ext_event2(a1=*0x%x, a2=*0x%x, a3=*0x%x, a4=*0x%x, a4=0x%xll", a1, a2, a3, a4, a4);

	if (a4 != 0 && a4 != 1)
	{
		return CELL_EINVAL;
	}

	// a1 == 7 - 'console too hot, restart'
	// a2 looks to be used if a1 is either 5 or 3?
	// a3 looks to be ignored in vsh

	if (a1) *a1 = 0; else return CELL_EFAULT;
	if (a2) *a2 = 0; else return CELL_EFAULT;
	if (a3) *a3 = 0; else return CELL_EFAULT;

	// eagain for no event
	return not_an_error(CELL_EAGAIN);
}

error_code sys_sm_shutdown(ppu_thread& ppu, u16 op, vm::ptr<void> param, u64 size)
{
	ppu.state += cpu_flag::wait;

	sys_sm.success("sys_sm_shutdown(op=0x%x, param=*0x%x, size=0x%x)", op, param, size);

	if (!g_ps3_process_info.has_root_perm())
	{
		return CELL_ENOSYS;
	}

	switch (op)
	{
	case 0x100:
	case 0x1100:
	{
		sys_sm.success("Received shutdown request from application");
		_sys_process_exit(ppu, 0, 0, 0);
		break;
	}
	case 0x200:
	case 0x1200:
	{
		sys_sm.success("Received reboot request from application");
		lv2_exitspawn(ppu, Emu.argv, Emu.envp, Emu.data);
		break;
	}
	case 0x8201:
	case 0x8202:
	case 0x8204:
	{
		sys_sm.warning("Unsupported LPAR operation: 0x%x", op);
		return CELL_ENOTSUP;
	}
	default: return CELL_EINVAL;
	}

	return CELL_OK;
}

error_code sys_sm_set_shop_mode(s32 mode)
{
	sys_sm.todo("sys_sm_set_shop_mode(mode=0x%x)", mode);

	return CELL_OK;
}

error_code sys_sm_control_led(u8 led, u8 action)
{
	sys_sm.todo("sys_sm_control_led(led=0x%x, action=0x%x)", led, action);

	return CELL_OK;
}

error_code sys_sm_ring_buzzer(u64 packet, u64 a1, u64 a2)
{
	sys_sm.todo("sys_sm_ring_buzzer(packet=0x%x, a1=0x%x, a2=0x%x)", packet, a1, a2);

	return CELL_OK;
}

namespace
{
	// The console's fan curve, in the shape its SYSCON thermal configuration
	// stores it: a fancon table of duty steps, each with the temperature it
	// rises at, plus a footer that fixes the minimum and maximum duty and the
	// policy.  Step 1 is the speed the fan sits at from cold; every later step
	// adds a notch as the cell temperature climbs.
	//
	// Both the temperature and the fan are simulated: the emulator has no
	// thermal sensors, so it fabricates the reading and runs the selected
	// board's table over it.  The tables are the ones docs/thermal.txt reads
	// out of each board's SYSCON - the firmware's own steps, not the host's
	// hardware.
	struct fan_step
	{
		u8 duty;
		u16 temp_up;    // 0.1 C, as the console's tables store it
	};

	// CECHCxx, COK-002 (CXR713, 14 cm Type_1).
	constexpr fan_step curve_cok_002[] =
	{
		{0x40, 720},    // 25 % at 72 C
		{0x48, 740},    // 28 % at 74 C
		{0x4D, 750},    // 31 % at 75 C
		{0x55, 760},    // 35 % at 76 C, the last step the doc reads out
	};

	// CECH-20xx, DYN-001 (SW2, 10 cm Type_5).
	constexpr fan_step curve_dyn_001[] =
	{
		{0x39, 530},    // 22 % at 53 C
		{0x3B, 540},    // 23 % at 54 C
		{0x3E, 550},    // 24 % at 55 C
		{0x40, 560},    // 25 % at 56 C
		{0x43, 570},    // 26 % at 57 C
		{0x45, 600},    // 27 % at 60 C
		{0x48, 650},    // 28 % at 65 C
		{0x4A, 690},    // 29 % at 69 C
	};

	// CECH-25xx, JTP-001 (SW2, 10 cm Type_5).
	constexpr fan_step curve_jtp_001[] =
	{
		{0x39, 580},    // 22 % at 58 C
		{0x3B, 590},    // 23 % at 59 C
		{0x3E, 600},    // 24 % at 60 C
		{0x40, 620},    // 25 % at 62 C
		{0x43, 630},    // 26 % at 63 C
		{0x45, 640},    // 27 % at 64 C
		{0x48, 650},    // 28 % at 65 C
		{0x4A, 700},    // 29 % at 70 C
		{0x50, 730},    // 31 % at 73 C
	};

	// CECH-25xx, JSD-001 (SW2, 10 cm Type_5).
	constexpr fan_step curve_jsd_001[] =
	{
		{0x39, 590},    // 22 % at 59 C
		{0x3B, 600},    // 23 % at 60 C
		{0x3E, 610},    // 24 % at 61 C
		{0x40, 620},    // 25 % at 62 C
		{0x43, 640},    // 26 % at 64 C
		{0x45, 650},    // 27 % at 65 C
		{0x48, 690},    // 28 % at 69 C
		{0x4A, 700},    // 29 % at 70 C
	};

	// SW3 (CECHL/M/P/Q, VER-001): docs/thermal.txt reads no steps out of these
	// boards, so this is the shape its measured consoles show - around 30 % at
	// 70 C, climbing to half speed before the shutdown temperature.
	constexpr fan_step curve_sw3[] =
	{
		{0x39, 600},    // 22 % at 60 C
		{0x3E, 650},    // 24 % at 65 C
		{0x43, 680},    // 26 % at 68 C
		{0x48, 710},    // 28 % at 71 C
		{0x4A, 730},    // 29 % at 73 C
		{0x50, 750},    // 31 % at 75 C
		{0x60, 780},    // 38 % at 78 C
	};

	// The footer: 0x00 full, 0x01 auto (the curve), 0x02 manual.
	constexpr u8 policy_full = 0x00;
	constexpr u8 policy_auto = 0x01;
	constexpr u8 policy_manual = 0x02;
	constexpr u8 duty_max = 0xFF;

	// Step 1 of every board table in docs/thermal.txt is 0x33 (20 %): the speed
	// the fan sits at from cold up to the first step's temperature.
	constexpr u8 duty_min = 0x33;

	// The fan comes back down a notch only once the console is 2 C below the
	// step it climbed at, so a temperature hovering on a step does not make it
	// hunt.
	constexpr u16 hysteresis = 20;

	atomic_t<u8> s_policy{policy_auto};
	atomic_t<u8> s_manual_duty{0};
	atomic_t<u8> s_last_duty{0};

	// The RSX's share of the heat.  Its die process is what changed across the
	// models (docs/rsxdef.txt): the 90 nm part has an 80 W TDP, and each shrink
	// after it took the heat down.  The offsets are the model's, in 0.1 C.
	u16 rsx_heat()
	{
		const std::string& rsx = g_cfg.sys.rsx_type.get();

		if (rsx.find("90nm") != std::string::npos) return 60;
		if (rsx.find("65nm") != std::string::npos) return 30;
		if (rsx.find("40nm") != std::string::npos) return 10;

		return 0; // 28 nm, D5305
	}

	// The simulated temperature: the emulator has nothing to measure, so this is
	// the model's steady state for what the console is doing - about 72 C while
	// it runs, 60 C once it is idle - plus the heat the chosen RSX adds.  No
	// host sensor is ever read.
	u16 console_temperature()
	{
		const u16 base = Emu.IsRunning() || Emu.IsPaused() ? 720 : 600;
		return base + rsx_heat();
	}

	// The board table the settings pick, by the board name docs/thermal.txt
	// uses.  An unknown name falls back to the SW3 shape.
	std::span<const fan_step> fan_curve()
	{
		const std::string& board = g_cfg.sys.fan_curve.get();

		if (board == "COK-002") return curve_cok_002;
		if (board == "DYN-001") return curve_dyn_001;
		if (board == "JTP-001") return curve_jtp_001;
		if (board == "JSD-001") return curve_jsd_001;

		return curve_sw3;
	}

	// The curve, with each step's hysteresis: the duty rises at temp_up and
	// only falls back once the temperature is 2 C below it.
	u8 duty_for(u16 temperature, u8 previous)
	{
		u8 duty = duty_min;

		for (const fan_step& step : fan_curve())
		{
			const bool rise = temperature >= step.temp_up;
			const bool stay = previous >= step.duty && temperature + hysteresis >= step.temp_up;

			if (rise || stay)
			{
				duty = step.duty;
			}
		}

		return std::clamp<u8>(duty, duty_min, duty_max);
	}
}

error_code sys_sm_set_fan_policy(ppu_thread& ppu, u8 setting, u8 unknown, u8 fan_speed)
{
	sys_sm.trace("sys_sm_set_fan_policy(setting=0x%x, unknown=0x%x, fan_speed=0x%x)", setting, unknown, fan_speed);

	s_policy = setting <= policy_manual ? setting : static_cast<u8>(policy_auto);
	s_manual_duty = fan_speed;

	return CELL_OK;
}

error_code sys_sm_get_fan_policy(ppu_thread& ppu, u8 setting, vm::ptr<u8> unknown, vm::ptr<u8> fan_speed, vm::ptr<u8> temperature)
{
	const u16 temp = console_temperature();
	const u8 policy = s_policy;

	u8 duty = duty_for(temp, s_last_duty);

	if (policy == policy_full)
	{
		duty = duty_max;
	}
	else if (policy == policy_manual)
	{
		duty = std::clamp<u8>(s_manual_duty ? s_manual_duty.load() : duty, duty_min, duty_max);
	}

	s_last_duty = duty;

	if (unknown) *unknown = 0;
	if (fan_speed) *fan_speed = duty;
	if (temperature) *temperature = static_cast<u8>(temp / 10);

	sys_sm.trace("sys_sm_get_fan_policy(setting=0x%x): %u C, duty 0x%x, policy %u", setting, temp / 10, duty, policy);

	return CELL_OK;
}
