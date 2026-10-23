#include "stdafx.h"
#include "system_config.h"

#include <random>

cfg_root g_cfg{};
cfg_root g_backup_cfg{};

std::string cfg_root::node_sys::get_random_system_name()
{
	std::srand(static_cast<u32>(std::time(nullptr)));
	return "RPCS3-" + std::to_string(100 + std::rand() % 899);
}

u128 cfg_root::node_sys::default_idps()
{
	// The IDPS a retail console is born with, as a value: the bytes are the
	// ones sys_ss hands out when nothing is configured.
	constexpr u8 idps[16] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x89, 0x00, 0x0B, 0x14, 0x00, 0xEF, 0xDD, 0xCA, 0x25, 0x52, 0x66};

	u128 out = 0;

	for (const u8 byte : idps)
	{
		out = (out << 8) | byte;
	}

	return out;
}

u128 cfg_root::node_sys::get_random_psid()
{
	// Generate seed for each 32-bits for maximum entropy using Standard Library
	std::uniform_int_distribution<u32> uniform_dist;
	std::mt19937 prng;

	u128 result{};
	prng.seed(std::random_device()()), result += u128{uniform_dist(prng)} << 0;
	prng.seed(std::random_device()()), result += u128{uniform_dist(prng)} << 32;
	prng.seed(std::random_device()()), result += u128{uniform_dist(prng)} << 64;
	prng.seed(std::random_device()()), result += u128{uniform_dist(prng)} << 96;

	return result;
}
