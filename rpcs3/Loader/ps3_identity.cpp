#include "stdafx.h"

#include "ps3_identity.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>

namespace ps3::identity
{
	namespace
	{
		int hex_value(char c)
		{
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			return -1;
		}
	}

	bool parse_dump(std::string_view text, dump& out)
	{
		std::string digits;
		digits.reserve(32);

		for (const char c : text)
		{
			if (hex_value(c) >= 0)
			{
				digits.push_back(c);
			}
			else if (!std::isspace(static_cast<unsigned char>(c)) && c != ':' && c != '-' && c != '_')
			{
				// A byte outside the hex alphabet: this is not a hex listing.
				return false;
			}

			if (digits.size() > 32)
			{
				return false;
			}
		}

		if (digits.size() != 32)
		{
			return false;
		}

		for (std::size_t i = 0; i < 16; i++)
		{
			out[i] = static_cast<std::uint8_t>((hex_value(digits[i * 2]) << 4) | hex_value(digits[i * 2 + 1]));
		}

		return true;
	}

	bool read_dump(const std::string& path, dump& out)
	{
		std::ifstream file(path, std::ios::binary);

		if (!file)
		{
			return false;
		}

		const std::string data(std::istreambuf_iterator<char>(file), {});

		// The hex form first: a 16-byte dump can never be mistaken for it.
		if (parse_dump(data, out))
		{
			return true;
		}

		if (data.size() < 16)
		{
			return false;
		}

		std::copy_n(reinterpret_cast<const std::uint8_t*>(data.data()), 16, out.begin());
		return true;
	}

	std::string bios_dir()
	{
		// Next to config.yml, which is the config subdirectory, not the data
		// directory the emulator is run from.
		return fs::get_config_dir(true) + "bios/";
	}

	std::string find_in_bios(std::initializer_list<std::string_view> names)
	{
		const std::string dir = bios_dir();

		// The folder is where those dumps go, so it exists even when it is empty.
		fs::create_path(dir);

		for (const std::string_view name : names)
		{
			std::string path = dir + std::string(name);

			if (fs::is_file(path))
			{
				return path;
			}
		}

		return {};
	}

	const char* name(generation value)
	{
		return value == generation::metldr_2 ? "metldr.2" : "metldr";
	}

	std::string chain_name(generation value)
	{
		return value == generation::metldr_2 ? "metldr.2 + lv0ldr.2" : "metldr + lv0ldr";
	}

	generation from_name(std::string_view name)
	{
		return name == "metldr" ? generation::metldr : generation::metldr_2;
	}

	failure_led failure_led_for(generation value)
	{
		// The chain a console boots is what it answers for: CECH-2001A and
		// earlier carry metldr + lv0ldr and flash yellow, the later ones carry
		// metldr.2 + lv0ldr.2 and flash red.
		return value == generation::metldr ? failure_led::yellow : failure_led::red;
	}
}
