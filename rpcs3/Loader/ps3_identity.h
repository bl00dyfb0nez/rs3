#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

// The console's identity, as the emulator presents it.
//
// IDPS is the console's own 16-byte id and PSID the 16-byte PSN id that travels
// with it.  A real console reads both out of flash; a dump of either is those 16
// bytes, written either raw or as 32 hex characters with any separators a
// dumping tool puts between them.
//
// The loader generation is the other half: a console boots metldr + lv0ldr
// (pre-3.60) or metldr.2 + lv0ldr.2 (3.60 and later), and a chain that mixes
// them does not boot at all.  The emulator has no flash to read, so the pair is
// chosen, not discovered - and the two pairs are what ps3_boot_chain.h reads
// out of a dump.
namespace ps3::identity
{
	using dump = std::array<std::uint8_t, 16>;

	enum class generation
	{
		metldr,
		metldr_2,
	};

	// The power LED a console shows when it refuses a boot chain: three beeps
	// and a flashing light.  The early phat models flash yellow - the YLOD -
	// and the later ones flash red, which is what replaced the yellow there.
	enum class failure_led
	{
		red,
		yellow,
	};

	// The 32 hex characters of a dump, whatever separators surround them.
	bool parse_dump(std::string_view text, dump& out);

	// A file holding one: 16 raw bytes, or the same as hex text.
	bool read_dump(const std::string& path, dump& out);

	const char* name(generation value);

	// "metldr + lv0ldr" or "metldr.2 + lv0ldr.2".
	std::string chain_name(generation value);

	// The generation a configured name asks for; metldr_2 for anything that is
	// not recognisably the older pair.
	generation from_name(std::string_view name);

	// CECH-2001A and earlier - the metldr + lv0ldr generation - flash yellow,
	// the YLOD; the later consoles, which are also the default, flash red, the
	// light that replaced the yellow there (docs/sysconerr.txt, 1200 and 2024).
	failure_led failure_led_for(generation value);
}
