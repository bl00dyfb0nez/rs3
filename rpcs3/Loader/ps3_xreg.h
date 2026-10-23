#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// xRegistry.sys is the console's registry, /dev_flash2/etc/xRegistry.sys
// (docs/xreg.txt): a 0x40000-byte file in four 0x10000 areas of which the first
// two are used - a key table from 0x10 and a value table from 0x10000.
//
// A key entry is <u16 id, u16 key length, u8 type, key, NUL>; a value entry is
// <u16 flags, u16 key offset (relative to the 0x10 header), u16 id, u16 value
// length, u8 value type, value, NUL>.  Both tables end with the marker
// 0xAABBCCDDEE0000, which also appears where the console erased an entry and
// left it as a break point.  This module reads both tables, writes them back in
// the same shape, and offers the settings as keyed values so a region can be
// changed the way the XMB stores it.
namespace ps3::xreg
{
	using bytes = std::vector<std::uint8_t>;

	inline constexpr std::uint32_t file_size = 0x40000;
	inline constexpr std::uint32_t header_size = 0x10;
	inline constexpr std::uint32_t value_table = 0x10000;
	inline constexpr std::array<std::uint8_t, 7> terminator{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x00};

	enum class type : std::uint8_t
	{
		boolean = 0,
		integer = 1,
		text = 2,
	};

	// A key entry: "0 = unlocked/in use, 1 = locked/inactive, 2 = hidden, 3 =
	// directory".
	struct key
	{
		std::string path;
		std::uint16_t id = 0;
		std::uint8_t state = 0;
	};

	// A value entry, tied to its key by the key's offset in the table.
	struct value
	{
		std::string path;
		std::uint16_t id = 0;
		std::uint16_t flags = 0;
		type kind = type::integer;
		bytes data;   // the raw bytes, excluding the terminator
	};

	struct registry
	{
		std::vector<key> keys;
		std::vector<value> values;

		// The value stored for a key, if the table has one.
		const value* find(std::string_view path) const;

		// Writes a value, adding the key when it is not there yet.  The type is
		// taken from the value: a text is ASCII, an integer is little endian.
		bool set_text(std::string_view path, std::string_view text);
		bool set_integer(std::string_view path, std::uint32_t number);
		bool set_boolean(std::string_view path, bool state);
	};

	// The DVD region the console reports, /setting/parental/dvdRegion: the two
	// letters of the country code as a big-endian number, so "GB" is 0x4742.
	bool set_region(registry& reg, std::string_view letters);

	// The region currently stored, as the two letters, or empty.
	std::string region(const registry& reg);

	bool parse(const bytes& image, registry& out, std::string& error);
	bool write(const registry& reg, bytes& image, std::string& error);
}
