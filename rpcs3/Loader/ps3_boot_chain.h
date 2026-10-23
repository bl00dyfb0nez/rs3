#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The PS3 boot chain starts in flash, not in a SELF file:
//
//   metldr (or metldr.2)  ->  lv0ldr (or lv0ldr.2)  ->  lv0  ->  lv1ldr  ->  lv2
//
// metldr authenticates lv0ldr, and lv0ldr authenticates lv0.  Both are loader
// containers rather than SELF files: a 0x40-byte header followed by the body.
// The header carries the block count twice, a 12-byte counter, a 12-byte
// per-console nonce, a 16-byte key field and a 16-byte tag; the body is
// AES-128-CTR over that counter and the tag is a CBC-MAC.  Because the MAC
// travels with the body, an image sealed for the same console (same counter,
// nonce and key field) is written in place as it is, in 0x2000-byte NOR blocks,
// without any key - the same thing the console's own flash updater does with a
// signed update.
//
// Where they live:
//   NOR   16 MiB, 512-byte sectors: metldr(.2) at 0x000840 (its name at
//         0x000820, so one 0x200-byte sector read covers name and header),
//         lv0ldr(.2) at 0xFC0000.
//   NAND  256 MiB: the same containers, at addresses this module does not
//         assume - they are found by their names and a header that agrees with
//         itself, which is what a dump of either kind can be checked against.
//
// A console with metldr.2 has the 3.60+ boot chain and pairs with lv0ldr.2;
// metldr pairs with lv0ldr.  The pairing is checked against the containers
// themselves: both halves of one chain carry the same 12-byte per-console
// nonce at 0x14, because they were sealed for the same console in the same
// update, while the counters at 0x04 differ per container.  A chain pieced
// together from two dumps - metldr with lv0ldr.2 or the other way round -
// therefore disagrees on the nonce even when both labels are erased or made to
// agree, and the console answers with the three beeps and the flashing light.
namespace ps3::boot
{
	enum class geometry
	{
		nor,
		nand,
		// Something that is not a flash image but may still carry loaders, such
		// as a firmware PUP.  The containers are found by name and only a chain
		// that is actually present is judged.
		payload,
	};

	struct container
	{
		bool found = false;
		std::string name;          // "metldr", "metldr.2", "lv0ldr", "lv0ldr.2"
		std::uint32_t offset = 0;  // flash offset of the 0x40 header
		std::uint32_t blocks = 0;        // encrypted blocks, the word at 0x00
		std::uint32_t total_blocks = 0;  // total blocks, the word at 0x10
		std::uint32_t length = 0;        // 0x40 + total_blocks * 16
		std::string counter;       // 12 bytes, hex
		std::string nonce;         // 12 bytes, hex
		std::string key;           // 16 bytes, hex
		std::string tag;           // 16 bytes, hex
		bool erased = false;       // header reads as FF, the slot is blank
		std::string error;         // why it cannot be used, empty when it can

		bool usable() const { return found && error.empty() && !erased; }
		bool is_360() const { return name == "metldr.2" || name == "lv0ldr.2"; }
	};

	struct chain
	{
		geometry flash = geometry::nor;
		container metldr;
		container lv0ldr;
		bool has_loaders = false;  // both containers were found and usable
		std::vector<std::string> failures;

		bool bootable() const { return failures.empty(); }
		std::string summary() const;
	};

	inline constexpr std::uint32_t nor_metldr_offset = 0x000840;
	inline constexpr std::uint32_t nor_lv0ldr_offset = 0xFC0000;
	inline constexpr std::uint32_t header_size = 0x40;
	inline constexpr std::uint32_t name_gap = 0x20;      // name sits 0x20 before the header
	inline constexpr std::uint32_t max_blocks = 0x8000;  // a container is at most 512 KiB

	// The container whose header starts at `offset`, or one with `error` set.
	container read_container(std::span<const std::uint8_t> image, std::uint32_t offset);

	// The first container called `name` in the image (name, then a header 0x20
	// later that agrees with itself).  Used for NAND, whose addresses are not
	// fixed, and for NOR images that were carved out of something else.
	container find_container(std::span<const std::uint8_t> image, std::string_view name);

	// The whole chain as one verdict: both containers, their pairing and the
	// reasons a console would refuse to boot.
	chain inspect(std::span<const std::uint8_t> image, geometry flash);

	// The same verdict for a file, so a flash dump or a firmware PUP can be
	// checked without loading it whole: the file is scanned in windows large
	// enough to hold a container, and a container crossing a window boundary is
	// still seen because consecutive windows overlap.
	chain inspect_file(const std::string& path, geometry flash);
}
