#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The PS3 boot chain starts in flash, not in a SELF file:
//
//   metldr (or metldr.2)  ->  lv0ldr (or lv0ldr.2)  ->  lv0  ->  lv1ldr  ->  lv1
//                         ->  lv2ldr  ->  lv2  ->  appldr  ->  vsh
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
//
// Below the loaders the console runs what the CoreOS bank names: lv0, then the
// lv1ldr/lv2ldr/appldr tree - lv1.self, lv2_kernel.self and, out of dev_flash,
// vsh.self.  lv0 is not only its 0x500-byte slot: its SELF declares 0xE7100
// bytes, and the four loaders it encapsulates (lv1ldr, lv2ldr, appldr, isoldr)
// live past the slot, which is why a write that stops at the stub never carries
// them.  A bank whose table no longer names lv1 or lv2, or whose lv0 does not
// reach over its loaders, is one the console stops in: lv0 runs, and there is
// nothing left for lv1ldr or lv2ldr to load, so vsh never starts.  That is what
// a write of the wrong window leaves behind, so the stages are checked in the
// order the console follows them and the first one that cannot run is the one
// the verdict names.
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

	// The CoreOS bank the loaders stand on.  Its header is 0x30 bytes - the bank
	// size at +0x08, version 1 at +0x10, the entry count at +0x14 and the size
	// again at +0x18 - and 0x30-byte entries follow from +0x30: a 0x20-byte
	// name, the file's offset in the bank (big-endian 64-bit) and its size.  A
	// 4301C's ros0 and ros1 both hold 25 entries in this order: default.spp
	// (0xE0200, 0x1388A0 bytes), lv1.self (0x218B00, 0xE7600), lv0 (0x300100,
	// 0x500), lv0.2 (0x300600, 0x183508), lv2_kernel.self (0x483B08, 0x70F94)
	// and eurus_fw.bin, each starting where the one before it ends.  The offsets
	// are inside the bank, not in the flash image.
	struct bank_entry
	{
		std::string name;
		std::uint64_t offset = 0;  // in the bank
		std::uint64_t size = 0;
		bool present = false;      // named by the table with a size to load
		bool erased = false;       // the slot reads as FF

		// The SELF at the slot (0x10 bytes into it) declares the file's own
		// length, which for lv0 is longer than its 0x500-byte table slot: the
		// four loaders it encapsulates live in the bytes past the slot.  0 when
		// the bytes are not in the span being read or are not a SELF.
		std::uint64_t self_size = 0;
	};

	struct bank
	{
		bool found = false;
		std::uint32_t offset = 0;  // where the bank starts in the image
		std::uint64_t size = 0;    // the size its header declares
		std::uint32_t count = 0;
		std::vector<bank_entry> entries;
		std::string error;

		const bank_entry* entry(std::string_view name) const;
	};

	// One link below the loaders, as the console runs it: what it loads, and the
	// loader from the figure that hands it over.
	struct stage
	{
		std::string name;    // "lv0", "lv1", "lv2", and the four lv0 carries
		std::string loader;  // "lv0ldr", "lv1ldr", "lv2ldr", "lv0"
		std::string file;    // "lv0.2", "lv1.self", "lv2_kernel.self"
		std::uint64_t offset = 0;     // absolute in the image
		std::uint64_t size = 0;       // the extent the console loads
		std::uint64_t slot_size = 0;  // what the bank table reserves for it
		bool found = false;
		bool self_readable = false;   // a SELF header was read at the slot
		bool extent_from_self = false; // the extent is the SELF's, past the slot
		std::string error;            // why the console cannot run it

		bool usable() const { return found && error.empty(); }
	};

	struct chain
	{
		geometry flash = geometry::nor;
		container metldr;
		container lv0ldr;
		bool has_loaders = false;  // both containers were found and usable
		bank ros;                  // the CoreOS bank, when the image carries one
		stage lv0;                 // the three links below the loaders, in order
		stage lv1;
		stage lv2;

		// The four loaders lv0 carries inside its own extent - lv1ldr, lv2ldr,
		// appldr and isoldr (docs/ldrs.txt, README "lv0 component bank").  They
		// are not table entries of their own, and the slot table of the
		// decrypted ELF (0x8044138, eight 32-byte slots by id) cannot be read in
		// a sealed image: what carries them is the extent lv0's SELF declares.
		std::vector<stage> encapsulated;
		std::vector<std::string> failures;

		bool bootable() const { return failures.empty(); }
		std::string summary() const;
	};

	inline constexpr std::uint32_t nor_metldr_offset = 0x000840;
	inline constexpr std::uint32_t nor_lv0ldr_offset = 0xFC0000;
	inline constexpr std::uint32_t nor_ros0_offset = 0x0C0000;  // the bank the console boots
	inline constexpr std::uint32_t nor_ros1_offset = 0x7C0000;  // its second copy
	inline constexpr std::uint32_t header_size = 0x40;
	inline constexpr std::uint32_t name_gap = 0x20;      // name sits 0x20 before the header
	inline constexpr std::uint32_t max_blocks = 0x8000;  // a container is at most 512 KiB

	// The container whose header starts at `offset`, or one with `error` set.
	container read_container(std::span<const std::uint8_t> image, std::uint32_t offset);

	// The first container called `name` in the image (name, then a header 0x20
	// later that agrees with itself).  Used for NAND, whose addresses are not
	// fixed, and for NOR images that were carved out of something else.
	container find_container(std::span<const std::uint8_t> image, std::string_view name);

	// The bank whose header is at `offset`, or one with `error` set.  Only the
	// header and the table are read, so a bank cut by the end of a window can
	// still be judged: the entries are checked against the size the bank itself
	// declares.
	bank read_bank(std::span<const std::uint8_t> image, std::uint32_t offset);

	// The first CoreOS bank in the image: ros0 at its documented NOR offset, or -
	// for a NAND dump or a firmware PUP - wherever a valid table sits.  The table
	// is found through the name of a stage rather than by scanning for a header,
	// so a bank in a PUP member is found wherever the member was placed.
	bank find_bank(std::span<const std::uint8_t> image);

	// The whole chain as one verdict: both containers, their pairing, the CoreOS
	// bank's stages and the reasons a console would refuse to boot.
	chain inspect(std::span<const std::uint8_t> image, geometry flash);

	// The same verdict for a file, so a flash dump or a firmware PUP can be
	// checked without loading it whole: the file is scanned in windows large
	// enough to hold a container, and a container crossing a window boundary is
	// still seen because consecutive windows overlap.
	chain inspect_file(const std::string& path, geometry flash);
}
