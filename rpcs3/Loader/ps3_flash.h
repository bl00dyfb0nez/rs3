#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// The emulated console's NOR flash, as the dump operation answers it.
//
// RPCS3 has no flash chip: what a flasher would read is built from the state
// the console is modeled with - the boot chain it carries, its console id, the
// HDD name it reports, and the CoreOS patch the flash writer (or bgtoolset)
// installed.  The regions and their offsets are the ones in docs/flash.txt and
// FLASH_LAYOUT.md, so the image is read by the same tools as a real dump:
// norunpack walks its table of contents, carves bootldr and trvk_prg0/1 and
// finds CELL_EXTNOR_AREA at 0xF20000.
//
// What the emulator can fill is the plaintext structure: the flash headers, the
// region table, the asecure_loader entry table that names metldr, the SCE
// records of the revoke lists, the hard drive block with its SHA-1, the ros
// bank headers and the bootldr header.  The encrypted bodies (metldr itself,
// lv0ldr, the CoreOS files) are left erased, because the emulator keeps the
// firmware as files and has no ciphertext to copy; the layout says where each
// of them would be.
//
// The boot chain headers are sealed for the modeled console the way the console
// seals its own: the two halves share one 12-byte nonce, and the nonce, key
// field and tag are derived from its console id.  That is a simulation of the
// per-console sealing, not a console's real one - but it is consistent, so
// ps3::boot::inspect() reads the dumped image the way it reads a real dump and
// finds a chain that boots.
namespace ps3::flash
{
	using bytes = std::vector<std::uint8_t>;

	// A superslim stores the boot chain in a 16 MiB NOR chip and everything else
	// - /dev_flash, the VSH - on eMMC, which docs/flash.txt maps exactly like
	// NAND.  The eMMC image is therefore the NAND map: 256 MiB, bootldr at 0,
	// the flash header at 0x40000 and the eFlash area from 0xF00000.
	enum class chip
	{
		nor,   // 16 MiB, the phat and slim models
		emmc,  // 256 MiB, the map NAND and eMMC share
	};

	inline constexpr std::uint32_t image_size = 0x1000000;   // a 16 MiB NOR chip
	inline constexpr std::uint32_t emmc_size = 0x10000000;   // a 256 MiB NAND/eMMC
	inline constexpr std::uint32_t ros_size = 0x700000;     // one CoreOS bank
	inline constexpr std::uint32_t ros0_offset = 0x0C0000;
	inline constexpr std::uint32_t ros1_offset = 0x7C0000;
	inline constexpr std::uint32_t bootldr_offset = 0xFC0000;

	// lv0 and lv0.2 in a ros bank, as the flash writer's window measures them:
	// the shipped writer starts at bank 0x200 and ends on lv0's slot, the 4.93
	// page's fourth step ends 0xE6C00 further on, at lv0's own extent
	// (FLASH_LAYOUT.md).
	inline constexpr std::uint32_t lv0_slot = 0x300600;
	inline constexpr std::uint32_t lv0_extent = 0xE7100;
	inline constexpr std::uint32_t lv0_2_slot = lv0_slot + lv0_extent;
	inline constexpr std::uint32_t lv0_2_size = 0x1834F8;

	struct console
	{
		std::string boot_loader;             // "metldr" or "metldr.2"
		std::array<std::uint8_t, 16> idps{}; // sealed-for id of the modeled console
		std::string hdd_model;
		std::string hdd_serial;
		chip flash = chip::nor;              // NOR, or the eMMC/NAND map of a superslim
		bool dex = false;                    // a debug console (DEX), whose dev_flash is not sealed
		std::string coreos_image;            // the bank extracted from the installed firmware, empty when none
		std::string coreos_patch;            // path of the installed CoreOS image, empty when none
		std::uint32_t coreos_patch_span = 0; // bytes written into the bank
	};

	struct region
	{
		std::string name;
		std::uint32_t offset;
		std::uint32_t size;
		bool modeled;   // the emulator filled it, rather than reserving it
	};

	// Every region the image carries, in offset order.
	std::vector<region> layout(chip flash = chip::nor);

	// The image a flasher would read from this console.
	bytes build(const console& c);

	// Writes the image, and reports why it could not.
	bool write_file(const std::string& path, const bytes& image, std::string& error);

	// What the image holds, region by region, for the log and the dialog.
	std::string summary(const console& c);

	// The size of the image a console's flash answers with.
	std::uint32_t image_size_of(chip flash);

	// The flash writer and bgtoolset install a flat copy of a ros bank: the
	// window starts at bank 0x200 on NOR and ends on lv0's slot.  The 4.93 page
	// writes further, to the end of lv0's extent, which is why its fourth step
	// is the one that carries the encapsulated loaders.
	enum class writer_mode
	{
		stock,     // as shipped through 4.91
		span_493,  // the 4.93 page's fourth step
	};

	struct writer_plan
	{
		writer_mode mode = writer_mode::stock;
		std::uint32_t start = 0;   // bank offset the window starts at
		std::uint32_t bytes = 0;   // bytes the window writes
		bool refused = false;
		std::string reason;        // why the tool refuses this console
		std::vector<std::string> notes;
	};

	// The window the tool would write, and the gates it applies first: the
	// shipped writer reads the console's minimum firmware version and refuses
	// anything above 3.56 (a Metldr.2 console carries 3.60 or higher, so it
	// fails there), and both it and bgtoolset refuse a console already running
	// patched CoreOS.
	writer_plan plan_writer(const console& c, writer_mode mode);

	// Checks a patch image against the plan: the tool's own image carries a
	// 0x20-byte header that is not written, so the file has to be at least the
	// window plus that header.
	bool check_patch(const std::string& path, const writer_plan& plan, std::string& error);

	// Copies the window of the patch image into ros0 of `image`.  The bytes
	// outside the window - lv0's file record and everything after it - are left
	// as they were, which is what makes the stock and 4.93 spans comparable.
	bool apply_patch(bytes& image, const std::string& path, const writer_plan& plan, std::string& error);
}
