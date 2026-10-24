#pragma once

#include "Loader/ps3_flash.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The console's CoreOS, out of the flash image the console carries.
//
// The ros bank is the console's, not the firmware's: a ros region at 0x0C0000
// and 0x7C0000 on NOR, twice inside the ros region of the NAND/eMMC map, and
// each bank holds lv0, lv0.2, lv1.self, lv2_kernel.self, the isolated SPU
// modules, the revoke packages and emer_init behind a table that names them.
//
// The firmware PUP cannot supply it.  CoreOS.PKG (entry 0x200) is a SELF whose
// payload is a zlib-compressed PowerPC ELF - the updater's own program, with no
// TAR, no lv0 and no lv1.self anywhere in it - and the console's installer does
// not build a bank out of it; the bank is flashed with the console's own image
// and updated in place by the CoreOS patches of the flash writers.
//
// The bank is what the boot chain stands on: bootldr hands over to lv0, and lv0
// runs lv1ldr -> lv1 and lv2ldr -> lv2 out of it, so a console without a bank
// whose table names those stages has nothing to boot.  RPCS3 keeps the firmware
// as files under dev_flash and never had the bank; this module carves it out of
// the console's flash dump (or reads a bank file), so the emulated console can
// carry the CoreOS its dump carries - the bank the boot-chain checks and the
// generated flash dump then describe.
//
// The layout is the console's own: a 0x30-byte header (the bank size at +0x08,
// version 1 at +0x10, the entry count at +0x14, the size again at +0x18), one
// 0x30-byte record per file from +0x30 (a 0x20-byte name, the offset in the
// bank as a big-endian 64-bit word and its size), then the files in table
// order, each starting where the one before it ends.  lv0 is the whole SELF -
// 0xE7600 bytes on 4.93, of which its header declares 0xE7100 - so the loaders
// it encapsulates travel inside the bank just as they do in a dump.
namespace ps3::coreos
{
	using bytes = std::vector<std::uint8_t>;

	// One ros bank, and the shape of its header and table.
	inline constexpr std::uint32_t bank_size = 0x700000;
	inline constexpr std::uint32_t header_size = 0x20;
	inline constexpr std::uint32_t record_size = 0x30;
	inline constexpr std::uint32_t name_size = 0x20;

	struct file
	{
		std::string name;
		std::uint64_t offset = 0;  // in the bank
		std::uint64_t size = 0;
	};

	struct image
	{
		bool found = false;
		std::string version;     // the bank's sdk_version, e.g. "4.9300"
		std::string source;      // the dump it was carved from
		std::vector<file> files; // in the bank's order
		bytes bank;              // what ros0 and ros1 hold
		std::string error;       // why it could not be read

		std::string summary() const;
	};

	// The ros bank inside a flash image: ros0 at 0x0C0000 on both maps, and the
	// map the chip uses decides how large the image has to be.
	image read_dump(const std::string& dump_path, ps3::flash::chip flash);

	// Writes `img` as `dir/ros0.bin` and `dir/ros1.bin` - the console's two
	// banks, identical as they are on a console.
	bool write(const image& img, const std::string& dir, std::string& error);

	// Reads the bank at `path` back, so a boot or a dump can be judged against
	// what the console actually carries.
	image read_bank(const std::string& path);

	// The other half of the console's pair: ros0 and ros1 are the same bank, the
	// active one and the spare behind it, so the name of one gives the path of
	// the other in the same directory.  Empty when the name is neither.
	std::string spare_path(const std::string& path);

	// The bank dropped in the BIOS folder, for a console whose bank was never
	// chosen in the settings: ros0 unless the spare is asked for, and the other
	// one when only it is there.  Empty when neither is.
	std::string bios_bank(bool spare);

	// What a bank holds, stage by stage: the three the console runs below the
	// loaders, and the reason it would stop when one of them is not there.
	struct verdict
	{
		bool found = false;
		std::uint32_t count = 0;
		bool lv0 = false;
		bool lv1 = false;
		bool lv2 = false;
		std::uint64_t lv0_size = 0;      // the extent its SELF declares
		unsigned loaders = 0;            // lv1ldr, lv2ldr, appldr, isoldr carried by lv0
		std::string sdk_version;         // the bank's sdk_version file
		std::string error;

		// The console starts lv0, then whatever lv0 hands to lv1ldr and
		// lv2ldr: without either of them it stops, and vsh.self never starts.
		bool runs() const { return found && error.empty() && lv0 && lv1 && lv2; }

		std::string summary() const;
	};

	verdict inspect(std::span<const std::uint8_t> bank);
	verdict inspect_file(const std::string& path);

	// One record of the bank, served to the emulator where it sits.
	//
	// The recovery environment is not booted from a copy written next to the
	// bank: lv2 starts emer_init out of the ros area, so the boot is handed the
	// SELF that is inside the bank itself.  Each record is the file behind a
	// 0x10-byte bank prefix, and the SELF that follows it is what the loader
	// gets - read-only, out of the image the console carries, with nothing
	// extracted and no PARAM.SFO invented for it (a system self has none).
	//
	// Returns the path to boot, or an empty string with `error` set.
	inline constexpr char bank_device_path[] = "/vfsv0_virtual_coreos_bank_fs_dev";
	std::string serve(const image& img, std::string_view name, std::string& error);

	// The emulator's copy of the console's CoreOS: `dir` holds ros0.bin and
	// ros1.bin, carved out of the dump.  `bank` is the file the settings
	// record; empty when the dump carried no bank.
	struct installed
	{
		bool ok = false;
		std::string bank;
		std::string version;
		std::string summary;
		std::string error;
	};

	installed install(const std::string& dump_path, const std::string& dir, ps3::flash::chip flash);
}
