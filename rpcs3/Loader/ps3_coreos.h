#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

// The console's CoreOS, out of the firmware PUP it was installed from.
//
// A PUP carries CoreOS.PKG (entry 0x200) as an encrypted SELF whose payload is
// a TAR: lv0, lv0.2, lv1.self, lv2_kernel.self, the isolated SPU modules, the
// revoke packages and emer_init.  The console's installer unpacks that TAR into
// a ros bank - the region its flash carries at 0x0C0000 and 0x7C0000 on NOR,
// twice inside the ros region of the NAND/eMMC map.
//
// The bank is what the boot chain stands on: bootldr hands over to lv0, and lv0
// runs lv1ldr -> lv1 and lv2ldr -> lv2 out of it, so a console without a bank
// whose table names those stages has nothing to boot.  RPCS3 keeps the firmware
// as files under dev_flash and never had the bank; this module reads it back
// out of the PUP, so the emulated console can carry the CoreOS it was installed
// with - the bank the boot-chain checks and the flash dump then describe.
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

	// CoreOS.PKG is PUP entry 0x200, and the version the PUP carries is 0x100.
	inline constexpr std::uint64_t pup_coreos_entry = 0x200;
	inline constexpr std::uint64_t pup_version_entry = 0x100;

	// One ros bank, and the shape of its header and table.
	inline constexpr std::uint32_t bank_size = 0x700000;
	inline constexpr std::uint32_t header_size = 0x30;
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
		std::string version;     // the PUP's version.txt, e.g. "4.93"
		std::vector<file> files; // in the bank's order
		bytes bank;              // what ros0 and ros1 hold
		std::string error;       // why it could not be read

		std::string summary() const;
	};

	// CoreOS.PKG from `pup_path`, decrypted and its TAR extracted into
	// `files_dir`, laid out as the bank the console's installer writes.
	image read(const std::string& pup_path, const std::string& files_dir);

	// Writes `img` as `dir/ros0.bin` and `dir/ros1.bin` - the console's two
	// banks, identical as they are on a console.
	bool write(const image& img, const std::string& dir, std::string& error);

	// Reads the bank at `path` back, so a boot or a dump can be judged against
	// what the console actually carries.
	image read_bank(const std::string& path);

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

	// The emulator's copy of the console's CoreOS: `dir` holds ros0.bin,
	// ros1.bin and the TAR's files under `files/`.  `bank` is the file the
	// settings record; empty when the extraction failed.
	struct installed
	{
		bool ok = false;
		std::string bank;
		std::string version;
		std::string summary;
		std::string error;
	};

	installed install(const std::string& pup_path, const std::string& dir);
}
