#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

// The PS3 Backup And Restore (BAR) container: archive.dat is the index of the
// backup, archive_XX.dat the backed data, archive2.dat the index of the
// copy-protected content and archive2_XX.dat that content.
//
// Every file is
//
//   DAT header (0x40) | encrypted payload | footer (archive.dat only, 0x20)
//
// and the payload starts with an archive header:
//
//   index    archive header + file blocks + EOS + directory blocks + EOS
//   data     archive header + the raw file data, packed in index order
//
// The DAT content is always encrypted: AES-128-CBC with a key, an IV and an
// HMAC key that come from a 64-byte key material block.  That block is what the
// console's VTRM engine answers when handed a zeroed 64-byte buffer carrying
// the key seed at offset zero - an all-zero seed, encrypted with a zeroed IV,
// for a backup sealed to the console's own IDPS (encryption type 0x30), or the
// random seed from the header through the portability path for a backup meant
// to restore on another console (0x40).  Nothing else in the file is keyed.
//
// The data files are one encrypted stream per file, cut at 0x100000 or so by
// the console, so the last block can end on a non-16-byte boundary: that tail
// is not padded.  Instead it is treated as a CFB step - the previous cipher
// block (or the IV, for a payload shorter than one block) is run through AES in
// the encrypt direction and XORed with the remaining bytes.
namespace ps3::bar
{
	using bytes = std::vector<std::uint8_t>;

	inline constexpr std::uint32_t dat_header_size = 0x40;
	inline constexpr std::uint32_t archive_header_size = 0x18;
	inline constexpr std::uint32_t file_block_size = 0x558;   // path 0x520, stats 0x34, flags 4
	inline constexpr std::uint32_t dir_block_size = 0x458;    // path 0x420, stats 0x34, flags 4
	inline constexpr std::uint32_t footer_size = 0x20;
	inline constexpr std::uint32_t path_room = 0x520;
	inline constexpr std::uint32_t dir_path_room = 0x420;

	// The encryption type in the DAT header, and the DAT type: 0x30/0x40 and
	// 0x03/0x05 (0x04 for the registry and database backup utilities).
	struct dat_header
	{
		std::uint32_t encryption = 0x30;  // 0x30 = sealed to the console's IDPS, 0x40 = the seed is portable
		std::uint32_t dat_type = 0x05;
		std::array<std::uint8_t, 0x14> hash{};  // HMAC-SHA1 of the encrypted payload
		std::array<std::uint8_t, 0x14> seed{};  // all zero for 0x30
	};

	struct archive_header
	{
		std::uint64_t id = 0;
		std::uint32_t index = 0;         // 0 for an index file, counting from 0 for the data files
		std::uint8_t archive_type = 0x05; // 0x04 copy-protected content, 0x05 ordinary data
		bool index_file = true;           // the DAT header's file type: 1 for an index, 0 for data
	};

	// A sysFSStat's 0x34 bytes, kept as they were rather than decoded.
	struct stat_block
	{
		std::array<std::uint8_t, 0x34> bytes{};
	};

	struct file_entry
	{
		std::string path;                 // the full absolute path, /dev_hdd0/...
		stat_block stat;
		std::uint32_t flags = 0;          // 0x01 when the file is in /dev_flash2
	};

	struct dir_entry
	{
		std::string path;
		stat_block stat;
		std::uint32_t flags = 0x01;       // 0x03 when the directory is in /dev_flash2
	};

	struct index
	{
		archive_header header;
		std::vector<file_entry> files;
		std::vector<dir_entry> dirs;
		std::uint64_t file_sizes = 0;     // the EOS file block's total
	};

	struct footer
	{
		std::array<std::uint8_t, 0x10> open_psid{};  // the console the backup was made on
		std::uint64_t archive2_sizes = 0;            // what archive2.dat's EOS says
	};

	// What the console's VTRM answers for a seed: the 0x10-byte key, 0x10-byte
	// IV and 0x14-byte HMAC key, taken from the 64 bytes it returns.
	struct key_material
	{
		std::array<std::uint8_t, 0x10> key{};
		std::array<std::uint8_t, 0x10> iv{};
		std::array<std::uint8_t, 0x14> hmac{};
	};

	// The key material for a header.  For 0x30 the console's IDPS is the seed
	// and the engine's type-3 path answers; for 0x40 the header's seed goes
	// through the portability path (type 1).
	bool derive_keys(const dat_header& header, std::span<const std::uint8_t, 16> idps, key_material& out, std::string& error);

	// AES-128-CBC over the payload, with the non-padded tail as a CFB step.  The
	// same call encrypts and decrypts.
	bytes cipher(bytes& payload, const key_material& keys, bool encrypt);

	// The DAT header for these bytes; `hash` is filled by write_index/read_index.
	dat_header make_header(std::uint32_t dat_type, bool portable, const std::array<std::uint8_t, 0x14>& seed);

	// Reads an index file (archive.dat or archive2.dat): the DAT header, the
	// decrypted archive header, both block lists and - for archive.dat - the
	// footer.  The HMAC is checked when `verify` is set.
	bool read_index(std::span<const std::uint8_t> image, std::span<const std::uint8_t, 16> idps, index& out, footer& foot, std::string& error, bool verify = true);

	// Writes one back, DAT header, HMAC and footer included.
	bool write_index(const index& in, const footer& foot, std::span<const std::uint8_t, 16> idps, bytes& out, std::string& error, bool portable = false);

	// A data file: DAT header, archive header, then the payload as it is.
	bool read_data(std::span<const std::uint8_t> image, std::span<const std::uint8_t, 16> idps, bytes& payload, std::string& error);
	bool write_data(const archive_header& header, std::span<const std::uint8_t, 16> idps, const bytes& payload, bool portable, bytes& out, std::string& error);
}
