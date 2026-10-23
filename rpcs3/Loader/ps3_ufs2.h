#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// A PS3 HDD, as a device outside the console sees it.
//
// The drive the console formats is not a plain disk: every sector is sealed by
// the ATA layer with keys the console derives from its EID root key (ERK), and
// the plaintext inside is a big-endian UFS2 filesystem with each 16-bit word
// byte-swapped on the wire.  That is why a drive read out of one console cannot
// be read out of another, and why a tool that wants to build or read one needs
// the ERK the console read out of its own EID - the 0x30 bytes that
// `eid0dec`/`ps3toolset` dump, of which 0x20 key the derivation and 0x10 are
// the IV.
//
//   ERK (0x30)  ->  data key / tweak key (0x20 each)      kgen.c
//               ->  sector 0 disklabel                     ps3.h
//               ->  UFS2 at the gameOS partition           fs.h / dinode.h
//
// Two sealing layers exist, and the model decides which one a drive uses:
//
//   phat (NAND, and the NOR models up to CECH-20xx)  AES-128-CBC-192 per
//       sector with a zero IV behind the first sector, data key truncated to
//       192 bits;
//   slim and later                                   AES-128-XTS per sector,
//       tweaked with the sector number, data key and tweak key.
//
// This module reads a sealed image, lists and extracts what the UFS2 volume
// holds, and can *create* one: a disklabel naming the gameOS partition followed
// by an empty UFS2 filesystem.  The formatter is meant for a device that is not
// the console's own - a spare drive, or an image - and it writes only what it
// creates; the console's own formatter is still what produces a drive a system
// will boot from, because the rest of the volume (dev_flash2, dev_flash3,
// dev_hdd1 and the files the system installs) is the system's to lay out.
//
// A whole disk can also be named as the device (\\.\PhysicalDriveN on Windows,
// /dev/sdX on Linux, /dev/diskN on macOS), which needs administrator rights and
// destroys what was on it; an image file needs neither.
namespace ps3::ufs2
{
	using bytes = std::vector<std::uint8_t>;

	inline constexpr std::uint32_t sector_size = 0x200;
	inline constexpr std::uint64_t ufs2_superblock = 0x10000;   // SBLOCK_UFS2
	inline constexpr std::uint32_t ufs2_magic = 0x19540119;     // FS_UFS2_MAGIC
	inline constexpr std::uint64_t magic1 = 0x0FACE0FFull;
	inline constexpr std::uint64_t magic2 = 0xDEADFACEull;
	inline constexpr std::uint32_t root_inode = 2;              // ROOTINO

	// The smallest drive the console will take.  A PS3 refuses anything under
	// 20 GB when it formats a replacement, and an image smaller than that is not
	// a drive it would accept, so the formatter refuses it too - the check is
	// here, not in the dialog, so every caller gets it.
	inline constexpr std::uint64_t minimum_gigabytes = 20;
	inline constexpr std::uint64_t minimum_sectors = (minimum_gigabytes << 30) / sector_size;

	// The EID root key: 0x20 bytes of key followed by the 0x10-byte IV.  A dump
	// is either the 0x30 bytes themselves or the same as 96 hex characters.
	struct erk
	{
		std::array<std::uint8_t, 0x30> value{};

		bool empty() const;
	};

	bool parse_erk(std::string_view text, erk& out);
	bool read_erk(const std::string& path, erk& out);

	// What the console derives from the ERK, and what the ATA layer is keyed
	// with: AES-256-CBC over the console's seed tablets with the ERK's own IV
	// (kgen.c, generate_ata_keys).
	struct keys
	{
		std::array<std::uint8_t, 0x20> data{};
		std::array<std::uint8_t, 0x20> tweak{};
	};

	keys derive(const erk& key);

	enum class layer
	{
		phat,   // AES-192-CBC, the NAND and early NOR models
		slim,   // AES-128-XTS, CECH-20xx and later
	};

	// A disklabel partition, as the console writes it.
	struct partition
	{
		std::uint64_t start = 0;   // sector
		std::uint64_t size = 0;    // sectors
	};

	struct disklabel
	{
		std::array<partition, 8> partitions{};

		bool valid() const;
	};

	// What materialising an image wrote.
	struct materialise_result
	{
		std::uint64_t files = 0;
		std::uint64_t directories = 0;
		std::uint64_t bytes = 0;
	};

	// One file or directory entry of a directory listing.
	struct entry
	{
		std::string name;
		std::uint32_t inode = 0;
		std::uint8_t type = 0;
	};

	// The UFS2 geometry this module writes and understands.
	struct geometry
	{
		std::uint32_t block_size = 0x4000;
		std::uint32_t frag_size = 0x800;
		std::uint32_t frags_per_block = 8;
		std::uint32_t inodes_per_group = 4096;
		std::uint32_t frags_per_group = 0x2000;   // 16 MiB per cylinder group
		std::uint32_t inode_size = 0x100;
	};

	struct format_request
	{
		std::uint64_t sectors = 0;          // size of the image being formatted
		layer seal = layer::slim;
		geometry fs{};
		std::uint64_t partition_start = 0x800;   // sector the gameOS volume starts at

		// Only for tests and for reading back what has already been written:
		// the dialog never sets it, so a user cannot format under the floor.
		bool allow_undersized = false;
	};

	struct format_result
	{
		std::uint64_t sectors = 0;
		std::uint64_t partition_start = 0;
		std::uint64_t partition_size = 0;
		std::uint32_t cylinder_groups = 0;
		std::uint64_t inodes = 0;
	};

	// A PS3 disk image or device, opened through the ATA layer.
	class volume
	{
	public:
		volume() = default;
		~volume();
		volume(const volume&) = delete;
		volume& operator=(const volume&) = delete;

		// Opens an existing image and reports why it is not a PS3 drive.  The
		// label is read through the layer the caller names; a console that
		// wrote it with the other one produces a label that does not validate.
		// `sectors` is the size of a device, whose length cannot be measured
		// the way a file's can; leave it zero for an image.
		bool open(const std::string& path, const erk& key, layer seal, std::string& error, bool writable = false, std::uint64_t sectors = 0);

		bool is_open() const { return m_fd >= 0; }
		const disklabel& label() const { return m_label; }
		const geometry& fs_geometry() const { return m_fs; }

		// The sectors a partition holds, decrypted.
		bool read_sectors(std::uint64_t sector, std::uint32_t count, std::uint8_t* out, std::string& error);
		bool write_sectors(std::uint64_t sector, std::uint32_t count, const std::uint8_t* in, std::string& error);

		// The gameOS partition, and the filesystem inside it.
		bool read_superblock(std::string& error);
		bool list(std::string_view path, std::vector<entry>& out, std::string& error);
		bool read_file(std::string_view path, bytes& out, std::string& error);

		// Writes the tree the image holds under `root`, directory by directory
		// and file by file, so a console's filesystem can be given to the
		// emulator as its dev_hdd0 before it boots.
		bool materialise(const std::string& root, materialise_result& result, std::string& error);

		// Builds a fresh label and an empty UFS2 filesystem on a device of the
		// requested size.  Everything outside what it writes is left as it was.
		bool format(const format_request& request, format_result& result, std::string& error);

	private:
		friend bool format_file(const std::string& path, const erk& key, layer seal, const format_request& request, format_result& result, std::string& error);
		friend bool format_device(const std::string& path, const erk& key, layer seal, const format_request& request, format_result& result, std::string& error);

		bool open_file(const std::string& path, bool writable, std::string& error, std::uint64_t sectors = 0);

		bool read_partition_sectors(const partition& part, std::uint64_t sector, std::uint32_t count, std::uint8_t* out, std::string& error);
		bool write_partition_sectors(const partition& part, std::uint64_t sector, std::uint32_t count, const std::uint8_t* in, std::string& error);

		bool read_inode(std::uint32_t inode, std::array<std::uint8_t, 0x100>& out, std::string& error);
		bool read_dir(std::uint32_t inode, std::vector<entry>& out, std::string& error);
		bool lookup(std::string_view path, std::uint32_t& inode, std::string& error);
		bool is_directory(std::uint32_t inode);
		bool read_blocks(const std::array<std::uint8_t, 0x100>& inode, std::uint64_t offset, std::uint64_t size, std::uint8_t* out, std::string& error);

		int m_fd = -1;
		bool m_device = false;   // a raw device: its length is fixed and there is no tail to pad
		std::uint64_t m_sectors = 0;
		layer m_seal = layer::slim;
		keys m_keys{};
		disklabel m_label{};
		geometry m_fs{};
		std::uint32_t m_inopb = 0;
		std::uint32_t m_fpg = 0;
		std::uint32_t m_ipg = 0;
		std::uint64_t m_sblkno = 0;
		std::uint64_t m_cblkno = 0;
		std::uint64_t m_iblkno = 0;
		std::uint64_t m_dblkno = 0;
		std::uint32_t m_ncg = 0;
		partition m_gameos{};
	};

	// Creates or truncates `path`, writes a label and an empty UFS2 gameOS
	// volume on it, and leaves the file closed.  The image is raw sectors; see
	// ps3_qcow2.h for the container the virtual machines use.
	bool format_file(const std::string& path, const erk& key, layer seal, const format_request& request, format_result& result, std::string& error);

	// The same layout, written into a device that is already there - an image
	// file opened writable, or \\.\PhysicalDriveN.  Nothing is created and no
	// length is changed: the device's own capacity is passed in as
	// `request.sectors`, and the write is bounded by it.  Opening a raw device
	// needs administrator rights; the console's own drive is still the one
	// thing this must not be pointed at.
	bool format_device(const std::string& path, const erk& key, layer seal, const format_request& request, format_result& result, std::string& error);

	// A disk attached to this machine, as the settings page lists it.
	struct device_info
	{
		std::string path;          // \\.\PhysicalDriveN
		std::uint64_t bytes = 0;
	};

	// Only the disks Windows reports, so the dialog can name them rather than
	// have the user type one in.
	std::vector<device_info> devices();

	// The capacity of a device or an image, in sectors.  Zero if it cannot be
	// asked, which is what keeps a format from being aimed at a path it does
	// not know the length of.
	std::uint64_t device_sectors(const std::string& path);

	// The "is this a drive this console wrote" answer, for the log and the
	// dialog: which layer opened it and what the partition table names.
	std::string describe(const volume& disk);
}
