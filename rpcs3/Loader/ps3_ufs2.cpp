#include "stdafx.h"

#include "ps3_ufs2.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>

// The I/O is the CRT's low-level layer rather than stdio: a 20 GB image is
// past the 2 GB an fseek offset can hold, and a raw device only takes whole
// sectors at sector boundaries, which is what one write hands it.  Windows and
// MinGW give the 64-bit-offset calls the leading underscore, POSIX does not.
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#define UFS_OPEN(p, flags) _open(p, flags, _S_IREAD | _S_IWRITE)
#define UFS_CLOSE _close
#define UFS_SEEK _lseeki64
#define UFS_READ _read
#define UFS_WRITE _write
#define UFS_COMMIT _commit
#define UFS_O_BINARY _O_BINARY
#define UFS_O_RDONLY _O_RDONLY
#define UFS_O_RDWR _O_RDWR
#define UFS_O_CREAT _O_CREAT
#define UFS_O_TRUNC _O_TRUNC
#else
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/fs.h>
#endif

#ifdef __APPLE__
#include <sys/disk.h>
#endif

#define UFS_OPEN(p, flags) ::open(p, flags, 0600)
#define UFS_CLOSE ::close

// lseek, not lseek64: off_t is 64 bits wide on every target this builds for
// (64-bit glibc, macOS, the BSDs), and lseek64 does not exist outside the
// Linux C library - FreeBSD declares only lseek.
#define UFS_SEEK ::lseek
#define UFS_READ ::read
#define UFS_WRITE ::write
#define UFS_COMMIT ::fsync
#define UFS_O_BINARY 0
#define UFS_O_RDONLY O_RDONLY
#define UFS_O_RDWR O_RDWR
#define UFS_O_CREAT O_CREAT
#define UFS_O_TRUNC O_TRUNC
#endif
#include <cstring>
#include <fstream>
#include <filesystem>
#include <iterator>
#include <ctime>
#include <string>

#include "Crypto/aes.h"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#endif

namespace ps3::ufs2
{
	namespace
	{
#ifdef _WIN32
		// Windows refuses writes to the boot sector of a disk whose volume is
		// still mounted, so the volumes on the device are locked and dismounted
		// first.  The drive letter is not needed by anything here, only the
		// handle that keeps the lock alive.
		class volume_locks
		{
		public:
			~volume_locks()
			{
				for (HANDLE handle : handles)
				{
					CloseHandle(handle);
				}
			}

			void lock_disk(unsigned disk)
			{
				char name[] = "\\\\.\\A:";

				for (char letter = 'A'; letter <= 'Z'; letter++)
				{
					name[4] = letter;
					HANDLE handle = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

					if (handle == INVALID_HANDLE_VALUE)
					{
						continue;
					}

					VOLUME_DISK_EXTENTS extents{};
					DWORD returned = 0;
					const bool ours = DeviceIoControl(handle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, &extents, sizeof(extents), &returned, nullptr) &&
						extents.NumberOfDiskExtents > 0 && extents.Extents[0].DiskNumber == disk;

					if (ours && DeviceIoControl(handle, FSCTL_LOCK_VOLUME, nullptr, 0, nullptr, 0, &returned, nullptr))
					{
						DeviceIoControl(handle, FSCTL_DISMOUNT_VOLUME, nullptr, 0, nullptr, 0, &returned, nullptr);
						handles.push_back(handle);
						continue;
					}

					CloseHandle(handle);
				}
			}

		private:
			std::vector<HANDLE> handles;
		};

		// "\\.\PhysicalDrive3" -> 3, and anything else -> -1.
		int physical_disk_number(const std::string& path)
		{
			const std::size_t at = path.find("PhysicalDrive");

			if (at == std::string::npos)
			{
				return -1;
			}

			return std::atoi(path.c_str() + at + 13);
		}
#endif
		// The seed tablets the keys are derived from (kgen.c).  They are not
		// secrets - the ERK is - and they are what makes the derivation the
		// console's rather than anyone's.
		constexpr std::array<std::uint8_t, 0x20> seed_data{
			0xD9, 0x2D, 0x65, 0xDB, 0x05, 0x7D, 0x49, 0xE1, 0xA6, 0x6F, 0x22, 0x74, 0xB8, 0xBA, 0xC5, 0x08,
			0x83, 0x84, 0x4E, 0xD7, 0x56, 0xCA, 0x79, 0x51, 0x63, 0x62, 0xEA, 0x8A, 0xDA, 0xC6, 0x03, 0x26};

		constexpr std::array<std::uint8_t, 0x20> seed_tweak{
			0xC3, 0xB3, 0xB5, 0xAA, 0xCC, 0x74, 0xCD, 0x6A, 0x48, 0xEF, 0xAB, 0xF4, 0x4D, 0xCD, 0xF1, 0x6E,
			0x37, 0x9F, 0x55, 0xF5, 0x77, 0x7D, 0x09, 0xFB, 0xEE, 0xDE, 0x07, 0x05, 0x8E, 0x94, 0xBE, 0x08};

		// An arcade unit's ERK is the seeded one and uses its own tablets; the
		// derivation is the same, only the seeds differ.
		constexpr std::array<std::uint8_t, 0x20> arc_erk{
			0x35, 0x9F, 0x59, 0xBB, 0x8C, 0x25, 0x6B, 0x91, 0x09, 0x3A, 0x92, 0x00, 0x72, 0x03, 0xAB, 0xB3,
			0x3B, 0xAD, 0xF5, 0xAC, 0x09, 0xA0, 0xDC, 0x00, 0x58, 0x59, 0xD6, 0xF1, 0x59, 0xC4, 0xF5, 0x4F};

		constexpr std::array<std::uint8_t, 0x10> arc_iv{
			0x92, 0x92, 0x14, 0xD8, 0xFC, 0xCB, 0x4C, 0xE7, 0x09, 0x9A, 0xCE, 0xBD, 0xFC, 0x66, 0x12, 0xB9};

		constexpr std::array<std::uint8_t, 0x20> arc_seed_data{
			0xDA, 0x73, 0xED, 0x90, 0x20, 0x91, 0x8F, 0x4C, 0x0A, 0x70, 0x3D, 0xCC, 0xF8, 0x90, 0x61, 0x7B,
			0xFF, 0xD2, 0x5E, 0x33, 0x40, 0x00, 0x91, 0x09, 0x58, 0x3C, 0x64, 0x3D, 0xF4, 0xA2, 0x13, 0x24};

		constexpr std::array<std::uint8_t, 0x20> arc_seed_tweak{
			0xDA, 0x73, 0xED, 0x90, 0x20, 0x91, 0x8F, 0x4C, 0x0A, 0x70, 0x3D, 0xCC, 0xF8, 0x90, 0x61, 0x7B,
			0xFF, 0xD2, 0x5E, 0x33, 0x40, 0x00, 0x91, 0x09, 0x58, 0x3C, 0x64, 0x3D, 0xF4, 0xA2, 0x13, 0x24};

		constexpr std::uint32_t superblock_area = 0x2000;   // fs_sbsize
		constexpr std::uint32_t cylinder_group_area = 0x800; // fs_cgsize
		constexpr std::uint32_t inode_used_map = 0x100;      // cg_iusedoff
		constexpr std::uint32_t free_map_after = 0x100;      // relative to iusedoff

		int hex_value(char c)
		{
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			return -1;
		}

		std::uint16_t be16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }
		std::uint32_t be32(const std::uint8_t* p) { return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) | p[3]; }
		std::uint64_t be64(const std::uint8_t* p) { return (std::uint64_t(be32(p)) << 32) | be32(p + 4); }

		void put_be16(std::uint8_t* p, std::uint16_t v) { p[0] = std::uint8_t(v >> 8); p[1] = std::uint8_t(v); }
		void put_be32(std::uint8_t* p, std::uint32_t v) { p[0] = std::uint8_t(v >> 24); p[1] = std::uint8_t(v >> 16); p[2] = std::uint8_t(v >> 8); p[3] = std::uint8_t(v); }
		void put_be64(std::uint8_t* p, std::uint64_t v) { put_be32(p, std::uint32_t(v >> 32)); put_be32(p + 4, std::uint32_t(v)); }

		// Every sector on the wire has each 16-bit word byte-swapped, in front
		// of the ATA layer rather than behind it (device.c, _es16_buffer).
		void swap_words(std::uint8_t* p, std::size_t size)
		{
			for (std::size_t i = 0; i + 1 < size; i += 2)
			{
				std::swap(p[i], p[i + 1]);
			}
		}

		void xts_multiply(std::uint8_t* tweak)
		{
			std::uint8_t carry = 0;

			for (std::size_t i = 0; i < 16; i++)
			{
				const std::uint8_t next = std::uint8_t(tweak[i] >> 7);
				tweak[i] = std::uint8_t((tweak[i] << 1) | carry);
				carry = next;
			}

			if (carry)
			{
				tweak[0] ^= 0x87;
			}
		}

		// One sector through one layer.  `seal` encrypts, `unseal` decrypts.
		void aes_cbc192(bool encrypt, const keys& k, std::uint8_t* sector)
		{
			aes_context ctx{};
			std::uint8_t iv[16]{};

			if (encrypt) aes_setkey_enc(&ctx, k.data.data(), 192);
			else aes_setkey_dec(&ctx, k.data.data(), 192);

			aes_crypt_cbc(&ctx, encrypt ? AES_ENCRYPT : AES_DECRYPT, sector_size, iv, sector, sector);
		}

		void aes_xts128(bool encrypt, const keys& k, std::uint64_t number, std::uint8_t* sector)
		{
			aes_context data{};
			aes_context tweak{};
			std::uint8_t tweak_block[16]{};

			// XTS needs the data key scheduled for the direction in use: the
			// AES context is a key schedule, not a pair of operations.
			if (encrypt) aes_setkey_enc(&data, k.data.data(), 128);
			else aes_setkey_dec(&data, k.data.data(), 128);

			aes_setkey_enc(&tweak, k.tweak.data(), 128);

			// The tweak is the sector number in the first 16 bytes, encrypted.
			// The console orders it little-endian (aes_xts_crypt in the tool
			// takes the raw sector index).
			std::uint64_t value = number;

			for (std::size_t i = 0; i < 8; i++)
			{
				tweak_block[i] = std::uint8_t(value);
				value >>= 8;
			}

			aes_crypt_ecb(&tweak, AES_ENCRYPT, tweak_block, tweak_block);

			for (std::size_t block = 0; block < sector_size; block += 16)
			{
				std::uint8_t buf[16];

				for (std::size_t i = 0; i < 16; i++)
				{
					buf[i] = sector[block + i] ^ tweak_block[i];
				}

				aes_crypt_ecb(&data, encrypt ? AES_ENCRYPT : AES_DECRYPT, buf, buf);

				for (std::size_t i = 0; i < 16; i++)
				{
					sector[block + i] = buf[i] ^ tweak_block[i];
				}

				xts_multiply(tweak_block);
			}
		}

		void seal_sector(layer seal, const keys& k, std::uint64_t number, bool encrypt, std::uint8_t* sector)
		{
			if (seal == layer::slim)
			{
				aes_xts128(encrypt, k, number, sector);
			}
			else
			{
				aes_cbc192(encrypt, k, sector);
			}
		}

		constexpr std::uint32_t disklabel_size = 0x600;
		constexpr std::uint32_t partition_offset = 0x30;
		constexpr std::uint32_t partition_size = 0x90;

		disklabel parse_label(const std::uint8_t* raw)
		{
			disklabel out;

			if (be64(raw + 0x10) != magic1 || be64(raw + 0x18) != magic2)
			{
				return out;
			}

			for (std::size_t i = 0; i < 8; i++)
			{
				const std::uint8_t* p = raw + partition_offset + i * partition_size;
				out.partitions[i].start = be64(p);
				out.partitions[i].size = be64(p + 8);
			}

			return out;
		}

		bytes build_label(const std::array<partition, 8>& parts)
		{
			bytes out(disklabel_size, 0);

			put_be64(out.data() + 0x10, magic1);
			put_be64(out.data() + 0x18, magic2);

			for (std::size_t i = 0; i < 8; i++)
			{
				put_be64(out.data() + partition_offset + i * partition_size, parts[i].start);
				put_be64(out.data() + partition_offset + i * partition_size + 8, parts[i].size);
			}

			return out;
		}

		// A directory entry: <u32 ino, u16 reclen, u8 type, u8 namlen, name, NUL>.
		std::uint16_t entry_size(std::size_t name_length)
		{
			const std::size_t raw = 8 + name_length + 1;
			return static_cast<std::uint16_t>((raw + 3) & ~std::size_t(3));
		}

		bytes root_directory()
		{
			bytes out(0x200, 0);
			std::uint8_t* p = out.data();

			const auto write = [&p](std::uint32_t ino, std::uint16_t reclen, std::uint8_t type, const char* name)
			{
				const std::size_t length = std::strlen(name);
				put_be32(p, ino);
				put_be16(p + 4, reclen);
				p[6] = type;
				p[7] = static_cast<std::uint8_t>(length);
				std::memcpy(p + 8, name, length);
				p += reclen;
			};

			write(root_inode, entry_size(1), 4, ".");
			write(root_inode, entry_size(2), 4, "..");

			// The rest of the DIRBLKSIZ block is one free entry.
			put_be32(p, 0);
			put_be16(p + 4, static_cast<std::uint16_t>(0x200 - (entry_size(1) + entry_size(2))));
			return out;
		}

		void build_root_inode(std::uint8_t* inode, std::uint64_t data_frag, std::uint32_t frag_size, std::time_t now)
		{
			constexpr std::uint16_t mode = 0040755;   // IFDIR | 0755
			put_be16(inode + 0x00, mode);
			put_be16(inode + 0x02, 2);                // nlink: . and ..
			put_be32(inode + 0x04, 0);                // uid
			put_be32(inode + 0x08, 0);                // gid
			put_be32(inode + 0x0C, frag_size);        // di_blksize
			put_be64(inode + 0x10, 0x200);            // di_size
			put_be64(inode + 0x18, 1);                // di_blocks, in 512-byte units
			put_be64(inode + 0x20, now);
			put_be64(inode + 0x28, now);
			put_be64(inode + 0x30, now);
			put_be64(inode + 0x38, now);
			put_be64(inode + 0x70, data_frag);        // di_db[0] at 0x70
		}

		std::uint32_t block_count(std::uint64_t size, std::uint32_t block)
		{
			return static_cast<std::uint32_t>((size + block - 1) / block);
		}
	}

	bool erk::empty() const
	{
		return std::all_of(value.begin(), value.end(), [](std::uint8_t b) { return b == 0; });
	}

	bool parse_erk(std::string_view text, erk& out)
	{
		std::string digits;

		for (const char c : text)
		{
			if (hex_value(c) >= 0)
			{
				digits.push_back(c);
			}
			else if (!std::isspace(static_cast<unsigned char>(c)) && c != ':' && c != '-' && c != '_')
			{
				return false;
			}
		}

		if (digits.size() != 0x30 * 2)
		{
			return false;
		}

		for (std::size_t i = 0; i < 0x30; i++)
		{
			out.value[i] = static_cast<std::uint8_t>((hex_value(digits[i * 2]) << 4) | hex_value(digits[i * 2 + 1]));
		}

		return true;
	}

	bool read_erk(const std::string& path, erk& out)
	{
		std::ifstream file(path, std::ios::binary);

		if (!file)
		{
			return false;
		}

		const std::string data{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};

		if (parse_erk(data, out))
		{
			return true;
		}

		if (data.size() < 0x30)
		{
			return false;
		}

		std::memcpy(out.value.data(), data.data(), 0x30);
		return true;
	}

	keys derive(const erk& key)
	{
		keys out;
		aes_context ctx{};
		std::uint8_t iv[16];

		const bool arcade = std::equal(arc_erk.begin(), arc_erk.end(), key.value.begin());
		const auto& data_seed = arcade ? arc_seed_data : seed_data;
		const auto& tweak_seed = arcade ? arc_seed_tweak : seed_tweak;
		const std::uint8_t* data_key = arcade ? arc_erk.data() : key.value.data();
		const std::uint8_t* data_iv = arcade ? arc_iv.data() : key.value.data() + 0x20;
		const std::uint8_t* tweak_key = key.value.data();
		const std::uint8_t* tweak_iv = key.value.data() + 0x20;

		std::memcpy(iv, data_iv, 16);
		aes_setkey_enc(&ctx, data_key, 256);
		aes_crypt_cbc(&ctx, AES_ENCRYPT, 0x20, iv, data_seed.data(), out.data.data());

		aes_context ctx2{};
		std::memcpy(iv, tweak_iv, 16);
		aes_setkey_enc(&ctx2, tweak_key, 256);
		aes_crypt_cbc(&ctx2, AES_ENCRYPT, 0x20, iv, tweak_seed.data(), out.tweak.data());

		return out;
	}

	bool disklabel::valid() const
	{
		return partitions[0].size != 0 && partitions[0].start != 0;
	}

	volume::~volume()
	{
		if (m_fd >= 0)
		{
			UFS_CLOSE(m_fd);
		}
	}

	// The I/O is the CRT's low-level layer rather than stdio: a 20 GB image is
	// past the 2 GB an fseek offset can hold, and a raw device only takes whole
	// sectors at sector boundaries, which is what _write hands it.
	bool volume::open_file(const std::string& path, bool writable, std::string& error, std::uint64_t sectors)
	{
		m_fd = UFS_OPEN(path.c_str(), (writable ? UFS_O_RDWR : UFS_O_RDONLY) | UFS_O_BINARY);

		if (m_fd < 0)
		{
			error = "the image could not be opened: " + path;
			return false;
		}

		// A device reports no length to ftell, so its capacity is given.
		if (sectors)
		{
			m_sectors = sectors;
			return true;
		}

		const long long size = UFS_SEEK(m_fd, 0, SEEK_END);

		if (size <= 0)
		{
			error = "the image is empty";
			return false;
		}

		m_sectors = static_cast<std::uint64_t>(size) / sector_size;
		return true;
	}

	bool volume::read_sectors(std::uint64_t sector, std::uint32_t count, std::uint8_t* out, std::string& error)
	{
		if (m_fd < 0)
		{
			error = "no image is open";
			return false;
		}

		if (sector + count > m_sectors)
		{
			error = "the read runs past the end of the image";
			return false;
		}

		if (UFS_SEEK(m_fd, static_cast<long long>(sector * sector_size), SEEK_SET) < 0 ||
			UFS_READ(m_fd, out, static_cast<unsigned int>(std::size_t(count) * sector_size)) != static_cast<int>(std::size_t(count) * sector_size))
		{
			error = "the image could not be read";
			return false;
		}

		for (std::uint32_t i = 0; i < count; i++)
		{
			std::uint8_t* p = out + i * sector_size;
			swap_words(p, sector_size);
			seal_sector(m_seal, m_keys, sector + i, false, p);
		}

		return true;
	}

	bool volume::write_sectors(std::uint64_t sector, std::uint32_t count, const std::uint8_t* in, std::string& error)
	{
		if (m_fd < 0)
		{
			error = "no image is open";
			return false;
		}

		if (sector + count > m_sectors)
		{
			error = "the write runs past the end of the image";
			return false;
		}

		bytes buffer(in, in + std::size_t(count) * sector_size);

		for (std::uint32_t i = 0; i < count; i++)
		{
			std::uint8_t* p = buffer.data() + i * sector_size;
			seal_sector(m_seal, m_keys, sector + i, true, p);
			swap_words(p, sector_size);
		}

		const std::size_t length = std::size_t(count) * sector_size;

		if (UFS_SEEK(m_fd, static_cast<long long>(sector * sector_size), SEEK_SET) < 0 ||
			UFS_WRITE(m_fd, buffer.data(), static_cast<unsigned int>(length)) != static_cast<int>(length))
		{
			error = "the image could not be written";
			return false;
		}

		UFS_COMMIT(m_fd);
		return true;
	}

	bool volume::open(const std::string& path, const erk& key, layer seal, std::string& error, bool writable, std::uint64_t sectors)
	{
		m_keys = derive(key);
		m_seal = seal;

		if (!open_file(path, writable, error, sectors))
		{
			return false;
		}

		std::uint8_t raw[disklabel_size]{};

		if (!read_sectors(0, disklabel_size / sector_size, raw, error))
		{
			return false;
		}

		m_label = parse_label(raw);

		if (!m_label.valid())
		{
			char seen[64];
			std::snprintf(seen, sizeof(seen), "%016llx %016llx",
				static_cast<unsigned long long>(be64(raw + 0x10)), static_cast<unsigned long long>(be64(raw + 0x18)));

			error = std::string("the disklabel does not validate (read ") + seen +
				"): this is not a PS3 image, or the ERK is not the console's";
			return false;
		}

		m_gameos = m_label.partitions[0];

		if (!read_superblock(error))
		{
			return false;
		}

		return true;
	}

	bool volume::read_partition_sectors(const partition& part, std::uint64_t sector, std::uint32_t count, std::uint8_t* out, std::string& error)
	{
		if (sector + count > part.size)
		{
			error = "the read runs past the end of the partition";
			return false;
		}

		return read_sectors(part.start + sector, count, out, error);
	}

	bool volume::write_partition_sectors(const partition& part, std::uint64_t sector, std::uint32_t count, const std::uint8_t* in, std::string& error)
	{
		if (sector + count > part.size)
		{
			error = "the write runs past the end of the partition";
			return false;
		}

		return write_sectors(part.start + sector, count, in, error);
	}

	bool volume::read_superblock(std::string& error)
	{
		std::uint8_t raw[superblock_area]{};

		if (!read_partition_sectors(m_gameos, ufs2_superblock / sector_size, superblock_area / sector_size, raw, error))
		{
			return false;
		}

		if (be32(raw + 0x55C) != ufs2_magic)
		{
			error = "the gameOS partition does not hold a UFS2 filesystem";
			return false;
		}

		m_fs.block_size = be32(raw + 0x030);
		m_fs.frag_size = be32(raw + 0x034);
		m_fs.frags_per_block = be32(raw + 0x038);
		m_fs.inodes_per_group = be32(raw + 0x0B8);
		m_fs.frags_per_group = be32(raw + 0x0BC);
		m_fs.inode_size = 0x100;

		m_sblkno = be32(raw + 0x008);
		m_cblkno = be32(raw + 0x00C);
		m_iblkno = be32(raw + 0x010);
		m_dblkno = be32(raw + 0x014);
		m_ncg = be32(raw + 0x02C);
		m_inopb = be32(raw + 0x078);
		m_ipg = m_fs.inodes_per_group;
		m_fpg = m_fs.frags_per_group;

		if (!m_fs.block_size || !m_fs.frag_size || !m_inopb || !m_ipg || !m_fpg)
		{
			error = "the superblock has no usable geometry";
			return false;
		}

		return true;
	}

	bool volume::read_inode(std::uint32_t inode, std::array<std::uint8_t, 0x100>& out, std::string& error)
	{
		if (!m_ipg || inode >= m_ipg * (m_ncg > 1 ? m_ncg : 1))
		{
			error = "the inode number is out of range";
			return false;
		}

		const std::uint64_t group = inode / m_ipg;
		const std::uint64_t index = inode % m_ipg;
		const std::uint64_t frag = std::uint64_t(m_fpg) * group + m_iblkno;
		const std::uint64_t byte = frag * m_fs.frag_size + index * m_fs.inode_size;
		const std::uint64_t sector = byte / sector_size;
		const std::uint64_t inside = byte % sector_size;

		// The inode is 0x100 bytes and a sector is 0x200, but it need not start
		// at 0 or 0x100, so two sectors are read and the inode copied from where
		// it actually is.  One sector with a copy from `inside` reads past the
		// end of the buffer whenever the inode straddles a boundary.
		std::uint8_t sectors[sector_size * 2]{};

		if (!read_partition_sectors(m_gameos, sector, 2, sectors, error))
		{
			return false;
		}

		std::memcpy(out.data(), sectors + inside, m_fs.inode_size);
		return true;
	}

	bool volume::read_blocks(const std::array<std::uint8_t, 0x100>& inode, std::uint64_t offset, std::uint64_t size, std::uint8_t* out, std::string& error)
	{
		const std::uint32_t block = m_fs.block_size;
		const std::uint32_t per_block = block / 8;
		std::uint64_t done = 0;

		while (done < size)
		{
			const std::uint64_t logical = (offset + done) / block;
			std::uint64_t frag = 0;

			if (logical < 12)
			{
				frag = be64(inode.data() + 0x70 + logical * 8);
			}
			else
			{
				const std::uint64_t indirect = be64(inode.data() + 0xB0);   // di_ib[0]

				if (!indirect)
				{
					error = "the file is sparse past its direct blocks";
					return false;
				}

				const std::uint32_t index = static_cast<std::uint32_t>(logical - 12);

				if (index >= per_block)
				{
					error = "the file needs double-indirect blocks, which this reader does not follow";
					return false;
				}

				bytes table(block);

				if (!read_partition_sectors(m_gameos, indirect * m_fs.frag_size / sector_size, block / sector_size, table.data(), error))
				{
					return false;
				}

				frag = be64(table.data() + index * 8);
			}

			const std::uint64_t in_block = (offset + done) % block;
			const std::uint64_t take = std::min<std::uint64_t>(size - done, block - in_block);

			if (!frag)
			{
				std::memset(out + done, 0, take);
			}
			else if (!read_partition_sectors(m_gameos, (frag * m_fs.frag_size + in_block) / sector_size,
				static_cast<std::uint32_t>((take + (in_block % sector_size) + sector_size - 1) / sector_size), out + done, error))
			{
				return false;
			}

			done += take;
		}

		return true;
	}

	bool volume::read_dir(std::uint32_t inode, std::vector<entry>& out, std::string& error)
	{
		out.clear();

		std::array<std::uint8_t, 0x100> node{};

		if (!read_inode(inode, node, error))
		{
			return false;
		}

		const std::uint64_t size = be64(node.data() + 0x10);

		if (!size)
		{
			return true;
		}

		// A directory that claims to be bigger than a dirent block of this size
		// is not one this walk can read; refusing beats allocating what it asks.
		if (size > 0x10000000)
		{
			error = "the directory claims an implausible size";
			return false;
		}

		bytes data(static_cast<std::size_t>(size));

		if (!read_blocks(node, 0, size, data.data(), error))
		{
			return false;
		}

		for (std::size_t at = 0; at + 8 <= data.size();)
		{
			const std::uint32_t ino = be32(data.data() + at);
			const std::uint16_t reclen = be16(data.data() + at + 4);
			const std::uint8_t namlen = data[at + 7];

			if (!reclen || at + reclen > data.size())
			{
				break;
			}

			if (ino && at + 8 + namlen <= data.size())
			{
				entry e;
				e.inode = ino;
				e.type = data[at + 6];
				e.name.assign(reinterpret_cast<const char*>(data.data() + at + 8), namlen);
				out.push_back(std::move(e));
			}

			at += reclen;
		}

		return true;
	}

	bool volume::lookup(std::string_view path, std::uint32_t& out, std::string& error)
	{
		out = root_inode;

		std::string tail(path);

		while (!tail.empty() && tail.front() == '/')
		{
			tail.erase(tail.begin());
		}

		std::size_t start = 0;

		while (start < tail.size())
		{
			const std::size_t end = tail.find('/', start);
			const std::string name = tail.substr(start, end == std::string::npos ? std::string::npos : end - start);

			std::vector<entry> children;

			if (!read_dir(out, children, error))
			{
				return false;
			}

			bool found = false;

			for (const entry& e : children)
			{
				if (e.name == name)
				{
					out = e.inode;
					found = true;
					break;
				}
			}

			if (!found)
			{
				error = "there is no " + std::string(path);
				return false;
			}

			if (end == std::string::npos)
			{
				break;
			}

			start = end + 1;
		}

		return true;
	}

	bool volume::list(std::string_view path, std::vector<entry>& out, std::string& error)
	{
		std::uint32_t inode = root_inode;

		if (!lookup(path, inode, error))
		{
			return false;
		}

		return read_dir(inode, out, error);
	}

	bool volume::read_file(std::string_view path, bytes& out, std::string& error)
	{
		out.clear();

		std::uint32_t inode = root_inode;

		if (!lookup(path, inode, error))
		{
			return false;
		}

		std::array<std::uint8_t, 0x100> node{};

		if (!read_inode(inode, node, error))
		{
			return false;
		}

		const std::uint64_t size = be64(node.data() + 0x10);

		if (size > 0x40000000ull)
		{
			error = "the file claims an implausible size";
			return false;
		}

		out.resize(static_cast<std::size_t>(size));

		if (size && !read_blocks(node, 0, size, out.data(), error))
		{
			return false;
		}

		return true;
	}

	bool volume::materialise(const std::string& root, materialise_result& result, std::string& error)
	{
		result = {};

		if (root.empty())
		{
			error = "no directory to materialise into";
			return false;
		}

		std::error_code ec;
		std::filesystem::create_directories(root, ec);

		if (ec)
		{
			error = "the directory could not be created: " + ec.message();
			return false;
		}

		// Depth-first, the way the console's tree is laid out: a directory is
		// read, each name is written where it belongs, and a subdirectory is
		// walked the same way.  Sixteen levels is deeper than anything the
		// console keeps and stops a corrupted tree from recursing forever.
		struct walk
		{
			volume& disk;
			materialise_result& result;
			std::string& error;

			bool run(std::uint32_t inode, const std::string& path, int depth)
			{
				if (depth > 16)
				{
					error = "the tree is deeper than 16 levels at " + path;
					return false;
				}

				std::vector<entry> children;

				if (!disk.read_dir(inode, children, error))
				{
					return false;
				}

				for (const entry& child : children)
				{
					if (child.name == "." || child.name == "..")
					{
						continue;
					}

					const std::string here = path + "/" + child.name;
					std::error_code entry_ec;

					if (child.type == 4 || (child.type == 0 && disk.is_directory(child.inode)))
					{
						std::filesystem::create_directories(here, entry_ec);
						result.directories++;

						if (entry_ec)
						{
							error = "the directory " + here + " could not be created: " + entry_ec.message();
							return false;
						}

						if (!run(child.inode, here, depth + 1))
						{
							return false;
						}

						continue;
					}

					bytes data;

					if (!disk.read_file(here, data, error))
						{
							return false;
						}

					std::ofstream file(std::filesystem::path(here), std::ios::binary);

					if (!file)
						{
							error = "the file " + here + " could not be written";
							return false;
						}

					if (!data.empty())
						{
							file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
						}

					result.files++;
					result.bytes += data.size();
				}

				return true;
			}
		};

		walk w{*this, result, error};
		return w.run(root_inode, root, 0);
	}

	bool volume::is_directory(std::uint32_t inode)
	{
		std::array<std::uint8_t, 0x100> node{};
		std::string ignored;

		if (!read_inode(inode, node, ignored))
		{
			return false;
		}

		return (be16(node.data()) & 0170000) == 0040000;
	}

	std::string describe(const volume& disk)
	{
		const disklabel& label = disk.label();
		std::string text = "gameOS partition at sector " + std::to_string(label.partitions[0].start) +
			", " + std::to_string(label.partitions[0].size) + " sectors\n";

		std::uint32_t used = 0;

		for (const partition& part : label.partitions)
		{
			if (part.size)
			{
				used++;
			}
		}

		text += std::to_string(used) + " partition(s) in the label\n";
		text += "UFS2 block " + std::to_string(disk.fs_geometry().block_size) +
			", fragment " + std::to_string(disk.fs_geometry().frag_size) + "\n";
		return text;
	}

	bool volume::format(const format_request& request, format_result& result, std::string& error)
	{
		if (m_fd < 0)
		{
			error = "no image is open";
			return false;
		}

		const geometry& fs = request.fs;
		const std::uint64_t sectors = request.sectors ? request.sectors : m_sectors;
		const std::uint64_t start = request.partition_start;

		if (!fs.block_size || !fs.frag_size || fs.frags_per_block != fs.block_size / fs.frag_size)
		{
			error = "the requested geometry is inconsistent";
			return false;
		}

		if (!request.allow_undersized && sectors < minimum_sectors)
		{
			error = "the image is smaller than the " + std::to_string(minimum_gigabytes) +
				" GB a PS3 accepts (" + std::to_string(sectors * sector_size / (1024 * 1024)) + " MiB)";
			return false;
		}

		if (start + 2 > sectors)
		{
			error = "the image is too small for a partition";
			return false;
		}

		const partition part{start, sectors - start};
		const std::uint64_t frags = part.size * sector_size / fs.frag_size;
		const std::uint32_t ncg = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, (frags + fs.frags_per_group - 1) / fs.frags_per_group));
		const std::uint64_t inode_frags = std::uint64_t(fs.inodes_per_group) * fs.inode_size / fs.frag_size;

		const std::uint64_t sblkno = ufs2_superblock / fs.frag_size;
		const std::uint64_t cblkno = 1;
		const std::uint64_t iblkno = 2;
		const std::uint64_t dblkno = iblkno + inode_frags;
		const std::uint64_t superblock_frags = superblock_area / fs.frag_size;
		const std::uint64_t csaddr = sblkno + superblock_frags;
		const std::uint64_t cs_frags = std::max<std::uint64_t>(1, (ncg * 12 + fs.frag_size - 1) / fs.frag_size);

		if (dblkno + 1 + cs_frags >= fs.frags_per_group)
		{
			error = "the geometry does not fit one cylinder group";
			return false;
		}

		m_label = disklabel{};
		m_label.partitions[0] = part;
		m_gameos = part;
		m_fs = fs;
		m_ipg = fs.inodes_per_group;
		m_fpg = fs.frags_per_group;
		m_ncg = ncg;
		m_sblkno = sblkno;
		m_cblkno = cblkno;
		m_iblkno = iblkno;
		m_dblkno = dblkno;
		m_inopb = fs.block_size / fs.inode_size;

		const std::time_t now = std::time(nullptr);

		// The label first, so a reader that stops after it still sees a drive.
		{
			const bytes label = build_label(m_label.partitions);
			std::uint8_t raw[disklabel_size]{};
			std::memcpy(raw, label.data(), label.size());

			if (!write_sectors(0, disklabel_size / sector_size, raw, error))
			{
				return false;
			}
		}

		// The superblock.
		{
			std::array<std::uint8_t, superblock_area> sb{};
			std::uint8_t* p = sb.data();

			put_be32(p + 0x008, static_cast<std::uint32_t>(sblkno));
			put_be32(p + 0x00C, static_cast<std::uint32_t>(cblkno));
			put_be32(p + 0x010, static_cast<std::uint32_t>(iblkno));
			put_be32(p + 0x014, static_cast<std::uint32_t>(dblkno));
			put_be32(p + 0x020, static_cast<std::uint32_t>(now));
			put_be32(p + 0x024, static_cast<std::uint32_t>(std::min<std::uint64_t>(frags, 0xFFFFFFF0)));
			put_be32(p + 0x028, static_cast<std::uint32_t>(frags));
			put_be32(p + 0x02C, ncg);
			put_be32(p + 0x030, fs.block_size);
			put_be32(p + 0x034, fs.frag_size);
			put_be32(p + 0x038, fs.frags_per_block);
			put_be32(p + 0x03C, 8);                                    // minfree
			put_be32(p + 0x048, ~(fs.block_size - 1));                 // bmask
			put_be32(p + 0x04C, ~(fs.frag_size - 1));                  // fmask
			put_be32(p + 0x050, 14);                                   // bshift, 16 KiB
			put_be32(p + 0x054, 11);                                   // fshift, 2 KiB
			put_be32(p + 0x058, fs.frags_per_block);                   // maxcontig
			put_be32(p + 0x05C, fs.frags_per_group / 4);               // maxbpg
			put_be32(p + 0x060, 3);                                    // fragshift
			put_be32(p + 0x064, 2);                                    // fsbtodb, 2048 / 512
			put_be32(p + 0x068, superblock_area);                      // sbsize
			put_be32(p + 0x074, fs.block_size / 8);                    // nindir
			put_be32(p + 0x078, m_inopb);
			put_be32(p + 0x07C, fs.frag_size / sector_size);           // old_nspf
			put_be32(p + 0x090, 0x1234);                               // id
			put_be32(p + 0x094, 0x5678);
			put_be32(p + 0x098, static_cast<std::uint32_t>(csaddr));   // old_csaddr
			put_be32(p + 0x09C, static_cast<std::uint32_t>(cs_frags * fs.frag_size));
			put_be32(p + 0x0A0, cylinder_group_area);                  // cgsize
			put_be32(p + 0x0B8, fs.inodes_per_group);
			put_be32(p + 0x0BC, fs.frags_per_group);
			p[0x0D1] = 1;                                              // clean
			put_be32(p + 0x35C, fs.block_size);                        // maxbsize
			put_be64(p + 0x3E8, ufs2_superblock);                      // sblockloc
			put_be64(p + 0x430, now);
			put_be64(p + 0x438, frags);                                // size
			put_be64(p + 0x440, frags - dblkno);                       // dsize
			put_be64(p + 0x448, csaddr);
			put_be32(p + 0x4AC, 0x4000);                               // avgfilesize
			put_be32(p + 0x4B0, 16);                                   // avgfpdir
			put_be32(p + 0x4B4, cylinder_group_area);                  // save_cgsize
			put_be32(p + 0x524, 0);                                    // contigsumsize
			put_be32(p + 0x528, 0x78);                                 // maxsymlinklen
			put_be32(p + 0x52C, 2);                                    // FS_44INODEFMT
			put_be64(p + 0x530, std::uint64_t(12 + m_inopb) * fs.block_size); // maxfilesize
			put_be64(p + 0x538, ~std::uint64_t(fs.block_size - 1));    // qbmask
			put_be64(p + 0x540, ~std::uint64_t(fs.frag_size - 1));     // qfmask
			put_be32(p + 0x548, 0);                                    // state
			put_be32(p + 0x55C, ufs2_magic);

			if (!write_partition_sectors(m_gameos, ufs2_superblock / sector_size, superblock_area / sector_size, sb.data(), error))
			{
				return false;
			}
		}

		// One cylinder group per group, each with its header, inode area, root
		// inode and one frag of root directory.
		{
			std::array<std::uint8_t, cylinder_group_area> cg{};

			for (std::uint32_t group = 0; group < ncg; group++)
			{
				const std::uint64_t base = std::uint64_t(fs.frags_per_group) * group;

				std::fill(cg.begin(), cg.end(), 0);

				put_be32(cg.data() + 0x004, 0x090255);                            // CG_MAGIC
				put_be32(cg.data() + 0x008, static_cast<std::uint32_t>(now));
				put_be32(cg.data() + 0x00C, group);                               // cg_cgx
				put_be32(cg.data() + 0x014, static_cast<std::uint32_t>(fs.frags_per_group));
				put_be32(cg.data() + 0x058, inode_used_map);                      // iusedoff
				put_be32(cg.data() + 0x05C, inode_used_map + free_map_after);      // freeoff
				put_be32(cg.data() + 0x060, 0);                                   // nextfreeoff
				put_be32(cg.data() + 0x068, 0);                                   // clusterblks
				put_be32(cg.data() + 0x06C, fs.inodes_per_group);                 // niblk
				put_be32(cg.data() + 0x070, fs.inodes_per_group);                 // initediblk
				put_be64(cg.data() + 0x088, now);                                 // cg_time

				std::uint8_t* used = cg.data() + inode_used_map;
				std::uint8_t* free_map = cg.data() + inode_used_map + free_map_after;

				used[0] = 0xE0;   // inodes 0, 1 and 2: reserved, reserved, root

				const auto mark = [&free_map](std::uint64_t frag)
				{
					free_map[frag / 8] |= std::uint8_t(1u << (frag % 8));
				};

				for (std::uint64_t frag = 0; frag < dblkno; frag++)
				{
					mark(frag);
				}

				if (group == 0)
				{
					for (std::uint64_t frag = sblkno; frag < sblkno + superblock_frags; frag++)
					{
						mark(frag);
					}

					for (std::uint64_t frag = csaddr; frag < csaddr + cs_frags; frag++)
					{
						mark(frag);
					}

					mark(dblkno);   // the root directory's fragment
				}

				put_be32(cg.data() + 0x060, inode_used_map + free_map_after + (fs.frags_per_group + 7) / 8);

				const std::uint64_t cg_byte = (base + cblkno) * fs.frag_size;

				if (!write_partition_sectors(m_gameos, cg_byte / sector_size, cylinder_group_area / sector_size, cg.data(), error))
				{
					return false;
				}

				// The inode area is written zeroed apart from group 0's root.
				std::array<std::uint8_t, 0x200> empty_inodes{};

				if (!write_partition_sectors(m_gameos, (base + iblkno) * fs.frag_size / sector_size,
					static_cast<std::uint32_t>(std::min<std::uint64_t>(inode_frags * fs.frag_size, 0x200) / sector_size), empty_inodes.data(), error))
				{
					return false;
				}
			}

			// An inode lives at its number times the inode size inside the
			// inode area, so inode 2 is 0x200 past its start, not at it.
			const std::uint64_t inode_byte = iblkno * fs.frag_size + std::uint64_t(root_inode) * m_fs.inode_size;
			std::array<std::uint8_t, sector_size> inodes{};
			build_root_inode(inodes.data() + (inode_byte % sector_size), dblkno, fs.frag_size, now);

			if (!write_partition_sectors(m_gameos, inode_byte / sector_size, 1, inodes.data(), error))
			{
				return false;
			}

			const bytes directory = root_directory();

			if (!write_partition_sectors(m_gameos, dblkno * fs.frag_size / sector_size, 1, directory.data(), error))
			{
				return false;
			}
		}

		// An image is extended to its nominal size by the last sector; a device
		// is already its own size and has no tail to write.
		if (m_fd >= 0 && !m_device)
		{
			std::uint8_t zero[sector_size]{};

			if (UFS_SEEK(m_fd, static_cast<long long>((sectors - 1) * sector_size), SEEK_SET) < 0 ||
				UFS_WRITE(m_fd, zero, sector_size) != sector_size)
			{
				error = "the image could not be sized";
				return false;
			}

			UFS_COMMIT(m_fd);
		}

		result.sectors = sectors;
		result.partition_start = part.start;
		result.partition_size = part.size;
		result.cylinder_groups = ncg;
		result.inodes = std::uint64_t(ncg) * fs.inodes_per_group;
		return true;
	}

	bool format_file(const std::string& path, const erk& key, layer seal, const format_request& request, format_result& result, std::string& error)
	{
		volume disk;

		// A formatted image is created, not opened: there is nothing to read
		// in a device that is about to be laid out.
		disk.m_fd = UFS_OPEN(path.c_str(), UFS_O_RDWR | UFS_O_CREAT | UFS_O_TRUNC | UFS_O_BINARY);

		if (disk.m_fd < 0)
		{
			error = "the image could not be created: " + path;
			return false;
		}

		disk.m_sectors = request.sectors;
		disk.m_keys = derive(key);
		disk.m_seal = seal;

		return disk.format(request, result, error);
	}

	std::vector<device_info> devices()
	{
		std::vector<device_info> out;

#ifdef _WIN32
		for (int index = 0; index < 32; index++)
		{
			const std::string path = "\\\\.\\PhysicalDrive" + std::to_string(index);
			const HANDLE handle = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

			if (handle == INVALID_HANDLE_VALUE)
			{
				continue;
			}

			DISK_GEOMETRY_EX geometry{};
			DWORD returned = 0;
			const bool ok = DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, &geometry, sizeof(geometry), &returned, nullptr);
			CloseHandle(handle);

			if (ok && geometry.DiskSize.QuadPart > 0)
			{
				out.push_back({ "\\\\.\\PhysicalDrive" + std::to_string(index), static_cast<std::uint64_t>(geometry.DiskSize.QuadPart) });
			}
		}
#elif defined(__linux__)
		// Every whole disk has a directory in /sys/block; its `size` is in
		// 512-byte units whatever the device's logical sector size is.  Loop and
		// device-mapper entries are not drives a console could be given.
		std::error_code ec;

		for (const auto& entry : std::filesystem::directory_iterator("/sys/block", ec))
		{
			const std::string name = entry.path().filename().string();

			if (name.rfind("loop", 0) == 0 || name.rfind("ram", 0) == 0 || name.rfind("dm-", 0) == 0 || name.rfind("sr", 0) == 0 || name.rfind("zram", 0) == 0)
			{
				continue;
			}

			std::ifstream size_file(entry.path() / "size");
			std::uint64_t sectors = 0;

			if (!(size_file >> sectors) || !sectors)
			{
				continue;
			}

			out.push_back({ "/dev/" + name, sectors * 512 });
		}
#elif defined(__APPLE__)
		// /dev/disk0, /dev/disk1, ... are the whole disks; the rdisk nodes are
		// the same drives unbuffered and are not listed twice.  A disk whose
		// size cannot be read is not offered.
		for (int index = 0; index < 32; index++)
		{
			const std::string path = "/dev/disk" + std::to_string(index);

			if (const std::uint64_t sectors = device_sectors(path); sectors)
			{
				out.push_back({ path, sectors * sector_size });
			}
		}
#endif

		return out;
	}

	std::uint64_t device_sectors(const std::string& path)
	{
#ifdef _WIN32
		const HANDLE handle = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

		if (handle != INVALID_HANDLE_VALUE)
		{
			DISK_GEOMETRY_EX geometry{};
			DWORD returned = 0;
			const bool ok = DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nullptr, 0, &geometry, sizeof(geometry), &returned, nullptr);
			CloseHandle(handle);

			if (ok && geometry.DiskSize.QuadPart > 0)
			{
				return static_cast<std::uint64_t>(geometry.DiskSize.QuadPart) / sector_size;
			}
		}
#elif defined(__linux__)
		// A block device reports its length through the driver, not through
		// lseek, which fails on a device node.
		const int device = UFS_OPEN(path.c_str(), UFS_O_RDONLY | UFS_O_BINARY);

		if (device >= 0)
		{
			std::uint64_t bytes = 0;

			if (ioctl(device, BLKGETSIZE64, &bytes) == 0 && bytes)
			{
				UFS_CLOSE(device);
				return bytes / sector_size;
			}

			UFS_CLOSE(device);
		}
#elif defined(__APPLE__)
		const int device = UFS_OPEN(path.c_str(), UFS_O_RDONLY | UFS_O_BINARY);

		if (device >= 0)
		{
			std::uint32_t block_size = 0;
			std::uint64_t blocks = 0;
			const bool sized = ioctl(device, DKIOCGETBLOCKSIZE, &block_size) == 0 && block_size &&
				ioctl(device, DKIOCGETBLOCKCOUNT, &blocks) == 0 && blocks;

			UFS_CLOSE(device);

			if (sized)
			{
				return (blocks * block_size) / sector_size;
			}
		}
#endif

		const int fd = UFS_OPEN(path.c_str(), UFS_O_RDONLY | UFS_O_BINARY);

		if (fd < 0)
		{
			return 0;
		}

		const long long size = UFS_SEEK(fd, 0, SEEK_END);
		UFS_CLOSE(fd);
		return size > 0 ? static_cast<std::uint64_t>(size) / sector_size : 0;
	}

	bool format_device(const std::string& path, const erk& key, layer seal, const format_request& request, format_result& result, std::string& error)
	{
		if (!request.sectors)
		{
			error = "the device size is not known";
			return false;
		}

		volume disk;

#ifdef _WIN32
		volume_locks locks;

		if (const int number = physical_disk_number(path); number >= 0)
		{
			locks.lock_disk(static_cast<unsigned>(number));
		}
#endif

		// No UFS_O_TRUNC and no UFS_O_CREAT: a device has no length to truncate, and
		// asking to create one only turns a working open into an error.
		disk.m_fd = UFS_OPEN(path.c_str(), UFS_O_RDWR | UFS_O_BINARY);

		if (disk.m_fd < 0)
		{
#ifdef _WIN32
			error = "the device could not be opened for writing: " + path + " (a raw device needs administrator rights)";
#else
			error = "the device could not be opened for writing: " + path + " (a raw device needs root: run the emulator with sudo)";
#endif
			return false;
		}

		disk.m_sectors = request.sectors;
		disk.m_device = true;
		disk.m_keys = derive(key);
		disk.m_seal = seal;

		return disk.format(request, result, error);
	}
}
