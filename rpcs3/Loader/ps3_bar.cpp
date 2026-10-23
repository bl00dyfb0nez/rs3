#include "stdafx.h"

#include "ps3_bar.h"

#include <algorithm>
#include <cstring>

#include "Crypto/aes.h"
#include "Crypto/sha1.h"
#include "Crypto/utils.h"

namespace ps3::bar
{
	namespace
	{
		std::uint32_t le32(const std::uint8_t* p)
		{
			return std::uint32_t{p[0]} | (std::uint32_t{p[1]} << 8) | (std::uint32_t{p[2]} << 16) | (std::uint32_t{p[3]} << 24);
		}

		std::uint64_t le64(const std::uint8_t* p)
		{
			return std::uint64_t{le32(p)} | (std::uint64_t{le32(p + 4)} << 32);
		}

		void put_le32(bytes& out, std::size_t at, std::uint32_t value)
		{
			out[at + 0] = static_cast<std::uint8_t>(value);
			out[at + 1] = static_cast<std::uint8_t>(value >> 8);
			out[at + 2] = static_cast<std::uint8_t>(value >> 16);
			out[at + 3] = static_cast<std::uint8_t>(value >> 24);
		}

		void put_le64(bytes& out, std::size_t at, std::uint64_t value)
		{
			put_le32(out, at, static_cast<std::uint32_t>(value));
			put_le32(out, at + 4, static_cast<std::uint32_t>(value >> 32));
		}

		// The name in a block is a NUL-terminated path; anything after the NUL is
		// padding and is not part of it.
		std::string read_path(const std::uint8_t* p, std::uint32_t room)
		{
			std::string out;

			for (std::uint32_t i = 0; i < room && p[i]; i++)
			{
				out.push_back(static_cast<char>(p[i]));
			}

			return out;
		}

		void put_path(bytes& out, std::size_t at, std::uint32_t room, const std::string& path)
		{
			std::fill_n(out.begin() + at, room, std::uint8_t{0});
			std::memcpy(out.data() + at, path.data(), std::min<std::size_t>(path.size(), room));
		}

		bool payload_ok(std::span<const std::uint8_t> image, std::string& error)
		{
			if (image.size() < dat_header_size + archive_header_size)
			{
				error = "the file is smaller than its two headers";
				return false;
			}

			return true;
		}

		// CBC for the whole blocks, then the documented CFB step for the tail.
		void crypt(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, const key_material& keys, bool encrypt)
		{
			aes_context enc{}, dec{};
			aes_setkey_enc(&enc, keys.key.data(), 128);
			aes_setkey_dec(&dec, keys.key.data(), 128);

			std::array<std::uint8_t, 16> iv = keys.iv;
			const std::size_t blocks = in.size() / 16;
			const std::size_t tail = in.size() % 16;

			for (std::size_t i = 0; i < blocks; i++)
			{
				const std::uint8_t* src = in.data() + i * 16;
				std::uint8_t* dst = out.data() + i * 16;

				if (encrypt)
				{
					std::array<std::uint8_t, 16> block{};
					std::memcpy(block.data(), src, 16);

					for (std::size_t b = 0; b < 16; b++)
					{
						block[b] ^= iv[b];
					}

					aes_crypt_ecb(&enc, AES_ENCRYPT, block.data(), dst);
					std::memcpy(iv.data(), dst, 16);
				}
				else
				{
					std::array<std::uint8_t, 16> block{};
					aes_crypt_ecb(&dec, AES_DECRYPT, src, block.data());

					for (std::size_t b = 0; b < 16; b++)
					{
						dst[b] = static_cast<std::uint8_t>(block[b] ^ iv[b]);
					}

					std::memcpy(iv.data(), src, 16);
				}
			}

			if (tail)
			{
				// The last block is short: the stream goes on from the previous
				// cipher block, whose AES encryption is the keystream.
				std::array<std::uint8_t, 16> stream{};
				aes_crypt_ecb(&enc, AES_ENCRYPT, iv.data(), stream.data());

				for (std::size_t b = 0; b < tail; b++)
				{
					out[blocks * 16 + b] = static_cast<std::uint8_t>(in[blocks * 16 + b] ^ stream[b]);
				}
			}
		}

		void put_archive_header(bytes& out, std::size_t at, const archive_header& header)
		{
			put_le64(out, at, header.id);
			put_le32(out, at + 0x08, header.index);
			out[at + 0x0C] = header.archive_type;
			out[at + 0x0D] = header.index_file ? 1 : 0;
			out[at + 0x0E] = 0;
			out[at + 0x0F] = 0;
		}

		bool get_archive_header(std::span<const std::uint8_t> data, archive_header& out, std::string& error)
		{
			if (data.size() < archive_header_size)
			{
				error = "the archive header is missing";
				return false;
			}

			out.id = le64(data.data());
			out.index = le32(data.data() + 0x08);
			out.archive_type = data[0x0C];
			out.index_file = data[0x0D] == 1;

			if (out.archive_type != 0x04 && out.archive_type != 0x05)
			{
				error = "the archive type is neither 0x04 nor 0x05";
				return false;
			}

			return true;
		}
	}

	bool derive_keys(const dat_header& header, std::span<const std::uint8_t, 16> idps, key_material& out, std::string& error)
	{
		// The engine is handed a zeroed 64-byte buffer with the seed at its
		// start, encrypted with a zeroed IV.  An all-zero seed is the console's
		// IDPS; anything else travels through the portability path.
		std::array<std::uint8_t, 64> block{};
		std::array<std::uint8_t, 16> iv{};

		if (header.encryption == 0x30)
		{
			std::copy(idps.begin(), idps.end(), block.begin());
		}
		else if (header.encryption == 0x40)
		{
			std::copy(header.seed.begin(), header.seed.end(), block.begin());
		}
		else
		{
			error = "the DAT header carries an encryption type that is neither 0x30 nor 0x40";
			return false;
		}

		const int result = header.encryption == 0x30
			? vtrm_decrypt(3, iv.data(), block.data(), block.data())
			: vtrm_decrypt_with_portability(1, iv.data(), block.data(), block.data());

		if (result != 0)
		{
			error = "the VTRM engine refused the key seed";
			return false;
		}

		std::memcpy(out.key.data(), block.data(), 0x10);
		std::memcpy(out.iv.data(), block.data() + 0x10, 0x10);
		std::memcpy(out.hmac.data(), block.data() + 0x2C, 0x14);

		return true;
	}

	dat_header make_header(std::uint32_t dat_type, bool portable, const std::array<std::uint8_t, 0x14>& seed)
	{
		dat_header header;
		header.encryption = portable ? 0x40 : 0x30;
		header.dat_type = dat_type;

		if (portable)
		{
			header.seed = seed;
		}

		return header;
	}

	bytes cipher(bytes& payload, const key_material& keys, bool encrypt)
	{
		bytes out(payload.size());
		crypt(payload, out, keys, encrypt);
		return out;
	}

	bool read_index(std::span<const std::uint8_t> image, std::span<const std::uint8_t, 16> idps, index& out, footer& foot, std::string& error, bool verify)
	{
		if (!payload_ok(image, error))
		{
			return false;
		}

		dat_header header;
		header.encryption = le32(image.data());
		header.dat_type = le32(image.data() + 0x04);
		std::memcpy(header.hash.data(), image.data() + 0x08, 0x14);
		std::memcpy(header.seed.data(), image.data() + 0x1C, 0x14);

		key_material keys;

		if (!derive_keys(header, idps, keys, error))
		{
			return false;
		}

		if (verify)
		{
			std::array<std::uint8_t, 20> mac{};
			sha1_hmac(keys.hmac.data(), keys.hmac.size(), image.data() + dat_header_size, image.size() - dat_header_size, mac.data());

			if (std::memcmp(mac.data(), header.hash.data(), 0x14) != 0)
			{
				error = "the HMAC does not match the payload";
				return false;
			}
		}

		bytes payload(image.begin() + dat_header_size, image.end());
		bytes plain = cipher(payload, keys, false);

		if (!get_archive_header(plain, out.header, error))
		{
			return false;
		}

		std::size_t at = archive_header_size;

		const auto room = [&](std::size_t need)
		{
			if (at + need > plain.size())
			{
				error = "a block runs past the end of the file";
				return false;
			}

			return true;
		};

		// The file list, ended by the block whose first eight bytes are zero.
		while (true)
		{
			if (!room(8))
			{
				return false;
			}

			if (le64(plain.data() + at) == 0)
			{
				if (!room(file_block_size))
				{
					return false;
				}

				if (le64(plain.data() + at + 0x08) != out.files.size())
				{
					error = "the end-of-files block does not count the files before it";
					return false;
				}

				out.file_sizes = le64(plain.data() + at + 0x10);
				at += file_block_size;
				break;
			}

			if (!room(file_block_size))
			{
				return false;
			}

			file_entry entry;
			entry.path = read_path(plain.data() + at, path_room);
			std::memcpy(entry.stat.bytes.data(), plain.data() + at + path_room, 0x34);
			entry.flags = le32(plain.data() + at + path_room + 0x34);
			out.files.push_back(std::move(entry));
			at += file_block_size;
		}

		// The directory list, the same way.
		while (true)
		{
			if (!room(8))
			{
				return false;
			}

			if (le64(plain.data() + at) == 0)
			{
				if (!room(dir_block_size))
				{
					return false;
				}

				if (le64(plain.data() + at + 0x08) != out.dirs.size())
				{
					error = "the end-of-directories block does not count the directories before it";
					return false;
				}

				at += dir_block_size;
				break;
			}

			if (!room(dir_block_size))
			{
				return false;
			}

			dir_entry entry;
			entry.path = read_path(plain.data() + at, dir_path_room);
			std::memcpy(entry.stat.bytes.data(), plain.data() + at + dir_path_room, 0x34);
			entry.flags = le32(plain.data() + at + dir_path_room + 0x34);
			out.dirs.push_back(std::move(entry));
			at += dir_block_size;
		}

		// archive.dat carries the footer: the console the backup came from and
		// the size of the copy-protected set.
		if (out.header.index_file && out.header.archive_type == 0x05)
		{
			if (at + footer_size <= plain.size())
			{
				std::memcpy(foot.open_psid.data(), plain.data() + at, 0x10);
				foot.archive2_sizes = le64(plain.data() + at + 0x10);
			}
		}

		return true;
	}

	bool write_index(const index& in, const footer& foot, std::span<const std::uint8_t, 16> idps, bytes& out, std::string& error, bool portable)
	{
		bytes plain(archive_header_size);
		archive_header header = in.header;
		header.index_file = true;
		put_archive_header(plain, 0, header);

		for (const file_entry& entry : in.files)
		{
			const std::size_t at = plain.size();
			plain.resize(at + file_block_size, 0);
			put_path(plain, at, path_room, entry.path);
			std::memcpy(plain.data() + at + path_room, entry.stat.bytes.data(), 0x34);
			put_le32(plain, at + path_room + 0x34, entry.flags);
		}

		{
			const std::size_t at = plain.size();
			plain.resize(at + file_block_size, 0);
			put_le64(plain, at + 0x08, in.files.size());
			put_le64(plain, at + 0x10, in.file_sizes);
		}

		for (const dir_entry& entry : in.dirs)
		{
			const std::size_t at = plain.size();
			plain.resize(at + dir_block_size, 0);
			put_path(plain, at, dir_path_room, entry.path);
			std::memcpy(plain.data() + at + dir_path_room, entry.stat.bytes.data(), 0x34);
			put_le32(plain, at + dir_path_room + 0x34, entry.flags);
		}

		{
			const std::size_t at = plain.size();
			plain.resize(at + dir_block_size, 0);
			put_le64(plain, at + 0x08, in.dirs.size());
		}

		if (header.archive_type == 0x05)
		{
			const std::size_t at = plain.size();
			plain.resize(at + footer_size, 0);
			std::memcpy(plain.data() + at, foot.open_psid.data(), 0x10);
			put_le64(plain, at + 0x10, foot.archive2_sizes);
		}

		// The index describes ordinary data (0x05) or the copy-protected set
		// (0x04); the DAT type stays 0x05 for both, and the console seals the
		// key to its own IDPS unless the backup is meant to travel.
		dat_header dat = make_header(0x05, portable, {});

		key_material keys;

		if (!derive_keys(dat, idps, keys, error))
		{
			return false;
		}

		const bytes encrypted = cipher(plain, keys, true);

		out.assign(dat_header_size + encrypted.size(), 0);
		put_le32(out, 0x00, dat.encryption);
		put_le32(out, 0x04, dat.dat_type);
		std::memcpy(out.data() + 0x1C, dat.seed.data(), 0x14);
		std::memcpy(out.data() + dat_header_size, encrypted.data(), encrypted.size());

		std::array<std::uint8_t, 20> mac{};
		sha1_hmac(keys.hmac.data(), keys.hmac.size(), out.data() + dat_header_size, encrypted.size(), mac.data());
		std::memcpy(out.data() + 0x08, mac.data(), 0x14);

		return true;
	}

	bool read_data(std::span<const std::uint8_t> image, std::span<const std::uint8_t, 16> idps, bytes& payload, std::string& error)
	{
		if (!payload_ok(image, error))
		{
			return false;
		}

		dat_header header;
		header.encryption = le32(image.data());
		header.dat_type = le32(image.data() + 0x04);
		std::memcpy(header.hash.data(), image.data() + 0x08, 0x14);
		std::memcpy(header.seed.data(), image.data() + 0x1C, 0x14);

		key_material keys;

		if (!derive_keys(header, idps, keys, error))
		{
			return false;
		}

		bytes body(image.begin() + dat_header_size, image.end());
		payload = cipher(body, keys, false);

		return true;
	}

	bool write_data(const archive_header& header, std::span<const std::uint8_t, 16> idps, const bytes& payload, bool portable, bytes& out, std::string& error)
	{
		// The data file's own archive header is the first thing in the stream.
		bytes plain(archive_header_size + payload.size());
		put_archive_header(plain, 0, header);
		std::memcpy(plain.data() + archive_header_size, payload.data(), payload.size());

		dat_header dat = make_header(0x05, portable, {});
		key_material keys;

		if (!derive_keys(dat, idps, keys, error))
		{
			return false;
		}

		const bytes encrypted = cipher(plain, keys, true);

		out.assign(dat_header_size + encrypted.size(), 0);
		put_le32(out, 0x00, dat.encryption);
		put_le32(out, 0x04, dat.dat_type);
		std::memcpy(out.data() + 0x1C, dat.seed.data(), 0x14);
		std::memcpy(out.data() + dat_header_size, encrypted.data(), encrypted.size());

		std::array<std::uint8_t, 20> mac{};
		sha1_hmac(keys.hmac.data(), keys.hmac.size(), out.data() + dat_header_size, encrypted.size(), mac.data());
		std::memcpy(out.data() + 0x08, mac.data(), 0x14);

		return true;
	}
}
