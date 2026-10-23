#include "stdafx.h"

#include "ps3_qcow2.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

namespace ps3::qcow2
{
	namespace
	{
		constexpr std::uint32_t cluster_bits = 16;
		constexpr std::uint64_t cluster_size = 1ull << cluster_bits;
		constexpr std::uint32_t l2_entries = cluster_size / 8;
		constexpr std::uint32_t refs_per_block = cluster_size / 2;

		std::uint32_t be32(const std::uint8_t* p)
		{
			return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) | p[3];
		}

		std::uint64_t be64(const std::uint8_t* p)
		{
			return (std::uint64_t(be32(p)) << 32) | be32(p + 4);
		}

		void put_be32(std::uint8_t* p, std::uint32_t v)
		{
			p[0] = std::uint8_t(v >> 24); p[1] = std::uint8_t(v >> 16); p[2] = std::uint8_t(v >> 8); p[3] = std::uint8_t(v);
		}

		void put_be64(std::uint8_t* p, std::uint64_t v)
		{
			put_be32(p, std::uint32_t(v >> 32)); put_be32(p + 4, std::uint32_t(v));
		}

		struct file
		{
			std::FILE* handle = nullptr;

			~file()
			{
				if (handle) std::fclose(handle);
			}

			bool read(std::uint64_t offset, void* data, std::size_t size)
			{
				return std::fseek(handle, static_cast<long>(offset), SEEK_SET) == 0 && std::fread(data, 1, size, handle) == size;
			}

			bool write(std::uint64_t offset, const void* data, std::size_t size)
			{
				return std::fseek(handle, static_cast<long>(offset), SEEK_SET) == 0 && std::fwrite(data, 1, size, handle) == size;
			}
		};

		struct header
		{
			std::uint64_t virtual_size = 0;
			std::uint32_t l1_size = 0;
			std::uint64_t l1_offset = 0;
			std::uint64_t refcount_table = 0;
			std::uint32_t refcount_clusters = 0;
			std::uint64_t cluster = cluster_size;
			std::uint32_t l2 = l2_entries;
			std::uint32_t refs = refs_per_block;
		};

		bool read_header(file& in, header& out, std::string& error)
		{
			std::uint8_t raw[0x70]{};

			if (!in.read(0, raw, sizeof(raw)))
			{
				error = "the image is too short for a qcow2 header";
				return false;
			}

			static constexpr std::uint8_t magic[4] = {'Q', 'F', 'I', 0xFB};

			if (std::memcmp(raw, magic, 4) != 0)
			{
				error = "this is not a qcow2 image";
				return false;
			}

			const std::uint32_t version = be32(raw + 4);

			if (version < 2 || version > 3)
			{
				error = "qcow2 version " + std::to_string(version) + " is not supported";
				return false;
			}

			if (be32(raw + 0x20) != 0)
			{
				error = "encrypted qcow2 images are not supported";
				return false;
			}

			const std::uint32_t bits = be32(raw + 0x14);

			if (bits < 9 || bits > 21)
			{
				error = "the cluster size is not usable";
				return false;
			}

			out.cluster = 1ull << bits;
			out.l2 = static_cast<std::uint32_t>(out.cluster / 8);
			out.refs = static_cast<std::uint32_t>(out.cluster / 2);
			out.virtual_size = be64(raw + 0x18);
			out.l1_size = be32(raw + 0x24);
			out.l1_offset = be64(raw + 0x28);
			out.refcount_table = be64(raw + 0x30);
			out.refcount_clusters = be32(raw + 0x38);

			if (!out.virtual_size || !out.l1_size || !out.l1_offset)
			{
				error = "the qcow2 header is not usable";
				return false;
			}

			return true;
		}

		// Where the cluster at `index` starts, or 0 when it is unallocated.
		bool cluster_at(file& in, const header& h, std::uint64_t index, std::uint64_t& offset, std::string& error)
		{
			offset = 0;

			const std::uint64_t l1_index = index / h.l2;

			if (l1_index >= h.l1_size)
			{
				error = "the cluster is past the end of the image";
				return false;
			}

			std::uint8_t entry[8]{};

			if (!in.read(h.l1_offset + l1_index * 8, entry, 8))
			{
				error = "the L1 table could not be read";
				return false;
			}

			const std::uint64_t l2_offset = be64(entry) & 0x00FFFFFFFFFFFE00ull;

			if (!l2_offset)
			{
				return true;
			}

			if (!in.read(l2_offset + (index % h.l2) * 8, entry, 8))
			{
				error = "the L2 table could not be read";
				return false;
			}

			offset = be64(entry) & 0x00FFFFFFFFFFFE00ull;
			return true;
		}
	}

	bool size(const std::string& path, std::uint64_t& bytes, std::string& error)
	{
		file in;
		in.handle = std::fopen(path.c_str(), "rb");

		if (!in.handle)
		{
			error = "the image could not be opened: " + path;
			return false;
		}

		header h;

		if (!read_header(in, h, error))
		{
			return false;
		}

		bytes = h.virtual_size;
		return true;
	}

	bool unpack(const std::string& qcow2_path, const std::string& raw_path, std::string& error)
	{
		file in;
		in.handle = std::fopen(qcow2_path.c_str(), "rb");

		if (!in.handle)
		{
			error = "the image could not be opened: " + qcow2_path;
			return false;
		}

		header h;

		if (!read_header(in, h, error))
		{
			return false;
		}

		file out;
		out.handle = std::fopen(raw_path.c_str(), "w+b");

		if (!out.handle)
		{
			error = "the raw image could not be created: " + raw_path;
			return false;
		}

		std::vector<std::uint8_t> buffer(h.cluster, 0);
		std::vector<std::uint8_t> zeros(h.cluster, 0);
		const std::uint64_t clusters = (h.virtual_size + h.cluster - 1) / h.cluster;

		for (std::uint64_t index = 0; index < clusters; index++)
		{
			std::uint64_t offset = 0;

			if (!cluster_at(in, h, index, offset, error))
			{
				return false;
			}

			std::uint64_t take = std::min(h.cluster, h.virtual_size - index * h.cluster);

			if (offset)
			{
				if (!in.read(offset, buffer.data(), static_cast<std::size_t>(h.cluster)))
				{
					error = "a cluster could not be read";
					return false;
				}
			}
			else
			{
				std::copy(zeros.begin(), zeros.end(), buffer.begin());
			}

			if (!out.write(index * h.cluster, buffer.data(), static_cast<std::size_t>(take)))
			{
				error = "the raw image could not be written";
				return false;
			}
		}

		return true;
	}

	bool pack(const std::string& raw_path, const std::string& qcow2_path, std::string& error)
	{
		file raw;
		raw.handle = std::fopen(raw_path.c_str(), "rb");

		if (!raw.handle)
		{
			error = "the raw image could not be opened: " + raw_path;
			return false;
		}

		std::fseek(raw.handle, 0, SEEK_END);
		const long long raw_size = std::ftell(raw.handle);

		if (raw_size <= 0)
		{
			error = "the raw image is empty";
			return false;
		}

		file out;
		out.handle = std::fopen(qcow2_path.c_str(), "w+b");

		if (!out.handle)
		{
			error = "the qcow2 image could not be created: " + qcow2_path;
			return false;
		}

		const std::uint64_t size = static_cast<std::uint64_t>(raw_size);
		const std::uint64_t clusters = (size + cluster_size - 1) / cluster_size;
		const std::uint32_t l1_size = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, (clusters + l2_entries - 1) / l2_entries));
		const std::uint64_t l1_clusters = (std::uint64_t(l1_size) * 8 + cluster_size - 1) / cluster_size;
		const std::uint64_t refcount_table_cluster = 1;
		const std::uint64_t l1_cluster = refcount_table_cluster + 1;
		std::uint64_t next_cluster = l1_cluster + l1_clusters;

		std::vector<std::uint8_t> zero(cluster_size, 0);

		if (!out.write(refcount_table_cluster * cluster_size, zero.data(), zero.size()))
		{
			error = "the refcount table could not be written";
			return false;
		}

		for (std::uint64_t i = 0; i < l1_clusters; i++)
		{
			if (!out.write((l1_cluster + i) * cluster_size, zero.data(), zero.size()))
			{
				error = "the L1 table could not be written";
				return false;
			}
		}

		// Refcount blocks are written on demand; the table names them.
		std::vector<std::uint64_t> refcount_block(cluster_size / 8, 0);

		const auto set_refcount = [&](std::uint64_t index, std::uint16_t value) -> bool
		{
			const std::uint64_t block = index / refs_per_block;

			if (!refcount_block[block])
			{
				const std::uint64_t fresh = next_cluster++;
				refcount_block[block] = fresh;

				std::uint8_t entry[8];
				put_be64(entry, fresh);

				if (!out.write(refcount_table_cluster * cluster_size + block * 8, entry, 8) ||
					!out.write(fresh * cluster_size, zero.data(), zero.size()))
				{
					return false;
				}

				std::uint8_t one[2];
				put_be64(one, 0);
				one[0] = 0;
				one[1] = 1;

				if (!out.write(fresh * cluster_size + (fresh % refs_per_block) * 2, one, 2))
				{
					return false;
				}
			}

			std::uint8_t raw[2];
			raw[0] = std::uint8_t(value >> 8);
			raw[1] = std::uint8_t(value);

			return out.write(refcount_block[block] * cluster_size + (index % refs_per_block) * 2, raw, 2);
		};

		for (std::uint64_t index = 0; index < next_cluster; index++)
		{
			if (!set_refcount(index, 1))
			{
				error = "the refcounts could not be written";
				return false;
			}
		}

		std::vector<std::uint8_t> buffer(cluster_size, 0);
		std::vector<std::uint64_t> l2_tables(l1_size, 0);

		for (std::uint64_t index = 0; index < clusters; index++)
		{
			const std::uint64_t remaining = size - index * cluster_size;
			const std::size_t take = static_cast<std::size_t>(std::min(cluster_size, remaining));

			if (!raw.read(index * cluster_size, buffer.data(), take))
			{
				error = "the raw image could not be read";
				return false;
			}

			if (std::all_of(buffer.begin(), buffer.begin() + take, [](std::uint8_t b) { return b == 0; }))
			{
				continue;
			}

			const std::uint64_t l1_index = index / l2_entries;

			if (!l2_tables[l1_index])
			{
				const std::uint64_t fresh = next_cluster++;
				l2_tables[l1_index] = fresh;

				std::uint8_t entry[8];
				put_be64(entry, (fresh * cluster_size) | (1ull << 63));

				if (!set_refcount(fresh, 1) ||
					!out.write(l1_cluster * cluster_size + l1_index * 8, entry, 8) ||
					!out.write(fresh * cluster_size, zero.data(), zero.size()))
				{
					error = "an L2 table could not be written";
					return false;
				}
			}

			const std::uint64_t first = next_cluster++;

			if (!set_refcount(first, 1) ||
				!out.write(first * cluster_size, buffer.data(), cluster_size))
			{
				error = "a cluster could not be written";
				return false;
			}

			std::uint8_t entry[8];
			put_be64(entry, (first * cluster_size) | (1ull << 63));

			if (!out.write(l2_tables[l1_index] * cluster_size + (index % l2_entries) * 8, entry, 8))
			{
				error = "the L2 table could not be written";
				return false;
			}
		}

		std::uint8_t header_raw[0x68]{};
		header_raw[0] = 'Q'; header_raw[1] = 'F'; header_raw[2] = 'I'; header_raw[3] = 0xFB;
		put_be32(header_raw + 0x04, 3);
		put_be32(header_raw + 0x14, cluster_bits);
		put_be64(header_raw + 0x18, size);
		put_be32(header_raw + 0x20, 0);
		put_be32(header_raw + 0x24, l1_size);
		put_be64(header_raw + 0x28, l1_cluster * cluster_size);
		put_be64(header_raw + 0x30, refcount_table_cluster * cluster_size);
		put_be32(header_raw + 0x38, 1);
		put_be32(header_raw + 0x3C, 0);
		put_be64(header_raw + 0x40, 0);
		put_be64(header_raw + 0x48, 0);
		put_be64(header_raw + 0x50, 0);
		put_be64(header_raw + 0x58, 0);
		put_be32(header_raw + 0x60, 4);
		put_be32(header_raw + 0x64, sizeof(header_raw));

		if (!out.write(0, header_raw, sizeof(header_raw)))
		{
			error = "the qcow2 header could not be written";
			return false;
		}

		return true;
	}
}
