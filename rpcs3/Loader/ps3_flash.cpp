#include "stdafx.h"

#include "ps3_flash.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>

#include "Crypto/sha1.h"

#include "ps3_coreos.h"

namespace ps3::flash
{
	namespace
	{
		// The table of contents the flash keeps at 0x400: a count at +0x04 and
		// 0x30-byte entries from +0x10, a u64 offset relative to the table, a
		// u64 size and a 0x20-byte name.  These are the regions docs/flash.txt
		// lists for NOR, with the names the tools use (`extnor` is the name
		// norunpack looks for; the block itself is marked CELL_EXTNOR_AREA).
		struct toc_entry
		{
			const char* name;
			std::uint32_t offset;
			std::uint32_t size;
		};

		constexpr toc_entry toc[] =
		{
			{"asecure_loader", 0x000800, 0x02E800},
			{"eEID",           0x02F000, 0x010000},
			{"cISD",           0x03F000, 0x000800},
			{"cCSD",           0x03F800, 0x000800},
			{"trvk_prg0",      0x040000, 0x020000},
			{"trvk_prg1",      0x060000, 0x020000},
			{"trvk_pkg0",      0x080000, 0x020000},
			{"trvk_pkg1",      0x0A0000, 0x020000},
			{"ros0",           0x0C0000, 0x700000},
			{"ros1",           0x7C0000, 0x700000},
			{"cvtrm",          0xEC0000, 0x040000},
			{"extnor",         0xF20000, 0x020000},
			{"CRL1",           0xF40000, 0x020000},
			{"DRL1",           0xF60000, 0x020000},
			{"CRL2",           0xF80000, 0x020000},
			{"DRL2",           0xFA0000, 0x020000},
			{"bootldr",        0xFC0000, 0x040000},
		};

		// The eMMC/NAND map (docs/flash.txt): bootldr at flash 0, the flash
		// header at 0x40000, the table at 0x40200 and one ros region of 0xE00000.
		// /dev_flash and the rest of the eFlash area are regions of their own
		// below 0xF00000, not table of contents entries.
		constexpr toc_entry toc_emmc[] =
		{
			{"asecure_loader", 0x040800, 0x040000},
			{"eEID",           0x080800, 0x010000},
			{"cISD",           0x090800, 0x000800},
			{"cCSD",           0x091000, 0x000800},
			{"trvk_prg",       0x091800, 0x002000},
			{"trvk_pkg",       0x093800, 0x002000},
			{"creserved_0",    0x095800, 0x02A800},
			{"ros",            0x0C0000, 0xE00000},
			{"cvtrm",          0xEC0000, 0x040000},
		};

		constexpr std::uint32_t emmc_toc = 0x40200;
		constexpr std::uint32_t emmc_metldr = 0x040840;
		constexpr std::uint32_t emmc_asecure = 0x040800;
		constexpr std::uint32_t emmc_ros = 0x0C0000;
		constexpr std::uint32_t emmc_bootldr_mirror = 0xF000000;
		constexpr std::uint32_t dev_flash = 0x0F40000;

		constexpr std::uint32_t toc_offset = 0x400;
		constexpr std::uint32_t metldr_offset = 0x000840;
		constexpr std::uint32_t asecure_size = 0x02E800;
		constexpr std::uint32_t extnor_offset = 0xF20000;
		constexpr std::uint32_t extnor_info = extnor_offset + 0x200;  // the hashed hard drive block
		constexpr std::uint32_t writer_start = 0x200;

		// The writer's two spans (FLASH_LAYOUT.md): the shipped one is the image
		// less its 0x20-byte header and stops on lv0's slot; the 4.93 page's
		// fourth step ends at lv0's own extent.
		constexpr std::uint32_t writer_stock_bytes = 0x300400 - 0x20;
		constexpr std::uint32_t writer_493_end = 0x3E7200;

		// The revision a dump of this chain carries.  The block counts and their
		// counter suffixes are rows of the tables in FLASH_LAYOUT.md.
		struct revision
		{
			std::uint32_t blocks;
			const char* counter;  // 12 bytes, hex
		};

		struct chain_revision
		{
			revision metldr;
			revision bootldr;
		};

		// metldr 0x0E8E / 99873BC7 is the 3.40 loader, its bootldr pair 0x2F4B;
		// metldr.2 0x0F8E and bootldr 0x2FFB are the 3.60+ pair.
		constexpr chain_revision chain_metldr{{0x0E8E, "99873BC715F280809C302225"}, {0x2F4B, "CB9E152428B44FD2F93FBC43"}};
		constexpr chain_revision chain_metldr_2{{0x0F8E, "6ED7BCD81F11EA34425F9B9D"}, {0x2FFB, "13ECA74A8E14D473129128E8"}};

		void put_be32(bytes& image, std::uint32_t at, std::uint32_t value)
		{
			image[at + 0] = static_cast<std::uint8_t>(value >> 24);
			image[at + 1] = static_cast<std::uint8_t>(value >> 16);
			image[at + 2] = static_cast<std::uint8_t>(value >> 8);
			image[at + 3] = static_cast<std::uint8_t>(value);
		}

		void put_be64(bytes& image, std::uint32_t at, std::uint64_t value)
		{
			put_be32(image, at, static_cast<std::uint32_t>(value >> 32));
			put_be32(image, at + 4, static_cast<std::uint32_t>(value));
		}

		// A region the docs describe as zeros rather than as erased flash.
		void zeros(bytes& image, std::uint32_t at, std::uint32_t len)
		{
			std::fill_n(image.begin() + at, len, std::uint8_t{0});
		}

		void text_at(bytes& image, std::uint32_t at, std::string_view text, std::uint32_t room, std::uint8_t pad)
		{
			std::fill_n(image.begin() + at, room, pad);
			std::memcpy(image.data() + at, text.data(), std::min<std::size_t>(text.size(), room));
		}

		std::array<std::uint8_t, 20> digest(const console& c, std::string_view label)
		{
			std::string input(reinterpret_cast<const char*>(c.idps.data()), c.idps.size());
			input.append(label);

			std::array<std::uint8_t, 20> out{};
			sha1(reinterpret_cast<const unsigned char*>(input.data()), input.size(), out.data());
			return out;
		}

		std::vector<std::uint8_t> unhex(std::string_view text)
		{
			const auto value = [](char c) -> int
			{
				if (c >= '0' && c <= '9') return c - '0';
				if (c >= 'a' && c <= 'f') return c - 'a' + 10;
				if (c >= 'A' && c <= 'F') return c - 'A' + 10;
				return 0;
			};

			std::vector<std::uint8_t> out;

			for (std::size_t i = 0; i + 1 < text.size(); i += 2)
			{
				out.push_back(static_cast<std::uint8_t>((value(text[i]) << 4) | value(text[i + 1])));
			}

			return out;
		}

		const chain_revision& revision_for(const console& c)
		{
			return c.boot_loader == "metldr" ? chain_metldr : chain_metldr_2;
		}

		std::string hex(std::uint32_t value)
		{
			char text[16];
			std::snprintf(text, sizeof(text), "0x%X", value);
			return text;
		}

		std::uint32_t window_bytes(writer_mode mode)
		{
			return mode == writer_mode::stock ? writer_stock_bytes : writer_493_end - writer_start;
		}

		// The window on its own, without the gates: what build() replays once a
		// patch has been installed.
		writer_plan window_plan(writer_mode mode)
		{
			writer_plan plan;
			plan.mode = mode;
			plan.start = writer_start;
			plan.bytes = window_bytes(mode);
			return plan;
		}

		// metldr and bootldr share one header: encrypted-block count, a 12-byte
		// counter suffix, the total block count, then the per-console nonce, key
		// field and masked tag.  The two halves of a chain are sealed in the same
		// update, so they carry the same nonce; the counter differs per container
		// and the tag is the one that half presents.
		void seal(bytes& image, std::uint32_t at, const revision& rev, const console& c, std::string_view label)
		{
			const std::vector<std::uint8_t> counter = unhex(rev.counter);
			const auto nonce = digest(c, "chain nonce");
			const auto key = digest(c, "chain key");
			const auto tag = digest(c, label);

			put_be32(image, at + 0x00, rev.blocks);
			std::copy_n(counter.begin(), std::min<std::size_t>(counter.size(), 12), image.begin() + at + 0x04);
			put_be32(image, at + 0x10, rev.blocks);
			std::copy_n(nonce.begin(), 12, image.begin() + at + 0x14);
			std::copy_n(key.begin(), 16, image.begin() + at + 0x20);
			std::copy_n(tag.begin(), 16, image.begin() + at + 0x30);
		}

		void write_revoke_list(bytes& image, std::uint32_t at, std::uint64_t data_size)
		{
			// "8 bytes unknown, u64 data size, then the SCE record" - the shape
			// norunpack reads.  The list itself is signed and encrypted, so it
			// stays erased.
			zeros(image, at, 0x2C0);
			put_be64(image, at + 0x08, data_size);
			std::memcpy(image.data() + at + 0x10, "SCE\0", 4);
			put_be32(image, at + 0x14, 2);
			put_be32(image, at + 0x18, 2);
			put_be64(image, at + 0x20, 0x200);
			put_be64(image, at + 0x28, 0xE0);
		}

		void write_ros_bank(bytes& image, std::uint32_t bank)
		{
			// The bank header: 8 reserved bytes, the bank size twice, a version
			// word and the entry count.  The entries name the files and give each
			// one's offset and size; the bodies stay erased.  lv0 and lv0.2 sit
			// where the flash writer's window measures them, so the window's end
			// can be checked against them.
			struct entry
			{
				const char* name;
				std::uint32_t offset;
				std::uint32_t size;
			};

			// The order is the one FLASH_LAYOUT.md gives for a bank - the two
			// reserved entries, the isolated modules of CoreOS (docs/isomod.txt),
			// default.spp, lv1.self, lv0, lv0.2 and the kernel - with vsh.self at
			// the end.  A real bank puts me_iso_spu_module.self at 0x1E0, which is
			// where the flash writer's image starts; the emulator's table keeps the
			// documented order rather than padding to that offset.
			const entry entries[] =
			{
				{"creserved_0",          0, 0},
				{"sdk_version",          0x300, 0x20},
				{"aim_spu_module.self",  0x320, 0},
				{"manu_info_spu_module.self", 0x340, 0},
				{"mc_iso_spu_module.self", 0x360, 0},
				{"me_iso_for_ps2emu.self", 0x380, 0},
				{"me_iso_spu_module.self", 0x3A0, 0},
				{"sb_iso_spu_module.self", 0x3C0, 0},
				{"sc_iso.self",          0x3E0, 0},
				{"default.spp",          0x400, 0},
				{"lv1.self",             0x420, 0},
				{"lv0",                  lv0_slot, 0x500},
				{"lv0.2",                lv0_2_slot, lv0_2_size},
				{"lv2_kernel.self",      lv0_2_slot + lv0_2_size, 0},
				{"vsh.self",             lv0_2_slot + lv0_2_size + 0x10000, 0},
			};

			// The header is 0x20 bytes and the records follow from it: the
			// offset and the size as big-endian 64-bit words, then the name.
			zeros(image, bank, 0x20);
			put_be64(image, bank + 0x08, ros_size);
			put_be32(image, bank + 0x10, 1);
			put_be32(image, bank + 0x14, static_cast<std::uint32_t>(std::size(entries)));
			put_be64(image, bank + 0x18, ros_size);

			for (std::size_t i = 0; i < std::size(entries); i++)
			{
				const std::uint32_t at = bank + 0x20 + static_cast<std::uint32_t>(i) * 0x30;
				put_be64(image, at, entries[i].offset);
				put_be64(image, at + 0x08, entries[i].size);
				text_at(image, at + 0x10, entries[i].name, 0x20, 0);
			}
		}

		// The CoreOS the console runs, when it was extracted from the firmware it
		// was installed from: both banks then carry its files instead of the
		// empty table written above, so the dump's chain is the one the console
		// actually boots.  The bank is what ps3::coreos lays out (one ros bank,
		// 0x700000 bytes), and ros1 is its second copy.
		void install_coreos(bytes& image, const console& c, std::uint32_t bank0, std::uint32_t bank1)
		{
			if (c.coreos_image.empty())
			{
				return;
			}

			std::ifstream file(c.coreos_image, std::ios::binary);

			bytes bank(ros_size, 0);

			// The carved file carries the table and the bodies, not the erased
			// tail of the bank: what is there is copied and the rest stays zero,
			// the way an unused bank reads.
			if (!file || !file.read(reinterpret_cast<char*>(bank.data()), ros_size))
			{
				const std::streamsize got = file ? file.gcount() : 0;

				if (got <= 0)
				{
					return;
				}

				std::fill(bank.begin() + static_cast<std::ptrdiff_t>(got), bank.end(), std::uint8_t{0});
			}

			std::copy(bank.begin(), bank.end(), image.begin() + bank0);
			std::copy(bank.begin(), bank.end(), image.begin() + bank1);
		}

		void write_extnor(bytes& image, const console& c)
		{
			// CELL_EXTNOR_AREA: a marker, the length of the hashed block and its
			// SHA-1, then the block itself - country code, the drive's brand and
			// model and its serial, space padded.  These are the console's own
			// HDD settings, so this region is really the modeled console's.
			zeros(image, extnor_offset, 0x20000);
			std::memcpy(image.data() + extnor_offset, "CELL_EXTNOR_AREA", 16);
			put_be32(image, extnor_offset + 0x10, 1);
			put_be32(image, extnor_offset + 0x20, 0x200);
			put_be32(image, extnor_offset + 0x24, 0x44);

			text_at(image, extnor_info + 0x04, c.hdd_model, 0x2C, ' ');
			text_at(image, extnor_info + 0x30, c.hdd_serial, 0x10, ' ');

			std::array<std::uint8_t, 20> hash{};
			sha1(image.data() + extnor_info, 0x200, hash.data());
			std::copy(hash.begin(), hash.end(), image.begin() + extnor_offset + 0x2C);
		}
	}

	std::vector<region> layout(chip flash)
	{
		std::vector<region> out;

		if (flash == chip::emmc)
		{
			// The NAND/eMMC map: the same regions, moved, plus the eFlash area
			// that holds /dev_flash - and with it the VSH - below 0xF00000.
			out.push_back({"bootldr", 0x000000, 0x40000, true});
			out.push_back({"flash header", 0x040000, 0x200, true});
			out.push_back({"table of contents", emmc_toc, 0x600, true});

			for (const toc_entry& entry : toc_emmc)
			{
				const std::string_view name{entry.name};
				const bool modeled = name == "asecure_loader" || name.starts_with("trvk") || name == "ros";

				out.push_back({entry.name, entry.offset, entry.size, modeled});
			}

			out.push_back({"flash header (second)", 0xF00000, 0x1000, true});
			out.push_back({"/dev_flash", dev_flash, 0xC7C0000, false});
			out.push_back({"/dev_flash2", 0xD700000, 0x1000000, false});
			out.push_back({"/dev_flash3", 0xE700000, 0x80000, false});
			out.push_back({"cell_ext_os_area", 0xE780000, 0x10, false});
			out.push_back({"bootldr mirror", emmc_bootldr_mirror, 0x40000, true});
			return out;
		}

		out.push_back({"flash header", 0x000000, 0x200, true});
		out.push_back({"flash format", 0x000200, 0x200, true});
		out.push_back({"table of contents", toc_offset, 0x400, true});

		for (const toc_entry& entry : toc)
		{
			const std::string_view name{entry.name};
			const bool modeled = name == "asecure_loader" || name == "trvk_prg0" || name == "trvk_prg1" ||
				name.starts_with("ros") || name == "extnor" || name == "bootldr";

			out.push_back({entry.name, entry.offset, entry.size, modeled});
		}

		out.push_back({"flash header (second)", 0xF00000, 0x1000, true});
		return out;
	}

	namespace
	{
		bytes build_nor(const console& c)
		{
		bytes image(image_size, 0xFF);

		// The two magic headers: 0xFACE0FF/DEADBEEF at the start and
		// 0xFACE0FF/DEADFACE at 0xF00000, the word at +0x14 each time.
		zeros(image, 0x10, 0x10);
		put_be32(image, 0x14, 0x0FACE0FF);
		put_be32(image, 0x1C, 0xDEADBEEF);

		// The flash format block: "IFI\0" and two version words.
		zeros(image, 0x200, 0x10);
		std::memcpy(image.data() + 0x200, "IFI\0", 4);
		put_be32(image, 0x204, 1);
		put_be32(image, 0x208, 2);

		// The table of contents.
		zeros(image, toc_offset, 0x10 + static_cast<std::uint32_t>(std::size(toc)) * 0x30);
		put_be32(image, toc_offset + 0x04, static_cast<std::uint32_t>(std::size(toc)));

		for (std::size_t i = 0; i < std::size(toc); i++)
		{
			const std::uint32_t at = toc_offset + 0x10 + static_cast<std::uint32_t>(i) * 0x30;
			put_be64(image, at + 0x00, toc[i].offset - toc_offset);
			put_be64(image, at + 0x08, toc[i].size);
			text_at(image, at + 0x10, toc[i].name, 0x20, 0);
		}

		// asecure_loader: its own small table names the one file in it, metldr,
		// which sits 0x40 bytes after the table (the name in the entry is then
		// 0x20 before metldr's header, which is where the loader looks for it).
		const chain_revision& rev = revision_for(c);
		const std::string metldr_name = c.boot_loader == "metldr" ? "metldr" : "metldr.2";
		const std::uint32_t metldr_length = rev.metldr.blocks * 0x10 + 0x40;

		zeros(image, 0x800, 0x40);
		put_be32(image, 0x800, 1);
		put_be32(image, 0x804, 1);
		put_be64(image, 0x808, asecure_size);
		put_be64(image, 0x810, metldr_offset - 0x800);
		put_be64(image, 0x818, metldr_length);
		text_at(image, 0x820, metldr_name, 0x20, 0);
		seal(image, metldr_offset, rev.metldr, c, metldr_name);

		// The revoke lists: trvk_prg0 and trvk_prg1 at their fixed NOR slots.
		write_revoke_list(image, 0x040000, 0x2C0);
		write_revoke_list(image, 0x060000, 0x2E0);

		// The second magic header, then the block that carries the HDD info.
		zeros(image, 0xF00010, 0x10);
		put_be32(image, 0xF00014, 0x0FACE0FF);
		put_be32(image, 0xF0001C, 0xDEADFACE);

		write_extnor(image, c);

		// Both CoreOS banks carry a header and a table; the bodies are the
		// firmware, which the emulator keeps as files, so they stay erased - 
		// unless the firmware's CoreOS was extracted, in which case both banks
		// carry it.
		write_ros_bank(image, ros0_offset);
		write_ros_bank(image, ros1_offset);
		install_coreos(image, c, ros0_offset, ros1_offset);

		// bootldr (lv0ldr): the last 256 KiB of the chip.  It is the other half
		// of the chain, sealed in the same update and so carrying the same nonce.
		seal(image, bootldr_offset, rev.bootldr, c, "lv0ldr");

		// What the flash writer or bgtoolset installed, when one was run against
		// this console: the patch image's window, copied into the active bank.
		if (!c.coreos_patch.empty() && c.coreos_patch_span)
		{
			const writer_mode mode = c.coreos_patch_span == writer_stock_bytes ? writer_mode::stock : writer_mode::span_493;
			std::string error;

			apply_patch(image, c.coreos_patch, window_plan(mode), error);
		}

		return image;
		}

		// The eMMC map a superslim uses - the same one NAND uses, so a DEX
		// superslim's image carries its /dev_flash and the VSH that lives in it
		// as the eFlash area below 0xF00000.  The boot chain moves with the map:
		// bootldr at flash 0 (and again at 0xF000000), metldr inside the
		// asecure_loader region at 0x40000, and one ros region for both banks.
		bytes build_emmc(const console& c)
		{
			bytes image(emmc_size, 0xFF);

			const chain_revision& rev = revision_for(c);
			const std::string metldr_name = c.boot_loader == "metldr" ? "metldr" : "metldr.2";
			const std::uint32_t metldr_length = rev.metldr.blocks * 0x10 + 0x40;

			// bootldr first, at flash 0.  It is the other half of the chain, so
			// its label follows the generation.
			const std::string lv0ldr_name = c.boot_loader == "metldr" ? "lv0ldr" : "lv0ldr.2";
			seal(image, 0x0, rev.bootldr, c, lv0ldr_name);

			// The flash header and table at 0x40000.
			zeros(image, 0x40000, 0x200);
			put_be32(image, 0x40014, 0x0FACE0FF);
			put_be32(image, 0x4001C, 0xDEADBEEF);
			zeros(image, emmc_toc, 0x10 + static_cast<std::uint32_t>(std::size(toc_emmc)) * 0x30);
			put_be32(image, emmc_toc + 0x04, static_cast<std::uint32_t>(std::size(toc_emmc)));

			for (std::size_t i = 0; i < std::size(toc_emmc); i++)
			{
				const std::uint32_t at = emmc_toc + 0x10 + static_cast<std::uint32_t>(i) * 0x30;
				put_be64(image, at + 0x00, toc_emmc[i].offset - emmc_toc);
				put_be64(image, at + 0x08, toc_emmc[i].size);
				text_at(image, at + 0x10, toc_emmc[i].name, 0x20, 0);
			}

			// asecure_loader, with metldr in it.
			zeros(image, emmc_asecure, 0x40);
			put_be32(image, emmc_asecure, 1);
			put_be32(image, emmc_asecure + 4, 1);
			put_be64(image, emmc_asecure + 8, 0x40000);
			put_be64(image, emmc_asecure + 0x10, emmc_metldr - emmc_asecure);
			put_be64(image, emmc_asecure + 0x18, metldr_length);
			text_at(image, emmc_asecure + 0x20, metldr_name, 0x20, 0);
			seal(image, emmc_metldr, rev.metldr, c, metldr_name);

			// The revoke lists behind one header at 0x91800: offsets to both.
			zeros(image, 0x91800, 0x2000);
			put_be64(image, 0x91800, 0x20);
			put_be64(image, 0x91808, 0x20);
			put_be64(image, 0x91810, 0x2000);
			write_revoke_list(image, 0x91800 + 0x20, 0x2C0);
			write_revoke_list(image, 0x91800 + 0x1010, 0x2E0);

			// Both CoreOS banks inside the one ros region.
			write_ros_bank(image, emmc_ros);
			write_ros_bank(image, emmc_ros + ros_size);
			install_coreos(image, c, emmc_ros, emmc_ros + ros_size);

			// The eFlash area: the second magic header, and - on a debug console
			// - the cell_ext_os_area marker that says the console has one.
			zeros(image, 0xF00010, 0x10);
			put_be32(image, 0xF00014, 0x0FACE0FF);
			put_be32(image, 0xF0001C, 0xDEADFACE);

			if (c.dex)
			{
				std::memcpy(image.data() + 0xE780000, "cell_ext_os_area", 16);
			}

			// The bootldr mirror, and the label its neighbour carries so the
			// chain reads back from either copy.
			std::copy_n(image.begin(), 0x40000, image.begin() + emmc_bootldr_mirror);
			text_at(image, emmc_bootldr_mirror - 0x20, lv0ldr_name, 0x20, 0);

			if (!c.coreos_patch.empty() && c.coreos_patch_span)
			{
				const writer_mode mode = c.coreos_patch_span == writer_stock_bytes ? writer_mode::stock : writer_mode::span_493;
				std::string error;

				apply_patch(image, c.coreos_patch, window_plan(mode), error);
			}

			return image;
		}
	}

	bytes build(const console& c)
	{
		return c.flash == chip::emmc ? build_emmc(c) : build_nor(c);
	}

	std::uint32_t image_size_of(chip flash)
	{
		return flash == chip::emmc ? emmc_size : image_size;
	}

	bool write_file(const std::string& path, const bytes& image, std::string& error)
	{
		std::ofstream file(path, std::ios::binary | std::ios::trunc);

		if (!file)
		{
			error = "the file could not be opened for writing";
			return false;
		}

		file.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));

		if (!file)
		{
			error = "the image could not be written";
			return false;
		}

		return true;
	}

	writer_plan plan_writer(const console& c, writer_mode mode)
	{
		writer_plan plan = window_plan(mode);

		plan.notes.emplace_back("the window starts at bank 0x200, where the writer reads from 0x8C000020 on NOR");

		if (mode == writer_mode::stock)
		{
			plan.notes.emplace_back("it ends at " + hex(plan.start + plan.bytes) + ", just short of lv0's slot at " + hex(lv0_slot));
		}
		else
		{
			plan.notes.emplace_back("the 4.93 fourth step ends at " + hex(plan.start + plan.bytes) + ", lv0's own extent");
			plan.notes.emplace_back("lv0's file record runs to " + hex(lv0_2_slot - 0x20) + ", so lv0.2's slot and everything after it are left alone");
		}

		if (c.boot_loader != "metldr")
		{
			plan.refused = true;
			plan.reason = "the shipped writer reads the console's minimum firmware version and refuses anything above 3.56; "
				"a Metldr.2 console carries 3.60 or higher";
			return plan;
		}

		if (!c.coreos_patch.empty())
		{
			plan.refused = true;
			plan.reason = "the console already runs patched CoreOS - the toolset refuses it, and there is nothing to write that is not there already";
			return plan;
		}

		return plan;
	}

	bool check_patch(const std::string& path, const writer_plan& plan, std::string& error)
	{
		std::ifstream file(path, std::ios::binary | std::ios::ate);

		if (!file)
		{
			error = "the patch image could not be opened";
			return false;
		}

		const auto size = static_cast<std::uint64_t>(file.tellg());

		if (size < std::uint64_t{plan.bytes} + 0x20)
		{
			error = "the image is " + std::to_string(size) + " bytes, shorter than the writer's window plus its 0x20-byte header";
			return false;
		}

		return true;
	}

	bool apply_patch(bytes& image, const std::string& path, const writer_plan& plan, std::string& error)
	{
		if (!check_patch(path, plan, error))
		{
			return false;
		}

		if (plan.start + plan.bytes > ros_size)
		{
			error = "the window does not fit in the CoreOS bank";
			return false;
		}

		std::ifstream file(path, std::ios::binary);

		if (!file)
		{
			error = "the patch image could not be opened";
			return false;
		}

		file.seekg(0x20);

		const std::uint32_t at = ros0_offset + plan.start;

		if (!file.read(reinterpret_cast<char*>(image.data() + at), plan.bytes))
		{
			error = "the patch image could not be read";
			return false;
		}

		return true;
	}

	std::string summary(const console& c)
	{
		std::string out = c.flash == chip::emmc
			? "Emulated PS3 flash: the 256 MiB eMMC map of a superslim (the NAND map), built from this console's modeled state.\n\n"
			: "Emulated PS3 flash: a 16 MiB NOR chip, built from this console's modeled state.\n\n";

		out += c.dex
			? "Console: DEX (debug). Its /dev_flash is not sealed per console, which is why a debug console's can be copied as it is.\n"
			: "Console: CEX (retail).\n";

		out += "Boot chain: ";
		out += c.boot_loader == "metldr" ? "metldr + lv0ldr" : "metldr.2 + lv0ldr.2";
		out += ". The two containers are sealed for this console's id, so the chain pairs with itself.\n";

		out += "\nModeled: the flash header and format blocks, the table of contents, the asecure_loader table that\n"
			"names metldr, the SCE records of trvk_prg0/1, the ros0/ros1 bank headers with their entry tables, the\n"
			"CELL_EXTNOR_AREA block with this console's HDD name and serial and its SHA-1, and the bootldr header.\n";

		out += "\nReserved, left erased: eEID, cISD, cCSD, the revoke packages, cvtrm and the four revocation\n"
			"blocks.";

		if (c.coreos_image.empty())
		{
			out += " The CoreOS file bodies as well: the emulator keeps the firmware as files and has no\n"
				"ciphertext, so there is nothing to copy into them; the layout says where each one sits.";
		}
		else
		{
			out += " The CoreOS bodies are not left erased: they are the bank carved from the console's flash dump.\n";
		}

		out += "\n";

		if (c.flash == chip::emmc)
		{
			out += "\nThe eFlash area carries /dev_flash, /dev_flash2 and /dev_flash3 at their documented offsets - where\n"
				"the VSH lives (vsh.self is also the last entry of each ros bank's table) - plus the second magic\n"
				"header and, on a debug console, the cell_ext_os_area marker. Those regions stay erased for the same\n"
				"reason: the files they would hold are the emulator's dev_flash directory, not a flash image.\n";
		}

		if (!c.coreos_image.empty())
		{
			const ps3::coreos::verdict bank = ps3::coreos::inspect_file(c.coreos_image);
			out += "\nCoreOS: carved from the console's flash dump, " + c.coreos_image + ".\n" + bank.summary() + "\n";
		}

		if (c.coreos_patch.empty())
		{
			out += "\nCoreOS patch: none installed. The flash writer and bgtoolset both write a flat copy of a bank\n"
				"starting at bank 0x200; neither has been run against this console.\n";
		}
		else
		{
			out += "\nCoreOS patch: installed from " + c.coreos_patch + ", " + std::to_string(c.coreos_patch_span) + " bytes written at bank 0x200.\n";
		}

		return out;
	}
}
