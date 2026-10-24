#include "stdafx.h"

#include "ps3_boot_chain.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <initializer_list>
#include <string>
#include <utility>

namespace ps3::boot
{
	namespace
	{
		std::uint32_t be32(const std::uint8_t* p)
		{
			return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) |
			       (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
		}

		std::uint64_t be64(const std::uint8_t* p)
		{
			return (std::uint64_t{be32(p)} << 32) | be32(p + 4);
		}

		std::string hex64(std::uint64_t value)
		{
			char text[24];
			std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(value));
			return text;
		}

		std::string hex(const std::uint8_t* p, std::size_t n)
		{
			static constexpr char digits[] = "0123456789ABCDEF";
			std::string out;
			out.reserve(n * 2);

			for (std::size_t i = 0; i < n; i++)
			{
				out.push_back(digits[p[i] >> 4]);
				out.push_back(digits[p[i] & 0xF]);
			}

			return out;
		}

		bool erased(std::span<const std::uint8_t> image, std::uint32_t offset, std::uint32_t len)
		{
			if (offset + len > image.size())
			{
				return false;
			}

			for (std::uint32_t i = 0; i < len; i++)
			{
				if (image[offset + i] != 0xFF)
				{
					return false;
				}
			}

			return true;
		}

		// The name that precedes a container header: 16 ASCII bytes, NUL padded,
		// stopped at the first non-printable byte.  Empty when the slot holds
		// something else.
		std::string name_before(std::span<const std::uint8_t> image, std::uint32_t offset)
		{
			if (offset < name_gap)
			{
				return {};
			}

			std::string out;

			for (std::uint32_t i = offset - name_gap; i < offset; i++)
			{
				const std::uint8_t c = image[i];

				if (c == 0)
				{
					continue;
				}

				if (c < 0x20 || c > 0x7E)
				{
					return {};
				}

				out.push_back(static_cast<char>(c));
			}

			return out;
		}

		bool matches(std::string_view name, std::string_view prefix)
		{
			return name.empty() || name == prefix || (name.size() == prefix.size() + 2 && name.substr(0, prefix.size()) == prefix && name.ends_with(".2"));
		}

		// A bank record's name: 0x20 ASCII bytes, NUL padded.  A record that reads
		// as FF (an empty slot) or holds something else has no name.
		std::string entry_name(std::span<const std::uint8_t> image, std::uint32_t at)
		{
			std::string out;

			for (std::uint32_t i = 0; i < 0x20 && at + i < image.size(); i++)
			{
				const std::uint8_t c = image[at + i];

				if (c == 0)
				{
					continue;
				}

				if (c < 0x20 || c > 0x7E)
				{
					return {};
				}

				out.push_back(static_cast<char>(c));
			}

			return out;
		}

		// One stage of the figure's tree, read out of the bank: the first of the
		// labels the stage may carry that the table actually names.
		stage read_stage(const bank& ros, std::string_view name, std::string_view loader,
			std::initializer_list<std::string_view> files)
		{
			stage out;
			out.name = name;
			out.loader = loader;
			out.file = files.size() ? std::string{*files.begin()} : std::string{};

			const bank_entry* found = nullptr;

			for (const std::string_view file : files)
			{
				const bank_entry* const e = ros.entry(file);

				if (!e)
				{
					continue;
				}

				// A slot that is named but empty is still the label the reason
				// should carry.
				if (!found)
				{
					out.file = e->name;
				}

				if (e->present)
				{
					found = e;
					out.file = e->name;
					break;
				}
			}

			if (!found)
			{
				out.error = out.name + " (" + out.file + ") is not in the CoreOS bank at " + hex64(ros.offset);
				return out;
			}

			out.found = true;
			out.offset = std::uint64_t{ros.offset} + found->offset;
			out.size = found->size;
			out.slot_size = found->size;

			// A stage whose SELF declares more than its slot is one whose payload
			// runs on past the slot - that is lv0, whose four loaders live in the
			// bytes between 0x300600 and 0x3E7210 on a 4.93 bank.
			if (found->self_size > found->size)
			{
				out.size = found->self_size;
				out.extent_from_self = true;
			}

			out.self_readable = found->self_size != 0;

			if (found->offset + out.size > ros.size)
			{
				out.error = out.name + " (" + out.file + ") runs past the end of the CoreOS bank: " +
					hex64(found->offset) + " + " + hex64(out.size) + " bytes in a bank of " + hex64(ros.size);
			}

			return out;
		}

		// The console runs the bank's stages in the figure's order and stops on
		// the first one it cannot: nothing below it is reached, so nothing below
		// it is blamed - which is why a broken lv1 is reported as lv1 and not as
		// a missing vsh.  An image that carries no bank at all (a payload of the
		// loaders alone) has no stages to judge.
		void judge_stages(chain& out)
		{
			if (!out.ros.found)
			{
				return;
			}

			// The loadable lv0 is the `lv0` entry on every generation: on 3.60+ the
			// `lv0.2` entry next to it is the record bootldr checks lv0 against,
			// not the loader, so it is only a fallback for a bank that has no
			// `lv0` of its own.
			out.lv0 = read_stage(out.ros, "lv0", "lv0ldr", {"lv0", "lv0.2"});

			out.lv1 = read_stage(out.ros, "lv1", "lv1ldr", {"lv1.self"});
			out.lv2 = read_stage(out.ros, "lv2", "lv2ldr", {"lv2_kernel.self"});

			// lv0's own payload: the four loaders the decrypted ELF keeps in its
			// slot table (0x8044138; ids 0x01 lv1ldr, 0x02 lv2ldr, 0x03 appldr,
			// 0x04 isoldr).  A sealed image cannot show the slots, so what says
			// they are there is lv0's SELF reaching past its 0x500-byte slot.
			static constexpr const char* loader_names[] = {"lv1ldr", "lv2ldr", "appldr", "isoldr"};

			const bool carries = out.lv0.usable() && out.lv0.extent_from_self;

			for (const char* const name : loader_names)
			{
				stage s;
				s.name = name;
				s.loader = "lv0";
				s.file = "inside lv0";
				s.offset = out.lv0.offset;
				s.size = out.lv0.size;
				s.slot_size = out.lv0.slot_size;
				s.found = carries;

				if (!carries && out.lv0.usable() && out.lv0.self_readable)
				{
					s.error = std::string{name} + ": lv0's SELF declares " + hex64(out.lv0.size) +
						" bytes, no more than its " + hex64(out.lv0.slot_size) + "-byte slot, so the loaders it encapsulates are not in the image";
				}

				out.encapsulated.push_back(std::move(s));
			}

			for (const stage* const s : {&out.lv0, &out.lv1, &out.lv2})
			{
				if (s->usable())
				{
					continue;
				}

				out.failures.emplace_back(s->error + (s->name == "lv1"
					? " - lv1ldr has nothing to load, so lv2 and vsh.self never start"
					: s->name == "lv2"
					? " - lv2ldr has nothing to load, so vsh.self never starts"
					: " - lv0ldr has nothing to hand over, so the console stops before lv1"));
				return;
			}

			// The stages above are all present, but the four loaders they hand over
			// through are carried by lv0's extent: a stub that stops at the slot
			// has none of them, and nothing else in the image would say so.
			if (!carries && out.lv0.usable() && out.lv0.self_readable)
			{
				out.failures.emplace_back("lv0 (" + out.lv0.file + ") does not carry the four loaders it encapsulates (lv1ldr, lv2ldr, appldr, isoldr): "
					"its SELF declares " + hex64(out.lv0.size) + " bytes, no more than its " + hex64(out.lv0.slot_size) +
					"-byte slot, so lv1, lv2 and vsh.self never start");
			}
		}

		// Both slots, their pairing and the reasons a console would refuse to
		// boot.  A payload that carries neither loader has nothing to answer for.
		void judge(chain& out)
		{
			if (out.flash == geometry::payload && !out.metldr.found && !out.lv0ldr.found)
			{
				return;
			}

			const auto report = [&out](const container& c, const char* what, std::string_view prefix)
			{
				if (!c.found)
				{
					out.failures.emplace_back(std::string{what} + " was not found in the image");
					return;
				}

				if (!c.error.empty())
				{
					out.failures.emplace_back(std::string{what} + ": " + c.error);
					return;
				}

				if (!c.name.empty() && !matches(c.name, prefix))
				{
					out.failures.emplace_back(std::string{what} + " carries '" + c.name + "' at its slot");
				}
			};

			report(out.metldr, "metldr/metldr.2", "metldr");
			report(out.lv0ldr, "lv0ldr/lv0ldr.2", "lv0ldr");

			out.has_loaders = out.metldr.usable() && out.lv0ldr.usable();

			// The two halves are sealed for one console in one update, and both
			// carry that console's 0x14 nonce: our own dumps show the same twelve
			// bytes in metldr and lv0ldr, and the card's pair shows the same in
			// metldr.2 and lv0ldr.  metldr holds the tag it will accept for
			// lv0ldr, so halves from different updates cannot authenticate - the
			// console answers with the three beeps.  This is checked before any
			// label, because a label can be erased and the containers in a PUP
			// can be relabelled: the nonce is in the sealed header itself.
			if (out.has_loaders && out.metldr.nonce != out.lv0ldr.nonce)
			{
				out.failures.emplace_back("the chain is mixed: metldr and lv0ldr were sealed for different consoles (nonce " +
					out.metldr.nonce + " against " + out.lv0ldr.nonce + ")");
			}

			// The generation is written in the name, and the name is just a label
			// in the slot: a dump can carry a header with the label erased.  Only
			// two labels that are both there can contradict each other.
			const bool named = !out.metldr.name.empty() && !out.lv0ldr.name.empty();

			if (out.has_loaders && named && out.metldr.is_360() != out.lv0ldr.is_360())
			{
				out.failures.emplace_back("the boot chain is mixed: " + out.metldr.name + " pairs with " +
					(out.metldr.is_360() ? "lv0ldr.2" : "lv0ldr") + ", not " + out.lv0ldr.name);
			}

			// Below the loaders: what the bank names, in the order the console runs
			// it.  A payload whose bank is absent has nothing here to judge.
			if (out.has_loaders)
			{
				judge_stages(out);
			}
		}
	}

	container read_container(std::span<const std::uint8_t> image, std::uint32_t offset)
	{
		container out;
		out.offset = offset;

		if (offset > image.size() || image.size() - offset < header_size)
		{
			out.error = "the header is past the end of the image";
			return out;
		}

		out.found = true;
		out.name = name_before(image, offset);

		if (erased(image, offset, header_size))
		{
			out.erased = true;
			out.error = "the slot reads as erased (all FF)";
			return out;
		}

		const std::uint8_t* h = image.data() + offset;
		const std::uint32_t size1 = be32(h + 0x00);
		const std::uint32_t size2 = be32(h + 0x10);

		// The two words are different fields, not a repeat of one value: 0x00
		// counts the encrypted blocks and 0x10 the whole container, so a
		// revision with an unencrypted tail has them disagree (bootldr.txt).
		if (!size1 || size1 > max_blocks || !size2 || size2 > max_blocks)
		{
			out.error = "implausible block count";
			return out;
		}

		if (size2 < size1)
		{
			out.error = "the total block count is below the encrypted one";
			return out;
		}

		out.blocks = size1;
		out.total_blocks = size2;
		out.length = header_size + size2 * 16;

		if (out.length > image.size() - offset)
		{
			out.error = "the container runs past the end of the image";
			return out;
		}

		out.counter = hex(h + 0x04, 12);
		out.nonce   = hex(h + 0x14, 12);
		out.key     = hex(h + 0x20, 16);
		out.tag     = hex(h + 0x30, 16);
		return out;
	}

	container find_container(std::span<const std::uint8_t> image, std::string_view name)
	{
		if (name.empty() || image.size() < header_size + name_gap)
		{
			return {};
		}

		const auto first = image.begin();
		const auto last = image.end() - (header_size + name_gap);

		for (auto it = std::search(first, last, name.begin(), name.end()); it != last;
			it = std::search(it + 1, last, name.begin(), name.end()))
		{
			const std::uint32_t header_at = static_cast<std::uint32_t>(it - first) + name_gap;
			container c = read_container(image, header_at);

			if (c.found && !c.erased && c.error.empty())
			{
				return c;
			}
		}

		return {};
	}

	const bank_entry* bank::entry(std::string_view name) const
	{
		for (const bank_entry& e : entries)
		{
			if (e.name == name)
			{
				return &e;
			}
		}

		return nullptr;
	}

	bank read_bank(std::span<const std::uint8_t> image, std::uint32_t offset)
	{
		bank out;
		out.offset = offset;

		if (offset > image.size() || image.size() - offset < 0x30)
		{
			out.error = "the header is past the end of the image";
			return out;
		}

		const std::uint8_t* const h = image.data() + offset;
		const std::uint64_t size1 = be64(h + 0x08);
		const std::uint32_t version = be32(h + 0x10);
		const std::uint32_t count = be32(h + 0x14);
		const std::uint64_t size2 = be64(h + 0x18);

		// The two size words are the same field written twice; the version is 1
		// and the table is short.  Anything else is not a bank header.
		if (version != 1 || !count || count > 0x100 || size1 != size2
			|| size1 < 0x30ull + std::uint64_t{count} * 0x30ull || size1 > 0x2000000ull)
		{
			out.error = "the header is not a CoreOS bank's";
			return out;
		}

		if (std::uint64_t{offset} + 0x30ull + std::uint64_t{count} * 0x30ull > image.size())
		{
			out.error = "the bank table runs past the end of the image";
			return out;
		}

		out.found = true;
		out.size = size1;
		out.count = count;
		out.entries.reserve(count);

		std::size_t named = 0;

		for (std::uint32_t i = 0; i < count; i++)
		{
			const std::uint32_t at = offset + 0x30 + i * 0x30;
			bank_entry e;
			e.name = entry_name(image, at);
			e.offset = be64(image.data() + at + 0x20);
			e.size = be64(image.data() + at + 0x28);
			e.erased = e.offset == ~std::uint64_t{0} && e.size == ~std::uint64_t{0};
			e.present = !e.name.empty() && !e.erased && e.size != 0;
			named += e.name.empty() ? 0 : 1;

			// The SELF at the slot starts 0x10 bytes in: magic "SCE\0", the header
			// size at +0x0C and the file's own length at +0x18.  lv0's length is
			// the one that matters: 0xE7100 against a 0x500-byte slot, i.e. the
			// bytes its four loaders sit in.
			if (e.present)
			{
				const std::uint64_t self_at = std::uint64_t{offset} + e.offset + 0x10;

				if (self_at + 0x20 <= image.size())
				{
					const std::uint8_t* const s = image.data() + self_at;
					const std::uint32_t header_size = be32(s + 0x0C);
					const std::uint64_t file_size = be64(s + 0x18);

					if (s[0] == 'S' && s[1] == 'C' && s[2] == 'E' && s[3] == 0
						&& header_size >= 0x20 && header_size <= 0x10000
						&& file_size >= 0x20 && file_size <= 0x2000000)
					{
						e.self_size = file_size;
					}
				}
			}

			out.entries.push_back(std::move(e));
		}

		// One name would also match a stretch of code with a 1 in the version
		// word; a bank names a dozen things.
		if (named < 3)
		{
			out = {};
			out.offset = offset;
			out.error = "the table names nothing";
		}

		return out;
	}

	bank find_bank(std::span<const std::uint8_t> image)
	{
		// The bank is found through the name of one of its stages: its table is a
		// run of 0x30-byte records, so the header is a few records back from the
		// name and has to agree with itself when read.  This finds a bank in a
		// NAND dump or in a PUP member, where the documented NOR offset does not
		// apply.
		static constexpr std::string_view names[] = {"lv1.self", "lv2_kernel.self", "default.spp"};

		for (const std::string_view name : names)
		{
			if (image.size() <= name.size())
			{
				return {};
			}

			const auto first = image.begin();
			const auto last = image.end() - name.size();

			for (auto it = std::search(first, last, name.begin(), name.end()); it != last;
				it = std::search(it + 1, last, name.begin(), name.end()))
			{
				const std::uint32_t at = static_cast<std::uint32_t>(it - first);

				for (std::uint32_t back = 1; back <= 0x100; back++)
				{
					if (at < back * 0x30)
					{
						break;
					}

					bank b = read_bank(image, at - back * 0x30);

					if (b.found && back <= b.count && b.entries[back - 1].name == name)
					{
						return b;
					}
				}
			}
		}

		return {};
	}

	chain inspect(std::span<const std::uint8_t> image, geometry flash)
	{
		chain out;
		out.flash = flash;

		if (flash == geometry::nor)
		{
			out.metldr = read_container(image, nor_metldr_offset);
			out.lv0ldr = read_container(image, nor_lv0ldr_offset);

			// A carved image or a dump that starts elsewhere: fall back to the
			// name, which is also how a NAND image is read.
			if (!out.metldr.usable())
			{
				if (container c = find_container(image, "metldr.2"); c.found)
				{
					out.metldr = std::move(c);
				}
				else if (container d = find_container(image, "metldr"); d.found)
				{
					out.metldr = std::move(d);
				}
			}

			if (!out.lv0ldr.usable())
			{
				if (container c = find_container(image, "lv0ldr.2"); c.found)
				{
					out.lv0ldr = std::move(c);
				}
				else if (container d = find_container(image, "lv0ldr"); d.found)
				{
					out.lv0ldr = std::move(d);
				}
			}
		}
		else
		{
			// NAND and payloads: the addresses are not fixed, so the names decide.
			out.metldr = find_container(image, "metldr.2");
			if (!out.metldr.found)
			{
				out.metldr = find_container(image, "metldr");
			}

			out.lv0ldr = find_container(image, "lv0ldr.2");
			if (!out.lv0ldr.found)
			{
				out.lv0ldr = find_container(image, "lv0ldr");
			}
		}

		// The bank the loaders' stages come out of.  A NOR dump keeps ros0 at
		// 0x0C0000 and its second copy at 0x7C0000; anything else is found by its
		// table.
		if (flash == geometry::nor)
		{
			out.ros = read_bank(image, nor_ros0_offset);

			if (!out.ros.found)
			{
				out.ros = read_bank(image, nor_ros1_offset);
			}
		}

		if (!out.ros.found)
		{
			out.ros = find_bank(image);
		}

		judge(out);
		return out;
	}

	chain inspect_file(const std::string& path, geometry flash)
	{
		chain out;
		out.flash = flash;

		std::ifstream file(path, std::ios::binary);

		if (!file)
		{
			out.failures.emplace_back("the file could not be opened");
			return out;
		}

		file.seekg(0, std::ios::end);
		const std::uint64_t size = static_cast<std::uint64_t>(file.tellg());
		file.seekg(0);

		// A flash dump is small enough to look at whole.
		if (size <= (32u << 20))
		{
			std::vector<std::uint8_t> image(static_cast<std::size_t>(size));
			file.read(reinterpret_cast<char*>(image.data()), static_cast<std::streamsize>(image.size()));
			return inspect(image, flash);
		}

		// A file the size of a NAND image or a firmware PUP: sweep it in windows
		// that overlap by more than one container, so nothing straddles a cut.
		constexpr std::uint32_t window = 8u << 20;
		constexpr std::uint64_t overlap = header_size + max_blocks * 16ull + name_gap;
		std::vector<std::uint8_t> buffer(window);

		for (std::uint64_t pos = 0; pos < size; pos += window - overlap)
		{
			file.clear();
			file.seekg(static_cast<std::streamoff>(pos));
			file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
			const std::size_t got = static_cast<std::size_t>(file.gcount());

			if (!got)
			{
				break;
			}

			const std::span<const std::uint8_t> slice(buffer.data(), got);

			const auto take = [&slice, pos](container& slot, const char* newer, const char* older)
			{
				if (slot.usable())
				{
					return;
				}

				for (const char* name : {newer, older})
				{
					container c = find_container(slice, name);

					if (c.found && !c.erased && c.error.empty())
					{
						c.offset += static_cast<std::uint32_t>(pos);
						slot = std::move(c);
						return;
					}
				}
			};

			take(out.metldr, "metldr.2", "metldr");
			take(out.lv0ldr, "lv0ldr.2", "lv0ldr");

			// The bank's table is 12 KiB at the most, well inside one window's
			// overlap, so a bank found in a slice is whole even when the bank
			// itself is larger than the slice.
			if (!out.ros.found)
			{
				if (bank b = find_bank(slice); b.found)
				{
					b.offset += static_cast<std::uint32_t>(pos);
					out.ros = std::move(b);
				}
			}
		}

		judge(out);
		return out;
	}

	std::string chain::summary() const
	{
		static constexpr char digits[] = "0123456789ABCDEF";

		const auto hex32 = [](std::uint32_t v)
		{
			std::string s(8, '0');

			for (int i = 7; i >= 0; i--)
			{
				s[i] = digits[v & 0xF];
				v >>= 4;
			}

			return s;
		};

		const auto slot = [&hex32](const container& c, const char* fallback)
		{
			if (!c.found)
			{
				return std::string{fallback} + ": not found";
			}

			std::string line = (c.name.empty() ? std::string{fallback} : c.name) + " @ 0x" + hex32(c.offset);

			if (!c.error.empty())
			{
				line += ": " + c.error;
				return line;
			}

			line += ": " + std::to_string(c.blocks) + " blocks";

			if (c.total_blocks != c.blocks)
			{
				line += " of " + std::to_string(c.total_blocks);
			}

			line += " (" + std::to_string(c.length) + " bytes), tag " + c.tag;
			return line;
		};

		std::string out = slot(metldr, "metldr") + "\n" + slot(lv0ldr, "lv0ldr") + "\n";

		if (metldr.usable() && lv0ldr.usable())
		{
			const auto label = [](const container& c, const char* fallback)
			{
				return c.name.empty() ? std::string{fallback} + " (label erased)" : c.name;
			};

			// The figure's chain, in the order the console runs it: the two
			// containers, then the bank's stages and the VSH the app loader
			// starts out of dev_flash.
			out += "chain: " + label(metldr, "metldr") + " + " + label(lv0ldr, "lv0ldr") +
				" -> lv0 -> lv1 -> lv2 -> vsh.self" +
				(metldr.is_360() ? " (3.60+ boot chain)" : " (pre-3.60 boot chain)") + "\n";
		}

		if (ros.found)
		{
			out += "CoreOS bank @ 0x" + hex32(ros.offset) + ": " + std::to_string(ros.count) +
				" entries, " + hex64(ros.size) + " bytes\n";

			const auto stage_line = [](const stage& s)
			{
				std::string line = "  " + s.loader + " -> " + s.file;

				if (!s.found)
				{
					return line + ": not in the bank\n";
				}

				line += " @ " + hex64(s.offset) + ": " + hex64(s.size) + " bytes";

				if (s.extent_from_self)
				{
					line += " (the SELF's extent, past its " + hex64(s.slot_size) + "-byte slot)";
				}

				if (!s.error.empty())
				{
					line += " - " + s.error;
				}

				return line + "\n";
			};

			// The stages are only named when the chain was judged: a payload that
			// carries a bank but no loaders has nothing to answer for, and must
			// not read as three missing files.
			if (has_loaders)
			{
				out += stage_line(lv0) + stage_line(lv1) + stage_line(lv2);
				out += "  appldr -> vsh.self: in dev_flash, not in the bank\n";

				if (!encapsulated.empty())
				{
					std::string loaders;

					for (const stage& s : encapsulated)
					{
						loaders += (loaders.empty() ? "" : ", ") + s.name;
					}

					if (encapsulated.front().found)
					{
						out += "  lv0 carries " + loaders + " inside its extent (docs/ldrs.txt)\n";
					}
					else if (!encapsulated.front().error.empty())
					{
						out += "  lv0 does not reach the loaders it encapsulates (" + loaders + ")\n";
					}
					else
					{
						out += "  the loaders lv0 encapsulates (" + loaders + ") were not checked: its SELF is outside the bytes read\n";
					}
				}
			}
		}

		if (bootable())
		{
			out += flash == geometry::payload && !has_loaders ? "verdict: this payload carries no boot loaders, nothing to check\n" : "verdict: boots\n";
			return out;
		}

		out += "verdict: the console would not boot - three beeps and a flashing red light\n";

		for (const std::string& failure : failures)
		{
			out += "  - " + failure + "\n";
		}

		return out;
	}
}
