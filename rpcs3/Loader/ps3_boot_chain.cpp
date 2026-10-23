#include "stdafx.h"

#include "ps3_boot_chain.h"

#include <algorithm>
#include <fstream>
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

			out += "chain: " + label(metldr, "metldr") + " + " + label(lv0ldr, "lv0ldr") +
				(metldr.is_360() ? " (3.60+ boot chain)" : " (pre-3.60 boot chain)") + "\n";
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
