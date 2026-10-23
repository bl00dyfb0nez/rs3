#include "stdafx.h"

#include "ps3_xreg.h"

#include <algorithm>
#include <cstring>

namespace ps3::xreg
{
	namespace
	{
		std::uint16_t le16(const std::uint8_t* p)
		{
			return static_cast<std::uint16_t>(std::uint16_t{p[0]} | (std::uint16_t{p[1]} << 8));
		}

		void put_le16(bytes& out, std::size_t at, std::uint16_t value)
		{
			out[at + 0] = static_cast<std::uint8_t>(value);
			out[at + 1] = static_cast<std::uint8_t>(value >> 8);
		}

		bool is_terminator(const std::uint8_t* p)
		{
			return std::memcmp(p, terminator.data(), terminator.size()) == 0;
		}

		std::string read_text(const std::uint8_t* p, std::size_t room)
		{
			std::string out;

			for (std::size_t i = 0; i < room && p[i]; i++)
			{
				out.push_back(static_cast<char>(p[i]));
			}

			return out;
		}

		void put_text(bytes& out, std::size_t at, std::size_t room, const std::string& text)
		{
			std::fill_n(out.begin() + at, room, std::uint8_t{0});
			std::memcpy(out.data() + at, text.data(), std::min<std::size_t>(text.size(), room));
		}

		std::uint32_t read_number(const bytes& data)
		{
			std::uint32_t out = 0;

			for (std::size_t i = 0; i < data.size() && i < 4; i++)
			{
				out |= static_cast<std::uint32_t>(data[i]) << (i * 8);
			}

			return out;
		}

		void put_number(bytes& data, std::uint32_t number)
		{
			data.assign(4, 0);

			for (std::size_t i = 0; i < 4; i++)
			{
				data[i] = static_cast<std::uint8_t>(number >> (i * 8));
			}
		}
	}

	const value* registry::find(std::string_view path) const
	{
		for (const value& entry : values)
		{
			if (entry.path == path)
			{
				return &entry;
			}
		}

		return nullptr;
	}

	bool registry::set_text(std::string_view path, std::string_view text)
	{
		const key* owner = nullptr;

		for (const key& entry : keys)
		{
			if (entry.path == path)
			{
				owner = &entry;
			}
		}

		if (!owner)
		{
			// The console adds the key and its value together.
			key added;
			added.path = std::string{path};
			added.id = static_cast<std::uint16_t>(0x1000 + keys.size());
			keys.push_back(std::move(added));
			owner = &keys.back();
		}

		for (value& entry : values)
		{
			if (entry.path == path)
			{
				entry.kind = type::text;
				entry.data.assign(text.begin(), text.end());
				return true;
			}
		}

		value added;
		added.path = std::string{path};
		added.id = owner->id;
		added.kind = type::text;
		added.data.assign(text.begin(), text.end());
		values.push_back(std::move(added));
		return true;
	}

	bool registry::set_integer(std::string_view path, std::uint32_t number)
	{
		if (!set_text(path, {}))
		{
			return false;
		}

		for (value& entry : values)
		{
			if (entry.path == path)
			{
				entry.kind = type::integer;
				put_number(entry.data, number);
				return true;
			}
		}

		return false;
	}

	bool registry::set_boolean(std::string_view path, bool state)
	{
		if (!set_integer(path, state ? 1 : 0))
		{
			return false;
		}

		for (value& entry : values)
		{
			if (entry.path == path)
			{
				entry.kind = type::boolean;
				return true;
			}
		}

		return false;
	}

	bool set_region(registry& reg, std::string_view letters)
	{
		if (letters.size() != 2)
		{
			return false;
		}

		const std::uint32_t code = (std::uint32_t{static_cast<std::uint8_t>(letters[0])} << 8) |
			static_cast<std::uint8_t>(letters[1]);

		return reg.set_integer("/setting/parental/dvdRegion", code);
	}

	std::string region(const registry& reg)
	{
		const value* entry = reg.find("/setting/parental/dvdRegion");

		if (!entry || entry->data.size() < 2)
		{
			return {};
		}

		const std::uint32_t code = read_number(entry->data);
		std::string out;
		out.push_back(static_cast<char>((code >> 8) & 0xFF));
		out.push_back(static_cast<char>(code & 0xFF));
		return out;
	}

	bool parse(const bytes& image, registry& out, std::string& error)
	{
		if (image.size() < file_size)
		{
			error = "the registry file is smaller than 0x40000 bytes";
			return false;
		}

		// The key table, from 0x10 up to the value table.
		std::size_t at = header_size;

		while (at + 7 <= value_table)
		{
			if (is_terminator(image.data() + at))
			{
				break;
			}

			if (at + 5 > value_table)
			{
				error = "a key entry runs past the key table";
				return false;
			}

			const std::uint16_t length = le16(image.data() + at + 2);

			if (length == 0 || at + 5 + length + 1 > value_table)
			{
				error = "a key entry's length does not fit the table";
				return false;
			}

			key entry;
			entry.id = le16(image.data() + at);
			entry.state = image[at + 4];
			entry.path = read_text(image.data() + at + 5, length);
			out.keys.push_back(std::move(entry));
			at += 5 + length + 1;
		}

		// The value table, from 0x10000: every entry states its own length, so
		// the gaps the console leaves are simply scrolled over.
		at = value_table;

		while (at + 7 <= image.size())
		{
			if (is_terminator(image.data() + at))
			{
				break;
			}

			if (at + 9 > image.size())
			{
				error = "a value entry runs past the file";
				return false;
			}

			const std::uint16_t key_offset = le16(image.data() + at + 2);
			const std::uint16_t length = le16(image.data() + at + 6);

			if (at + 9 + length + 1 > image.size())
			{
				error = "a value entry's length does not fit the file";
				return false;
			}

			value entry;
			entry.flags = le16(image.data() + at);
			entry.id = le16(image.data() + at + 4);
			entry.kind = static_cast<type>(image[at + 8]);
			entry.data.assign(image.begin() + at + 9, image.begin() + at + 9 + length);

			// The key the value belongs to sits at key_offset + the header size.
			const std::size_t owner = header_size + key_offset;

			if (owner >= header_size && owner < value_table)
			{
				entry.path = read_text(image.data() + owner + 5, le16(image.data() + owner + 2));
			}

			out.values.push_back(std::move(entry));
			at += 9 + length + 1;
		}

		if (out.keys.empty())
		{
			error = "no key entries were found";
			return false;
		}

		return true;
	}

	bool write(const registry& reg, bytes& image, std::string& error)
	{
		image.assign(file_size, 0);

		// The header the doc calls static.
		image[0] = 0xBC;
		image[1] = 0xAD;
		image[2] = 0xAD;
		image[3] = 0xBC;
		image[4] = 0x00;
		image[5] = 0x00;
		image[6] = 0x00;
		image[7] = 0x90;
		image[8] = 0x00;
		image[9] = 0x00;
		image[10] = 0x00;
		image[11] = 0x02;
		image[12] = 0xBC;
		image[13] = 0xAD;
		image[14] = 0xAD;
		image[15] = 0xBC;

		// The key table first: the value entries point into it by offset, so the
		// offsets have to be known before they are written.
		std::vector<std::uint16_t> offsets;
		std::size_t at = header_size;

		for (const key& entry : reg.keys)
		{
			const std::size_t need = 5 + entry.path.size() + 1;

			if (at + need + 7 > value_table)
			{
				error = "the key table does not fit before the value table";
				return false;
			}

			offsets.push_back(static_cast<std::uint16_t>(at - header_size));
			put_le16(image, at, entry.id);
			put_le16(image, at + 2, static_cast<std::uint16_t>(entry.path.size()));
			image[at + 4] = entry.state;
			put_text(image, at + 5, entry.path.size() + 1, entry.path);
			at += need;
		}

		if (at + 7 > value_table)
		{
			error = "there is no room for the key terminator";
			return false;
		}

		std::copy(terminator.begin(), terminator.end(), image.begin() + at);

		// Then the values, each pointing at its key's entry.
		at = value_table;

		for (const value& entry : reg.values)
		{
			const std::size_t need = 9 + entry.data.size() + 1;

			if (at + need + 7 > image.size())
			{
				error = "the value table does not fit the file";
				return false;
			}

			std::uint16_t key_offset = 0;

			for (std::size_t i = 0; i < reg.keys.size(); i++)
			{
				if (reg.keys[i].path == entry.path)
				{
					key_offset = offsets[i];
					break;
				}
			}

			put_le16(image, at, entry.flags);
			put_le16(image, at + 2, key_offset);
			put_le16(image, at + 4, entry.id);
			put_le16(image, at + 6, static_cast<std::uint16_t>(entry.data.size()));
			image[at + 8] = static_cast<std::uint8_t>(entry.kind);
			std::memcpy(image.data() + at + 9, entry.data.data(), entry.data.size());
			at += need;
		}

		if (at + 7 > image.size())
		{
			error = "there is no room for the value terminator";
			return false;
		}

		std::copy(terminator.begin(), terminator.end(), image.begin() + at);

		return true;
	}
}
