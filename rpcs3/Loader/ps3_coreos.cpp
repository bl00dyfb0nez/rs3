#include "stdafx.h"

#include "Loader/ps3_boot_chain.h"
#include "Loader/ps3_coreos.h"
#include "Loader/ps3_flash.h"

#include <span>

LOG_CHANNEL(coreos_log, "CoreOS");

namespace ps3::coreos
{
	namespace
	{
		std::string hex(std::uint64_t value)
		{
			static constexpr char digits[] = "0123456789ABCDEF";

			std::string out = "0x";
			bool started = false;

			for (int i = 60; i >= 0; i -= 4)
			{
				const std::uint32_t nibble = static_cast<std::uint32_t>((value >> i) & 0xF);

				if (nibble || started || i == 0)
				{
					out.push_back(digits[nibble]);
					started = true;
				}
			}

			return out;
		}

		std::string join(const std::string& dir, const std::string& name)
		{
			if (dir.empty() || dir.ends_with('/') || dir.ends_with('\\'))
			{
				return dir + name;
			}

			return dir + "/" + name;
		}

		bool read_all(const std::string& path, bytes& out, std::string& error)
		{
			fs::file file(path);

			if (!file)
			{
				error = "the file could not be opened: " + path;
				return false;
			}

			const usz size = file.size();

			if (!size)
			{
				error = "the file is empty: " + path;
				return false;
			}

			out.resize(size);

			if (file.read(out.data(), out.size()) != out.size())
			{
				error = "the file could not be read: " + path;
				return false;
			}

			return true;
		}
	}

	std::string image::summary() const
	{
		if (!found)
		{
			return "CoreOS: " + (error.empty() ? std::string{"no bank"} : error);
		}

		std::string out = "CoreOS " + (version.empty() ? "(version unknown)" : version) + ": " +
			std::to_string(files.size()) + " files, " + hex(bank.size()) + " bytes";

		if (!source.empty())
		{
			out += " from " + source;
		}

		if (!bank.empty())
		{
			out += "\n" + inspect(bank).summary();
		}

		return out;
	}

	image read_dump(const std::string& dump_path, ps3::flash::chip flash)
	{
		image out;

		if (!read_all(dump_path, out.bank, out.error))
		{
			out.bank.clear();
			return out;
		}

		// ros0 sits at 0x0C0000 on both maps: the NOR table lists it there, and
		// the NAND/eMMC map puts the ros region - ros0 with ros1 behind it -
		// there as well.  The bank is 0x700000 bytes, so the image has to reach
		// the end of it.
		const std::uint32_t need = ps3::flash::ros0_offset + ps3::flash::ros_size;

		if (out.bank.size() < need)
		{
			out.error = fmt::format("the image is 0x%x bytes, too small to hold the ros bank at 0x%x", out.bank.size(), ps3::flash::ros0_offset);
			out.bank.clear();
			return out;
		}

		bytes bank(out.bank.begin() + ps3::flash::ros0_offset, out.bank.begin() + need);
		out.bank.clear();

		// The table is the console's, so the bank is judged by the same reader
		// the boot chain and the flash dump use, and a dump whose ros0 is
		// erased or something else is refused rather than copied.
		const ps3::boot::bank ros = ps3::boot::read_bank(bank, 0);

		if (!ros.found)
		{
			out.error = "the image carries no CoreOS bank at 0x" + hex(ps3::flash::ros0_offset) + ": " + ros.error;
			return out;
		}

		for (const ps3::boot::bank_entry& entry : ros.entries)
		{
			out.files.push_back({entry.name, entry.offset, entry.size});
		}

		// sdk_version is the one file in the table that is text: it says which
		// firmware the console's CoreOS was built for.
		if (const ps3::boot::bank_entry* const sdk = ros.entry("sdk_version"); sdk && sdk->present && sdk->offset + sdk->size <= bank.size())
		{
			out.version.assign(reinterpret_cast<const char*>(bank.data() + sdk->offset), static_cast<std::size_t>(sdk->size));

			while (!out.version.empty() && (out.version.back() == '\n' || out.version.back() == '\r'
				|| out.version.back() == '\0' || out.version.back() == ' '))
			{
				out.version.pop_back();
			}
		}

		// The table names where every body sits; past the last of them the bank
		// is erased on a console, so only what it carries is kept.  That is what
		// ros0.bin holds: the table and the bodies, not a megabyte of padding.
		std::uint64_t used = 0x20 + std::uint64_t{ros.count} * 0x30;

		for (const ps3::boot::bank_entry& entry : ros.entries)
		{
			if (entry.present && entry.offset + entry.size > used && entry.offset + entry.size <= bank.size())
			{
				used = entry.offset + entry.size;
			}
		}

		if (used < bank.size())
		{
			bank.resize(static_cast<std::size_t>(used));
		}

		out.found = true;
		out.source = dump_path;
		out.bank = std::move(bank);

		coreos_log.success("CoreOS: carved %d files out of ros0 at 0x%x of %s (%s)",
			static_cast<int>(out.files.size()), ps3::flash::ros0_offset, dump_path,
			flash == ps3::flash::chip::nor ? "the NOR map" : "the NAND/eMMC map");
		return out;
	}

	bool write(const image& img, const std::string& dir, std::string& error)
	{
		if (!img.found || img.bank.size() < 0x20 || img.bank.size() > bank_size)
		{
			error = "there is no CoreOS bank to write";
			return false;
		}

		if (!fs::create_path(dir))
		{
			error = "the directory could not be created: " + dir;
			return false;
		}

		// ros0 and ros1 are the same bank: the console keeps a second copy so a
		// failed write to one of them still leaves a bootable console.
		for (const char* const name : {"ros0.bin", "ros1.bin"})
		{
			fs::file out;
			const std::string path = join(dir, name);

			if (!out.open(path, fs::rewrite) || out.write(img.bank.data(), img.bank.size()) != img.bank.size())
			{
				error = "the bank could not be written: " + path;
				return false;
			}

			out.close();
		}

		return true;
	}

	image read_bank(const std::string& path)
	{
		image out;

		if (!read_all(path, out.bank, out.error))
		{
			return out;
		}

		const ps3::boot::bank ros = ps3::boot::read_bank(out.bank, 0);

		if (!ros.found)
		{
			out.error = ros.error.empty() ? "the file is not a CoreOS bank" : ros.error;
			return out;
		}

		for (const ps3::boot::bank_entry& entry : ros.entries)
		{
			out.files.push_back({entry.name, entry.offset, entry.size});
		}

		out.found = true;
		return out;
	}

	verdict inspect(std::span<const std::uint8_t> bank)
	{
		verdict out;

		const ps3::boot::bank ros = ps3::boot::read_bank(bank, 0);

		if (!ros.found)
		{
			out.error = ros.error.empty() ? "the header is not a CoreOS bank's" : ros.error;
			return out;
		}

		out.found = true;
		out.count = ros.count;

		const auto present = [&ros](std::string_view name) -> const ps3::boot::bank_entry*
		{
			const ps3::boot::bank_entry* const entry = ros.entry(name);
			return entry && entry->present ? entry : nullptr;
		};

		if (const ps3::boot::bank_entry* const lv0 = present("lv0"))
		{
			out.lv0 = true;

			// lv0 is the file the console loads: its SELF declares the extent
			// its four loaders sit in, which on 4.93 is shorter than the record
			// the bank holds (0xE7100 against 0xE7600).
			out.lv0_size = lv0->self_size > lv0->size ? lv0->self_size : lv0->size;
			out.loaders = lv0->self_size ? 4 : 0;
		}

		out.lv1 = present("lv1.self") != nullptr;
		out.lv2 = present("lv2_kernel.self") != nullptr;

		if (const ps3::boot::bank_entry* const sdk = present("sdk_version"); sdk && sdk->offset + sdk->size <= bank.size())
		{
			out.sdk_version.assign(reinterpret_cast<const char*>(bank.data() + sdk->offset), static_cast<std::size_t>(sdk->size));

			while (!out.sdk_version.empty() && (out.sdk_version.back() == '\n' || out.sdk_version.back() == '\r'
				|| out.sdk_version.back() == '\0' || out.sdk_version.back() == ' '))
			{
				out.sdk_version.pop_back();
			}
		}

		// The console runs the three stages in order and stops on the first one
		// it cannot: nothing below it is reached, so nothing below it is blamed.
		if (!out.lv0)
		{
			out.error = "lv0ldr has nothing to hand over: the bank names no lv0";
		}
		else if (!out.lv1)
		{
			out.error = "lv1ldr has nothing to load: the bank names no lv1.self, so lv2 and vsh.self never start";
		}
		else if (!out.lv2)
		{
			out.error = "lv2ldr has nothing to load: the bank names no lv2_kernel.self, so vsh.self never starts";
		}

		return out;
	}

	verdict inspect_file(const std::string& path)
	{
		bytes data;
		std::string error;

		if (!read_all(path, data, error))
		{
			verdict out;
			out.error = error;
			return out;
		}

		return inspect(data);
	}

	std::string verdict::summary() const
	{
		if (!found)
		{
			return "the bank cannot be read: " + (error.empty() ? std::string{"no header"} : error);
		}

		std::string out = "CoreOS bank: " + std::to_string(count) + " files";

		if (!sdk_version.empty())
		{
			out += ", sdk_version " + sdk_version;
		}

		out += lv0 ? ", lv0" : ", no lv0";
		out += lv1 ? ", lv1.self" : ", no lv1.self";
		out += lv2 ? ", lv2_kernel.self" : ", no lv2_kernel.self";

		if (loaders)
		{
			out += " (lv0 declares " + hex(lv0_size) + " bytes, its loaders with it)";
		}

		out += runs()
			? "\nthe console can run it: lv0, lv1 and lv2 are all in the bank"
			: "\nthe console would stop in it: " + error;

		return out;
	}

	installed install(const std::string& dump_path, const std::string& dir, ps3::flash::chip flash)
	{
		installed out;

		image img = read_dump(dump_path, flash);

		if (!img.found)
		{
			out.error = img.error;
			return out;
		}

		std::string error;

		if (!write(img, dir, error))
		{
			out.error = error;
			return out;
		}

		out.ok = true;
		out.bank = join(dir, "ros0.bin");
		out.version = img.version;
		out.summary = img.summary();
		return out;
	}

}
