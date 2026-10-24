#include "stdafx.h"

#include "Crypto/unself.h"

#include "Loader/PUP.h"
#include "Loader/TAR.h"
#include "Loader/ps3_boot_chain.h"
#include "Loader/ps3_coreos.h"

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

		void put_be32(bytes& image, std::size_t at, std::uint32_t value)
		{
			image[at + 0] = static_cast<std::uint8_t>(value >> 24);
			image[at + 1] = static_cast<std::uint8_t>(value >> 16);
			image[at + 2] = static_cast<std::uint8_t>(value >> 8);
			image[at + 3] = static_cast<std::uint8_t>(value);
		}

		void put_be64(bytes& image, std::size_t at, std::uint64_t value)
		{
			for (int i = 0; i < 8; i++)
			{
				image[at + i] = static_cast<std::uint8_t>(value >> ((7 - i) * 8));
			}
		}

		void put_name(bytes& image, std::size_t at, const std::string& name)
		{
			const std::size_t len = std::min<std::size_t>(name.size(), name_size);

			for (std::size_t i = 0; i < len; i++)
			{
				image[at + i] = static_cast<std::uint8_t>(name[i]);
			}
		}

		// A TAR member's name as the bank's records carry it: the TAR writes
		// "./lv0" where the bank names "lv0".
		std::string record_name(const std::string& path)
		{
			std::string name = path;

			while (name.starts_with("./"))
			{
				name.erase(0, 2);
			}

			while (name.starts_with('/'))
			{
				name.erase(0, 1);
			}

			return name;
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
			return "CoreOS: " + (error.empty() ? std::string{"not extracted"} : error);
		}

		std::string out = "CoreOS " + (version.empty() ? "(version unknown)" : version) + ": " +
			std::to_string(files.size()) + " files, " + hex(bank.size()) + " bytes";

		if (!bank.empty())
		{
			out += "\n" + inspect(bank).summary();
		}

		return out;
	}

	image read(const std::string& pup_path, const std::string& files_dir)
	{
		image out;

		fs::file pup_f(pup_path);

		if (!pup_f)
		{
			out.error = "the file could not be opened";
			return out;
		}

		pup_object pup(std::move(pup_f));

		if (pup.operator pup_error() != pup_error::ok)
		{
			out.error = "the file is not a firmware PUP";

			if (!pup.get_formatted_error().empty())
			{
				out.error += ": " + pup.get_formatted_error();
			}

			return out;
		}

		if (fs::file version = pup.get_file(pup_version_entry))
		{
			out.version = version.to_string();

			if (const usz newline = out.version.find('\n'); newline != umax)
			{
				out.version.erase(newline);
			}
		}

		fs::file pkg = pup.get_file(pup_coreos_entry);

		if (!pkg)
		{
			out.error = "the firmware carries no CoreOS.PKG";
			return out;
		}

		// CoreOS.PKG is a SELF like the dev_flash packages: the TAR is the
		// third file it makes, the encrypted body and its ELF around it.
		SCEDecrypter self_dec(pkg);

		if (!self_dec.LoadHeaders() || !self_dec.LoadMetadata(SCEPKG_ERK, SCEPKG_RIV) || !self_dec.DecryptData())
		{
			out.error = "CoreOS.PKG could not be decrypted";
			return out;
		}

		std::vector<fs::file> members = self_dec.MakeFile();

		if (members.size() < 3)
		{
			out.error = "CoreOS.PKG does not hold a TAR";
			return out;
		}

		tar_object tar(members[2]);

		if (!fs::create_path(files_dir))
		{
			out.error = "the CoreOS files could not be written to " + files_dir;
			return out;
		}

		if (!tar.extract(files_dir, false))
		{
			out.error = "the CoreOS TAR could not be extracted";
			return out;
		}

		std::vector<file> files;

		for (const std::string& name : tar.get_filenames())
		{
			fs::stat_t stat{};

			if (!fs::get_stat(join(files_dir, name), stat) || stat.is_directory)
			{
				continue;
			}

			files.push_back({record_name(name), 0, stat.size});
		}

		if (files.empty())
		{
			out.error = "the CoreOS TAR holds no files";
			return out;
		}

		// The table sits at the front of the bank and the files follow it in
		// the same order, each starting where the one before it ends.  That is
		// the whole of the layout the console's installer writes.
		const std::uint64_t base = header_size + static_cast<std::uint64_t>(files.size()) * record_size;

		if (base > bank_size)
		{
			out.error = "the CoreOS TAR names more files than a bank's table holds";
			return out;
		}

		std::uint64_t cursor = (base + 0xF) & ~std::uint64_t{0xF};

		for (file& entry : files)
		{
			entry.offset = cursor;

			if (entry.size > bank_size - cursor)
			{
				out.error = "the CoreOS files do not fit in a bank: " + entry.name + " runs past its end";
				return out;
			}

			cursor += entry.size;
		}

		bytes bank(bank_size, 0);

		put_be64(bank, 0x08, bank_size);
		put_be32(bank, 0x10, 1);
		put_be32(bank, 0x14, static_cast<std::uint32_t>(files.size()));
		put_be64(bank, 0x18, bank_size);

		for (std::size_t i = 0; i < files.size(); i++)
		{
			const std::uint64_t at = header_size + static_cast<std::uint64_t>(i) * record_size;

			put_name(bank, at, files[i].name);
			put_be64(bank, at + 0x20, files[i].offset);
			put_be64(bank, at + 0x28, files[i].size);

			if (!files[i].size)
			{
				continue;
			}

			fs::file source(join(files_dir, files[i].name));

			if (!source || source.read_at(0, bank.data() + files[i].offset, files[i].size) != files[i].size)
			{
				out.error = "the extracted file " + files[i].name + " could not be read back";
				return out;
			}
		}

		out.found = true;
		out.files = std::move(files);
		out.bank = std::move(bank);

		coreos_log.success("CoreOS %s: %d files laid out in a bank of 0x%x bytes", out.version, static_cast<int>(out.files.size()), bank_size);
		return out;
	}

	bool write(const image& img, const std::string& dir, std::string& error)
	{
		if (!img.found || img.bank.size() != bank_size)
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

	installed install(const std::string& pup_path, const std::string& dir)
	{
		installed out;

		image img = read(pup_path, join(dir, "files"));

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
