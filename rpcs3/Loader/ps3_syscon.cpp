#include "stdafx.h"

#include "Loader/ps3_syscon.h"

#include "Crypto/aes.h"
#include "util/sysinfo.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

LOG_CHANNEL(syscon_log, "SysCon");

namespace ps3::syscon
{
	namespace
	{
		// Recursive: a command handler reads and writes the EEPROM, which locks
		// the same state the command itself was taken under.
		std::recursive_mutex g_mutex;
		std::string g_transcript;
		bool g_recover = false;

		// The system's own bytes, as lv2 starts out with them: language and vsh
		// target set, everything else erased (0xFF).
		std::unordered_map<std::uint32_t, std::uint8_t> g_eeprom
		{
			{0x48C18, 0x00},
			{0x48C19, 0x00},
			{0x48C1A, 0x00},
			{0x48C1B, 0x01},
			{0x48C1C, 0x00},
			{0x48C1D, 0x00},
			{0x48C1E, 0x00},
			{0x48C1F, 0x00},
		};

		constexpr std::array<std::uint8_t, 16> sc2tb{0x71, 0xf0, 0x3f, 0x18, 0x4c, 0x01, 0xc5, 0xeb, 0xc3, 0xf6, 0xa2, 0x2a, 0x42, 0xba, 0x95, 0x25};
		constexpr std::array<std::uint8_t, 16> tb2sc{0x90, 0x7e, 0x73, 0x0f, 0x4d, 0x4e, 0x0a, 0x0b, 0x7b, 0x75, 0xf0, 0x30, 0xeb, 0x1d, 0x9d, 0x36};
		constexpr std::array<std::uint8_t, 16> tb_value{0x33, 0x50, 0xBD, 0x78, 0x20, 0x34, 0x5C, 0x29, 0x05, 0x6A, 0x22, 0x3B, 0xA2, 0x20, 0xB3, 0x23};
		constexpr std::array<std::uint8_t, 16> zero{};
		constexpr std::array<std::uint8_t, 16> auth1r_header{0x10, 0x10, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		constexpr std::array<std::uint8_t, 16> auth2_header{0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

		int hex_value(char c)
		{
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			return -1;
		}

		std::vector<std::uint8_t> from_hex(std::string_view text)
		{
			std::vector<std::uint8_t> out;

			for (std::size_t i = 0; i + 1 < text.size(); i += 2)
			{
				const int hi = hex_value(text[i]);
				const int lo = hex_value(text[i + 1]);

				if (hi < 0 || lo < 0)
				{
					return {};
				}

				out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
			}

			return out;
		}

		std::string to_hex(const std::uint8_t* data, std::size_t size)
		{
			static constexpr char digits[] = "0123456789ABCDEF";
			std::string out;
			out.reserve(size * 2);

			for (std::size_t i = 0; i < size; i++)
			{
				out.push_back(digits[data[i] >> 4]);
				out.push_back(digits[data[i] & 0xF]);
			}

			return out;
		}

		std::string trim(std::string_view text)
		{
			std::size_t begin = 0;
			std::size_t end = text.size();

			while (begin < end && (text[begin] == ' ' || text[begin] == '\r' || text[begin] == '\n' || text[begin] == '\t'))
			{
				begin++;
			}

			while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\r' || text[end - 1] == '\n' || text[end - 1] == '\t'))
			{
				end--;
			}

			return std::string(text.substr(begin, end - begin));
		}

		std::string upper(std::string text)
		{
			for (char& c : text)
			{
				c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
			}

			return text;
		}

		std::vector<std::string> words(std::string_view text)
		{
			std::vector<std::string> out;
			std::string current;

			for (const char c : text)
			{
				if (c == ' ' || c == '\t')
				{
					if (!current.empty())
					{
						out.push_back(current);
						current.clear();
					}

					continue;
				}

				current.push_back(c);
			}

			if (!current.empty())
			{
				out.push_back(current);
			}

			return out;
		}

		bool parse_number(std::string_view text, std::uint32_t& out)
		{
			try
			{
				std::size_t used = 0;
				out = static_cast<std::uint32_t>(std::stoul(std::string(text), &used, 0));
				return used == text.size();
			}
			catch (...)
			{
				return false;
			}
		}

		std::vector<std::uint8_t> aes_cbc(bool encrypt, const std::array<std::uint8_t, 16>& key, const std::array<std::uint8_t, 16>& iv, const std::vector<std::uint8_t>& data)
		{
			if (data.empty() || data.size() % 16)
			{
				return {};
			}

			aes_context context{};

			if (encrypt)
			{
				aes_setkey_enc(&context, key.data(), 128);
			}
			else
			{
				aes_setkey_dec(&context, key.data(), 128);
			}

			std::array<std::uint8_t, 16> chain = iv;
			std::vector<std::uint8_t> out(data.size());

			if (aes_crypt_cbc(&context, encrypt ? AES_ENCRYPT : AES_DECRYPT, data.size(), chain.data(), data.data(), out.data()))
			{
				return {};
			}

			return out;
		}

		std::string checksum(const std::string& payload)
		{
			unsigned sum = 0;

			for (const char c : payload)
			{
				sum += static_cast<unsigned char>(c);
			}

			char text[8];
			std::snprintf(text, sizeof(text), "%02X", sum & 0xFF);
			return text;
		}

		void record(std::string_view direction, std::string_view line)
		{
			g_transcript += std::string(direction) + " " + std::string(line) + "\n";

			// The terminal is a window on the wire, not a log that grows without
			// bound.
			if (g_transcript.size() > 64 * 1024)
			{
				g_transcript.erase(0, g_transcript.size() - 48 * 1024);
			}
		}

		// The command itself, without its framing: the payload the controller
		// answers.  Empty when the command is not one it knows.
		std::string handle(std::string command)
		{
			const std::vector<std::string> parts = words(command);

			if (parts.empty())
			{
				return "NG 1";
			}

			const std::string& op = parts[0];

			if (op == "scopen")
			{
				return "OK 0 SC_READY";
			}

			if (op == "AUTH1")
			{
				if (parts.size() < 2)
				{
					return "NG 1";
				}

				std::array<std::uint8_t, 48> plain{};
				std::copy(tb_value.begin(), tb_value.end(), plain.begin() + 0x10);

				const std::vector<std::uint8_t> cipher = aes_cbc(true, sc2tb, zero, std::vector<std::uint8_t>(plain.begin(), plain.end()));

				if (cipher.size() != 48)
				{
					return "NG 1";
				}

				std::string payload = to_hex(auth1r_header.data(), auth1r_header.size());
				payload += to_hex(cipher.data(), cipher.size());
				return "OK 0 " + payload;
			}

			if (op == "AUTH2")
			{
				return "OK 0";
			}

			if (op == "EEP")
			{
				if (parts.size() < 3)
				{
					return "NG 1";
				}

				std::uint32_t address = 0;

				if (!parse_number(parts[2], address))
				{
					return "NG 1";
				}

				if (upper(parts[1]) == "GET")
				{
					const std::uint8_t value = read_eeprom(address);
					return "OK 0 " + to_hex(&value, 1);
				}

				if (upper(parts[1]) == "SET" && parts.size() >= 4)
				{
					std::uint32_t value = 0;

					if (!parse_number(parts[3], value))
					{
						return "NG 1";
					}

					write_eeprom(address, static_cast<std::uint8_t>(value));
					return "OK 0";
				}

				return "NG 1";
			}

			if (op == "r" || op == "R")
			{
				if (parts.size() < 2)
				{
					return "NG 1";
				}

				std::uint32_t address = 0;
				std::uint32_t count = 1;

				if (!parse_number(parts[1], address) || (parts.size() >= 3 && !parse_number(parts[2], count)) || count == 0 || count > 0x100)
				{
					return "NG 1";
				}

				std::string out = "OK 0";

				for (std::uint32_t i = 0; i < count; i++)
				{
					const std::uint8_t value = read_eeprom(address + i);
					out += " " + to_hex(&value, 1);
				}

				return out;
			}

			if (op == "w" || op == "W")
			{
				if (parts.size() < 3)
				{
					return "NG 1";
				}

				std::uint32_t address = 0;
				std::uint32_t value = 0;

				if (!parse_number(parts[1], address) || !parse_number(parts[2], value))
				{
					return "NG 1";
				}

				write_eeprom(address, static_cast<std::uint8_t>(value));
				return "OK 0";
			}

			if (op == "eepcsum")
			{
				unsigned sum = 0;

				for (std::uint32_t offset = 0x48C00; offset < 0x48D00; offset++)
				{
					sum += read_eeprom(offset);
				}

				char text[16];
				std::snprintf(text, sizeof(text), "%04X", sum & 0xFFFF);
				return "OK 0 " + std::string(text);
			}

			if (op == "errlog")
			{
				// No error has been recorded by the emulated controller: the
				// answer is the empty log, which is a valid one.
				return "OK 0";
			}

			if (op == "clearerrlog")
			{
				return "OK 0";
			}

			if (op == "patchvereep")
			{
				const std::string version = utils::get_firmware_version();
				return version.empty() ? "OK 0 0" : "OK 0 " + to_hex(reinterpret_cast<const std::uint8_t*>(version.data()), version.size());
			}

			if (op == "fantbl")
			{
				return "OK 0";
			}

			return "NG 1";
		}
	}

	std::uint8_t read_eeprom(std::uint32_t offset)
	{
		std::lock_guard lock(g_mutex);

		// The recover mode byte is the console's state, not a stored byte: it is
		// set while the machine is in recovery/service mode and erased after.
		if (offset == 0x48C07)
		{
			return g_recover ? 0x00 : 0xFF;
		}

		if (const auto found = g_eeprom.find(offset); found != g_eeprom.end())
		{
			return found->second;
		}

		return 0xFF;
	}

	void write_eeprom(std::uint32_t offset, std::uint8_t value)
	{
		std::lock_guard lock(g_mutex);

		if (offset == 0x48C07)
		{
			g_recover = value != 0xFF;
			return;
		}

		if (value != 0xFF)
		{
			g_eeprom[offset] = value;
		}
		else
		{
			g_eeprom.erase(offset);
		}
	}

	void set_recover_mode(bool enabled)
	{
		std::lock_guard lock(g_mutex);
		g_recover = enabled;
	}

	bool recover_mode()
	{
		std::lock_guard lock(g_mutex);
		return g_recover;
	}

	std::string uart_command(std::string_view line, bool sw)
	{
		const std::string text = trim(line);

		if (text.empty())
		{
			return {};
		}

		std::string command;

		if (sw)
		{
			// SW framing: "command:checksum".  The checksum is the controller's
			// to check; a line without one is taken as the command itself.
			const std::size_t colon = text.rfind(':');

			if (colon != std::string::npos && text.size() - colon - 1 == 2 && hex_value(text[colon + 1]) >= 0 && hex_value(text[colon + 2]) >= 0)
			{
				command = text.substr(0, colon);
			}
			else
			{
				command = text;
			}
		}
		else if (text.size() > 3 && text[0] == 'C' && text[1] == ':')
		{
			// CXR framing: "C:checksum:command".
			const std::size_t second = text.find(':', 2);
			command = second == std::string::npos ? text.substr(2) : text.substr(second + 1);
		}
		else
		{
			command = text;
		}

		std::string response;

		{
			std::lock_guard lock(g_mutex);
			record(">>", text);
			const std::string payload = handle(command);
			record("<<", payload);

			syscon_log.notice("UART: %s -> %s", command, payload);

			if (sw)
			{
				response = payload + ":" + checksum(payload) + "\r\n";
			}
			else
			{
				response = "R:" + checksum(payload) + ":" + payload + "\r\n";
			}
		}

		return response;
	}

	std::string transcript()
	{
		std::lock_guard lock(g_mutex);
		return g_transcript;
	}

	void clear()
	{
		std::lock_guard lock(g_mutex);
		g_transcript.clear();
	}
}
