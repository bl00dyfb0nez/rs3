#pragma once

#include <cstdint>
#include <string>
#include <string_view>

// The System Controller, as the console exposes it on its UART.
//
// A console's Cell talks to its SysCon over a serial link: the test bench
// protocol the PS3 UART Guide describes, with an AES handshake before the
// controller takes a command.  RPCS3 has no serial port, so the controller is
// emulated here - the UART page in Advanced PS3 Tools is the terminal on the
// other end of that wire - and the EEPROM it reads and writes is the one the
// guest's sys_ss_update_manager calls touch, so a write on the terminal is what
// the console reads back.
namespace ps3::syscon
{
	// EEPROM as the controller holds it: one byte per offset, 0xFF when unset.
	std::uint8_t read_eeprom(std::uint32_t offset);
	void write_eeprom(std::uint32_t offset, std::uint8_t value);

	// The recover mode byte at 0x48C07 (docs/fsm.txt, docs/recovery.txt): 0xFF
	// is inactive, anything else puts the console in recovery/service mode.
	void set_recover_mode(bool enabled);
	bool recover_mode();

	// One command line as the test bench sends it, answered the way the
	// controller answers.  `sw` is the SW framing (115200, "command:checksum"
	// and one answer line per command); otherwise CXR (57600, "C:checksum:command"
	// and a single R: line).
	std::string uart_command(std::string_view line, bool sw);

	// Whatever went over the wire so far, newest last, for the terminal.
	std::string transcript();
	void clear();
}
