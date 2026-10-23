#pragma once

#include <array>
#include <cstdint>
#include <string_view>

// The lv1 hypervisor's call table.
//
// On a console lv2 reaches lv1 by branching to an entry point inside lv1.self
// with the arguments in r3-r10, so a call is identified by its address, not by
// a number.  The addresses below are the ones in docs/lv1rev.txt, per revision:
// the eight memory/repository calls are documented for 3.15 only, and the call
// table plumbing for 3.15, 3.41 and 3.55.
//
// A function does not keep its address from one revision to the next (the same
// table sits at 0x364208 in 3.15, 0x362308 in 3.41 and 0x366088 in 3.55), so
// nothing is computed from one revision to another: an entry point that is not
// documented for a revision is 0 and simply not matched there.  Guessing would
// call the wrong function, which is worse than the honest CELL_ENOSYS.
//
// RPCS3 runs lv2 itself and has no lv1.self to execute, so the table is what
// makes those entry points callable from the CFW syscalls (sys_cfw_lv1_call):
// the memory call is answered with guest memory, and the calls that need a
// resource this emulator does not model - the hash table, the repository
// nodes - answer CELL_ENOSYS by name instead of being an unknown address.
namespace lv1
{
	enum class call_id : std::uint8_t
	{
		map_htab,
		unmap_htab,
		allocate_memory,
		release_memory,
		query_region_info,
		create_repository_node,
		get_repository_node_value,
		undocumented_231,
		set_hvcall_table,
		set_hvcall_table_entry_invalid,
		mm_call_table,
	};

	enum class revision : std::uint8_t
	{
		r315,
		r341,
		r355,
	};

	struct entry
	{
		call_id id;
		const char* name;
		std::uint8_t args;                      // arguments after the entry point, r3..r10
		std::array<std::uint32_t, 3> addresses;  // 3.15, 3.41, 3.55; 0 where not documented
	};

	inline constexpr std::array<entry, 11> table{{
		{call_id::map_htab, "lv1_map_htab", 1, {0x002D595C, 0, 0}},
		{call_id::unmap_htab, "lv1_unmap_htab", 0, {0x002D56B8, 0, 0}},
		{call_id::allocate_memory, "lv1_allocate_memory", 4, {0x002D72F0, 0, 0}},
		{call_id::release_memory, "lv1_release_memory", 2, {0x002D66A4, 0, 0}},
		{call_id::query_region_info, "lv1_query_logical_partition_address_region_info", 4, {0x002C9B24, 0, 0}},
		{call_id::create_repository_node, "lv1_create_repository_node", 6, {0x002DD014, 0, 0}},
		{call_id::get_repository_node_value, "lv1_get_repository_node_value", 6, {0x002DD260, 0, 0}},
		{call_id::undocumented_231, "lv1_undocumented_function_231", 2, {0x0030B560, 0, 0}},
		{call_id::set_hvcall_table, "set_lv1_hvcall_table", 2, {0x002C1F04, 0x002C02B4, 0x002C2B4C}},
		{call_id::set_hvcall_table_entry_invalid, "set_lv1_hvcall_table_entry_invalid", 2, {0x002C1F28, 0x002C02D8, 0x002C2B70}},
		{call_id::mm_call_table, "lv1_mm_call", 1, {0x00364208, 0x00362308, 0x00366088}},
	}};

	inline std::uint32_t address_of(const entry& call, revision rev)
	{
		return call.addresses[static_cast<unsigned>(rev)];
	}

	inline const entry* find(std::uint64_t address)
	{
		for (const entry& call : table)
		{
			for (const std::uint32_t at : call.addresses)
			{
				if (at && at == address)
				{
					return &call;
				}
			}
		}

		return nullptr;
	}

	inline const entry* find(std::string_view name)
	{
		for (const entry& call : table)
		{
			if (name == call.name)
			{
				return &call;
			}
		}

		return nullptr;
	}

	// Calls the entry the address names, with the console's argument registers
	// in order; the result is what r3 would hold on return.
	std::int64_t call(std::uint64_t address, const std::array<std::uint64_t, 8>& args);
}
