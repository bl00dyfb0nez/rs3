#include "stdafx.h"
#include "lv1.h"

#include "Emu/Cell/ErrorCodes.h"
#include "Emu/Memory/vm.h"
#include "Emu/Memory/vm_ptr.h"

#include <cstring>

LOG_CHANNEL(lv1_log, "LV1");

namespace lv1
{
	namespace
	{
		// The arguments are the console's r3-r10, so a call that asks for 4 of
		// them has them in args[0..3].
		std::int64_t allocate_memory(const std::array<std::uint64_t, 8>& args)
		{
			const std::uint64_t size = args[0];
			const std::uint64_t align = args[1] ? args[1] : 0x10000;
			const bool zero = args[2] != 0;
			const std::uint64_t out = args[3];

			if (!size || size > 0xFFFFFFFFull || !out || (align & (align - 1)))
			{
				return CELL_EINVAL;
			}

			// RPCS3 has no separate physical pool for lv1 to hand out: the guest
			// memory the emulator allocates is the memory lv2 would map, so the
			// address returned here is the one the caller can use.
			const u32 addr = vm::alloc(static_cast<u32>(size), vm::main, static_cast<u32>(align));

			if (!addr)
			{
				return CELL_ENOMEM;
			}

			if (zero && vm::check_addr(addr, vm::page_writable, static_cast<u32>(size)))
			{
				std::memset(vm::base(addr), 0, static_cast<usz>(size));
			}

			if (!vm::ptr<u64>{vm::cast(out)}.try_write(addr))
			{
				vm::dealloc(addr, vm::main);
				return CELL_EFAULT;
			}

			lv1_log.notice("lv1_allocate_memory: 0x%x bytes at 0x%x (align 0x%x, zero %d)",
				size, addr, align, zero ? 1 : 0);
			return CELL_OK;
		}

		std::int64_t release_memory(const std::array<std::uint64_t, 8>& args)
		{
			const std::uint64_t addr = args[0];

			if (!addr)
			{
				return CELL_EINVAL;
			}

			if (!vm::dealloc(static_cast<u32>(addr), vm::main))
			{
				lv1_log.warning("lv1_release_memory(0x%x): not an allocation", addr);
				return CELL_EINVAL;
			}

			return CELL_OK;
		}
	}

	std::int64_t call(std::uint64_t address, const std::array<std::uint64_t, 8>& args)
	{
		const entry* const call = find(address);

		if (!call)
		{
			lv1_log.warning("lv1 call to 0x%x: not an entry point in the table", address);
			return CELL_ENOSYS;
		}

		switch (call->id)
		{
		case call_id::allocate_memory:
			return allocate_memory(args);
		case call_id::release_memory:
			return release_memory(args);
		case call_id::map_htab:
		case call_id::unmap_htab:
			// The hash table is lv1's mapping of lv2's page tables.  RPCS3 maps
			// guest memory itself, so there is no table for the call to change.
			lv1_log.todo("%s: RPCS3 has no hash table to map", call->name);
			return CELL_ENOSYS;
		case call_id::query_region_info:
			lv1_log.todo("%s: the logical partition regions are not modelled", call->name);
			return CELL_ENOSYS;
		case call_id::create_repository_node:
		case call_id::get_repository_node_value:
			lv1_log.todo("%s: RPCS3 has no repository", call->name);
			return CELL_ENOSYS;
		case call_id::undocumented_231:
			lv1_log.todo("%s: undocumented", call->name);
			return CELL_ENOSYS;
		case call_id::set_hvcall_table:
		case call_id::set_hvcall_table_entry_invalid:
		case call_id::mm_call_table:
			// lv1's own call plumbing: the table the hypervisor keeps for its
			// HV calls, which this emulator answers directly instead.
			lv1_log.todo("%s: the hypervisor's own call table is not modelled", call->name);
			return CELL_ENOSYS;
		}

		return CELL_ENOSYS;
	}
}
