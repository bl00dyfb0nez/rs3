#pragma once

#include <cstdint>
#include <string>

// qcow2: the container a virtual machine reads, holding the same raw sectors a
// PS3 image is made of.
//
// `ps3::ufs2` works on raw sectors - the ATA layer, the disklabel and UFS2 do
// not care what carries them - so a qcow2 image is converted on the way in and
// on the way out instead of being a second code path inside the formatter:
//
//   raw_to_qcow2   format a raw image (ps3::ufs2::format_file), then pack it
//   qcow2_to_raw   unpack an image a VM wrote, then read it as a PS3 drive
//
// Only what a formatter produces is written: clusters that read as zeros stay
// unallocated, so an image of a freshly formatted drive is small.  Version 3 is
// produced and versions 2 and 3 are read; encrypted images are refused.
namespace ps3::qcow2
{
	// The virtual size of the image in bytes.
	bool size(const std::string& path, std::uint64_t& bytes, std::string& error);

	// Packs a raw image, zero clusters left unallocated.
	bool pack(const std::string& raw_path, const std::string& qcow2_path, std::string& error);

	// Unpacks an image to raw sectors of its full virtual size.
	bool unpack(const std::string& qcow2_path, const std::string& raw_path, std::string& error);
}
