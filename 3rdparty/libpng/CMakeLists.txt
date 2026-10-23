# libPNG
# Select the version of libpng to use, default is builtin
if (NOT USE_SYSTEM_LIBPNG)
	# We use libpng's static library and don't need to build the shared library and run the tests
	set(PNG_SHARED OFF CACHE BOOL "Build shared lib")
	set(PNG_TESTS OFF CACHE BOOL "Build libpng tests")
	set(SKIP_INSTALL_ALL ON)

	# libpng generates pnglibconf by preprocessing pnglibconf.c and passes
	# ZLIB_INCLUDE_DIRS as its only zlib include path. With the builtin zlib the
	# ZLIB::ZLIB target already carries those paths, so find_package(ZLIB) can
	# return without setting the variable and the generation step fails with
	# "Cannot open include file: 'zlib.h'". Point it at the builtin zlib.
	if (NOT USE_SYSTEM_ZLIB AND NOT ZLIB_INCLUDE_DIRS)
		set(ZLIB_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/../zlib/zlib"
		                      "${CMAKE_CURRENT_BINARY_DIR}/../zlib/zlib")
	endif()

	add_subdirectory(libpng EXCLUDE_FROM_ALL)
	target_include_directories(png_static SYSTEM INTERFACE "${libpng_BINARY_DIR}" "${libpng_SOURCE_DIR}")

	set(LIBPNG_TARGET png_static PARENT_SCOPE)
else()
	find_package(PNG REQUIRED)

	add_library(3rdparty_system_libpng INTERFACE)
	target_include_directories(3rdparty_system_libpng SYSTEM INTERFACE ${PNG_INCLUDE_DIR})
	target_link_libraries(3rdparty_system_libpng INTERFACE ${PNG_LIBRARY})
	target_compile_definitions(3rdparty_system_libpng INTERFACE ${PNG_DEFINITIONS})

	set(LIBPNG_TARGET 3rdparty_system_libpng PARENT_SCOPE)
endif()
