# - Try to find iconv include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(ICONV)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  ICONV_ROOT_DIR             Set this variable to the root installation of
#                            iconv if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  ICONV_FOUND                System has iconv, include and library dirs found
#  ICONV_INCLUDE_DIR          The iconv include directories.
#  ICONV_LIBRARY              The iconv library (possibly includes a thread
#                            library e.g. required by pf_ring's iconv)
#  HAVE_PF_RING              If a found version of iconv supports PF_RING

find_path(ICONV_ROOT_DIR
    NAMES include/iconv.h
)

find_path(ICONV_INCLUDE_DIR
    NAMES iconv.h
    HINTS ${ICONV_ROOT_DIR}/include
)

find_library(ICONV_LIBRARY
    NAMES ICONV
    HINTS ${ICONV_ROOT_DIR}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ICONV DEFAULT_MSG
    ICONV_LIBRARY
    ICONV_INCLUDE_DIR
)

include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${ICONV_LIBRARY})
check_c_source_compiles("int main() { return 0; }" ICONV_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)

# check if linking against iconv also needs to link against a thread library
if (NOT ICONV_LINKS_SOLO)
    find_package(Threads)
    if (THREADS_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${ICONV_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
        check_c_source_compiles("int main() { return 0; }" ICONV_NEEDS_THREADS)
        set(CMAKE_REQUIRED_LIBRARIES)
    endif ()
    if (THREADS_FOUND AND ICONV_NEEDS_THREADS)
        set(_tmp ${ICONV_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
        list(REMOVE_DUPLICATES _tmp)
        set(ICONV_LIBRARY ${_tmp}
            CACHE STRING "Libraries needed to link against iconv" FORCE)
    else ()
        message(FATAL_ERROR "Couldn't determine how to link against iconv")
    endif ()
endif ()

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES ${ICONV_LIBRARY})
check_function_exists(iconv_close HAVE_PF_RING)
set(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
    ICONV_ROOT_DIR
    ICONV_INCLUDE_DIR
    ICONV_LIBRARY
)