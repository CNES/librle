PROJECT(rle C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

include(FindPkgConfig)
include(tools.cmake)

# Options
#
OPTION(BUILD_TESTS "Build simple tests" ON)
OPTION(BUILD_DOC "Build documentation" ON)
OPTION(TIME_DEBUG "Print encapsulation and deencapsulation durations" OFF)
OPTION(COVERAGE "Allow code coverage. (requires GCOV. Optionnaly LCOV and genhtml for reports)" OFF)
OPTION(FUZZING "Instrumentation for fuzzing with AFL and ASAN. (requires AFL and ASAN)" OFF)

INCLUDE_DIRECTORIES(include)

SET(DESCRIPTION_SUMMARY "Return Link Encapsulation library")
SET(TARGET_NAME rle)

SET(ABI_VERSION_MAJOR "2")
SET(ABI_VERSION_MINOR "0")
SET(ABI_VERSION_PATCH "0")
SET(ABI_VERSION "${ABI_VERSION_MAJOR}.${ABI_VERSION_MINOR}.${ABI_VERSION_PATCH}")

SET(SRC_LIBRLE
	src/crc.c
	src/deencap.c
	src/encap.c
	src/pack.c
	src/header.c
	src/trailer.c
	src/fragmentation.c
	src/fragmentation_buffer.c
	src/reassembly.c
	src/reassembly_buffer.c
	src/rle_ctx.c
	src/rle_transmitter.c
	src/rle_receiver.c
	src/rle_conf.c
	src/rle_log.c
	src/rle_header_proto_type_field.c
)

add_definitions("-g -W -Wall -Wextra -Wuninitialized
-Wstrict-prototypes -Wcast-align -Wmissing-prototypes -Wchar-subscripts
-Wpointer-arith -Winline  -Wno-conversion -Wshadow -fno-strict-aliasing")

ADD_LIBRARY(rle SHARED ${SRC_LIBRLE})

TARGET_LINK_LIBRARIES(rle)
SET_TARGET_PROPERTIES(rle PROPERTIES SOVERSION ${ABI_VERSION_MAJOR} VERSION ${ABI_VERSION})

IF (FUZZING)
	set(ENV{AFL_USE_ASAN} 1)
	set(ENV{AFL_HARDEN} 1)
	set(CMAKE_C_COMPILER afl-gcc)
	add_definitions(-fno-omit-frame-pointer -g)
ELSE(FUZZING)
	add_definitions("-Werror")
ENDIF(FUZZING)

IF (BUILD_TESTS)
	ENABLE_TESTING()
	ADD_CUSTOM_TARGET(check COMMAND
	                  ${CMAKE_CTEST_COMMAND} --no-compress-output -T Test)
	ADD_SUBDIRECTORY(tests EXCLUDE_FROM_ALL)

	# check coding style
	ADD_CUSTOM_TARGET(coding_style
		COMMAND ${CMAKE_SOURCE_DIR}/contrib/coding_style_check.sh
		        ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
	ADD_DEPENDENCIES(check coding_style) # to build with make check
ENDIF(BUILD_TESTS)

IF (BUILD_DOC)
	ADD_SUBDIRECTORY(doc)
ENDIF(BUILD_DOC)

IF (TIME_DEBUG)
	add_definitions("-DTIME_DEBUG")
ENDIF(TIME_DEBUG)

IF (COVERAGE)
	add_definitions("-fprofile-arcs -ftest-coverage -O0")
	TARGET_LINK_LIBRARIES(rle
        gcov)
ELSE(COVERAGE)
	add_definitions("-O2")
ENDIF(COVERAGE)

INSTALL(TARGETS rle
	DESTINATION lib/)

INSTALL(FILES
	include/rle.h
	DESTINATION include/)

gen_pkg_config("${TARGET_NAME}" "${DESCRIPTION_SUMMARY}" "" "")
