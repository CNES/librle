INCLUDE_DIRECTORIES(include ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

# check cmocka
PKG_CHECK_MODULES(CMOCKA REQUIRED cmocka)
include_directories(${CMOCKA_INCLUDE_DIRS})
link_directories(${CMOCKA_LIBRARY_DIRS})

IF (COVERAGE)
	add_definitions("-fprofile-arcs -ftest-coverage -O0")
ELSE(COVERAGE)
	add_definitions("-O2")
ENDIF(COVERAGE)

SET(SRC_LIBRLE_TESTS
	test_rle_common.c
	test_rle_encap.c
	test_rle_encap_ctxtless.c
	test_rle_frag_ctxtless.c
	test_rle_frag.c
	test_rle_pack.c
	test_rle_decap.c
	test_rle_misc.c
	test_rle_api_robustness.c)

ADD_LIBRARY(rle_tests SHARED ${SRC_LIBRLE_TESTS})

ADD_EXECUTABLE(test_rle test_rle.c)
TARGET_LINK_LIBRARIES(test_rle rle_tests rle)

ADD_EXECUTABLE(test_rle_memory
	../src/crc.c
	../src/deencap.c
	../src/encap.c
	../src/pack.c
	../src/header.c
	../src/trailer.c
	../src/fragmentation.c
	../src/fragmentation_buffer.c
	../src/reassembly.c
	../src/reassembly_buffer.c
	../src/rle_ctx.c
	../src/rle_transmitter.c
	../src/rle_receiver.c
	../src/rle_conf.c
	../src/rle_log.c
	../src/rle_header_proto_type_field.c
	test_rle_memory.c)
set_target_properties(test_rle_memory PROPERTIES LINK_FLAGS "-Wl,--wrap=malloc")
TARGET_LINK_LIBRARIES(test_rle_memory ${CMOCKA_LDFLAGS})

ADD_EXECUTABLE(test_non_regression test_non_regression.c)
TARGET_LINK_LIBRARIES(test_non_regression rle pcap)

ADD_EXECUTABLE(test_non_regression_fpdu test_non_regression_fpdu.c)
TARGET_LINK_LIBRARIES(test_non_regression_fpdu rle pcap)

ADD_EXECUTABLE(test_perfs test_perfs.c)
TARGET_LINK_LIBRARIES(test_perfs rle pcap)

ADD_EXECUTABLE(test_perfs_fpdu test_perfs_fpdu.c)
TARGET_LINK_LIBRARIES(test_perfs_fpdu rle pcap)

ADD_EXECUTABLE(test_dump_fpdus test_dump_fpdus.c)
TARGET_LINK_LIBRARIES(test_dump_fpdus rle pcap)

# To build with make check
ADD_DEPENDENCIES(check rle_tests)
ADD_DEPENDENCIES(check test_rle)
ADD_DEPENDENCIES(check test_rle_memory)
ADD_DEPENDENCIES(check test_non_regression)
ADD_DEPENDENCIES(check test_non_regression_fpdu)
ADD_DEPENDENCIES(check test_perfs)
ADD_DEPENDENCIES(check test_perfs_fpdu)
ADD_DEPENDENCIES(check test_dump_fpdus)

# Definitions of the system commands for the next targets.
SET(SYS_CMD_GREP grep)
SET(SYS_CMD_ECHO echo)
SET(SYS_CMD_RM rm)
SET(SYS_CMD_LCOV lcov)
SET(SYS_CMD_GENHTML genhtml)
SET(SYS_CMD_AFL_FUZZ afl-fuzz)

# If coverage is on.
# generate coverage files with:
#   $ make check
# generate coverage report with: (automatically generate coverage files)
#   $ make cov_report
IF (COVERAGE)

	TARGET_LINK_LIBRARIES(rle_tests gcov)
	TARGET_LINK_LIBRARIES(test_rle gcov)
	TARGET_LINK_LIBRARIES(test_rle_memory gcov)
	TARGET_LINK_LIBRARIES(test_non_regression gcov)
	TARGET_LINK_LIBRARIES(test_non_regression_fpdu gcov)

    SET(CMAKE_CCOV_REPORT_COMMAND
           ${SYS_CMD_LCOV} -c -d ${CMAKE_BINARY_DIR}/CMakeFiles/rle.dir/src
                              -d ${CMAKE_BINARY_DIR}/tests/CMakeFiles/test_rle_memory.dir/__/src
										-o coverage.run
        && ${SYS_CMD_GENHTML} -o ${CMAKE_BINARY_DIR}/html/ coverage.run
        && ${SYS_CMD_ECHO} "Coverage report: ${CMAKE_BINARY_DIR}/html/index.html" )
    ADD_CUSTOM_TARGET(cov_report COMMAND ${CMAKE_CCOV_REPORT_COMMAND})
ENDIF(COVERAGE)

# Test targets for build automation

# Define directories path 
SET(SCRIPT_DIR ${CMAKE_SOURCE_DIR}/tests/scripts)
SET(SAMPLE_DIR ${CMAKE_SOURCE_DIR}/tests/samples)


ADD_TEST(NAME unit_test COMMAND test_rle)

ADD_TEST(NAME memory_test COMMAND test_rle_memory)

ADD_TEST(NAME non_regression_sdu_large_fragments
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression
                                              ${SAMPLE_DIR}/non_reg -f 2000)
ADD_TEST(NAME non_regression_sdu_medium_fragments
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression
                                              ${SAMPLE_DIR}/non_reg -f 50)
ADD_TEST(NAME non_regression_sdu_small_fragments
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression
                                              ${SAMPLE_DIR}/non_reg -f 11)

ADD_TEST(NAME non_regression_sdu_large_fragments_layer2
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression
                                              ${SAMPLE_DIR}/non_reg -f 2000 --include-layer2)
ADD_TEST(NAME non_regression_sdu_medium_fragments_layer2
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression
                                              ${SAMPLE_DIR}/non_reg -f 50 --include-layer2)
ADD_TEST(NAME non_regression_sdu_small_fragments_layer2
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression
                                              ${SAMPLE_DIR}/non_reg -f 11 --include-layer2)

ADD_TEST(NAME non_regression_sdu_too_large_ppdu_comp
         COMMAND ${CMAKE_BINARY_DIR}/tests/test_non_regression
                 -f 5000 ${SAMPLE_DIR}/ipv4/4088.pcap)
ADD_TEST(NAME non_regression_sdu_too_large_ppdu_start
         COMMAND ${CMAKE_BINARY_DIR}/tests/test_non_regression
                 -f 3000 ${SAMPLE_DIR}/ipv4/4088.pcap)
ADD_TEST(NAME non_regression_sdu_too_large_ppdu_cont
         COMMAND ${CMAKE_BINARY_DIR}/tests/test_non_regression
                 -f 1000 -f 3000 ${SAMPLE_DIR}/ipv4/4088.pcap)
ADD_TEST(NAME non_regression_sdu_too_large_ppdu_end
         COMMAND ${CMAKE_BINARY_DIR}/tests/test_non_regression
                 -f 2000 -f 3000 ${SAMPLE_DIR}/ipv4/4088.pcap)

ADD_TEST(NAME non_regression_sdu_fuzzing
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression
                                              ${SAMPLE_DIR}/fuzzing
                                              --ignore-malformed)
ADD_TEST(NAME non_regression_sdu_fuzzing_layer2
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression
                                              ${SAMPLE_DIR}/fuzzing
                                              --ignore-malformed --include-layer2)

ADD_TEST(NAME non_regression_fpdu
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression_fpdu
                                              ${SAMPLE_DIR}/non_reg_fpdu)

ADD_TEST(NAME non_regression_fpdu_fuzzing
         COMMAND ${SCRIPT_DIR}/on_all_pcap.sh ${CMAKE_BINARY_DIR}/tests/test_non_regression_fpdu
                                              ${SAMPLE_DIR}/fuzzing-fpdu
                                              --ignore-malformed)

# If fuzzing is on, launch AFL fuzzing with:
#   $ make fuzzing (or $ make fuzzing-fpdu)
# /!\ You may be requiered to execute those commands as root before the fuzzing:
#   # echo core >/proc/sys/kernel/core_pattern
#   # cd /sys/devices/system/cpu
#   # echo performance | tee cpu*/cpufreq/scaling_governor
IF(FUZZING)
    SET(CMAKE_CFUZZING_COMMAND
           ${SYS_CMD_RM} -rf ${CMAKE_BINARY_DIR}/findings/
        && ${SYS_CMD_AFL_FUZZ} -i ${SAMPLE_DIR}/fuzzing/
                               -o ${CMAKE_BINARY_DIR}/findings/
                               -m none -t 500 ${CMAKE_BINARY_DIR}/tests/test_non_regression
                               --ignore-malformed @@)
    ADD_CUSTOM_TARGET(fuzzing DEPENDS test_non_regression COMMAND ${CMAKE_CFUZZING_COMMAND})
    SET(CMAKE_CFUZZING_FPDU_COMMAND
           ${SYS_CMD_RM} -rf ${CMAKE_BINARY_DIR}/findings/
        && ${SYS_CMD_AFL_FUZZ} -i ${SAMPLE_DIR}/fuzzing-fpdu/
                               -o ${CMAKE_BINARY_DIR}/findings/
                               -m none -t 500 ${CMAKE_BINARY_DIR}/tests/test_non_regression_fpdu
                               --ignore-malformed @@)
    ADD_CUSTOM_TARGET(fuzzing-fpdu DEPENDS test_non_regression_fpdu
                      COMMAND ${CMAKE_CFUZZING_FPDU_COMMAND})
ENDIF(FUZZING)
