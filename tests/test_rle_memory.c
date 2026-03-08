/*
 * librle implements the Return Link Encapsulation (RLE) protocol
 *
 * Copyright (C) 2015-2016, Thales Alenia Space France - All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file   test_rle_memory.c
 * @brief  Test robustness to memory problems
 * @author Didier Barvaux
 * @date   03/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "rle.h"

#include <stdarg.h> /* required by cmocka header file */
#include <setjmp.h> /* required by cmocka header file */
#include <cmocka.h>
#include <stdio.h>

void * __real_malloc(size_t size);
void * __wrap_malloc(size_t size);

void test_rle_memory_frag_buf_new(void **state);
void test_rle_memory_transmitter_new(void **state);
void test_rle_memory_receiver_new(void **state);


int main(void)
{
	int test_status;

#if defined(cmocka_unit_test)
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_rle_memory_frag_buf_new),
		cmocka_unit_test(test_rle_memory_transmitter_new),
		cmocka_unit_test(test_rle_memory_receiver_new),
	};
	test_status = cmocka_run_group_tests(tests, NULL, NULL);
#else
	const UnitTest tests[] = {
		unit_test(test_rle_memory_frag_buf_new),
		unit_test(test_rle_memory_transmitter_new),
		unit_test(test_rle_memory_receiver_new),
	};
	test_status = run_tests(tests);
#endif
	return test_status;
}


void test_rle_memory_frag_buf_new(void **state __attribute__((unused)))
{
	struct rle_frag_buf *buf;

	will_return(__wrap_malloc, 0);
	buf = rle_frag_buf_new();
	assert_true(buf == NULL);
}

void test_rle_memory_transmitter_new(void **state __attribute__((unused)))
{
	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_transmitter *transmitter;
	size_t i;

	/* transmitter failure */
	will_return(__wrap_malloc, 0);
	transmitter = rle_transmitter_new(&conf);
	assert_true(transmitter == NULL);

	/* context failure */
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		size_t j;
		will_return(__wrap_malloc, 1);
		for (j = 0; j < i; j++) {
			will_return(__wrap_malloc, 1);
		}
		will_return(__wrap_malloc, 0);
		transmitter = rle_transmitter_new(&conf);
		assert_true(transmitter == NULL);
	}
}


void test_rle_memory_receiver_new(void **state __attribute__((unused)))
{
	const struct rle_config conf = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};
	struct rle_receiver *receiver;
	size_t i;

	/* receiver failure */
	will_return(__wrap_malloc, 0);
	receiver = rle_receiver_new(&conf);
	assert_true(receiver == NULL);

	/* context failure */
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		size_t j;
		will_return(__wrap_malloc, 1);
		for (j = 0; j < i; j++) {
			will_return(__wrap_malloc, 1);
		}
		will_return(__wrap_malloc, 0);
		receiver = rle_receiver_new(&conf);
		assert_true(receiver == NULL);
	}
}


/*---------------------------------------------------------------------------*/
/*--------------------------   WRAPPED FUNCTIONS  ---------------------------*/
/*---------------------------------------------------------------------------*/

void * __wrap_malloc(size_t size)
{
	void *ptr = mock_ptr_type(void *);

	if (ptr != NULL) {
		return __real_malloc(size);
	} else {
		return ptr;
	}
}
