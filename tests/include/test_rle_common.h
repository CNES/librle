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
 * @file   test_rle_common.h
 * @brief  Definition of RLE structure, functions and variables shared by the tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_COMMON_H__
#define __TEST_RLE_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "rle.h"

#define PRINT_TEST(S, ...) printf("TEST %s:l.%d "S "\n", __func__, __LINE__, ## __VA_ARGS__)
#define PRINT_TEST_STATUS(status) printf("RET %s:l.%d: %s\n", __func__, __LINE__, status == \
	                                 true ? "OK" : "KO")
#define PRINT_ERROR(S, ...) printf("ERROR %s:l.%d: "S "\n", __func__, __LINE__, ## __VA_ARGS__)


/**< The max length of the label, in bytes */
#define MAX_LABEL_LEN  6


/**
 * Payload initializer,
 * This initializer is big enough to test too big SDU/ALPDU cases.
 * How to use :
 * For a n octets sdu: memcpy((void *)sdu, (const void *)payload_initializer, (size_t)n).
 *
 * Sufficient for encap, frag and pack, but IP header checking in decap might need to modify some
 * of the first octets.
 */
extern const unsigned char payload_initializer[5000];

/*--  Common  --*/

/**
 * @brief         Specific statistics printer for transmitter
 *
 * @param receiver  The transmitter to print stats for
 * @return        true if OK, else false.
 */
void print_transmitter_stats(const struct rle_transmitter *const transmitter);

/**
 * @brief         Specific statistics printer for receiver
 *
 * @param receiver  The receiver to print stats for
 * @return        true if OK, else false.
 */
void print_receiver_stats(const struct rle_receiver *const receiver);

#endif /* __TEST_RLE_COMMON_H__ */
