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
 * @file   test_rle_frag.h
 * @brief  Definition of public functions used for the fragmentation tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __TEST_RLE_FRAG_H__
#define __TEST_RLE_FRAG_H__

#include "test_rle_common.h"

/**
 * @brief         Fragmentation test with a null transmitter.
 *
 * @return        true if the RLE_FRAG_ERR_BURST_TOO_SMALL is raised, else false.
 */
bool test_frag_null_transmitter(void);

/**
 * @brief         Fragmentation test with a too small burst size.
 *
 * @return        true if the RLE_FRAG_ERR_BURST_TOO_SMALL is raised, else false.
 */
bool test_frag_too_small(void);

/**
 * @brief         Fragmentation test with a null context.
 *
 * @return        true if the RLE_FRAG_ERR_CONTEXT_IS_NULL is raised, else false.
 */
bool test_frag_null_context(void);

/**
 * @brief         Fragmentation test with real-world configurations.
 *
 *                Fragments with realistic values and configurations, IPv4 is the protocol type per
 *                default and is omitted, SeqNo by default), with burst sizes in the set of the RCS
 *                mandatory burst sizes (14, 24, 38, 51, 55, 59, 62, 69, 84, 85, 93, 96, 100, 115,
 *                123, 130, 144, 170, 175, 188, 264, 298, 355, 400, 438, 444, 539, 599).
 *
 * @return        true if RLE_FRAG_ERR_INVALID_SIZE is raised, else false.
 */
bool test_frag_real_world(void);

/**
 * @brief         Fragmentation tests in general cases.
 *
 * @return        true if OK, else false.
 */
bool test_frag_all(void);

#endif /* __TEST_RLE_FRAG_H__ */
