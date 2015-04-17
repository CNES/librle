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
 * @return        BOOL_TRUE if the RLE_FRAG_ERR_BURST_TOO_SMALL is raised, else BOOL_FALSE.
 */
enum boolean test_frag_null_transmitter(void);

/**
 * @brief         Fragmentation test with a too small burst size.
 *
 * @return        BOOL_TRUE if the RLE_FRAG_ERR_BURST_TOO_SMALL is raised, else BOOL_FALSE.
 */
enum boolean test_frag_too_small(void);

/**
 * @brief         Fragmentation test with a null context.
 *
 * @return        BOOL_TRUE if the RLE_FRAG_ERR_CONTEXT_IS_NULL is raised, else BOOL_FALSE.
 */
enum boolean test_frag_null_context(void);

/**
 * @brief         Fragmentation test with an invalid burst size.
 *
 *                A burst size is invalid when the ALPDU protection bytes cannot be sent without
 *                being cut.
 *
 * @return        BOOL_TRUE if RLE_FRAG_ERR_INVALID_SIZE is raised, else BOOL_FALSE.
 */
enum boolean test_frag_invalid_size(void);

/**
 * @brief         Fragmentation tests in general cases.
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
enum boolean test_frag_all(void);

#endif /* __TEST_RLE_FRAG_H__ */
