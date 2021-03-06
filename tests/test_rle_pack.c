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
 * @file   test_rle_pack.c
 * @brief  Body file used for the packing tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "test_rle_pack.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>


/**
 * @brief         Generic packing test.
 *
 *                Simply pack a label and PPDUs in an FPDU
 *
 * @param[in]     fpdu_length              Max size of the FPDU
 * @param[in]     nb_ppdus                 Number of PPDUs
 * @param[in]     ppdus_length             Sizes of the PPDUs
 * @param[in]     label_length             Size of the label
 *
 * @return        true if OK, else false.
 */
static bool test_pack(const size_t fpdu_length,
                      const size_t nb_ppdus,
                      const size_t ppdus_length[],
                      const size_t label_length);

/**
 * @brief         Check an FPDU.
 *
 * @param[in]     fpdu                     The FPDU to check
 * @param[in]     fpdu_length              The size of the FPDU
 * @param[in]     ppdus                    The PPDUs in the FPDU
 * @param[in]     ppdus_length             The lengths of the PPDUs
 * @param[in]     nb_ppdus                 The number of PPDUs
 * @param[in]     label                    The label of the FPDU
 * @param[in]     label_length             The label length
 *
 * @return        true if OK, else false.
 */
static bool test_pack_check_fpdu(const unsigned char fpdu[], const size_t fpdu_length,
                                 const unsigned char *const ppdus[],
                                 const size_t *const ppdus_length, const size_t nb_ppdus,
                                 const unsigned char label[],
                                 const size_t label_length);

static bool test_pack_check_fpdu(const unsigned char fpdu[],
                                 const size_t fpdu_length,
                                 const unsigned char *const ppdus[],
                                 const size_t *const ppdus_length,
                                 const size_t nb_ppdus,
                                 const unsigned char label[],
                                 const size_t label_length)
{
	PRINT_TEST("subtest. sizes: FPDU %zu, label %zu. Nb of PPDU: %zu.\nPPDUs sizes:",
	           fpdu_length, label_length,
	           nb_ppdus);

	size_t iterator = 0;
	for (iterator = 0; iterator < nb_ppdus; ++iterator) {
		printf("- %zu\n", ppdus_length[iterator]);
	}

	bool output = false;
	unsigned char reass_fpdu[fpdu_length];
	for (iterator = 0; iterator < fpdu_length; ++iterator) {
		reass_fpdu[iterator] = '\0';
	}

	size_t reass_fpdu_length = 0;

	reass_fpdu_length += label_length;
	for (iterator = 0; iterator < nb_ppdus; ++iterator) {
		reass_fpdu_length += ppdus_length[iterator];
	}

	if (reass_fpdu_length > fpdu_length) {
		PRINT_ERROR("FPDU length and total length from PPDUs and label are different");
		goto exit_label;
	}

	{
		size_t reass_fpdu_offset = 0;

		memcpy((void *)reass_fpdu, (const void *)label, label_length);
		reass_fpdu_offset += label_length;

		for (iterator = 0; iterator < nb_ppdus; ++iterator) {
			memcpy((void *)(reass_fpdu + reass_fpdu_offset),
			       (const void *)ppdus[iterator], ppdus_length[iterator]);
			reass_fpdu_offset += ppdus_length[iterator];
		}
	}

	output = true;
	for (iterator = 0; iterator < fpdu_length; ++iterator) {
		if (fpdu[iterator] != reass_fpdu[iterator]) {
			PRINT_ERROR("FPDU and reassembled PPDUs are different, pos.%zu, "
			            "expected 0x%02x, get 0x%02x.", iterator, fpdu[iterator],
			            reass_fpdu[iterator]);
			output = false;
		}
	}

exit_label:
	PRINT_TEST_STATUS(output);
	return output;
}

static bool test_pack(const size_t fpdu_length,
                      const size_t nb_ppdus,
                      const size_t ppdus_length[],
                      const size_t label_length)
{
	PRINT_TEST("Test PACK. Sizes: FPDU %zu, Nb PPDU  %zu, Label %zu\nPPDUs sizes :",
	           fpdu_length, nb_ppdus, label_length);

	assert(nb_ppdus > 0);
	assert(label_length <= MAX_LABEL_LEN);

	size_t iterator = 0;
	for (iterator = 0; iterator < nb_ppdus; ++iterator) {
		printf("- %zu\n", ppdus_length[iterator]);
	}

	bool output = false;

	enum rle_pack_status pack_status = RLE_PACK_ERR;
	unsigned char fpdu[fpdu_length];

	for (iterator = 0; iterator < fpdu_length; ++iterator) {
		fpdu[iterator] = '\0';
	}

	unsigned char *ppdus[nb_ppdus];

	unsigned char label[MAX_LABEL_LEN];
	if (label_length != 0) {
		memcpy(label, payload_initializer, label_length);
	}

	for (iterator = 0; iterator < nb_ppdus; ++iterator) {
		ppdus[iterator] = calloc((size_t)1, ppdus_length[iterator]);
		memcpy((void *)ppdus[iterator], (const void *)payload_initializer,
		       ppdus_length[iterator]);
	}

	{
		size_t fpdu_current_pos = 0;
		size_t fpdu_remaining_size = fpdu_length;
		for (iterator = 0; iterator < nb_ppdus; ++iterator) {
			pack_status =
				rle_pack(ppdus[iterator], ppdus_length[iterator], label,
				         label_length, fpdu, &fpdu_current_pos,
				         &fpdu_remaining_size);
			if (pack_status != RLE_PACK_OK) {
				PRINT_ERROR("Unable to pack");
				goto exit_label;
			}
		}
	}

	output = test_pack_check_fpdu(fpdu, fpdu_length, (const unsigned char *const *)ppdus,
	                              ppdus_length, nb_ppdus, label, label_length);

exit_label:

	for (iterator = 0; iterator < nb_ppdus; ++iterator) {
		if (ppdus[iterator] != NULL) {
			free(ppdus[iterator]);
		}
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_pack_fpdu_too_small(void)
{
	PRINT_TEST("Test pack FPDU too small.");
	bool output = false;

	enum rle_pack_status pack_status = RLE_PACK_ERR;

	const size_t fpdu_length = 10;
	unsigned char fpdu[fpdu_length];

	{
		size_t fpdu_pos = 0;
		size_t fpdu_remaining_length = fpdu_length;

		const size_t ppdu_length = 7;
		const unsigned char ppdu[ppdu_length];

		const size_t label_length = 3;
		const unsigned char label[label_length];

		pack_status = rle_pack(ppdu, ppdu_length, label, label_length, fpdu, &fpdu_pos,
		                       &fpdu_remaining_length);
		if (pack_status != RLE_PACK_OK) {
			PRINT_ERROR("FPDU pack limit not passed");
			goto exit_label;
		}
	}

	{
		size_t fpdu_pos = 0;
		size_t fpdu_remaining_length = fpdu_length;

		const size_t ppdu_length = 8;
		const unsigned char ppdu[ppdu_length];

		const size_t label_length = 3;
		const unsigned char label[label_length];

		pack_status = rle_pack(ppdu, ppdu_length, label, label_length, fpdu, &fpdu_pos,
		                       &fpdu_remaining_length);
		if (pack_status != RLE_PACK_ERR_FPDU_TOO_SMALL) {
			PRINT_ERROR("FPDU too small not raised");
			goto exit_label;
		}
	}

	{
		size_t fpdu_pos = 0;
		size_t fpdu_remaining_length = fpdu_length;

		const size_t ppdu_length = 4;
		const unsigned char ppdu[ppdu_length];

		const size_t label_length_first = 3;
		const unsigned char label_first[label_length_first];

		const size_t label_length_sec = 0;
		const unsigned char *label_sec = NULL;

		pack_status = rle_pack(ppdu, ppdu_length, label_first, label_length_first, fpdu,
		                       &fpdu_pos, &fpdu_remaining_length);
		if (pack_status != RLE_PACK_OK) {
			PRINT_ERROR("Normal packing failed. %d", pack_status);
			goto exit_label;
		}

		pack_status = rle_pack(ppdu, ppdu_length, label_sec, label_length_sec, fpdu,
		                       &fpdu_pos, &fpdu_remaining_length);
		if (pack_status != RLE_PACK_ERR_FPDU_TOO_SMALL) {
			PRINT_ERROR("FPDU too small not raised, pos %zu, remaining size %zu",
			            fpdu_pos,
			            fpdu_remaining_length);
			goto exit_label;
		}
	}

	output = true;

exit_label:
	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_pack_invalid_ppdu(void)
{
	PRINT_TEST("Test PACK invalid PPDU.");
	bool output = false;

	enum rle_pack_status pack_status = RLE_PACK_ERR;

	const size_t fpdu_length = 1000;
	unsigned char fpdu[fpdu_length];

	{
		size_t fpdu_pos = 0;
		size_t fpdu_remaining_length = fpdu_length;

		const size_t ppdu_length = 0;
		const unsigned char ppdu[1];

		const size_t label_length = 3;
		const unsigned char label[label_length];

		pack_status = rle_pack(ppdu, ppdu_length, label, label_length, fpdu, &fpdu_pos,
		                       &fpdu_remaining_length);
		if (pack_status != RLE_PACK_ERR_INVALID_PPDU) {
			PRINT_ERROR("Invalid PPDU not raised");
			goto exit_label;
		}
	}

	{
		size_t fpdu_pos = 0;
		size_t fpdu_remaining_length = fpdu_length;

		const size_t ppdu_length = 3;
		const unsigned char *ppdu = NULL;

		const size_t label_length = 3;
		const unsigned char label[label_length];

		pack_status = rle_pack(ppdu, ppdu_length, label, label_length, fpdu, &fpdu_pos,
		                       &fpdu_remaining_length);
		if (pack_status != RLE_PACK_ERR_INVALID_PPDU) {
			PRINT_ERROR("Invalid PPDU not raised");
			goto exit_label;
		}
	}

	output = true;

exit_label:
	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_pack_invalid_label(void)
{
	PRINT_TEST("Test PACK invalid label.");

	bool output = false;

	enum rle_pack_status pack_status = RLE_PACK_ERR;

	const size_t fpdu_length = 1000;
	unsigned char fpdu[fpdu_length];

	{
		size_t fpdu_pos = 0;
		size_t fpdu_remaining_length = fpdu_length;

		const size_t ppdu_length = 30;
		const unsigned char ppdu[ppdu_length];

		const size_t label_length = 3;
		const unsigned char *label = NULL;

		pack_status = rle_pack(ppdu, ppdu_length, label, label_length, fpdu, &fpdu_pos,
		                       &fpdu_remaining_length);
		if (pack_status != RLE_PACK_ERR_INVALID_LAB) {
			PRINT_ERROR("Invalid label not raised");
			goto exit_label;
		}
	}

	{
		size_t fpdu_pos = 0;
		size_t fpdu_remaining_length = fpdu_length;

		const size_t ppdu_length = 30;
		const unsigned char ppdu[ppdu_length];

		const size_t label_length = 2;
		const unsigned char label[label_length];

		pack_status = rle_pack(ppdu, ppdu_length, label, label_length, fpdu, &fpdu_pos,
		                       &fpdu_remaining_length);
		if (pack_status != RLE_PACK_ERR_INVALID_LAB) {
			PRINT_ERROR("Invalid label not raised");
			goto exit_label;
		}
	}
	output = true;

exit_label:
	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

bool test_pack_all(void)
{
	PRINT_TEST("Test PACK with all general cases.");
	bool output = true;

	const size_t fpdu_length = 4000;

	const size_t nb_labels = 3;
	const size_t label_length[] = {
		0,
		3,
		6
	};

	const size_t single_ppdu[1] = { 500 };
	const size_t double_ppdus[2] = { 300, 200 };

	const size_t nb_ppdus_conf = 2;
	const size_t ppdus_length_size[] = { 1, 2 };
	const size_t *const ppdus_length[] = { single_ppdu, double_ppdus };

	size_t label_iterator = 0;
	for (label_iterator = 0; label_iterator < nb_labels; ++label_iterator) {
		size_t ppdus_iterator = 0;
		for (ppdus_iterator = 0; ppdus_iterator < nb_ppdus_conf; ++ppdus_iterator) {
			output &= test_pack(fpdu_length, ppdus_length_size[ppdus_iterator],
			                    ppdus_length[ppdus_iterator],
			                    label_length[label_iterator]);
		}
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}
