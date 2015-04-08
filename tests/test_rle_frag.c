/**
 * @file   test_rle_frag.c
 * @brief  Body file used for the fragmentation tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "test_rle_frag.h"

#include "rle_transmitter.h"

/**
 * @brief         Generic fragmentation test.
 *
 *                Simply fragment an encapsulated SDU from one of the frag id of a transmitter.
 *
 * @param[in]     protocol_type            The protocol type of the SDU
 * @param[in]     conf                     Configuration of the transmitter
 * @param[in]     length                   The protocol length of the SDU to encap before frag
 * @param[in]     burst_size               The size of the burst that the fragmentation depends on
 * @param[in]     frag_id                  The fragment id
 *
 * @return        BOOL_TRUE if OK, else BOOL_FALSE.
 */
static enum boolean test_frag(const uint16_t protocol_type,
                              const struct rle_context_configuration conf, const size_t length,
                              const size_t burst_size,
                              const uint8_t frag_id);

static enum boolean test_frag(const uint16_t protocol_type,
                              const struct rle_context_configuration conf, const size_t length,
                              const size_t burst_size,
                              const uint8_t frag_id)
{
	PRINT_TEST(
	        "protocole type 0x%04x, conf %s with %s, SDU length %zu, burst sizes %zu, frag id %d",
	        protocol_type, conf.use_ptype_omission == 0 ?
	        (conf.use_compressed_ptype == 0 ?
	         "uncompressed" : "compressed") : (conf.implicit_protocol_type == protocol_type ?
	                                           "omitted" : "non omitted"),
	        conf.use_alpdu_crc == 1 ? "CRC" : "SeqNo", length, burst_size, frag_id);
	enum boolean output = BOOL_FALSE;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = length,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}
	transmitter = rle_transmitter_new(conf);
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	sdu.buffer = calloc(sdu.size, sizeof(unsigned char));
	if (sdu.buffer == NULL) {
		PRINT_ERROR("SDU interface not created.");
		goto exit_label;
	}
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu.size);

	ret_encap = rle_encapsulate(transmitter, sdu, frag_id);

	if (ret_encap != RLE_ENCAP_OK) {
		PRINT_ERROR("Encap error in frag test.");
		goto exit_label;
	}

	{
		enum rle_frag_status ret_frag = RLE_FRAG_ERR;
		enum check_frag_status frag_status = FRAG_STATUS_KO;
		size_t frag_size = burst_size;
		unsigned char ppdu[frag_size];
		size_t *real_size = calloc((size_t)1, sizeof(size_t));

		while (rle_transmitter_get_queue_state(transmitter, frag_id) != BOOL_TRUE) {
			if ((RLE_CONT_HEADER_SIZE +
			     rle_transmitter_get_queue_size(transmitter, frag_id)) < frag_size) {
				frag_size = rle_transmitter_get_queue_size(transmitter, frag_id);
				frag_size += RLE_CONT_HEADER_SIZE; /* Size of Complete header */
			}

			ret_frag = rle_fragment(transmitter, frag_id, frag_size, ppdu, real_size);

			if (ret_frag != RLE_FRAG_OK) {
				PRINT_ERROR("fragmentation error.");
				goto exit_label;
			}
		}

		frag_status = rle_transmitter_check_frag_integrity(transmitter, frag_id);

		if (frag_status != FRAG_STATUS_OK) {
			PRINT_ERROR("Check integrity.");
			goto exit_label;
		}
	}

	output = BOOL_TRUE;

exit_label:

	print_transmitter_stats();

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

enum boolean test_frag_null_transmitter(void)
{
	enum boolean output = BOOL_FALSE;
	const uint16_t protocol_type = 0x0800; /* Arbitrarly */
	const uint8_t frag_id = 0; /* Arbitrarly */
	const size_t sdu_length = 100;
	const size_t burst_size = 30;
	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = 0,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	sdu.buffer = calloc(sdu_length, sizeof(unsigned char));
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu_length);
	sdu.size = sdu_length;

	{
		unsigned char ppdu[burst_size];
		size_t *real_size = calloc((size_t)1, sizeof(size_t));
		enum rle_frag_status status = RLE_FRAG_ERR;

		status = rle_fragment(transmitter, frag_id, burst_size, ppdu, real_size);
		if (status != RLE_FRAG_ERR_NULL_TRMT) {
			PRINT_ERROR("Fragmentation on null transmitter.");
			goto exit_label;
		}
	}

	output = BOOL_TRUE;

exit_label:

	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}
enum boolean test_frag_too_small(void)
{
	PRINT_TEST("Frag too small.");
	enum boolean output = BOOL_FALSE;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;

	const uint16_t protocol_type = 0x0800;
	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x0000,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 0
	};

	const size_t sdu_length = 100;
	const size_t burst_size = 2;
	const uint8_t frag_id = 1;

	enum rle_frag_status status = RLE_FRAG_ERR;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = sdu_length,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}
	transmitter = rle_transmitter_new(conf);
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	sdu.buffer = calloc(sdu.size, sizeof(unsigned char));

	if (sdu.buffer == NULL) {
		PRINT_ERROR("SDU interface not created.");
		goto exit_label;
	}
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu.size);

	ret_encap = rle_encapsulate(transmitter, sdu, frag_id);

	if (ret_encap != RLE_ENCAP_OK) {
		PRINT_ERROR("Encap error in frag test.");
		goto exit_label;
	}

	{
		unsigned char ppdu[burst_size];
		size_t real_size;
		if (rle_transmitter_get_queue_state(transmitter, frag_id) == BOOL_TRUE) {
			PRINT_ERROR("Nothing to frag");
			goto exit_label;
		}

		status = rle_fragment(transmitter, frag_id, burst_size, ppdu, &real_size);
	}

	output = (status == RLE_FRAG_ERR_BURST_TOO_SMALL);

exit_label:

	print_transmitter_stats();

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

enum boolean test_frag_null_context(void)
{
	PRINT_TEST("Null context");
	enum boolean output = BOOL_FALSE;
	/* enum rle_encap_status ret_encap = RLE_ENCAP_ERR;*/

	const uint16_t protocol_type = 0x0800;
	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x0000,
		.use_alpdu_crc = 0,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 0
	};

	const size_t sdu_length = 100; /* We could remove all the SDU manipulation parts, but I want to
	                                * make a test as realist as possible, here with a forgotten
	                                * encap leading to a null context. */
	const size_t burst_size = 50;
	const uint8_t frag_id = 1;

	enum rle_frag_status status = RLE_FRAG_ERR;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = sdu_length,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}
	transmitter = rle_transmitter_new(conf);
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	sdu.buffer = calloc(sdu.size, sizeof(unsigned char));

	if (sdu.buffer == NULL) {
		PRINT_ERROR("SDU interface not created.");
		goto exit_label;
	}

	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu.size);

	{
		unsigned char ppdu[burst_size];
		size_t *real_size = calloc((size_t)1, sizeof(size_t));

		status = rle_fragment(transmitter, frag_id, burst_size, ppdu, real_size);
	}

	output = (status == RLE_FRAG_ERR_CONTEXT_IS_NULL);

exit_label:

	print_transmitter_stats();

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}
	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

enum boolean test_frag_invalid_size(void)
{
	PRINT_TEST("Invalid size.");
	enum boolean output = BOOL_FALSE;
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;

	const uint16_t protocol_type = 0x0800;
	const struct rle_context_configuration conf = {
		.implicit_protocol_type = 0x0000,
		.use_alpdu_crc = 1,
		.use_compressed_ptype = 0,
		.use_ptype_omission = 0
	};

	const size_t sdu_length = 100;
	const size_t burst_size_start = 60;
	const size_t burst_size_end = 50; /* Not enough size for the CRC */
	const uint8_t frag_id = 1;

	enum rle_frag_status status = RLE_FRAG_ERR;

	struct rle_sdu sdu = {
		.buffer = NULL,
		.size = sdu_length,
		.protocol_type = protocol_type
	};

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}
	transmitter = rle_transmitter_new(conf);
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	sdu.buffer = calloc(sdu.size, sizeof(unsigned char));

	if (sdu.buffer == NULL) {
		PRINT_ERROR("SDU interface not created.");
		goto exit_label;
	}
	memcpy((void *)sdu.buffer, (const void *)payload_initializer, sdu.size);

	ret_encap = rle_encapsulate(transmitter, sdu, frag_id);

	if (ret_encap != RLE_ENCAP_OK) {
		PRINT_ERROR("Encap error in frag test.");
		goto exit_label;
	}

	{
		unsigned char ppdu[burst_size_start];
		size_t real_size;
		if (rle_transmitter_get_queue_state(transmitter, frag_id) == BOOL_TRUE) {
			PRINT_ERROR("Nothing to frag");
			goto exit_label;
		}

		status = rle_fragment(transmitter, frag_id, burst_size_start, ppdu, &real_size);

		if (status != RLE_FRAG_OK) {
			PRINT_ERROR("Starting frag error");
		}

		status = rle_fragment(transmitter, frag_id, burst_size_end, ppdu, &real_size);
	}

	output = (status == RLE_FRAG_ERR_INVALID_SIZE);

exit_label:

	print_transmitter_stats();

	if (transmitter != NULL) {
		rle_transmitter_destroy(transmitter);
		transmitter = NULL;
	}
	if (sdu.buffer != NULL) {
		free(sdu.buffer);
		sdu.buffer = NULL;
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}

enum boolean test_frag_all(void)
{
	PRINT_TEST("Test all the general fragmentation cases.");
	enum boolean output = BOOL_TRUE;
	uint16_t protocol_type = 0x0800; /* IPv4 Arbitrarily. */
	uint8_t frag_id = 1;
	const size_t sdu_length = 100;
	/* Those 4 burst sizes allow us to test all type of fragis and transitions.
	 * 30  -> START - CONT - CONT - END
	 * 40  -> START - CONT - END
	 * 80  -> START - END
	 * 120 -> COMP */
	const size_t burst_sizes[4] = { 30, 40, 80, 120 };
	size_t burst_iterator = 0;

	for (burst_iterator = 0; burst_iterator < 4; ++burst_iterator) {
		struct rle_context_configuration conf_uncomp = {
			.implicit_protocol_type = 0x0000,
			.use_alpdu_crc = 0,
			.use_compressed_ptype = 0,
			.use_ptype_omission = 0
		};

		/* Configuration for compressed protocol type */
		struct rle_context_configuration conf_comp = {
			.implicit_protocol_type = 0x0000,
			.use_alpdu_crc = 0,
			.use_compressed_ptype = 1,
			.use_ptype_omission = 0
		};

		/* Configuration for omitted protocol type */
		struct rle_context_configuration conf_omitted = {
			.implicit_protocol_type = protocol_type,
			.use_alpdu_crc = 0,
			.use_compressed_ptype = 0,
			.use_ptype_omission = 1
		};

		/* Configurations */
		struct rle_context_configuration *confs[] = {
			&conf_uncomp,
			&conf_comp,
			&conf_omitted,
			NULL
		};

		/* Configuration iterator */
		struct rle_context_configuration **conf;

		/* We launch the test on each configuration. All the cases then are test. */
		for (conf = confs; *conf; ++conf) {
			const enum boolean ret =
			        test_frag(protocol_type, **conf, sdu_length,
			                  burst_sizes[burst_iterator], frag_id);
			if (ret == BOOL_FALSE) {
				/* Only one fail means the encap test fail. */
				output = BOOL_FALSE;
			}
		}

		/* With CRC. */
		for (conf = confs; *conf; ++conf) {
			(**conf).use_alpdu_crc = 1;
			const enum boolean ret =
			        test_frag(protocol_type, **conf, sdu_length,
			                  burst_sizes[burst_iterator], frag_id);
			if (ret == BOOL_FALSE) {
				/* Only one fail means the encap test fail. */
				output = BOOL_FALSE;
			}
		}
	}

	PRINT_TEST_STATUS(output);
	printf("\n");
	return output;
}
