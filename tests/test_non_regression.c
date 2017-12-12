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
 * @file   test_non_regression.c
 * @brief  Body file used for the non regression tests.
 * @author Henrick Deschamps
 * @date   04/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "rle.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <pcap.h>

/** The program version */
#define TEST_VERSION  "RLE non-regression test application, version 1.0.1\n"


/** The length (in bytes) of the Ethernet header */
#define ETHER_HDR_LEN  14U

/** A simple minimum macro */
#define min(x, y) \
	(((x) < (y)) ? (x) : (y))

/** Burst size for fragmentation in the test. */
#define BURST_SIZE 14

/* prototypes of private functions */
static void usage(void);
static int test_encap_and_decap(const char *const src_filename);
static int encap_decap(struct rle_transmitter *const transmitter,
                       struct rle_receiver *const receiver,
                       const size_t *const packets_length,
                       const unsigned char *const *const packets,
                       const size_t number_of_packets,
                       const size_t link_len_src);

static int compare_packets(const unsigned char *const pkt1,
                           const int pkt1_size,
                           const unsigned char *const pkt2,
                           const int pkt2_size);

static void print_logs(const int module_id,
                       const int level,
                       const char *const file,
                       const int line,
                       const char *const func,
                       const char *const fmt,
                       ...)
__attribute__((format(printf, 6, 7), nonnull(3, 5, 6)));

static char * str_encap_error(const enum rle_encap_status status);
static char * str_frag_error(const enum rle_frag_status status);
static char * str_pack_error(const enum rle_pack_status status);
static char * str_decap_error(const enum rle_decap_status status);

/** Whether the application runs in verbose mode or not */
static int is_verbose = 0;

/** Whether the application includes the layer2 of packets or not */
static int include_layer2 = 0;

/** Whether the application ignores malformed packets or not. */
static int ignore_malformed = 0;

/** Size of PPDU fragment, BURST_SIZE by default. */
static size_t frag_len = BURST_SIZE;

#define TRACE(x ...) \
	do { \
		if (is_verbose) { \
			printf(x); \
		} \
	} while (0)

/**
 * @brief Main function for the RLE test program
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure,
 *              \li 77 in case test is skipped
 */
int main(int argc, char *argv[])
{
	char *src_filename = NULL;
	int status = 1;

	while (1) {
		int c;

		static struct option long_options[] =
		{
			{ "verbose", no_argument, &is_verbose, 1 },
			{ "include-layer2", no_argument, &include_layer2, 1 },
			{ "ignore-malformed", no_argument, &ignore_malformed, 1 },
			{ "fragment_size", required_argument, 0, 'b' },
			{ 0, 0, 0, 0 }
		};

		int option_index = 0;

		c = getopt_long(argc, argv, "vhf:", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0) {
				break;
			}
			printf("option %s", long_options[option_index].name);
			if (optarg) {
				printf(" with arg %s", optarg);
			}
			printf("\n");
			break;
		case 'f': /* Fragment Size */
			assert(optarg != NULL);
			printf("fragment size with value `%s'\n", optarg);
			frag_len = atoi(optarg);
			break;
		case 'v': /* Version */
			printf(TEST_VERSION);
			status = EXIT_SUCCESS;
			goto error;
		case 'h': /* Help */
			usage();
			status = EXIT_SUCCESS;
			goto error;
		case '?':
		default:
			usage();
			goto error;
		}
	}

	if (optind != argc - 1) {
		fprintf(stderr, "FLOW is a mandatory parameter\n\n");
		usage();
		goto error;
	}

	src_filename = argv[optind];

	/* test RLE encap/decap with the packets from the file */
	status = test_encap_and_decap(src_filename);

	printf("=== exit test with code %d\n", status);
error:
	return status;
}


/**
 * @brief Print usage of the performance test application
 */
static void usage(void)
{
	fprintf(stderr,
	        "RLE non-regression tool:  test the RLE library with a flow\n"
	        "                          of IP packets\n"
	        "\n"
	        "usage: test_non_regression [OPTIONS] FLOW\n"
	        "\n"
	        "with:\n"
	        "  FLOW                    The flow of Ethernet frames to test\n"
	        "                          (in PCAP format)\n"
	        "\n"
	        "options:\n"
	        "  -v                      Print version information and exit\n"
	        "  -h                      Print this usage and exit\n"
	        "  -f                      Size of the PPDU fragments (burst size by default)\n"
	        "  --include-layer2        Do not skip Ethernet header of packets\n"
	        "  --ignore-malformed      Ignore malformed packets for test\n"
	        "  --verbose               Run the test in verbose mode\n");
}


/**
 * @brief Encapsulate, fragmente, pack and and decapsulate one IP packet with the
 *        given transmitter and receiver.
 *
 * @param transmitter       The transmitter to use.
 * @param receiver          The receiver to use.
 * @param packets_length    Lenght of the packets to encapsulate/decapsulate.
 * @param packets           The packets to encapsulate/decapsulate (link layer included)
 * @param number_of_packets The number of packets.
 * @param link_len_src      The length of the link layer header before IP data
 * @return                  1 if the process is successful
 *                          2 if the process is not successful, but due to a misuse of the RLE lib.
 *                          0 if the decapsulated packet doesn't match the
 *                          original one
 *                          -1 if an error occurs while transmitting
 *                          -2 if an error occurs while receiving
 *                          -3 if the link layer is not Ethernet
 */
static int encap_decap(struct rle_transmitter *const transmitter,
                       struct rle_receiver *const receiver,
                       const size_t *const packets_length,
                       const unsigned char *const *const packets,
                       const size_t number_of_packets,
                       const size_t link_len_src)
{
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;
	enum rle_decap_status ret_decap = RLE_DECAP_ERR;

	size_t pkt_id;
	struct rle_sdu sdus_in[number_of_packets];

	int status = 3;

	size_t sdus_out_order[number_of_packets];
	size_t sdus_out_nr = 0;

	const size_t fpdus_max_nr = 1000; /* Arbitrarly */
	const size_t fpdu_length = 5000; /* Arbitrarly */
	unsigned char fpdus[fpdus_max_nr][fpdu_length];
	size_t fpdus_nr = 0;
	size_t fpdu_id;

	struct rle_sdu sdus_out[number_of_packets];
	const size_t sdu_out_buf_length = 5000;
	uint8_t sdu_out_buf[number_of_packets][sdu_out_buf_length];

	const size_t label_size = 3;
	const unsigned char label[3] = { 0x00, 0x01, 0x02 };
	size_t fpdu_cur_pos[fpdus_max_nr];
	size_t fpdu_remain_size[fpdus_max_nr];

	size_t sdus_nr = 0;
	unsigned char label_out[label_size];

	uint8_t frag_id;

	/* empty capture means immediate success */
	if (number_of_packets == 0) {
		status = 1;
		goto exit;
	}

	for (pkt_id = 0; pkt_id < number_of_packets; ++pkt_id) {
		sdus_in[pkt_id].buffer = (unsigned char *)packets[pkt_id] + link_len_src;
		sdus_in[pkt_id].size = packets_length[pkt_id] - link_len_src;
	}

	memset(fpdus, -1, fpdus_max_nr * fpdu_length);

	for (pkt_id = 0; pkt_id < number_of_packets; ++pkt_id) {
		memset((void *)sdu_out_buf[pkt_id], '\0', sdu_out_buf_length);
		sdus_out[pkt_id].buffer = sdu_out_buf[pkt_id] + link_len_src;
	}

	TRACE("\n=== prepare %zu packet(s)\n", number_of_packets);
	for (pkt_id = 0; pkt_id < number_of_packets; ++pkt_id) {
		sdus_in[pkt_id].protocol_type =
			ntohs(*(uint16_t *)(packets[pkt_id] + ETHER_HDR_LEN - 2));

		TRACE("=== %zu-byte SDU\n", sdus_in[pkt_id].size);
		unsigned char *p_buffer;
		for (p_buffer = sdus_in[pkt_id].buffer;
		     p_buffer < sdus_in[pkt_id].buffer + sdus_in[pkt_id].size;
		     ++p_buffer) {
			TRACE("%02x%s", *p_buffer,
			      (p_buffer - sdus_in[pkt_id].buffer) % 16 == 15 ? "\n" : " ");
		}
		TRACE("\n");
	}

	fpdu_cur_pos[fpdus_nr] = 0;
	fpdu_remain_size[fpdus_nr] = frag_len;
	for (pkt_id = 0, frag_id = 0;
	     pkt_id < number_of_packets;
	     pkt_id++, frag_id = (frag_id + 1) % RLE_MAX_FRAG_NUMBER) {
		bool is_context_empty[RLE_MAX_FRAG_NUMBER] = { false };

		TRACE("\n=== packet #%zu in context ID %u:\n", pkt_id + 1, frag_id);

		/* Encapsulate the IP packet into a RLE packet */
		TRACE("====== RLE encapsulation: start\n");
		ret_encap = rle_encapsulate(transmitter, &sdus_in[pkt_id], frag_id);
		switch (ret_encap) {
		case RLE_ENCAP_OK:
			TRACE("========= RLE encapsulation: success (%zu bytes in context)\n",
			      rle_transmitter_stats_get_queue_size(transmitter, frag_id));
			break;
		case RLE_ENCAP_ERR_NULL_TRMT:
		case RLE_ENCAP_ERR_SDU_TOO_BIG:
			TRACE("========= RLE encapsulation: ERROR: misuse (%s)\n",
			      str_encap_error(ret_encap));
			status = -1;
			goto exit;
		case RLE_ENCAP_ERR:
		default:
			TRACE("========= RLE encapsulation: ERROR: failure\n");
			status = -1;
			goto exit;
		}

		/* interlace all the packets RLE_MAX_FRAG_NUMBER by RLE_MAX_FRAG_NUMBER */
		if ((frag_id + 1U) != RLE_MAX_FRAG_NUMBER &&
		    (pkt_id + 1U) != number_of_packets) {
			continue;
		}

		/* fragment the all the encapsulated packets */
		size_t empty_contexts = 0;
		uint8_t i;
		while (empty_contexts < min(number_of_packets, RLE_MAX_FRAG_NUMBER)) {
			for (i = 0; i < min(number_of_packets, RLE_MAX_FRAG_NUMBER); i++) {
				size_t queue_size =
					rle_transmitter_stats_get_queue_size(transmitter, i);
				if (queue_size == 0) {
					TRACE("\n====== RLE fragmentation for context ID "
					      "%u: empty context\n", i);
					if (!is_context_empty[i]) {
						is_context_empty[i] = true;
						empty_contexts++;
						TRACE("====== packet #%u will output at position "
						      "#%zu\n", i + 1, sdus_out_nr + 1);
						sdus_out_order[sdus_out_nr] = i;
						sdus_out_nr++;
					}
					continue;
				}

				unsigned char *ppdu;
				size_t ppdu_len = 0;
				size_t ppdu_fragment_max_len;

				TRACE("\n====== RLE fragmentation for context ID %u: try to "
				      "empty the %zu-byte queue (max PPDU fragment = %zu "
				      "bytes)\n", i, queue_size, fpdu_remain_size[fpdus_nr]);

				if (fpdu_remain_size[fpdus_nr] == frag_len) {
					ppdu_fragment_max_len =
						fpdu_remain_size[fpdus_nr] - label_size;
				} else {
					ppdu_fragment_max_len = fpdu_remain_size[fpdus_nr];
				}

				ret_frag = rle_fragment(transmitter, i, ppdu_fragment_max_len,
				                        &ppdu, &ppdu_len);
				switch (ret_frag) {
				case RLE_FRAG_OK:
					TRACE("========= RLE fragmentation: success (%zu bytes "
					      "remaining -> %zu bytes remaining)\n", queue_size,
					      rle_transmitter_stats_get_queue_size(transmitter, i));
					TRACE("========= %zu-byte PPDU\n", ppdu_len);
					{
						unsigned char *ppdu_it;
						for (ppdu_it = ppdu;
						     ppdu_it < ppdu + ppdu_len;
						     ppdu_it++) {
							TRACE("%02x%s", *ppdu_it,
							      (ppdu_it - ppdu) % 16 ==
							      15 ? "\n" : " ");
						}
						TRACE("\n");
					}
					break;
				case RLE_FRAG_ERR_BURST_TOO_SMALL:
					TRACE("========= RLE packing: too few space for one PPDU, "
					      "continue with next FPDU\n");

					/* pad the FPDU */
					rle_pad(fpdus[fpdus_nr], fpdu_cur_pos[fpdus_nr],
					        fpdu_remain_size[fpdus_nr]);
					fpdu_cur_pos[fpdus_nr] += fpdu_remain_size[fpdus_nr];
					fpdu_remain_size[fpdus_nr] = 0;

					{
						TRACE("\n");
						TRACE("======= %zu-byte FPDU #%zu completed:\n",
						      fpdu_cur_pos[fpdus_nr], fpdus_nr + 1);
						size_t it = 0;
						for (it = 0; it < fpdu_cur_pos[fpdus_nr];
						     ++it) {
							TRACE("%02x%s", fpdus[fpdus_nr][it],
							      it % 16 == 15 ? "\n" : " ");
						}
						TRACE("\n");
					}

					/* next FPDU buffer */
					fpdus_nr++;
					if (fpdus_nr >= fpdus_max_nr) {
						TRACE("====== RLE packing: ERROR: too few FPDU\n");
						status = -1;
						goto exit;
					}
					fpdu_cur_pos[fpdus_nr] = 0;
					fpdu_remain_size[fpdus_nr] = frag_len;

					break;
				case RLE_FRAG_ERR_NULL_TRMT:
				case RLE_FRAG_ERR_INVALID_SIZE:
				case RLE_FRAG_ERR_CONTEXT_IS_NULL:
					TRACE("========= RLE fragmentation: ERROR: misuse (%s)\n",
					      str_frag_error(ret_frag));
					status = -1;
					goto exit;
				case RLE_FRAG_ERR:
				default:
					TRACE("========= RLE encapsulation: ERROR: failure\n");
					status = -1;
					goto exit;
				}

				if (ret_frag != RLE_FRAG_OK) {
					continue;
				}
				assert(ppdu_len <= fpdu_remain_size[fpdus_nr]);

				TRACE("\n====== RLE packing: start\n");
				ret_pack = rle_pack(ppdu, ppdu_len, label, label_size,
				                    fpdus[fpdus_nr], &fpdu_cur_pos[fpdus_nr],
				                    &fpdu_remain_size[fpdus_nr]);
				switch (ret_pack) {
				case RLE_PACK_OK:
					TRACE("========= RLE packing: success (%zu-byte FPDU, "
					      "max %zu bytes)\n", fpdu_cur_pos[fpdus_nr], frag_len);

					if (fpdu_remain_size[fpdus_nr] == 0) {
						TRACE("========= RLE packing: FPDU is full, "
						      "continue with next FPDU\n");
						TRACE("\n");
						TRACE("======= %zu-byte FPDU #%zu completed:\n",
						      fpdu_cur_pos[fpdus_nr], fpdus_nr + 1);
						size_t it = 0;
						for (it = 0; it < fpdu_cur_pos[fpdus_nr]; ++it) {
							TRACE("%02x%s", fpdus[fpdus_nr][it],
							      it % 16 == 15 ? "\n" : " ");
						}
						TRACE("\n");

						/* next FPDU buffer */
						fpdus_nr++;
						if (fpdus_nr >= fpdus_max_nr) {
							TRACE("====== RLE packing: ERROR: "
							      "too few FPDU\n");
							status = -1;
							goto exit;
						}
						fpdu_cur_pos[fpdus_nr] = 0;
						fpdu_remain_size[fpdus_nr] = frag_len;
					}
					break;
				case RLE_PACK_ERR_FPDU_TOO_SMALL:
					TRACE("========= RLE packing: FPDU too small for PPDU, "
					      "continue with next FPDU\n");

					/* pad the FPDU */
					rle_pad(fpdus[fpdus_nr], fpdu_cur_pos[fpdus_nr],
					        fpdu_remain_size[fpdus_nr]);
					fpdu_cur_pos[fpdus_nr] += fpdu_remain_size[fpdus_nr];
					fpdu_remain_size[fpdus_nr] = 0;

					{
						TRACE("\n");
						TRACE("======= %zu-byte FPDU #%zu completed:\n",
						      fpdu_cur_pos[fpdus_nr], fpdus_nr + 1);
						size_t it = 0;
						for (it = 0; it < fpdu_cur_pos[fpdus_nr]; ++it) {
							TRACE("%02x%s", fpdus[fpdus_nr][it],
							      it % 16 == 15 ? "\n" : " ");
						}
						TRACE("\n");
					}

					/* next FPDU buffer */
					fpdus_nr++;
					if (fpdus_nr >= fpdus_max_nr) {
						TRACE("====== RLE packing: ERROR: too few FPDU\n");
						status = -1;
						goto exit;
					}
					fpdu_cur_pos[fpdus_nr] = 0;
					fpdu_remain_size[fpdus_nr] = frag_len;
					break;
				case RLE_PACK_ERR_INVALID_LAB:
				case RLE_PACK_ERR_INVALID_PPDU:
					TRACE("========= RLE packing: ERROR: misuse (%s)\n",
					      str_pack_error(ret_pack));
					status = -1;
					goto exit;
				case RLE_PACK_ERR:
				default:
					TRACE("========= RLE packing: ERROR: failure\n");
					status = -1;
					goto exit;
				}

				{
					TRACE("========= %zu-byte FPDU #%zu being completed:\n",
					      fpdu_cur_pos[fpdus_nr], fpdus_nr + 1);
					size_t it = 0;
					for (it = 0; it < fpdu_cur_pos[fpdus_nr]; ++it) {
						TRACE("%02x%s", fpdus[fpdus_nr][it],
						      it % 16 == 15 ? "\n" : " ");
					}
					TRACE("\n");
				}
			}
		}
	}

	/* pad the last FPDU */
	rle_pad(fpdus[fpdus_nr], fpdu_cur_pos[fpdus_nr], fpdu_remain_size[fpdus_nr]);
	fpdu_cur_pos[fpdus_nr] += fpdu_remain_size[fpdus_nr];
	fpdu_remain_size[fpdus_nr] = 0;
	{
		TRACE("\n");
		TRACE("======= %zu-byte FPDU #%zu completed:\n",
		      fpdu_cur_pos[fpdus_nr], fpdus_nr + 1);
		size_t it = 0;
		for (it = 0; it < fpdu_cur_pos[fpdus_nr]; ++it) {
			TRACE("%02x%s", fpdus[fpdus_nr][it], it % 16 == 15 ? "\n" : " ");
		}
		TRACE("\n");
	}
	fpdus_nr++;

	TRACE("\n=== RLE transmitter built %zu FPDUs\n", fpdus_nr);

	/* decapsulate the FPDUs */
	size_t packet_offset = 0;
	for (fpdu_id = 0; fpdu_id < fpdus_nr; fpdu_id++) {
		TRACE("\n=== RLE decapsulation of FPDU #%zu: start (sdus = %p, "
		      "sdus_max_nr = %zu, sdus_nr = %p)\n", fpdu_id + 1, sdus_out,
		      number_of_packets, &sdus_nr);
		ret_decap =
			rle_decapsulate(receiver, fpdus[fpdu_id], frag_len, sdus_out,
			                number_of_packets, &sdus_nr, label_out, label_size);
		switch (ret_decap) {
		case RLE_DECAP_OK:
			TRACE("====== RLE decapsulation of FPDU #%zu: success (%zu SDUs)\n",
			      fpdu_id + 1, sdus_nr);
			break;
		case RLE_DECAP_ERR_NULL_RCVR:
		case RLE_DECAP_ERR_INV_FPDU:
		case RLE_DECAP_ERR_INV_PL:
		case RLE_DECAP_ERR_INV_SDUS:
			TRACE("====== RLE decapsulation of FPDU #%zu: ERROR: misuse (%s)\n",
			      fpdu_id + 1, str_decap_error(ret_decap));
			status = -1;
			goto exit;
		case RLE_DECAP_ERR:
		default:
			TRACE("====== RLE decapsulation of FPDU #%zu: ERROR: failure\n",
			      fpdu_id + 1);
			status = -2;
			goto exit;
		}

		for (pkt_id = 0; pkt_id < sdus_nr; ++pkt_id) {
			TRACE("====== %zu-byte decapsuled SDU #%zu:\n",
			      sdus_out[pkt_id].size, pkt_id + 1);
			size_t it = 0;
			for (it = 0; it < sdus_out[pkt_id].size; ++it) {
				TRACE("%02x%s", sdus_out[pkt_id].buffer[it],
				      it % 16 == 15 ? "\n" : " ");
			}
			TRACE("\n");
		}

		/* compare the decapsulated packet with the original one */
		for (pkt_id = 0; pkt_id < sdus_nr; pkt_id++) {
			size_t packet_id = sdus_out_order[packet_offset + pkt_id];
			TRACE("====== packet #%zu comparison: start\n", packet_id + 1);
			if (!compare_packets(packets[packet_id] + link_len_src,
			                     packets_length[packet_id] - link_len_src,
			                     sdus_out[pkt_id].buffer,
			                     sdus_out[pkt_id].size)) {
				TRACE("====== packet #%zu comparison: ERROR: failure\n",
				      packet_id + 1);
				status = 0;
				goto exit;
			} else {
				TRACE("====== packet #%zu comparison: success\n", packet_id + 1);
			}
		}
		packet_offset += sdus_nr;
	}

	/* check that all input packets are decapsulated correctly */
	if (packet_offset != number_of_packets) {
		TRACE("====== ERROR: %zu packets decapsulated in total, but %zu expected\n",
		      packet_offset, number_of_packets);
		status = -2;
		goto exit;
	}

	/* everything went fine */
	status = 1;

exit:
	TRACE("\n");
	return status;
}


/**
 * @brief Test the RLE library with a flow of IP packets going through
 *        encapsulation, fragmentation, packing and decapsulation
 *
 * @param src_filename         The name of the PCAP file that contains the
 *                             IP packets
 * @return                     0 in case of success,
 *                             1 in case of failure,
 *                             77 if test is skipped
 */
static int test_encap_and_decap(const char *const src_filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	size_t link_len_src;
	struct pcap_pkthdr header;

	unsigned char *packet;

	int counter;

	struct rle_transmitter *transmitter;
	struct rle_receiver *receiver;

	int ret;
	size_t nb_bad = 0, nb_ok = 0, err_transmission = 0, err_reception = 0, nb_ref = 0, nb_inv =
		0;
	int status = 1;

	/* Configuration for uncompressed protocol type */
	struct rle_config conf_uncomp = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Configuration for compressed protocol type */
	struct rle_config conf_comp = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 1,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Configuration for omitted protocol type */
	struct rle_config conf_omitted = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Ditto for IPv4 and v6 */
	struct rle_config conf_omitted_ip = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x30,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Ditto for IPv4 and v6 in VLAN */
	struct rle_config conf_omitted_vlan_ip = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x31,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Configuration for non omitted protocol type in omission conf */
	struct rle_config conf_not_omitted = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Configuration for uncompressed protocol type with CRC */
	struct rle_config conf_uncomp_crc = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 1,
		.allow_alpdu_sequence_number = 0,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Configuration for compressed protocol type with CRC */
	struct rle_config conf_comp_crc = {
		.allow_ptype_omission = 0,
		.use_compressed_ptype = 1,
		.allow_alpdu_crc = 1,
		.allow_alpdu_sequence_number = 0,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Configuration for omitted IPv4 protocol type with CRC */
	struct rle_config conf_omitted_crc = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 1,
		.allow_alpdu_sequence_number = 0,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x0d,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Ditto for IPv4 and v6 */
	struct rle_config conf_omitted_ip_crc = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 1,
		.allow_alpdu_sequence_number = 0,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x30,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Ditto for IPv4 and v6 in VLAN */
	struct rle_config conf_omitted_vlan_ip_crc = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 1,
		.allow_alpdu_sequence_number = 0,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x31,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Configuration for non omitted protocol type in omission conf with CRC */
	struct rle_config conf_not_omitted_crc = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 0,
		.allow_alpdu_crc = 1,
		.allow_alpdu_sequence_number = 0,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x00,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	/* Configurations */
	struct rle_config *confs[] = {
		&conf_uncomp,
		&conf_comp,
		&conf_omitted,
		&conf_omitted_ip,
		&conf_omitted_vlan_ip,
		&conf_not_omitted,
		&conf_uncomp_crc,
		&conf_comp_crc,
		&conf_omitted_crc,
		&conf_omitted_ip_crc,
		&conf_omitted_vlan_ip_crc,
		&conf_not_omitted_crc,
		NULL
	};

	printf("=== initialization:\n");

	/* open the source dump file */
	handle = pcap_open_offline(src_filename, errbuf);
	if (handle == NULL) {
		printf("failed to open the source pcap file: %s\n", errbuf);
		status = 1;
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if (link_layer_type_src != DLT_EN10MB) {
		printf("link layer type %d not supported in source dump (supported = "
		       "%d)\n", link_layer_type_src, DLT_EN10MB);
		status = 77;
		goto close_input;
	}
	if (include_layer2 == 1) {
		link_len_src = 0;
	} else {
		link_len_src = ETHER_HDR_LEN;
	}

	printf("\n");

	/* for each packet in the dump */
	unsigned char **packets = malloc(sizeof(unsigned char *));
	size_t *packets_length = malloc(sizeof(size_t));
	counter = 0;
	while ((packet = (unsigned char *)pcap_next(handle, &header)) != NULL) {
		/* check Ethernet frame length */
		if (header.len < link_len_src || header.len != header.caplen) {
			printf("bad PCAP packet (len = %d, caplen = %d)\n", header.len,
			       header.caplen);
			status = 1;
			goto free_alloc;
		}
		counter++;
		void *realloc_ret;
		realloc_ret = realloc((void *)packets, counter * sizeof(unsigned char *));
		if (realloc_ret == NULL) {
			printf("failed to copy the packets.\n");
			status = 1;
			goto free_alloc;
		}
		packets = realloc_ret;
		realloc_ret = realloc((void *)packets_length, counter * sizeof(size_t));
		if (realloc_ret == NULL) {
			printf("failed to copy the packets length.\n");
			status = 1;
			goto free_alloc;
		}
		packets_length = realloc_ret;
		packets_length[counter - 1] = header.len;

		packets[counter - 1] = calloc(packets_length[counter - 1], sizeof(unsigned char));
		if (packets[counter - 1] == NULL) {
			printf("failed to copy a packet.\n");
			status = 1;
			goto free_alloc;
		}

		memcpy((void *)packets[counter - 1], (const void *)packet,
		       packets_length[counter - 1]);
	}

	/* Configuration iterator */
	struct rle_config **conf;
	size_t counter_confs = 0;

	/* We launch the test on each configuration. All the cases then are test. */
	for (conf = confs; *conf; ++conf) {
		++counter_confs;

		/* configure trace handler */
		rle_set_trace_callback(print_logs);

		/* create the transmitter */
		transmitter = rle_transmitter_new(*conf);
		if (transmitter == NULL) {
			printf("failed to create the transmitter.\n");
			status = 1;
			receiver = NULL;
			goto destroy_modules;
		}

		/* create the receiver */
		receiver = rle_receiver_new(*conf);
		if (receiver == NULL) {
			printf("failed to create the receiver.\n");
			status = 1;
			goto destroy_modules;
		}

		/* Encapsulate & decapsulate from transmitter to receiver. */
		printf("=== test: \n");
		printf("===\tnumber of packets:   %d\n", counter);
		printf("===\timplicit ptype:      0x%02x\n", (**conf).implicit_protocol_type);
		printf("===\tALPDU protection:    %s\n",
		       (**conf).allow_alpdu_sequence_number ? "SeqNo" : "CRC");
		printf("===\tptype compression:   %s\n",
		       (**conf).use_compressed_ptype ? "On" : "Off");
		printf("===\tptype omission:      %s\n",
		       (**conf).allow_ptype_omission ? "On" : "Off");

		ret = encap_decap(transmitter, receiver, packets_length,
		                  (const unsigned char *const *const)packets,
		                  counter, link_len_src);

		printf("=== statistics: \n");
		{
			u_int8_t frag_id;
			struct rle_transmitter_stats stats;
			for (frag_id = 0; frag_id < RLE_MAX_FRAG_NUMBER; ++frag_id) {
				if (rle_transmitter_stats_get_counters(transmitter, frag_id,
				                                       &stats) != 0) {
					printf("failed to get transmitter counters\n");
					status = 1;
					goto free_alloc;
				}
				printf("===\tFrag ID %u\n", frag_id);
				printf("===\ttransmitter in:             %" PRIu64 "\n",
				       stats.sdus_in);
				printf("===\ttransmitter sent:           %" PRIu64 "\n",
				       stats.sdus_sent);
				printf("===\ttransmitter dropped:        %" PRIu64 "\n",
				       stats.sdus_dropped);
				printf("===\ttransmitter bytes in:       %" PRIu64 "\n",
				       stats.bytes_in);
				printf("===\ttransmitter bytes sent:     %" PRIu64 "\n",
				       stats.bytes_sent);
				printf("===\ttransmitter bytes dropped:  %" PRIu64 "\n",
				       stats.bytes_dropped);
				printf("\n");
				rle_transmitter_stats_reset_counters(transmitter, frag_id);
			}
		}

		if (ret == -1) {
			err_transmission++;
			/* break; */
		} else if (ret == -2) {
			err_reception++;
			/* break; */
		} else if (ret == 0) {
			nb_ref++;
		} else if (ret == 1) {
			nb_ok++;
		} else if (ret == 2) {
			nb_inv++;
		} else {
			nb_bad++;
		}

		/* destroy the transmitter and the receiver. */
destroy_modules:
		if (transmitter != NULL) {
			rle_transmitter_destroy(&transmitter);
		}
		if (receiver != NULL) {
			rle_receiver_destroy(&receiver);
		}
	}

	/* show the encapsulation/decapsulation results. */
	printf("=== summary:\n");
	printf("===\tFPDU processed:       %zu\n", counter_confs);
	printf("===\tmalformed:            %zu\n", nb_bad);
	printf("===\tinvalid:              %zu\n", nb_inv);
	printf("===\ttransmission_failed:  %zu\n", err_transmission);
	printf("===\treception_failed:     %zu\n", err_reception);
	printf("===\tmatches:              %zu\n", nb_ok);
	printf("\n");

	printf("=== shutdown:\n");
	if (err_transmission == 0 && err_reception == 0 &&
	    (ignore_malformed || nb_bad == 0) && nb_ref == 0 &&
	    (nb_ok + nb_bad + nb_inv) == counter_confs) {
		/* test is successful */
		status = 0;
	}

free_alloc:
	if (packets != NULL) {
		size_t pkt_id;
		for (pkt_id = 0; pkt_id < (size_t)counter; ++pkt_id) {
			if (packets[pkt_id] != NULL) {
				free(packets[pkt_id]);
			}
		}
		free(packets);
		packets = NULL;
	}
	if (packets_length != NULL) {
		free(packets_length);
		packets_length = NULL;
	}
close_input:
	pcap_close(handle);
error:
	return status;
}

/**
 * @brief Callback function registered in librle to handle the logs
 *
 * @param module_id  the rle internal module id
 * @param level      the log level requested (DEBUG, WARNING, etc.)
 * @param file       the filename in librle in which the log was requested
 * @param line       the line at which the log was requested in librle
 * @param func       the function in librle in which the log was requested
 * @param fmt        the string which contains the format of the message
 * @param ...        the additional parameters used to format the message
 */
static void print_logs(const int module_id,
                       const int level,
                       const char *const file,
                       const int line,
                       const char *const func,
                       const char *const fmt,
                       ...)
{
	if (level <= RLE_LOG_LEVEL_WARNING || is_verbose) {
		const char *const level_descr[] = {
			[RLE_LOG_LEVEL_CRI] = "CRITICAL",
			[RLE_LOG_LEVEL_ERROR] = "ERROR",
			[RLE_LOG_LEVEL_WARNING] = "WARNING",
			[RLE_LOG_LEVEL_INFO] = "INFO",
			[RLE_LOG_LEVEL_DEBUG] = "DEBUG",
		};
		va_list args;

		printf("[%s] [%d:%s:%d:%s()] ", level_descr[level], module_id, file, line, func);
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		printf("\n");
	}
}

/**
 * @brief Compare two network packets and print differences if any
 *
 * @param pkt1      The first packet
 * @param pkt1_size The size of the first packet
 * @param pkt2      The second packet
 * @param pkt2_size The size of the second packet
 * @return          Whether the packets are equal or not
 */
static int compare_packets(const unsigned char *const pkt1,
                           const int pkt1_size,
                           const unsigned char *const pkt2,
                           const int pkt2_size)
{
	int valid = 1;
	int min_size;
	int i, j, k;
	char str1[4][7], str2[4][7];
	char sep1, sep2;

	/* do not compare more than the shortest of the 2 packets */
	min_size = min(pkt1_size, pkt2_size);

	/* do not compare more than 180 bytes to avoid huge output */
	min_size = min(180, min_size);

	/* if packets are equal, do not print the packets */
	if (pkt1_size == pkt2_size && memcmp(pkt1, pkt2, pkt1_size) == 0) {
		goto skip;
	}

	/* packets are different */
	valid = 0;

	printf("------------------------------ Compare ------------------------------\n");
	printf("--------- reference ----------         ----------- new --------------\n");

	if (pkt1_size != pkt2_size) {
		printf("packets have different sizes (%d != %d), compare only the %d "
		       "first bytes\n", pkt1_size, pkt2_size, min_size);
	}

	j = 0;
	for (i = 0; i < min_size; i++) {
		if (pkt1[i] != pkt2[i]) {
			sep1 = '#';
			sep2 = '#';
		} else {
			sep1 = '[';
			sep2 = ']';
		}

		sprintf(str1[j], "%c0x%.2x%c", sep1, pkt1[i], sep2);
		sprintf(str2[j], "%c0x%.2x%c", sep1, pkt2[i], sep2);

		/* make the output human readable */
		if (j >= 3 || (i + 1) >= min_size) {
			for (k = 0; k < 4; k++) {
				if (k < (j + 1)) {
					printf("%s  ", str1[k]);
				} else { /* fill the line with blanks if nothing to print */
					printf("        ");
				}
			}

			printf("       ");

			for (k = 0; k < (j + 1); k++) {
				printf("%s  ", str2[k]);
			}

			printf("\n");

			j = 0;
		} else {
			j++;
		}
	}

	printf("----------------------- packets are different -----------------------\n");

skip:
	return valid;
}


/**
 * @brief     show the encapsulation error linked to the encapsulation status.
 *
 * @param[in] status          the encapsulation status.
 *
 * @return    a printable encapsulation error.
 */
static char * str_encap_error(const enum rle_encap_status status)
{
	switch (status) {
	case RLE_ENCAP_OK:
		return "[RLE_ENCAP_OK] no error detected.";
	case RLE_ENCAP_ERR:
		return "[RLE_ENCAP_ERR] Default error. SDU should be dropped.";
	case RLE_ENCAP_ERR_NULL_TRMT:
		return "[RLE_ENCAP_ERR_NULL_TRMT] The transmitter is NULL.";
	case RLE_ENCAP_ERR_SDU_TOO_BIG:
		return "[RLE_ENCAP_ERR_SDU_TOO_BIG] SDU too big to be encapsulated.";
	default:
		return "[Unknwon status]";
	}
}


/**
 * @brief     show the fragmentation error linked to the fragmentation status.
 *
 * @param[in] status          the fragmentation status.
 *
 * @return    a printable fragmentation error.
 */
static char * str_frag_error(const enum rle_frag_status status)
{
	switch (status) {
	case RLE_FRAG_OK:
		return "[RLE_FRAG_OK] no error detected.";
	case RLE_FRAG_ERR:
		return "[RLE_FRAG_ERR] SDU should be dropped.";
	case RLE_FRAG_ERR_NULL_TRMT:
		return "[RLE_FRAG_ERR_NULL_TRMT] The transmitter is NULL.";
	case RLE_FRAG_ERR_BURST_TOO_SMALL:
		return "[RLE_FRAG_ERR_BURST_TOO_SMALL] Burst size is too small.";
	case RLE_FRAG_ERR_CONTEXT_IS_NULL:
		return "[RLE_FRAG_ERR_CONTEXT_IS_NULL] Context is NULL, ALPDU may be empty.";
	case RLE_FRAG_ERR_INVALID_SIZE:
		return "[RLE_FRAG_ERR_INVALID_SIZE] Remaining data size may be invalid in End PPDU.";
	default:
		return "[Unknwon status]";
	}
}


/**
 * @brief     show the packing error linked to the packing status.
 *
 * @param[in] status          the packing status.
 *
 * @return    a printable packing error.
 */
static char * str_pack_error(const enum rle_pack_status status)
{
	switch (status) {
	case RLE_PACK_OK:
		return "[RLE_PACK_OK] no error detected.";
	case RLE_PACK_ERR:
		return "[RLE_PACK_ERR] SDUs should be dropped.";
	case RLE_PACK_ERR_FPDU_TOO_SMALL:
		return
		        "[RLE_PACK_ERR_FPDU_TOO_SMALL] FPDU is too small for the current PPDU. No drop.";
	case RLE_PACK_ERR_INVALID_PPDU:
		return
		        "[RLE_PACK_ERR_INVALID_PPDU] Current PPDU is invalid, maybe NULL or bad size.";
	case RLE_PACK_ERR_INVALID_LAB:
		return
		        "[RLE_PACK_ERR_INVALID_LAB] Current label is invalid, maybe NULL or bad size.";
	default:
		return "[Unknwon status]";
	}
}


/**
 * @brief     show the decapsulation error linked to the decapsulation status.
 *
 * @param[in] status          the decapsulation status.
 *
 * @return    a printable decapsulation error.
 */
static char * str_decap_error(const enum rle_decap_status status)
{
	switch (status) {
	case RLE_DECAP_OK:
		return "[RLE_DECAP_OK] no error detected.";
	case RLE_DECAP_ERR:
		return "[RLE_DECAP_ERR] SDUs should be dropped.";
	case RLE_DECAP_ERR_NULL_RCVR:
		return "[RLE_DECAP_ERR_NULL_RCVR] The receiver is NULL.";
	case RLE_DECAP_ERR_ALL_DROP:
		return "[RLE_DECAP_ERR_ALL_DROP] All current SDUs were dropped. Some may be lost.";
	case RLE_DECAP_ERR_SOME_DROP:
		return "[RLE_DECAP_ERR_SOME_DROP] Some SDUs were dropped. Some may be lost.";
	case RLE_DECAP_ERR_INV_FPDU:
		return "[RLE_DECAP_ERR_INV_FPDU] Invalid FPDU. Maybe Null or bad size.";
	case RLE_DECAP_ERR_INV_SDUS:
		return "[RLE_DECAP_ERR_INV_SDUS] Given preallocated SDUs array is invalid.";
	case RLE_DECAP_ERR_INV_PL:
		return "[RLE_DECAP_ERR_INV_PL] Given preallocated payload label array is invalid.";
	default:
		return "[Unknwon status]";
	}
}
