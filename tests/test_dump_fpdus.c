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
 * @file   test_dump_fpdus.c
 * @brief  Dump FPDUs in a trace.
 * @author Henrick Deschamps
 * @date   01/2016
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
#include <netinet/ip.h>
#include <sys/socket.h>
#include <getopt.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <linux/limits.h>

/** The program version */
#define TEST_VERSION  "RLE dump FPDUs test application, version 0.0.1\n"

/** The device MTU */
#define DEV_MTU  0xffffU

/** The length (in bytes) of the IP and Ethernet header */
#define ETHER_HDR_LEN  14U
#define IP_HDR_LEN     20U

/** A simple minimum macro */
#define min(x, y) \
	(((x) < (y)) ? (x) : (y))

/** Min, max and default ppdu sizes for fragmentation in the test. */
#define MIN_PPDU_SIZE     3
#define MAX_PPDU_SIZE     2049
#define DEFAULT_PPDU_SIZE MAX_PPDU_SIZE

/** Default FPDU size */
#define MIN_FPDU_SIZE     38
#define MAX_FPDU_SIZE     599
#define DEFAULT_FPDU_SIZE MAX_FPDU_SIZE

/** Default PCAP filename */
#define DEFAULT_OUTPUT "out.pcap"

/** dummy Ethernet header value for PCAP dumping. */
static const unsigned char ether_header[ETHER_HDR_LEN] =
	"\x11\x22\x33\x44\x55\x66\x66\x55\x44\x33\x22\x11\x08\x00";

/* prototypes of private functions */
static int init_pcap_dump(const char device_name[], const char pcap_filename[],
                          pcap_dumper_t **const dumpfile, unsigned char *const frame);
static uint16_t ip_checksum(const void *data, int len);
static uint16_t ip_checksum_fold(uint32_t tmp_sum);
static uint32_t ip_checksum_init(const unsigned short *data, size_t len);
static void packet_handler(pcap_dumper_t *const dumpfile,
                           const struct pcap_pkthdr *const header, const unsigned char *const data);
static void usage(void);
static void test_interrupt(int signum);
static void dump_buffer(const unsigned char *const buffer, const size_t buffer_length);
static int test_encap(const char device_name[], const char output[], const size_t ppdu_size,
                      const size_t fpdu_size);
static void dump_fpdu(unsigned char *const fpdu, const size_t fpdu_size,
                      size_t *const fpdu_cur_pos, size_t *const fpdu_remain_size,
                      size_t *const fpdus_nb, pcap_dumper_t *const dumpfile,
                      unsigned char frame[]);
static int encap(struct rle_transmitter *const transmitter, size_t *const fpdu_cur_pos,
                 unsigned char *const fpdu, const size_t packet_length,
                 const unsigned char *const packet, const size_t link_len_src,
                 const size_t ppdu_size, const size_t fpdu_size, size_t *const fpdus_nb,
                 pcap_dumper_t *const dumpfile, unsigned char frame[]);
static char * str_encap_error(const enum rle_encap_status status);
static char * str_frag_error(const enum rle_frag_status status);
static char * str_pack_error(const enum rle_pack_status status);

/** Whether the application runs in verbose mode or not */
static int is_verbose = 0;

#define printf_verbose(x ...) do { \
		if (is_verbose) { printf(x); } \
} while (0)

/** Whether to handle malformed packets as fatal for test or not */
static int ignore_malformed = 0;

/** Flag to stop the application */
static int stop_program = 0;

/** Counter for packet processed */
static size_t packets_counter = 0;

/**
 * @brief Main function for the RLE test program
 *
 * @param[in] argc The number of program arguments
 * @param[in] argv The program arguments
 *
 * @return         The unix return code:
 *                 \li 0 in case of success,
 *                 \li 1 in case of failure,
 *                 \li 77 in case test is skipped
 */
int main(int argc, char *argv[])
{
	char *device_name = NULL;
	char *output = NULL;
	int status = EXIT_FAILURE;
	size_t ppdu_size = DEFAULT_PPDU_SIZE;
	size_t fpdu_size = DEFAULT_FPDU_SIZE;

	/* parse program arguments, print the help message in case of failure */
	if (argc <= 1) {
		usage();
		goto error;
	}

	while (1) {
		int c;

		const char short_options[] = "vhp:f:o:";

		const struct option long_options[] =
		{
			{ "verbose", no_argument, &is_verbose, 1 },
			{ "ignore_malformed", no_argument, &ignore_malformed, 1 },
			{ "ppdu_size", required_argument, NULL, 'p' },
			{ "fpdu_size", required_argument, NULL, 'f' },
			{ "output", required_argument, NULL, 'o' },
			{ NULL, 0, NULL, 0 }
		};

		int option_index = 0;

		c = getopt_long(argc, argv, short_options, long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != NULL) {
				break;
			}
			printf("option %s", long_options[option_index].name);
			if (optarg) {
				printf(" with arg %s", optarg);
			}
			printf("\n");
			break;

		case 'p': /* PPDU Size */
			assert(optarg != NULL);
			printf("PPDU size with value `%s'\n", optarg);
			ppdu_size = atoi(optarg);

			if (ppdu_size < MIN_PPDU_SIZE) {
				printf("ERROR: %zu PPDU size is too small. Minimum = %d octets.\n",
				       ppdu_size, MIN_PPDU_SIZE);
				goto error;
			} else if (ppdu_size > MAX_PPDU_SIZE) {
				printf("ERROR: %zu PPDU size is too big. Maximum = %d octets.\n",
				       ppdu_size, MIN_PPDU_SIZE);
				goto error;
			}
			break;

		case 'f': /* FPDU Size */
			assert(optarg != NULL);
			printf("FPDU size with value `%s'\n", optarg);
			fpdu_size = atoi(optarg);

			if (fpdu_size < MIN_FPDU_SIZE) {
				printf("ERROR: %zu FPDU size is too small. Minimum = %d octets.\n",
				       fpdu_size, MIN_FPDU_SIZE);
				goto error;
			} else if (fpdu_size > MAX_FPDU_SIZE) {
				printf("ERROR: %zu FPDU size is too big. Maximum = %d octets.\n",
				       fpdu_size, MIN_FPDU_SIZE);
				goto error;
			}
			break;

		case 'o': /* Output */
			assert(optarg != NULL);
			if (strlen(optarg) >= PATH_MAX) {
				printf("ERROR: output path too long");
				goto error;
			}
			printf("Output set to `%s'\n", optarg);
			if (output != NULL) {
				free(output); /* in case option is given twice */
			}
			output = strdup(optarg);
			if (output == NULL) {
				printf("ERROR: Unable to allocate output filename.\n");
				goto error;
			}
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

	/* Instead of reporting ‘--verbose’
	 *      and ‘--brief’ as they are encountered,
	 *           we report the final status resulting from them. */
	if (is_verbose) {
		puts("verbose flag is set");
	}

	if (optind != argc - 1) {
		fprintf(stderr, "FLOW is a mandatory parameter\n\n");
		usage();
		goto error;
	}

	device_name = argv[optind];

	/* If output is not set, setting it to default value. */
	if (output == NULL) {
		output = strdup(DEFAULT_OUTPUT);
		if (output == NULL) {
			printf("ERROR: Unable to allocate output filename.\n");
			goto error;
		}
	}

	signal(SIGINT, test_interrupt);
	signal(SIGTERM, test_interrupt);
	signal(SIGSEGV, test_interrupt);
	signal(SIGABRT, test_interrupt);
	{
		struct sigaction action;
		memset(&action, 0, sizeof(struct sigaction));
		action.sa_handler = SIG_IGN;
		sigaction(SIGHUP, &action, NULL);
	}

	/* test RLE encap with the packets from the file with a given ppdu size */
	status = test_encap(device_name, output, ppdu_size, fpdu_size);

	printf("=== exit test with code %d\n", status);

error:

	if (output != NULL) {
		free(output);
	}

	return status;
}


/** Initialize the PCAP dump
 *
 * @param[in]      device_name          A net device
 * @param[in]      pcap_filename        The name of the trace
 * @param[in,out]  dumpfile             File used for dumping
 * @param[in,out]  frame                Ethernet frame (with preinitialized header) used for dumping
 */
static int init_pcap_dump(const char device_name[],
                          const char pcap_filename[],
                          pcap_dumper_t **const dumpfile,
                          unsigned char *const frame)
{
	int status = 1;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	memcpy((void *)frame, (const void *)ether_header, ETHER_HDR_LEN);

	handle = pcap_open_live(device_name, 0xFFFF, 1, 1e3, errbuf);

	if (!handle) {
		fprintf(stderr, "unable to create handle on %s, %s\n", device_name, errbuf);
		goto error;
	}

	/* Open the dump file */
	*dumpfile = pcap_dump_open(handle, pcap_filename);

	if (!*dumpfile) {
		fprintf(stderr, "error opening output file %s\n", pcap_geterr(handle));
		goto error;
	}

	status = 0;

error:
	return status;
}


/** Handle a single packet.
 *
 * @param[in,out]  dumpfile             File used for dumping
 * @param[in]      header               PCAP packet header
 * @param[in]      data                 PCAP data
 */
static void packet_handler(pcap_dumper_t *const dumpfile,
                           const struct pcap_pkthdr *const header,
                           const unsigned char *const data)
{
	if (!header) {
		fprintf(stderr, "error, header is not initialized\n");
		goto error;
	}

	if (!data) {
		fprintf(stderr, "error, data is not initialized\n");
		goto error;
	}

	if (!dumpfile) {
		fprintf(stderr, "error, dumpfile is not initialized\n");
		goto error;
	}

	pcap_dump((unsigned char *)dumpfile, header, data);

error:
	return;
}


/**
 * @brief Print usage of the dump FPDUs test application
 */
static void usage(void)
{
	fprintf(stderr,
	        "\n"
	        "RLE dump FPDUs test tool:  test the RLE library with a network interface.\n"
	        "\n"
	        "usage: test_dump_fpdus [OPTIONS] interface\n"
	        "\n"
	        "with:\n"
	        "\tinterface               The network interface to sniff.\n"
	        "\n"
	        "options:\n"
	        "\t-v                      Print version information and exit\n"
	        "\t-h                      Print this usage and exit\n"
	        "\t--ppdu_size, -p         Change the PPDU size (default %d octets)\n"
	        "\t--fpdu_size, -f         Change the FPDU size (default %d octets)\n"
	        "\t--output, -o            Change the output (default %s)\n"
	        "\t--ignore-malformed      Ignore malformed packets for test\n"
	        "\t--verbose               Run the test in verbose mode\n"
	        "\n",
	        DEFAULT_PPDU_SIZE, DEFAULT_FPDU_SIZE, DEFAULT_OUTPUT);

	return;
}


/**
 * @brief Handle UNIX signals that interrupt the program
 *
 * @param[in] signum  The received signal
 */
static void test_interrupt(int signum)
{
	/* end the program with next captured packet */
	printf_verbose("signal %d catched\n", signum);
	stop_program = 1;

	/* for SIGSEGV/SIGABRT, close the PCAP dumps, print the last debug traces,
	 * then kill the program */
	if (signum == SIGSEGV || signum == SIGABRT) {
		if (signum == SIGSEGV) {
			printf_verbose("a segfault occurred at packet #%zu\n", packets_counter);
		} else {
			printf_verbose("an assertion failed at packet #%zu\n", packets_counter);
		}

		if (signum == SIGSEGV) {
			struct sigaction action;
			memset(&action, 0, sizeof(struct sigaction));
			action.sa_handler = SIG_DFL;
			sigaction(SIGSEGV, &action, NULL);
			raise(signum);
		}
	}

	return;
}


/**
 * @brief      Dump a buffer
 * @param[in]  buffer_length  The size of the buffer
 * @param[in]  buffer         The buffer
 */
static void dump_buffer(const unsigned char *const buffer, const size_t buffer_length)
{
	size_t buffer_it;

	for (buffer_it = 0; buffer_it < buffer_length; ++buffer_it) {
		printf_verbose("%02x%s", buffer[buffer_it], buffer_it % 16 == 15 ? "\n" : " ");
	}
	printf_verbose("\n");

	return;
}


/**
 * IP Checksum Init
 *
 * Initialize the checksum calculation
 *
 * @param[in]  data  The data used to checksum
 * @param[in]  len   The length of the data
 *
 * return  A temp checksum
 */
static uint32_t ip_checksum_init(const unsigned short *data, size_t len)
{
	uint32_t tmp_sum = 0;

	while (len > 1) {
		tmp_sum += *data;
		data++;
		len -= 2;
	}

	if (len) {
		tmp_sum += *(uint8_t *)data;
	}

	return tmp_sum;
}


/**
 * Ip checksum fold
 *
 * Fold the temp checksum
 *
 * @param[in]  tmp_sum  the temp checksum to fold
 *
 * @return  A temp checksum
 */
static uint16_t ip_checksum_fold(uint32_t tmp_sum)
{
	if (tmp_sum & ~0xFFFF) {
		ip_checksum_fold((tmp_sum >> 16) + (tmp_sum & 0xFFFF));
	}

	return tmp_sum;
}


/**
 * IP checksum
 *
 * Calculate the IP checksum
 *
 * @param[in]  data  The data used to checksum
 * @param[in]  len   The length of the data
 *
 * @return  The checksum
 */
static uint16_t ip_checksum(const void *data, int len)
{
	return ~ip_checksum_fold(ip_checksum_init((unsigned short *)data, len));
}


/**
 * @brief          Pad and dump an FPDU, then reset it for the next SDU to pack.
 *
 *                 Does not actually send the FPDU, as this is not requiered in our algorithm.
 *
 * @param[in,out]  fpdu              The FPDU to send. Reseted after sending.
 * @param[in]      fpdu_size         The size of an FPDU.
 * @param[in,out]  fpdu_cur_pos      Current position in the FPDU. Reseted after sending.
 * @param[in,out]  fpdu_remain_size  Remaining size in the FPDU. Reseted after sending.
 * @param[in,out]  fpdus_nb          Number of sent FPDU.
 * @param[in,out]  dumpfile          File used for dumping
 * @param[in,out]  frame             Ethernet frame (with preinitialized header) used for dumping
 */
static void dump_fpdu(unsigned char *const fpdu,
                      const size_t fpdu_size,
                      size_t *const fpdu_cur_pos,
                      size_t *const fpdu_remain_size,
                      size_t *const fpdus_nb,
                      pcap_dumper_t *const dumpfile,
                      unsigned char frame[])
{
	/* Padding */
	rle_pad(fpdu, *fpdu_cur_pos, *fpdu_remain_size);

	printf_verbose("=== %zu-octets FPDU ready for dumping\n", fpdu_size);
	dump_buffer(fpdu, fpdu_size);
	printf_verbose("\n");
	++(*fpdus_nb);

	{
		static uint16_t ip_id = 0;
		struct pcap_pkthdr header = {
			.caplen = (bpf_u_int32)(ETHER_HDR_LEN + IP_HDR_LEN + fpdu_size),
			.len = (bpf_u_int32)(ETHER_HDR_LEN + IP_HDR_LEN + fpdu_size),
		};
		struct iphdr ip_hdr;

		ip_hdr.version = 0x4;
		ip_hdr.ihl = 0x5;
		ip_hdr.tos = 0;
		ip_hdr.tot_len = 0;
		ip_hdr.id = ntohs(ip_id);
		ip_hdr.frag_off = 0;
		ip_hdr.ttl = 10;
		ip_hdr.protocol = 0;
		ip_hdr.check = 0;
		ip_hdr.saddr = 0;
		ip_hdr.daddr = 0;
		ip_hdr.check = ip_checksum(&ip_hdr, IP_HDR_LEN);
		memcpy(frame + ETHER_HDR_LEN, &ip_hdr, IP_HDR_LEN);

		memcpy(frame + ETHER_HDR_LEN + IP_HDR_LEN, fpdu, fpdu_size);
		gettimeofday(&header.ts, NULL);
		packet_handler(dumpfile, &header, frame);


		++ip_id;
	}

	printf_verbose("=== Dumping done.\n");

	memset((void *)fpdu, '\0', fpdu_size);
	*fpdu_cur_pos = 0;
	*fpdu_remain_size = fpdu_size;

	return;
}

/**
 * @brief Encapsulate, fragment, pack one SDU with a given transmitter.
 *
 * @param[in,out] transmitter    The transmitter to use.
 * @param[in,out] fpdu_cur_pos   The current position in the FPDU
 * @param[in,out] fpdu           A buffer to contain the FPDU, preallocated. May contains
 *                               fragments of SDUs between function call.
 * @param[in]     packet_length  Length of the packet to encapsulate.
 * @param[in]     packet         The packet to encapsulate (link layer included)
 * @param[in]     link_len_src   The length of the link layer header before IP data
 * @param[in]     ppdu_size      The size of the ppdu to frag
 * @param[in]     ppdu_size      The size of the fpdu to pack
 * @param[out]    fpdus_nb       The number of FPDU sent
 * @param[in,out] dumpfile       File used for dumping
 * @param[in,out] frame          Ethernet frame (with preinitialized header) used for dumping
 *
 * @return                  1 if the process is successful
 *                          2 if the process is not successful, but due to a misuse of the RLE lib.
 *                          -1 if an error occurs while transmitting
 *                          -3 if the link layer is not Ethernet
 */
static int encap(struct rle_transmitter *const transmitter,
                 size_t *const fpdu_cur_pos,
                 unsigned char *const fpdu,
                 const size_t packet_length,
                 const unsigned char *const packet,
                 const size_t link_len_src,
                 const size_t ppdu_size,
                 const size_t fpdu_size,
                 size_t *const fpdus_nb,
                 pcap_dumper_t *const dumpfile,
                 unsigned char frame[])
{
	enum rle_encap_status ret_encap = RLE_ENCAP_ERR;
	enum rle_frag_status ret_frag = RLE_FRAG_ERR;
	enum rle_pack_status ret_pack = RLE_PACK_ERR;

	struct rle_sdu sdu_in;

	const size_t label_length = 0;
	const unsigned char *label = NULL;

	int status = 1;
	const uint8_t frag_id = 0;

	sdu_in.buffer = (unsigned char *)packet + link_len_src;
	sdu_in.size = packet_length - link_len_src;
	sdu_in.protocol_type = ntohs(*(uint16_t *)((void *)(packet + (ETHER_HDR_LEN - 2))));

	printf_verbose("=== %zu-byte SDU\n", sdu_in.size);
	dump_buffer(sdu_in.buffer, sdu_in.size);

	/* Encapsulate the IP packet into a RLE packet */
	printf_verbose("=== RLE encapsulation: start\n");
	ret_encap = rle_encapsulate(transmitter, &sdu_in, frag_id);

	switch (ret_encap) {
	case RLE_ENCAP_OK:
		printf_verbose("=== RLE encapsulation: success\n");
		break;
	case RLE_ENCAP_ERR_NULL_TRMT:
	case RLE_ENCAP_ERR_SDU_TOO_BIG:
		printf_verbose("=== RLE encapsulation: misuse\n    %s\n",
		               str_encap_error(ret_encap));
		status = 2;
		goto exit;
	case RLE_ENCAP_ERR:
	default:
		printf_verbose("=== RLE encapsulation: failure\n");
		status = -1;
		goto exit;
	}

	while (rle_transmitter_stats_get_queue_size(transmitter, frag_id) != 0) {
		size_t fpdu_remain_size = fpdu_size - *fpdu_cur_pos;
		printf_verbose("Remaining size : %zu\n", fpdu_remain_size);

		unsigned char *ppdu;
		size_t ppdu_length = 0;
		size_t ppdu_needed;

		/* If the FPDU already contains data, we try to make a PPDU small enough. If it is not
		 * possible to make a small PPDU, a regular one is made instead, and will be pack in a new
		 * FPDU. The old FPDU then is padded and send. */

		if (fpdu_remain_size < ppdu_size) {
			ppdu_needed = fpdu_remain_size;
		} else {
			ppdu_needed = ppdu_size;
		}

		/* Fragmentation */
		do {
			printf_verbose("=== RLE fragmentation: start\n");
			ret_frag = rle_fragment(transmitter, frag_id, ppdu_needed,
			                        &ppdu, &ppdu_length);

			switch (ret_frag) {
			case RLE_FRAG_OK:
				printf_verbose("=== RLE fragmentation: success. "
				               "ppdu_size: %zu, remaining alpdu: %zu.\n",
				               ppdu_length,
				               rle_transmitter_stats_get_queue_size(transmitter,
				                                                    frag_id));
				printf_verbose("=== %zu-byte PPDU\n", ppdu_length);
				dump_buffer(ppdu, ppdu_length);
				break;
			case RLE_FRAG_ERR_BURST_TOO_SMALL:
				printf_verbose("=== RLE fragementation: ppdu size (%zu) too small. "
				               "Retry fragmentation with max ppdu size (%zu)\n",
				               ppdu_needed, ppdu_size);
				ppdu_needed = ppdu_size;
				break;
			case RLE_FRAG_ERR_NULL_TRMT:
			case RLE_FRAG_ERR_INVALID_SIZE:
			case RLE_FRAG_ERR_CONTEXT_IS_NULL:
				printf_verbose("=== RLE fragmentation: misuse\n"
				               "    %s\n", str_frag_error(ret_frag));
				status = 2;
				goto exit;
			case RLE_FRAG_ERR:
			default:
				printf_verbose("=== RLE fragmentation: failure\n");
				status = -1;
				goto exit;
			}
		} while (ret_frag == RLE_FRAG_ERR_BURST_TOO_SMALL);

		/* Packing */
		printf_verbose("=== RLE packing: start\n");
		do {
			ret_pack = rle_pack(ppdu, ppdu_length, label, label_length,
			                    fpdu, fpdu_cur_pos, &fpdu_remain_size);

			switch (ret_pack) {
			case RLE_PACK_OK:
				printf_verbose("=== RLE packing: success\n");
				if (fpdu_remain_size != 0) {
					printf_verbose("===> packed in %zu-byte FPDU (remains %zu "
					               "bytes)\n", *fpdu_cur_pos, fpdu_remain_size);
				} else {
					printf_verbose("=== RLE packing: FPDU Full.  %zu-octet "
					               "FPDU ready to be sent\n", fpdu_size);
					dump_fpdu(fpdu, fpdu_size, fpdu_cur_pos, &fpdu_remain_size,
					          fpdus_nb, dumpfile, frame);
				}
				break;
			case RLE_PACK_ERR_FPDU_TOO_SMALL:
				/* FPDU too small to contain data. It is padded and send, and a new FPDU is created. */
				printf_verbose("=== RLE packing: FPDU Full,  padding, sending,"
				               "and starting new FPDU\n");
				dump_fpdu(fpdu, fpdu_size, fpdu_cur_pos, &fpdu_remain_size,
				          fpdus_nb, dumpfile, frame);
				break;
			case RLE_PACK_ERR_INVALID_LAB:
			case RLE_PACK_ERR_INVALID_PPDU:
				printf_verbose("=== RLE packing: misuse\n"
				               "    %s\n", str_pack_error(ret_pack));
				status = 2;
				goto exit;
			case RLE_PACK_ERR:
			default:
				printf_verbose("=== RLE packing: failure\n");
				status = -1;
				goto exit;
			}
			/* If the FPDU were too small, we retry the packing with a new one. */
		} while (ret_pack == RLE_PACK_ERR_FPDU_TOO_SMALL);
	}

exit:

	printf_verbose("\n");

	return status;
}


/**
 * @brief Test the RLE library with a flow of IP packets going through
 *        encapsulation, fragmentation, and packing.
 *
 * @param[in] device_name      The name of the interface listened
 * @param[in] output           The file used to dump th FPDUs
 * @param[in] ppdu_size        The size of the PPDUs.
 * @param[in] fpdu_size        The size of the FPDUs.
 *
 * @return                     0 in case of success,
 *                             1 in case of failure,
 *                             77 if test is skipped
 */
static int test_encap(const char device_name[],
                      const char output[],
                      const size_t ppdu_size,
                      const size_t fpdu_size)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type_src;
	size_t link_len_src;
	struct pcap_pkthdr header;

	unsigned char fpdu[MAX_FPDU_SIZE];
	size_t fpdu_cur_pos = 0;

	struct rle_transmitter *transmitter;

	int ret;
	size_t nb_bad = 0, nb_ok = 0, err_transmission = 0, nb_ref = 0, nb_inv = 0;
	int status = 1;

	size_t fpdus_processed = 0;

	const struct rle_config conf = {
		.allow_ptype_omission = 1,
		.use_compressed_ptype = 1,
		.allow_alpdu_crc = 0,
		.allow_alpdu_sequence_number = 1,
		.use_explicit_payload_header_map = 0,
		.implicit_protocol_type = 0x30,
		.implicit_ppdu_label_size = 0,
		.implicit_payload_label_size = 0,
		.type_0_alpdu_label_size = 0,
	};

	pcap_dumper_t *dumpfile = NULL;

	/** Ethernet frame buffer for PCAP dumping */
	unsigned char frame[ETHER_HDR_LEN + IP_HDR_LEN + MAX_FPDU_SIZE];

	transmitter = rle_transmitter_new(&conf);

	if (transmitter == NULL) {
		printf("ERROR: transmitter non initialized\n");
		goto error;
	}

	printf("=== initialization:\n");

	/* open the source dump file */
	handle = pcap_open_live(device_name, DEV_MTU, 0, 0, errbuf);
	if (handle == NULL) {
		printf("failed to open the source pcap file: %s\n", errbuf);
		status = EXIT_FAILURE;
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type_src = pcap_datalink(handle);
	if (link_layer_type_src != DLT_EN10MB) {
		printf("link layer type %d not supported in source dump (supported = %d)\n",
		       link_layer_type_src, DLT_EN10MB);
		status = EXIT_FAILURE;
		goto close_input;
	} else {
		link_len_src = ETHER_HDR_LEN;
	}

	if (init_pcap_dump(device_name, output, &dumpfile, frame) != 0) {
		printf("ERROR. PCAP initialization failed.\n");
		goto close_input;
	}

	printf("\n");

	printf("=== test: \n");
	printf("===\timplicit ptype:      0x%02x\n", conf.implicit_protocol_type);
	printf("===\tALPDU protection:    %s\n",
	       conf.allow_alpdu_sequence_number ? "SeqNo" : "CRC");
	printf("===\tptype compression:   %s\n", conf.use_compressed_ptype ? "On" : "Off");
	printf("===\tptype omission:      %s\n", conf.allow_ptype_omission ? "On" : "Off");

	stop_program = 0;

	printf("\nTest starting...\n");

	while (!stop_program) {
		size_t packet_length = 0;
		size_t delta_fpdus_processed = 0;
		unsigned char *packet = (unsigned char *)pcap_next(handle, &header);

		if (packet == NULL) {
			/* no packet captured, re-try */
			continue;
		}

		++packets_counter;
		packet_length = header.len;

		printf_verbose("Packet #%zu\n", packets_counter);
		ret = encap(transmitter, &fpdu_cur_pos, fpdu, (const size_t)packet_length,
		            (const unsigned char *const)packet, link_len_src, ppdu_size, fpdu_size,
		            &delta_fpdus_processed, dumpfile, frame);

		fpdus_processed += delta_fpdus_processed;

		if (ret == -1) {
			err_transmission++;
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
	}

	/* Pad and dump the last FPDU if exists. */
	if (fpdu_cur_pos != 0) {
		size_t delta_fpdus_processed = 0;
		size_t fpdu_remain_size = fpdu_size - fpdu_cur_pos;
		dump_fpdu(fpdu, fpdu_size, &fpdu_cur_pos, &fpdu_remain_size,
		          &delta_fpdus_processed, dumpfile, frame);
		fpdus_processed += delta_fpdus_processed;
	}

	printf("\n");

	printf("=== statistics: \n");
	{
		u_int8_t frag_id;
		for (frag_id = 0; frag_id < 8; ++frag_id) {
			printf("===\tFrag ID %u\n", frag_id);
			printf("===\ttransmitter in:             %" PRIu64 "\n",
			       rle_transmitter_stats_get_counter_sdus_in(transmitter, frag_id));
			printf("===\ttransmitter sent:           %" PRIu64 "\n",
			       rle_transmitter_stats_get_counter_sdus_sent(transmitter, frag_id));
			printf("===\ttransmitter dropped:        %" PRIu64 "\n",
			       rle_transmitter_stats_get_counter_sdus_dropped(transmitter,
			                                                      frag_id));
			printf("===\ttransmitter bytes in:       %" PRIu64 "\n",
			       rle_transmitter_stats_get_counter_bytes_in(transmitter, frag_id));
			printf("===\ttransmitter bytes sent:     %" PRIu64 "\n",
			       rle_transmitter_stats_get_counter_bytes_sent(transmitter, frag_id));
			printf("===\ttransmitter bytes dropped:  %" PRIu64 "\n",
			       rle_transmitter_stats_get_counter_bytes_dropped(transmitter,
			                                                       frag_id));
			printf("\n");
		}
	}

	/* show the encapsulation results. */
	printf("=== summary:\n");
	printf("===\tSDU processed:        %zu\n", packets_counter);
	printf("===\tFPDU processed:       %zu\n", fpdus_processed);
	printf("===\tmalformed:            %zu\n", nb_bad);
	printf("===\tinvalid:              %zu\n", nb_inv);
	printf("===\ttransmission_failed:  %zu\n", err_transmission);
	printf("===\tvalid:                %zu\n", nb_ok);
	printf("\n");

	printf("=== shutdown:\n");
	if (err_transmission == 0 &&
	    (ignore_malformed || nb_bad == 0) && nb_ref == 0 &&
	    (nb_ok + nb_bad + nb_inv) == packets_counter) {
		/* test is successful */
		status = 0;
	}

close_input:

	pcap_close(handle);

	if (transmitter != NULL) {
		rle_transmitter_destroy(&transmitter);
	}

error:

	return status;
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
		return "[RLE_FRAG_ERR_BURST_TOO_SMALL] ppdu size is too small.";
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
		return "[RLE_PACK_ERR_FPDU_TOO_SMALL] FPDU is too small for the "
		       "current PPDU. No drop.";
	case RLE_PACK_ERR_INVALID_PPDU:
		return "[RLE_PACK_ERR_INVALID_PPDU] Current PPDU is invalid, "
		       "maybe NULL or bad size.";
	case RLE_PACK_ERR_INVALID_LAB:
		return "[RLE_PACK_ERR_INVALID_LAB] Current label is invalid, "
		       "maybe NULL or bad size.";
	default:
		return "[Unknwon status]";
	}
}
