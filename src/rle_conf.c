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
 * @file   rle_conf.c
 * @brief  definition of rle configuration module.
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_conf.h"
#include "constants.h"
#include "header.h"
#include "fragmentation_buffer.h"

#include <stdbool.h>
#ifndef __KERNEL__
#include <net/ethernet.h>
#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_CONF


/*------------------------------------------------------------------------------------------------*/
/*-------------------------------- PRIVATE STRUCTS AND TYPEDEFS ----------------------------------*/
/*------------------------------------------------------------------------------------------------*/

bool rle_config_check(const struct rle_config *const conf)
{
	const uint8_t implicit_alpdu_label_size_max = 0x0f;
	const uint8_t implicit_ppdu_label_size_max = 0x0f;
	const uint8_t implicit_payload_label_size_max = 0x0f;

	if (conf == NULL) {
		RLE_WARN("NULL given as configuration");
		return false;
	}
	if (conf->allow_ptype_omission != 0 && conf->allow_ptype_omission != 1) {
		RLE_WARN("configuration parameter allow_ptype_omission set to %d "
		         "while 0 or 1 expected", conf->allow_ptype_omission);
		return false;
	}
	if (conf->use_compressed_ptype != 0 && conf->use_compressed_ptype != 1) {
		RLE_WARN("configuration parameter use_compressed_ptype set to %d "
		         "while 0 or 1 expected", conf->use_compressed_ptype);
		return false;
	}
	if (conf->allow_alpdu_crc != 0 && conf->allow_alpdu_crc != 1) {
		RLE_WARN("configuration parameter allow_alpdu_crc set to %d "
		         "while 0 or 1 expected", conf->allow_alpdu_crc);
		return false;
	}
	if (conf->allow_alpdu_sequence_number != 0 &&
	    conf->allow_alpdu_sequence_number != 1) {
		RLE_WARN("configuration parameter allow_alpdu_sequence_number set "
		         "to %d while 0 or 1 expected", conf->allow_ptype_omission);
		return false;
	}
	if (conf->allow_alpdu_crc == 0 && conf->allow_alpdu_sequence_number == 0) {
		RLE_WARN("configuration parameters allow_alpdu_crc and "
		         "allow_alpdu_sequence_number are both set to 0, set at "
		         "least one of them to 1");
		return false;
	}
	if (conf->use_explicit_payload_header_map != 0 &&
	    conf->use_explicit_payload_header_map != 1) {
		RLE_WARN("configuration parameter use_explicit_payload_header_map "
		         "set to %d while 0 or 1 expected",
		         conf->use_explicit_payload_header_map);
		return false;
	}
	if (conf->use_explicit_payload_header_map == 1) {
		RLE_WARN("configuration parameter use_explicit_payload_header_map "
		         "set to 1 is not supported yet");
		return false;
	}
	if (conf->implicit_ppdu_label_size > implicit_ppdu_label_size_max) {
		RLE_WARN("configuration parameter implicit_ppdu_label_size set to "
		         "%u while only values [0 ; %u] allowed",
		         conf->implicit_ppdu_label_size, implicit_ppdu_label_size_max);
		return false;
	}
	if (conf->implicit_payload_label_size > implicit_payload_label_size_max) {
		RLE_WARN("configuration parameter implicit_payload_label_size set "
		         "to %u while only values [0 ; %u] allowed",
		         conf->implicit_payload_label_size, implicit_payload_label_size_max);
		return false;
	}
	if (conf->type_0_alpdu_label_size > implicit_alpdu_label_size_max) {
		RLE_WARN("configuration parameter implicit_alpdu_label_size set to "
		         "%u while only values [0 ; %u] allowed",
		         conf->type_0_alpdu_label_size, implicit_alpdu_label_size_max);
		return false;
	}

	return true;
}

bool ptype_is_omissible(const uint16_t ptype,
                        const struct rle_config *const rle_conf,
                        const struct rle_frag_buf *const frag_buf)
{
	bool is_omissible;

	if (rle_conf->allow_ptype_omission != 1) {
		/* protocol omission is disabled in configuration */
		RLE_DEBUG("protocol type is NOT omissible (disabled in config)");
		is_omissible = false;
	} else if (ptype == RLE_PROTO_TYPE_SIGNAL_UNCOMP) {
		/* protocol omission is enabled in configuration, and protocol is signaling */
		RLE_DEBUG("protocol type is omissible (signaling)");
		is_omissible = true;
	} else {
		/* protocol omission is enabled in configuration, check the traffic payload */
		const uint8_t default_ptype = rle_conf->implicit_protocol_type;

		switch (default_ptype) {
		case RLE_PROTO_TYPE_IP_COMP:
		{
			uint8_t ip_version;

			/* protocol omission is possible if IPv4 or IPv6 is detected, and the first 4 bits
			 * of the SDU contain a supported IP version so that the RLE receiver is able to infer
			 * the IP version from them */
			if (frag_buf->sdu_info.size < 1) {
				RLE_DEBUG("protocol type is NOT omissible (too short IP packet)");
				is_omissible = false;
				break;
			}

			ip_version = (frag_buf->sdu.start[0] >> 4) & 0x0f;
			if ((ptype == RLE_PROTO_TYPE_IPV4_UNCOMP && ip_version == 4) ||
			    (ptype == RLE_PROTO_TYPE_IPV6_UNCOMP && ip_version == 6)) {
				RLE_DEBUG("protocol type is omissible (IP)");
				is_omissible = true;
			} else {
				RLE_DEBUG("protocol type is NOT omissible (unknown IP version)");
				is_omissible = false;
			}
			break;
		}
		case RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD:
		{
			/* VLAN protocol type can be compressed in 2 different ways:
			 *  - VLAN contains one IPv4 or IPv6 packet as payload,
			 *  - VLAN contains something else as payload.
			 */
			const uint8_t compressed_ptype =
				is_eth_vlan_ip_frame(frag_buf->sdu.start, frag_buf->sdu_info.size);
			is_omissible =
				(compressed_ptype == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD);
			RLE_DEBUG("protocol type is%s omissible", is_omissible ? "" : " NOT");
			break;
		}
		default:
			/* other normal cases */
			if (ptype == rle_header_ptype_decompression(default_ptype)) {
				RLE_DEBUG("protocol type is omissible (protocol type = 0x%04x, "
				          "implicit protocol type = 0x%02x)", ptype, default_ptype);
				is_omissible = true;
			} else {
				RLE_DEBUG("protocol type is NOT omissible (protocol type = 0x%04x, "
				          "implicit protocol type = 0x%02x)", ptype, default_ptype);
				is_omissible = false;
			}
			break;
		}
	}

	return is_omissible;
}

enum rle_header_size_status rle_get_header_size(const struct rle_config *const conf,
                                                const enum rle_fpdu_types fpdu_type,
                                                size_t *const rle_header_size)
{
	enum rle_header_size_status status = RLE_HEADER_SIZE_ERR;
	size_t header_size = 0;

	if (conf == NULL || rle_header_size == NULL) {
		goto error;
	}

	switch (fpdu_type) {
	case RLE_LOGON_FPDU:

		/* FPDU header. */
		/* payload label = 6 */
		header_size = 6;

		status = RLE_HEADER_SIZE_OK;
		break;

	case RLE_CTRL_FPDU:

		/* FPDU header. */
		/* payload label = 3 */
		header_size = 3;

		status = RLE_HEADER_SIZE_OK;
		break;

	case RLE_TRAFFIC_FPDU:

		/* Unable to guess the headers overhead size */

		status = RLE_HEADER_SIZE_ERR_NON_DETERMINISTIC;
		break;

	case RLE_TRAFFIC_CTRL_FPDU:

		/* FPDU header. */
		/* payload label = 3 */
		header_size = 3;

		/* PPDU header. Only complete PPDU. */
		/* se_length_ltt = 2 */
		/* pdu_label     = 0 */
		header_size += 2 + 0;

		/* ALPDU header. */
		/* protocol_type    = 0. May depends on conf with a different implementation. */
		/* alpdu_label      = 0 */
		/* protection_bytes = 0 */
		header_size += 0 + 0 + 0;

		status = RLE_HEADER_SIZE_OK;
		break;
	default:
		break;
	}

	*rle_header_size = header_size;

error:
	return status;
}
