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
 * @file   header.c
 * @brief  RLE encapsulation functions
 * @author Henrick Deschamps
 * @date   01/2016
 * @copyright
 *   Copyright (C) 2016, Thales Alenia Space France - All Rights Reserved
 */

#include "rle_transmitter.h"
#include "constants.h"
#include "fragmentation_buffer.h"
#include "rle_ctx.h"
#include "rle_conf.h"
#include "rle_header_proto_type_field.h"
#include "header.h"
#include "crc.h"

#include "rle.h"

#ifndef __KERNEL__

#include <stdlib.h>
#include <stdio.h>
#include <net/ethernet.h>

#else

#include <linux/types.h>

#endif


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------- PRIVATE CONSTANTS AND MACROS ---------------------------------*/
/*------------------------------------------------------------------------------------------------*/

#define MODULE_ID RLE_MOD_ID_HEADER


/*------------------------------------------------------------------------------------------------*/
/*--------------------------------------- PRIVATE FUNCTIONS --------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

/**
 *  @brief         create and push uncompressed ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf     the fragmentation buffer in use.
 *  @param[in]     ptype        the SDU protocol type
 *
 *  @ingroup
 */
static void push_uncomp_alpdu_hdr(struct rle_frag_buf *const frag_buf,
                                  const uint16_t ptype);

/**
 *  @brief         create and push compressed supported ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf     the fragmentation buffer in use.
 *  @param[in]     ptype        the compressed SDU protocol type
 *
 *  @ingroup
 */
static void push_comp_supported_alpdu_hdr(struct rle_frag_buf *const frag_buf,
                                          const uint8_t ptype);

/**
 *  @brief         create and push compressed fallback ALPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf     the fragmentation buffer in use.
 *  @param[in]     ptype        the SDU protocol type
 *
 *  @ingroup
 */
static void push_comp_fallback_alpdu_hdr(struct rle_frag_buf *const frag_buf,
                                         const uint16_t ptype);

/**
 *  @brief         create and push COMPLETE PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf          the fragmentation buffer in use.
 *  @param[in]     alpdu_label_type  the ALPDU label type field.
 *  @param[in]     ptype_suppressed  the protocol type suppressed field.
 *
 *  @ingroup
 */
static void push_comp_ppdu_hdr(struct rle_frag_buf *const frag_buf,
                               const uint8_t alpdu_label_type,
                               const uint8_t ptype_suppressed);

/**
 *  @brief         create and push START PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf          the fragmentation buffer in use.
 *  @param[in]     frag_id           the fragmentation context ID.
 *  @param[in]     alpdu_label_type  the ALPDU label type field.
 *  @param[in]     ptype_suppressed  the protocol type suppressed field.
 *  @param[in]     use_alpdu_crc     the use ALPDU CRC field.
 *
 *  @ingroup
 */
static void push_start_ppdu_hdr(struct rle_frag_buf *const frag_buf,
                                const uint8_t frag_id,
                                const uint8_t alpdu_label_type,
                                const uint8_t ptype_suppressed,
                                const bool use_alpdu_crc);

/**
 *  @brief         create and push CONT PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     frag_id              the fragmentation context ID.
 *
 *  @ingroup
 */
static void push_cont_ppdu_hdr(struct rle_frag_buf *const frag_buf, const uint8_t frag_id);

/**
 *  @brief         create and push END PPDU header into a fragmentation buffer.
 *
 *
 *  @param[in,out] frag_buf               the fragmentation buffer in use.
 *  @param[in]     frag_id              the fragmentation context ID.
 *
 *  @ingroup
 */
static void push_end_ppdu_hdr(struct rle_frag_buf *const frag_buf, const uint8_t frag_id);

/**
 * @brief Get uncompressed protocol type from the first 4 bits of the SDU
 *
 * @param sdu      The SDU bytes
 * @param sdu_len  The length of the SDU
 * @param[out] pt  The uncompressed protocol type in case of success
 * @return         true in case of success, false if SDU was too short
 */
static bool get_uncomp_ptype_from_sdu(const uint8_t *const sdu,
                                      const size_t sdu_len,
                                      uint16_t *const pt)
__attribute__((warn_unused_result, nonnull(1, 3)));


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------ PRIVATE FUNCTIONS CODE ------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

static void push_uncomp_alpdu_hdr(struct rle_frag_buf *const frag_buf, const uint16_t ptype)
{
	rle_alpdu_hdr_uncomp_t **alpdu_hdr;

	RLE_DEBUG("prepend a 2-byte ALPDU header with an uncompressed protocol type");

	alpdu_hdr = (rle_alpdu_hdr_uncomp_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**alpdu_hdr));
	(*alpdu_hdr)->proto_type = ptype;
}

static void push_comp_supported_alpdu_hdr(struct rle_frag_buf *const frag_buf, const uint8_t ptype)
{
	rle_alpdu_hdr_comp_supported_t **alpdu_hdr;

	RLE_DEBUG("prepend a 1-byte ALPDU header with a compressed protocol type");

	alpdu_hdr = (rle_alpdu_hdr_comp_supported_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**alpdu_hdr));
	(*alpdu_hdr)->proto_type = ptype;
}

static void push_comp_fallback_alpdu_hdr(struct rle_frag_buf *const frag_buf, const uint16_t ptype)
{
	rle_alpdu_hdr_comp_fallback_t **alpdu_hdr;

	RLE_DEBUG("prepend a 3-byte ALPDU header with an unknown compressed protocol "
	          "type");

	alpdu_hdr = (rle_alpdu_hdr_comp_fallback_t **)&frag_buf->alpdu.start;

	frag_buf_alpdu_push(frag_buf, sizeof(**alpdu_hdr));
	(*alpdu_hdr)->comp.proto_type = RLE_PROTO_TYPE_FALLBACK;
	(*alpdu_hdr)->uncomp.proto_type = ptype;
}

static void push_comp_ppdu_hdr(struct rle_frag_buf *const frag_buf,
                               const uint8_t alpdu_label_type,
                               const uint8_t ptype_suppressed)
{
	rle_ppdu_hdr_comp_t **ppdu_hdr;
	uint16_t ppdu_len_field;

	RLE_DEBUG("prepend a 2-byte PPDU COMP header");

	ppdu_hdr = (rle_ppdu_hdr_comp_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**ppdu_hdr));

	ppdu_len_field = frag_buf_get_current_ppdu_len(frag_buf) - 2;

	(*ppdu_hdr)->start_ind = 1;
	(*ppdu_hdr)->end_ind = 1;
	rle_ppdu_hdr_set_ppdu_len((rle_ppdu_hdr_t *)*ppdu_hdr, ppdu_len_field);
	(*ppdu_hdr)->label_type = alpdu_label_type;
	(*ppdu_hdr)->proto_type_supp = ptype_suppressed;
}

static void push_start_ppdu_hdr(struct rle_frag_buf *const frag_buf,
                                const uint8_t frag_id,
                                const uint8_t alpdu_label_type,
                                const uint8_t ptype_suppressed,
                                const bool use_alpdu_crc)
{
	rle_ppdu_hdr_start_t **ppdu_hdr;
	uint16_t ppdu_len_field;
	uint16_t total_len_field;

	RLE_DEBUG("prepend a 4-byte PPDU START header");

	ppdu_hdr = (rle_ppdu_hdr_start_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**ppdu_hdr));

	ppdu_len_field = frag_buf_get_current_ppdu_len(frag_buf) - 2;
	total_len_field = frag_buf_get_alpdu_hdr_len(frag_buf) +
	                  frag_buf_get_sdu_len(frag_buf) +
	                  frag_buf_get_alpdu_trailer_len(frag_buf);

	(*ppdu_hdr)->start_ind = 1;
	(*ppdu_hdr)->end_ind = 0;
	rle_ppdu_hdr_set_ppdu_len((rle_ppdu_hdr_t *)*ppdu_hdr, ppdu_len_field);
	(*ppdu_hdr)->frag_id = frag_id;
	(*ppdu_hdr)->use_crc = (use_alpdu_crc ? 1 : 0);
	rle_ppdu_hdr_start_set_total_len(*ppdu_hdr, total_len_field);
	(*ppdu_hdr)->label_type = alpdu_label_type;
	(*ppdu_hdr)->proto_type_supp = ptype_suppressed;
}

static void push_cont_ppdu_hdr(struct rle_frag_buf *const frag_buf, const uint8_t frag_id)
{
	rle_ppdu_hdr_cont_end_t **ppdu_hdr;
	uint16_t ppdu_len_field;

	RLE_DEBUG("prepend a 2-byte PPDU CONT header");

	ppdu_hdr = (rle_ppdu_hdr_cont_end_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**ppdu_hdr));

	ppdu_len_field = frag_buf_get_current_ppdu_len(frag_buf) - 2;

	(*ppdu_hdr)->start_ind = 0;
	(*ppdu_hdr)->end_ind = 0;
	rle_ppdu_hdr_set_ppdu_len((rle_ppdu_hdr_t *)*ppdu_hdr, ppdu_len_field);
	(*ppdu_hdr)->frag_id = frag_id;
}

static void push_end_ppdu_hdr(struct rle_frag_buf *const frag_buf, const uint8_t frag_id)
{
	rle_ppdu_hdr_cont_end_t **ppdu_hdr;
	uint16_t ppdu_len_field;

	RLE_DEBUG("prepend a 2-byte PPDU END header");

	ppdu_hdr = (rle_ppdu_hdr_cont_end_t **)&frag_buf->ppdu.start;

	frag_buf_ppdu_push(frag_buf, sizeof(**ppdu_hdr));

	ppdu_len_field = frag_buf_get_current_ppdu_len(frag_buf) - 2;

	(*ppdu_hdr)->start_ind = 0;
	(*ppdu_hdr)->end_ind = 1;
	rle_ppdu_hdr_set_ppdu_len((rle_ppdu_hdr_t *)*ppdu_hdr, ppdu_len_field);
	(*ppdu_hdr)->frag_id = frag_id;
}

static bool get_uncomp_ptype_from_sdu(const uint8_t *const sdu,
                                      const size_t sdu_len,
                                      uint16_t *const pt)
{
	uint8_t ip_version;

	if (sdu_len < 1) {
		/* the protocol type cannot be deduced from the IP payload */
		RLE_ERR("SDU is too short to deduce IP version from the first IP byte: "
		        "%zu bytes available, 1 byte required at least\n", sdu_len);
		goto error;
	}

	ip_version = (sdu[0] >> 4) & 0x0f;

	if (ip_version == 4) {
		*pt = RLE_PROTO_TYPE_IPV4_UNCOMP;
	} else if (ip_version == 6) {
		*pt = RLE_PROTO_TYPE_IPV6_UNCOMP;
	} else {
		RLE_ERR("unsupported IP Version %u\n", ip_version);
		goto error;
	}

	RLE_DEBUG("IP version %u detected, uncompressed protocol type is 0x%04x",
	          ip_version, *pt);

	return true;

error:
	return false;
}


/*------------------------------------------------------------------------------------------------*/
/*------------------------------------- PUBLIC FUNCTIONS CODE-------------------------------------*/
/*------------------------------------------------------------------------------------------------*/

int is_eth_vlan_ip_frame(const uint8_t *const sdu, const size_t sdu_len)
{
	const size_t eth_vlan_hdr_min_len = sizeof(struct ether_header) + sizeof(struct vlan_hdr);
	uint8_t comp_ptype = RLE_PROTO_TYPE_FALLBACK;

	if (sdu_len <= eth_vlan_hdr_min_len) {
		/* the protocol type of short Ethernet/VLAN frames cannot be compressed */
		RLE_DEBUG("frame is not Ethernet/VLAN/IPv4/6 (too short VLAN frame)");
		goto error;
	}

	/* retrieve the Ethernet protocol type */
	{
		const struct ether_header *const eth_hdr = (struct ether_header *)sdu;
		const uint16_t eth_proto_type = ntohs(eth_hdr->ether_type);

		const struct vlan_hdr *const vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);
		const uint16_t vlan_proto_type = ntohs(vlan_hdr->tpid);

		const uint8_t *const vlan_payload = (uint8_t *)(vlan_hdr + 1);
		const uint8_t ip_version = (vlan_payload[0] >> 4) & 0x0f;

		if (eth_proto_type != RLE_PROTO_TYPE_VLAN_UNCOMP) {
			/* unexpected protocol type in Ethernet frame: it should be VLAN */
			RLE_DEBUG("frame is not Ethernet/VLAN/IPv4/6 (malformed VLAN)");
			goto error;
		}

		/* embedded IPv4 or IPv6 use a special compressed protocol type that indicates
		 * to the RLE receiver that the protocol field of the VLAN header is suppressed */
		if ((vlan_proto_type == RLE_PROTO_TYPE_IPV4_UNCOMP && ip_version == 4) ||
		    (vlan_proto_type == RLE_PROTO_TYPE_IPV6_UNCOMP && ip_version == 6)) {
			RLE_DEBUG("frame is Ethernet/VLAN/IPv4/6");
			comp_ptype = RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD;
		} else {
			RLE_DEBUG("frame is Ethernet/VLAN but not Ethernet/VLAN/IPv4/6");
			comp_ptype = RLE_PROTO_TYPE_VLAN_COMP;
		}
	}

error:
	return comp_ptype;
}

void push_alpdu_hdr(struct rle_frag_buf *const frag_buf, const struct rle_config *const rle_conf)
{
	uint16_t ptype;

	RLE_DEBUG("prepend a ALPDU header");

	ptype = frag_buf->sdu_info.protocol_type;

	/* ALPDU: 4 cases, len € {0,1,2,3} */

	/* don't fill ALPDU ptype field if given ptype is equal to the default one and suppression is
	 * active, or if given ptype is for signalling packet */
	if (!ptype_is_omissible(ptype, rle_conf, frag_buf)) {
		const uint16_t net_ptype = ntohs(ptype);

		/* suppression is not possible, is compression enabled? */
		if (!rle_conf->use_compressed_ptype) {
			/* No compression, no suppression, ALPDU len = 2 */
			push_uncomp_alpdu_hdr(frag_buf, net_ptype);
		} else {
			/* No suppression, compression is enabled */
			uint8_t comp_ptype;

			/* is protocol type compressible? */
			if (rle_header_ptype_is_compressible(ptype) == C_OK) {
				comp_ptype = rle_header_ptype_compression(ptype, frag_buf);
			} else {
				comp_ptype = RLE_PROTO_TYPE_FALLBACK;
			}

			if (comp_ptype == RLE_PROTO_TYPE_FALLBACK) {
				/* protocol type is NOT compressible, prepend the 3-byte ALPDU before the SDU */
				push_comp_fallback_alpdu_hdr(frag_buf, net_ptype);
			} else {
				/* protocol type is compressible, ALPDU len = 1 */

				/* special case if the payload is VLAN with embedded IPv4 or IPv6:
				 *  - the RLE transmitter shall suppress the protocol field of the VLAN header,
				 *  - the RLE receiver shall detect IPv4/IPv6 with the 4 first bits of the
				 *    embedded payload. */
				if (ptype == RLE_PROTO_TYPE_VLAN_UNCOMP &&
				    comp_ptype == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
					RLE_DEBUG("omit the protocol field of the VLAN header "
					          "making SDU 2 bytes less (%zu bytes in total)",
					          frag_buf_get_sdu_len(frag_buf) - sizeof(ptype));
					memmove(frag_buf->sdu.start + sizeof(ptype),
					        frag_buf->sdu.start, sizeof(struct ether_header) +
					        sizeof(struct vlan_hdr) - sizeof(ptype));
					frag_buf_sdu_push(frag_buf, -(sizeof(ptype)));
				}

				/* prepend the 1-byte ALPDU before the SDU */
				push_comp_supported_alpdu_hdr(frag_buf, comp_ptype);
			}
		}
	} else {
		/* protocol type is omitted, ALPDU len == 0 */
		RLE_DEBUG("prepend a 0-byte ALPDU header with protocol type omitted");

		/* special case if the payload is VLAN with embedded IPv4 or IPv6:
		 *  - the RLE transmitter shall suppress the protocol field of the VLAN header,
		 *  - the RLE receiver shall detect IPv4/IPv6 with the 4 first bits of the
		 *    embedded payload. */
		if (ptype == RLE_PROTO_TYPE_VLAN_UNCOMP &&
		    rle_conf->implicit_protocol_type == RLE_PROTO_TYPE_VLAN_COMP_WO_PTYPE_FIELD) {
			RLE_DEBUG("omit the protocol field of the VLAN header "
			          "making SDU 2 bytes less (%zu bytes in total)",
			          frag_buf_get_sdu_len(frag_buf) - sizeof(ptype));
			memmove(frag_buf->sdu.start + sizeof(ptype), frag_buf->sdu.start,
			        sizeof(struct ether_header) + sizeof(struct vlan_hdr) -
			        sizeof(ptype));
			frag_buf_sdu_push(frag_buf, -(sizeof(ptype)));
		}
	}
}

bool push_ppdu_hdr(struct rle_frag_buf *const frag_buf,
                   const struct rle_config *const rle_conf,
                   const size_t ppdu_len,
                   struct rle_ctx_mngt *const rle_ctx)
{
	const size_t ppdu_base_hdr_len = 2;
	const size_t ppdu_std_max_len = RLE_MAX_PPDU_PL_SIZE + ppdu_base_hdr_len;
	size_t max_alpdu_frag_len = ppdu_len;
	const size_t remain_alpdu_len = frag_buf_get_remaining_alpdu_length(frag_buf);
	const bool use_alpdu_crc =
		(rle_conf->allow_alpdu_sequence_number ? false : !!rle_conf->allow_alpdu_crc);

	RLE_DEBUG("build one PPDU (%zu bytes max) with %zu remaining bytes of ALPDU",
	          ppdu_len, remain_alpdu_len);

	/* do not put more PPDU bytes than allowed by the standard, ie. length
	 * stored on 11 bits + 2 bytes of base header = 2047+2 = 2049 */
	if (max_alpdu_frag_len > ppdu_std_max_len) {
		RLE_DEBUG("do not build one %zu-byte PPDU, larger than the max "
		          "%zu bytes defined by RLE standard", max_alpdu_frag_len,
		          ppdu_std_max_len);
		max_alpdu_frag_len = ppdu_std_max_len;
	}

	if (frag_buf_is_fragmented(frag_buf)) {
		/* ALPDU is fragmented, use CONT or END PPDU */
		RLE_DEBUG("ALPDU was already fragmented, build one CONT or END PPDU");

		/* RLE context needed if ALPDU is fragmented */
		assert(rle_ctx != NULL);

		if (ppdu_len <= sizeof(rle_ppdu_hdr_cont_end_t)) {
			/* buffer is too small for the smallest PPDU CONT or END fragment plus 1 byte of payload:
			 * sending 0 byte of payload is useless, and even a problem: a CONT PPDU with 0 byte of
			 * payload may be confused with padding */
			goto error;
		}

		max_alpdu_frag_len -= sizeof(rle_ppdu_hdr_cont_end_t);

		/* Determine whether a END PPDU is possible or not: a END PPDU is possible only if all
		 * remaining ALPDU bytes may fit into the available room after the END PPDU header
		 *
		 * If END PPDU is not possible, use a CONT PPDU. The RLE reassembler does not support
		 * when the ALPDU trailer (CRC or seqnum) is fragmented. The seqnum fits into one
		 * single byte, so it cannot be fragmented. The CRC fits into 32 bits. So, if the RLE
		 * transmitter is configured for CRC, we should avoid to fragment the last 4 bytes of
		 * the ALPDU.
		 * Note: the `remain_alpdu_len` contain the ALPDU trailer length */
		if (remain_alpdu_len <= max_alpdu_frag_len) {
			/* END PPDU is possible: put all remaining bytes into the PPDU payload, then build
			 * the END PPDU header before the payload */
			RLE_DEBUG("build one END PPDU");
			frag_buf_ppdu_put(frag_buf, remain_alpdu_len);
			push_end_ppdu_hdr(frag_buf, rle_ctx->frag_id);
		} else {
			/* CONT PPDU is required: determine whether the trailer is fully contained in the
			 * next PPDU fragment or not ; if not, the trailer would be fragmented, so make
			 * the CONT PPDU fragment smaller to avoid the trailer fragmentation */
			RLE_DEBUG("build one CONT PPDU");

			const size_t trailer_len = (use_alpdu_crc ? RLE_CRC_SIZE : 0);
			const size_t alpdu_overflow_len = remain_alpdu_len - max_alpdu_frag_len;

			if (alpdu_overflow_len < trailer_len) {
				/* the number of ALPDU bytes that will be put in the next fragments is smaller
				 * than the ALPDU trailer, so the current CONT PPDU contains some bytes of the
				 * trailer, so make the PPDU fragment shorter */

				size_t trailer_len_in_cur_ppdu = trailer_len - alpdu_overflow_len;
				size_t alpdu_frag_len = max_alpdu_frag_len -
				                        trailer_len_in_cur_ppdu;

				/* do not build CONT PPDU with 0 byte of ALPDU: sending 0 byte of payload is useless,
				 * and even a problem: a CONT PPDU with 0 byte of payload may be confused with padding */
				if (alpdu_frag_len == 0) {
					goto error;
				}

				frag_buf_ppdu_put(frag_buf, alpdu_frag_len);
				push_cont_ppdu_hdr(frag_buf, rle_ctx->frag_id);
			} else {
				/* the ALPDU trailer will be fully transmitted in one of the next fragments,
				 * there is no risk of trailer fragmentation, so use the full room of the buffer */
				frag_buf_ppdu_put(frag_buf, max_alpdu_frag_len);
				push_cont_ppdu_hdr(frag_buf, rle_ctx->frag_id);
			}
		}
	} else {
		const bool ptype_suppressed = (frag_buf_get_alpdu_hdr_len(frag_buf) == 0);
		const uint8_t alpdu_label_type =
			get_alpdu_label_type(frag_buf->sdu_info.protocol_type, ptype_suppressed,
			                     rle_conf->type_0_alpdu_label_size);

		RLE_DEBUG("ALPDU was not fragmented yet, build one COMP or START PPDU");

		if (remain_alpdu_len + sizeof(rle_ppdu_hdr_comp_t) > max_alpdu_frag_len) {
			/* Start PPDU */
			RLE_DEBUG("build one START PPDU");

			const size_t ppdu_and_alpdu_hdrs_len =
				sizeof(rle_ppdu_hdr_start_t) + frag_buf_get_alpdu_hdr_len(frag_buf);

			/* RLE context needed if ALPDU is fragmented */
			if (!rle_ctx) {
				RLE_ERR("RLE context needed.");
				goto error;
			}

			if (max_alpdu_frag_len < (ppdu_and_alpdu_hdrs_len + 1)) {
				/* buffer is too small for the smallest PPDU START fragment: the buffer shall be large
				 * enough for the PPDU START header, the full ALPDU header and at least one byte of
				 * ALPDU because the fragmentation of the ALPDU header is not supported by the RLE
				 * reassembler yet */
				goto error;
			}
			max_alpdu_frag_len -= sizeof(rle_ppdu_hdr_start_t);

			push_alpdu_trailer(frag_buf, rle_conf, rle_ctx);

			frag_buf_ppdu_put(frag_buf, max_alpdu_frag_len);

			push_start_ppdu_hdr(frag_buf, rle_ctx->frag_id, alpdu_label_type,
			                    ptype_suppressed, use_alpdu_crc);
		} else {
			/* Complete PPDU */
			RLE_DEBUG("build one COMP PPDU");
			if (max_alpdu_frag_len < sizeof(rle_ppdu_hdr_comp_t)) {
				goto error;
			}
			max_alpdu_frag_len -= sizeof(rle_ppdu_hdr_comp_t);

			frag_buf_ppdu_put(frag_buf, max_alpdu_frag_len);

			push_comp_ppdu_hdr(frag_buf, alpdu_label_type, ptype_suppressed);
		}
	}

	frag_buf_set_cur_pos(frag_buf);

	return true;

error:
	return false;
}

void comp_ppdu_extract_alpdu_frag(unsigned char comp_ppdu[],
                                  const size_t ppdu_len,
                                  unsigned char **alpdu_frag,
                                  size_t *alpdu_frag_len)
{
	RLE_DEBUG("extract ALPDU from a %zu-byte PPDU COMP", ppdu_len);

	*alpdu_frag = comp_ppdu + sizeof(rle_ppdu_hdr_comp_t);
	*alpdu_frag_len = ppdu_len - sizeof(rle_ppdu_hdr_comp_t);

	RLE_DEBUG("%zu-byte ALPDU extracted from PPDU COMP", (*alpdu_frag_len));
}

void start_ppdu_extract_alpdu_frag(unsigned char start_ppdu[],
                                   const size_t ppdu_len,
                                   unsigned char *alpdu_frag[],
                                   size_t *const alpdu_frag_len,
                                   size_t *const alpdu_total_len,
                                   int *const is_crc_used)
{
	const rle_ppdu_hdr_start_t *const start_ppdu_header =
		(rle_ppdu_hdr_start_t *)start_ppdu;

	RLE_DEBUG("extract ALPDU fragment from a %zu-byte PPDU START", ppdu_len);

	*alpdu_frag = start_ppdu + sizeof(rle_ppdu_hdr_start_t);
	*alpdu_frag_len = ppdu_len - sizeof(rle_ppdu_hdr_start_t);
	*alpdu_total_len = rle_ppdu_hdr_start_get_total_len(start_ppdu_header);
	*is_crc_used = start_ppdu_header->use_crc;

	assert(ppdu_len == (sizeof(rle_ppdu_hdr_start_t) + (*alpdu_frag_len)));

	RLE_DEBUG("%zu-byte ALPDU fragment extracted from PPDU START (ALPDU total "
	          "length = %zu bytes, protected by %s)", (*alpdu_frag_len),
	          (*alpdu_total_len), ((*is_crc_used) == 1 ? "CRC" : "seqnum"));
}

void cont_end_ppdu_extract_alpdu_frag(const unsigned char cont_end_ppdu[],
                                      const size_t ppdu_len,
                                      const unsigned char *alpdu_frag[],
                                      size_t *const alpdu_frag_len)
{
	RLE_DEBUG("extract ALPDU fragment from a %zu-byte PPDU CONT/END", ppdu_len);

	*alpdu_frag = cont_end_ppdu + sizeof(rle_ppdu_hdr_cont_end_t);
	*alpdu_frag_len = ppdu_len - sizeof(rle_ppdu_hdr_cont_end_t);

	RLE_DEBUG("%zu-byte ALPDU fragment extracted from PPDU CONT/END", (*alpdu_frag_len));
}

int signal_alpdu_extract_sdu_frag(const unsigned char alpdu_frag[],
                                  const size_t alpdu_frag_len,
                                  uint16_t *ptype,
                                  uint8_t *comp_ptype,
                                  const unsigned char *sdu_frag[],
                                  size_t *const sdu_frag_len)
{
	*ptype = RLE_PROTO_TYPE_SIGNAL_UNCOMP;
	*comp_ptype = RLE_PROTO_TYPE_SIGNAL_COMP;
	*sdu_frag = alpdu_frag;
	*sdu_frag_len = alpdu_frag_len;

	return 0;
}

int suppr_alpdu_extract_sdu_frag(const unsigned char alpdu_frag[],
                                 const size_t alpdu_frag_len,
                                 uint16_t *ptype,
                                 uint8_t *comp_ptype,
                                 const unsigned char *sdu_frag[],
                                 size_t *const sdu_frag_len,
                                 const struct rle_config *const rle_conf)
{
	const uint8_t default_ptype = rle_conf->implicit_protocol_type;
	int status = 0;

	RLE_DEBUG("extract SDU from a %zu-byte ALPDU with protocol type omitted", alpdu_frag_len);

	*comp_ptype = default_ptype;
	*sdu_frag = alpdu_frag;
	*sdu_frag_len = alpdu_frag_len;
	RLE_DEBUG("%zu-byte SDU with implicit protocol type 0x%02x extracted from ALPDU",
	          (*sdu_frag_len), default_ptype);

	if (default_ptype == RLE_PROTO_TYPE_IP_COMP) {
		RLE_DEBUG("implicit protocol type 0x%02x requires to detect IP version "
		          "from SDU", default_ptype);
		if (!get_uncomp_ptype_from_sdu(*sdu_frag, *sdu_frag_len, ptype)) {
			RLE_ERR("failed to get uncompressed protocol type from the "
			        "first 4 bits of SDU\n");
			status = 1;
			goto out;
		}
	} else {
		*ptype = rle_header_ptype_decompression(default_ptype);
	}

	RLE_DEBUG("implicit protocol type 0x%02x decompressed to 0x%04x", default_ptype, (*ptype));

out:
	return status;
}

int uncomp_alpdu_extract_sdu_frag(const unsigned char alpdu_frag[],
                                  const size_t alpdu_frag_len,
                                  uint16_t *ptype,
                                  uint8_t *comp_ptype,
                                  const unsigned char *sdu_frag[],
                                  size_t *const sdu_frag_len)
{
	const rle_alpdu_hdr_uncomp_t *const uncomp_alpdu_hdr =
		(rle_alpdu_hdr_uncomp_t *)alpdu_frag;
	int status = 0;

	RLE_DEBUG("extract SDU from a %zu-byte ALPDU with protocol type uncompressed",
	          alpdu_frag_len);

	if (alpdu_frag_len < sizeof(rle_alpdu_hdr_uncomp_t)) {
		RLE_ERR("Invalid alpdu fragment len: %zu\n", alpdu_frag_len);
		status = 1;
		goto out;
	}
	*comp_ptype = RLE_PROTO_TYPE_FALLBACK;
	*ptype = htons(uncomp_alpdu_hdr->proto_type);
	*sdu_frag = alpdu_frag + sizeof(rle_alpdu_hdr_uncomp_t);
	*sdu_frag_len = alpdu_frag_len - sizeof(rle_alpdu_hdr_uncomp_t);

	RLE_DEBUG("%zu-byte SDU with uncompressed protocol type 0x%04x extracted "
	          "from ALPDU", (*sdu_frag_len), (*ptype));

out:
	return status;
}

int comp_alpdu_extract_sdu_frag(const unsigned char alpdu_frag[],
                                const size_t alpdu_frag_len,
                                uint16_t *ptype,
                                uint8_t *comp_ptype,
                                const unsigned char *sdu_frag[],
                                size_t *const sdu_frag_len,
                                size_t *const alpdu_hdr_len)
{
	const rle_alpdu_hdr_t *const alpdu_hdr = (rle_alpdu_hdr_t *)alpdu_frag;
	int status = 0;

	RLE_DEBUG("extract SDU from a %zu-byte ALPDU with protocol type compressed",
	          alpdu_frag_len);

	if (alpdu_frag_len < 1) {
		RLE_ERR("ALPDU fragment smaller (%zu) than the ALPDU header with compressed "
		        "protocol type\n", alpdu_frag_len);
		status = 1;
		goto out;
	}
	*comp_ptype = alpdu_hdr->comp_supported.proto_type;
	RLE_DEBUG("SDU got compressed protocol type 0x%02x", (*comp_ptype));

	if ((*comp_ptype) == RLE_PROTO_TYPE_FALLBACK) {
		if (alpdu_frag_len < sizeof(alpdu_hdr->comp_fallback)) {
			RLE_ERR("Alpdu fragment smaller (%zu) than a header (%zu)\n",
			        alpdu_frag_len, sizeof(alpdu_hdr->comp_fallback));
			status = 1;
			goto out;
		}
		*ptype = htons(alpdu_hdr->comp_fallback.uncomp.proto_type);
		*sdu_frag = alpdu_frag + sizeof(alpdu_hdr->comp_fallback);
		*sdu_frag_len = alpdu_frag_len - sizeof(alpdu_hdr->comp_fallback);
		if (alpdu_hdr_len) {
			*alpdu_hdr_len = sizeof(alpdu_hdr->comp_fallback);
		}
		RLE_DEBUG("%zu-byte SDU with uncompressed protocol type 0x%04x extracted "
		          "from ALPDU", (*sdu_frag_len), (*ptype));
	} else {
		if (alpdu_frag_len < sizeof(alpdu_hdr->comp_supported)) {
			RLE_ERR("Alpdu fragment smaller (%zu) than a header (%zu)\n",
			        alpdu_frag_len, sizeof(alpdu_hdr->comp_supported));
			status = 1;
			goto out;
		}
		*sdu_frag = alpdu_frag + sizeof(alpdu_hdr->comp_supported);
		*sdu_frag_len = alpdu_frag_len - sizeof(alpdu_hdr->comp_supported);
		if (alpdu_hdr_len) {
			*alpdu_hdr_len = sizeof(alpdu_hdr->comp_supported);
		}

		/* determine the Ethertype of the payload */
		if ((*comp_ptype) == RLE_PROTO_TYPE_IP_COMP) {
			/* compressed protocol type 0x30 may indicate IPv4 or IPv6, disambiguation
			 * is performed by checking the first 4 bits of the SDU */
			RLE_DEBUG("compressed protocol type 0x%02x requires to detect IP "
			          "version from SDU", *comp_ptype);
			if (!get_uncomp_ptype_from_sdu(*sdu_frag, *sdu_frag_len, ptype)) {
				RLE_ERR("failed to get uncompressed protocol type from the "
				        "first 4 bits of SDU\n");
				status = 1;
				goto out;
			}
		} else {
			*ptype = rle_header_ptype_decompression(*comp_ptype);
		}

		RLE_DEBUG("%zu-byte SDU with uncompressed protocol type 0x%04x extracted "
		          "from ALPDU", (*sdu_frag_len), (*ptype));
	}

out:
	return status;
}
