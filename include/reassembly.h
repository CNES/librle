/**
 * @file   reassembly.h
 * @brief  Definition of RLE reassembly structure, functions and variables
 * @author Aurelien Castanie, Henrick Deschamps
 * @date   03/2015
 * @copyright
 *   Copyright (C) 2015, Thales Alenia Space France - All Rights Reserved
 */

#ifndef __REASSEMBLY_H__
#define __REASSEMBLY_H__

#include "rle_ctx.h"
#include "rle_conf.h"

/**
 *  @brief Reassemble fragmented RLE packet to get the PDU
 *
 *  @warning
 *
 *  @param rle_ctx			the rle reassembly context
 *  @param pdu_buffer		pdu buffer's address to reassemble
 *  @param pdu_proto_type	the pdu protocol type
 *  @param pdu_length		the pdu buffer's length
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_get_pdu(struct rle_ctx_management *rle_ctx, void *pdu_buffer, int *pdu_proto_type,
                       uint32_t *pdu_length);

/**
 *  @brief Reassemble fragmented RLE packet to get the PDU
 *
 *  @warning
 *
 *  @param rle_ctx			the rle reassembly context
 *  @param rle_conf 			the rle configuration
 *  @param data_buffer		data buffer's address to reassemble
 *  @param data_length		the data_buffer's length
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
int reassembly_reassemble_pdu(struct rle_ctx_management *rle_ctx,
                              struct rle_configuration *rle_conf, void *data_buffer,
                              size_t data_length,
                              int frag_type);

/**
 *  @brief Remove RLE header from fragment
 *
 *  @warning
 *
 *  @param rle_ctx		the rle reassembly context
 *  @param data_buffer		data buffer's address to reassemble
 *  @param type_rle_header	the RLE header type
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
/* int reassembly_remove_header(struct rle_ctx_management *rle_ctx,
 *                void *data_buffer, int type_rle_header);
 */

/**
 *  @brief Modify RLE header to reassemble
 *
 *  @warning
 *
 *  @param rle_ctx		the rle fragment context
 *  @param data_buffer		data buffer's address to reassemble
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
/* int reassembly_modify_header(struct rle_ctx_management *rle_ctx,
 *                 void *data_buffer);
 */

/**
 *  @brief Compute RLE packet length
 *
 *  @warning
 *
 *  @param rle_ctx		the rle reassembly context
 *  @param data_buffer		data buffer's address to reassemble
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
/* int reassembly_compute_packet_length(struct rle_ctx_management *rle_ctx,
 *                 void *data_buffer);
 */

/**
 *  @brief Check RLE reassembled packet validity with seq nb or CRC
 *
 *  @warning
 *
 *  @param rle_ctx		the rle reassembly context
 *  @param data_buffer		data buffer's address to reassemble
 *
 *  @return	C_ERROR in case of error
 *		C_OK otherwise
 *
 *  @ingroup
 */
/* int reassembly_check_packet_validity(struct rle_ctx_management *rle_ctx,
 *                 void *data_buffer);
 */

#endif /* __REASSEMBLY_H__ */
