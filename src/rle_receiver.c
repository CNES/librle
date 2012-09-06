/**
 * @file   rle_receiver.c
 * @author Aurelien Castanie
 *
 * @brief  RLE receiver functions
 *
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include "rle_receiver.h"
#include "rle_ctx.h"
#include "constants.h"
#include "header.h"
#include "trailer.h"
#include "deencap.h"
#include "reassembly.h"

#define MODULE_NAME "RECEIVER"

static int get_first_free_frag_ctx(struct receiver_module *_this)
{
	int i;
	pthread_mutex_lock(&_this->ctx_mutex);
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		if (((_this->free_ctx >> i) & 0x1) == 0)
			pthread_mutex_unlock(&_this->ctx_mutex);
			return i;
	}
	pthread_mutex_unlock(&_this->ctx_mutex);

	return C_ERROR;
}

static void set_nonfree_frag_ctx(struct receiver_module *_this,
				int index)
{
	pthread_mutex_lock(&_this->ctx_mutex);
	_this->free_ctx |= (1 << index);
	pthread_mutex_unlock(&_this->ctx_mutex);
}

static void set_free_frag_ctx(struct receiver_module *_this,
				int index)
{
	pthread_mutex_lock(&_this->ctx_mutex);
	_this->free_ctx = (0 << index) & 0xff;
	pthread_mutex_unlock(&_this->ctx_mutex);
}

static void set_free_all_frag_ctx(struct receiver_module *_this)
{
	pthread_mutex_lock(&_this->ctx_mutex);
	_this->free_ctx = 0;
	pthread_mutex_unlock(&_this->ctx_mutex);
}

static int get_fragment_type(void *data_buffer)
{
	union rle_header_all *head = (union rle_header_all *)data_buffer;
	int type_rle_frag = C_ERROR;

#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d: RLE packet S %d E %d \n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__,
			head->b.start_ind, head->b.end_ind);
#endif

	switch (head->b.start_ind) {
		case 0x0:
			if (head->b.end_ind == 0x0)
				type_rle_frag = RLE_PDU_CONT_FRAG;
			else
				type_rle_frag = RLE_PDU_END_FRAG;
			break;
		case 0x1:
			if (head->b.end_ind == 0x0)
				type_rle_frag = RLE_PDU_START_FRAG;
			else
				type_rle_frag = RLE_PDU_COMPLETE;
			break;
		default:
			PRINT("ERROR %s %s:%s:%d: invalid/unknown RLE fragment"
					" type S [%x] E [%x]\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					head->b.start_ind, head->b.end_ind);
			break;
	}

	return type_rle_frag;
}

static uint16_t get_fragment_id(void *data_buffer)
{
	union rle_header_all *head = (union rle_header_all *)data_buffer;

	return head->b.LT_T_FID;
}

/* provided data_buffer pointer needs
 * to be set after data payload */
static uint8_t get_seq_no(void *data_buffer) __attribute__ ((unused));
static uint8_t get_seq_no(void *data_buffer)
{
	struct rle_trailer *trl = (struct rle_trailer *)data_buffer;

	return trl->seq_no;
}

/* provided data_buffer pointer needs
 * to be set after data payload */
static uint32_t get_crc(void *data_buffer) __attribute__ ((unused));
static uint32_t get_crc(void *data_buffer)
{
	struct rle_trailer *trl = (struct rle_trailer *)data_buffer;

	return trl->crc;
}

static uint16_t get_rle_packet_length(void *data_buffer) __attribute__ ((unused));
static uint16_t get_rle_packet_length(void *data_buffer)
{
	union rle_header_all *head = (union rle_header_all *)data_buffer;

	return head->b.rle_packet_length;
}

static void init(struct receiver_module *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int i;
	/* allocating buffer for each frag_id
	 * and initialize sequence number and
	 * fragment id */
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_init(&_this->rle_ctx_man[i]);
		rle_conf_init(_this->rle_conf[i]);
		rle_ctx_set_frag_id(&_this->rle_ctx_man[i], i);
		rle_ctx_set_seq_nb(&_this->rle_ctx_man[i], 0);
	}

	pthread_mutex_init(&_this->ctx_mutex, NULL);

	/* all frag_id are set to idle */
	set_free_all_frag_ctx(_this);
}

struct receiver_module *rle_receiver_new(void)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	struct receiver_module *_this = NULL;

	_this = MALLOC(sizeof(struct receiver_module));

	if (!_this) {
		PRINT("ERROR %s %s:%s:%d: allocating receiver module failed\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__);
		return NULL;
	}

	int i;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		_this->rle_conf[i] = rle_conf_new(_this->rle_conf[i]);
		if (!_this->rle_conf[i]) {
			PRINT("ERROR %s %s:%s:%d: allocating receiver module"
				       " configuration failed\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__);
			return NULL;
		}
	}

	init(_this);

	return _this;
}

void rle_receiver_destroy(struct receiver_module *_this)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int i;
	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++)
		rle_ctx_destroy(&_this->rle_ctx_man[i]);

	FREE(_this);
	_this = NULL;
}

int rle_receiver_deencap_data(struct receiver_module *_this,
				void *data_buffer, size_t data_length)
{
#ifdef DEBUG
	PRINT("DEBUG %s %s:%s:%d:\n",
			MODULE_NAME,
			__FILE__, __func__, __LINE__);
#endif

	int ret = C_ERROR;

	if (!data_buffer) {
		PRINT("ERROR %s %s:%s:%d: data buffer is invalid\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__);
		return ret;
	}

	if (!_this) {
		PRINT("ERROR %s %s:%s:%d: receiver module is invalid\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__);
		return ret;
	}

	/* check PPDU validity */
	if (data_length > RLE_MAX_PDU_SIZE) {
		PRINT("ERROR %s %s:%s:%d: Packet too long [%zu]\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__,
				data_length);
		return ret;
	}

	/* retrieve frag id if its a fragmented packet to append data to the
	 * right frag id context (SE bits)
	 * or
	 * search for the first free frag id context to put data into it */
	int frag_type = get_fragment_type(data_buffer);
	int index_ctx = -1;

	switch (frag_type) {
		case RLE_PDU_COMPLETE:
			index_ctx = get_first_free_frag_ctx(_this);
			if (index_ctx < 0) {
				PRINT("ERROR %s %s:%s:%d: no free reassembly context available "
						"for deencapsulation\n",
						MODULE_NAME,
						__FILE__, __func__, __LINE__);
				return C_ERROR;
			}
			break;
		case RLE_PDU_START_FRAG:
		case RLE_PDU_CONT_FRAG:
		case RLE_PDU_END_FRAG:
			index_ctx = get_fragment_id(data_buffer);
#ifdef DEBUG
			PRINT("DEBUG %s %s:%s:%d: fragment_id 0x%0x frag type %d\n",
					MODULE_NAME,
					__FILE__, __func__, __LINE__,
					index_ctx, frag_type);
#endif
			if ((index_ctx < 0) || (index_ctx > RLE_MAX_FRAG_ID)) {
				PRINT("ERROR %s %s:%s:%d: invalid fragment id [%d]\n",
						MODULE_NAME,
						__FILE__, __func__, __LINE__,
						index_ctx);
				return C_ERROR;
			}
			break;
		default:
			return C_ERROR;
			break;
	}

	/* set the previously free frag ctx
	 * or force already
	 * set frag ctx to 'used' state */
	set_nonfree_frag_ctx(_this, index_ctx);

	/* reassemble all fragments */
	ret = reassembly_reassemble_pdu(&_this->rle_ctx_man[index_ctx],
			_this->rle_conf[index_ctx],
			data_buffer,
			data_length,
			frag_type);
	if (ret != C_OK) {
		/* received RLE packet is invalid,
		 * we have to flush related context
		 * for this frag_id */
		rle_ctx_flush_buffer(&_this->rle_ctx_man[index_ctx]);
		rle_ctx_invalid_ctx(&_this->rle_ctx_man[index_ctx]);
		set_free_frag_ctx(_this, index_ctx);
		PRINT("ERROR %s %s:%s:%d: cannot reassemble data\n",
				MODULE_NAME,
				__FILE__, __func__, __LINE__);
		return ret;
	}

	ret = C_OK;
	return ret;
}

void rle_receiver_dump(struct receiver_module *_this)
{
	int i;

	for (i = 0; i < RLE_MAX_FRAG_NUMBER; i++) {
		rle_ctx_dump(&_this->rle_ctx_man[i],
				_this->rle_conf[i]);
	}
}

#ifdef __KERNEL__
EXPORT_SYMBOL(rle_receiver_new);
EXPORT_SYMBOL(rle_receiver_init);
EXPORT_SYMBOL(rle_receiver_destroy);
EXPORT_SYMBOL(rle_receiver_deencap_data);
EXPORT_SYMBOL(rle_receiver_dump);
#endif
