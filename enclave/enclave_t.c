#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_preset_account_t {
	unsigned char* ms_addr;
	unsigned char* ms_seckey;
} ms_ecall_preset_account_t;

typedef struct ms_ecall_create_account_t {
	unsigned char* ms_generated_addr;
} ms_ecall_create_account_t;

typedef struct ms_ecall_create_channel_t {
	unsigned int ms_nonce;
	unsigned char* ms_owner;
	unsigned char* ms_receiver;
	unsigned int ms_deposit;
	unsigned char* ms_signed_tx;
	unsigned int* ms_signed_tx_len;
} ms_ecall_create_channel_t;

typedef struct ms_ecall_onchain_payment_t {
	unsigned int ms_nonce;
	unsigned char* ms_owner;
	unsigned char* ms_receiver;
	unsigned int ms_amount;
	unsigned char* ms_signed_tx;
	unsigned int* ms_signed_tx_len;
} ms_ecall_onchain_payment_t;

typedef struct ms_ecall_pay_t {
	unsigned int ms_channel_id;
	unsigned int ms_amount;
	int* ms_is_success;
} ms_ecall_pay_t;

typedef struct ms_ecall_get_balance_t {
	unsigned int ms_channel_id;
	unsigned int* ms_balance;
} ms_ecall_get_balance_t;

typedef struct ms_ecall_close_channel_t {
	unsigned int ms_nonce;
	unsigned int ms_channel_id;
	unsigned char* ms_signed_tx;
	unsigned int* ms_signed_tx_len;
} ms_ecall_close_channel_t;

typedef struct ms_ecall_eject_t {
	unsigned int ms_nonce;
	unsigned int ms_pn;
	unsigned char* ms_signed_tx;
	unsigned int* ms_signed_tx_len;
} ms_ecall_eject_t;

typedef struct ms_ecall_receive_create_channel_t {
	unsigned int ms_channel_id;
	unsigned char* ms_owner;
	unsigned char* ms_receiver;
	unsigned int ms_deposit;
} ms_ecall_receive_create_channel_t;

typedef struct ms_ecall_go_pre_update_t {
	unsigned int ms_payment_num;
	unsigned int* ms_channel_id;
	int* ms_amount;
	unsigned int ms_size;
} ms_ecall_go_pre_update_t;

typedef struct ms_ecall_go_post_update_t {
	unsigned int ms_payment_num;
	unsigned int* ms_channel_id;
	int* ms_amount;
	unsigned int ms_size;
} ms_ecall_go_post_update_t;

typedef struct ms_ecall_go_idle_t {
	unsigned int ms_payment_num;
} ms_ecall_go_idle_t;

typedef struct ms_ecall_register_comminfo_t {
	unsigned int ms_channel_id;
	unsigned char* ms_ip;
	unsigned int ms_ip_size;
	unsigned int ms_port;
} ms_ecall_register_comminfo_t;

typedef struct ms_ecall_load_account_data_t {
	unsigned char* ms_addr;
	unsigned char* ms_seckey;
} ms_ecall_load_account_data_t;

typedef struct ms_ecall_load_channel_data_t {
	unsigned int ms_channel_id;
	unsigned int ms_type;
	unsigned int ms_channel_status;
	unsigned char* ms_my_addr;
	unsigned int ms_my_deposit;
	unsigned int ms_other_deposit;
	unsigned int ms_balance;
	unsigned int ms_locked_balance;
	unsigned char* ms_other_addr;
	unsigned char* ms_other_ip;
	unsigned int ms_ip_size;
	unsigned int ms_other_port;
} ms_ecall_load_channel_data_t;

typedef struct ms_ecall_load_payment_data_t {
	unsigned int ms_payment_num;
	unsigned int ms_channel_id;
	int ms_amount;
} ms_ecall_load_payment_data_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_ecall_preset_account(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_preset_account_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_preset_account_t* ms = SGX_CAST(ms_ecall_preset_account_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_addr = ms->ms_addr;
	size_t _len_addr = 40;
	unsigned char* _in_addr = NULL;
	unsigned char* _tmp_seckey = ms->ms_seckey;
	size_t _len_seckey = 64;
	unsigned char* _in_seckey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_addr, _len_addr);
	CHECK_UNIQUE_POINTER(_tmp_seckey, _len_seckey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_addr != NULL && _len_addr != 0) {
		if ( _len_addr % sizeof(*_tmp_addr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_addr = (unsigned char*)malloc(_len_addr);
		if (_in_addr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_addr, _len_addr, _tmp_addr, _len_addr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_seckey != NULL && _len_seckey != 0) {
		if ( _len_seckey % sizeof(*_tmp_seckey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_seckey = (unsigned char*)malloc(_len_seckey);
		if (_in_seckey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_seckey, _len_seckey, _tmp_seckey, _len_seckey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_preset_account(_in_addr, _in_seckey);

err:
	if (_in_addr) free(_in_addr);
	if (_in_seckey) free(_in_seckey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_account(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_account_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_account_t* ms = SGX_CAST(ms_ecall_create_account_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_generated_addr = ms->ms_generated_addr;



	ecall_create_account(_tmp_generated_addr);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_channel(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_channel_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_channel_t* ms = SGX_CAST(ms_ecall_create_channel_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_owner = ms->ms_owner;
	size_t _len_owner = 40;
	unsigned char* _in_owner = NULL;
	unsigned char* _tmp_receiver = ms->ms_receiver;
	size_t _len_receiver = 40;
	unsigned char* _in_receiver = NULL;
	unsigned char* _tmp_signed_tx = ms->ms_signed_tx;
	unsigned int* _tmp_signed_tx_len = ms->ms_signed_tx_len;

	CHECK_UNIQUE_POINTER(_tmp_owner, _len_owner);
	CHECK_UNIQUE_POINTER(_tmp_receiver, _len_receiver);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_owner != NULL && _len_owner != 0) {
		if ( _len_owner % sizeof(*_tmp_owner) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_owner = (unsigned char*)malloc(_len_owner);
		if (_in_owner == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_owner, _len_owner, _tmp_owner, _len_owner)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_receiver != NULL && _len_receiver != 0) {
		if ( _len_receiver % sizeof(*_tmp_receiver) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_receiver = (unsigned char*)malloc(_len_receiver);
		if (_in_receiver == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_receiver, _len_receiver, _tmp_receiver, _len_receiver)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_create_channel(ms->ms_nonce, _in_owner, _in_receiver, ms->ms_deposit, _tmp_signed_tx, _tmp_signed_tx_len);

err:
	if (_in_owner) free(_in_owner);
	if (_in_receiver) free(_in_receiver);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_onchain_payment(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_onchain_payment_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_onchain_payment_t* ms = SGX_CAST(ms_ecall_onchain_payment_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_owner = ms->ms_owner;
	size_t _len_owner = 40;
	unsigned char* _in_owner = NULL;
	unsigned char* _tmp_receiver = ms->ms_receiver;
	size_t _len_receiver = 40;
	unsigned char* _in_receiver = NULL;
	unsigned char* _tmp_signed_tx = ms->ms_signed_tx;
	unsigned int* _tmp_signed_tx_len = ms->ms_signed_tx_len;

	CHECK_UNIQUE_POINTER(_tmp_owner, _len_owner);
	CHECK_UNIQUE_POINTER(_tmp_receiver, _len_receiver);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_owner != NULL && _len_owner != 0) {
		if ( _len_owner % sizeof(*_tmp_owner) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_owner = (unsigned char*)malloc(_len_owner);
		if (_in_owner == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_owner, _len_owner, _tmp_owner, _len_owner)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_receiver != NULL && _len_receiver != 0) {
		if ( _len_receiver % sizeof(*_tmp_receiver) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_receiver = (unsigned char*)malloc(_len_receiver);
		if (_in_receiver == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_receiver, _len_receiver, _tmp_receiver, _len_receiver)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_onchain_payment(ms->ms_nonce, _in_owner, _in_receiver, ms->ms_amount, _tmp_signed_tx, _tmp_signed_tx_len);

err:
	if (_in_owner) free(_in_owner);
	if (_in_receiver) free(_in_receiver);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_pay(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pay_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pay_t* ms = SGX_CAST(ms_ecall_pay_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_is_success = ms->ms_is_success;



	ecall_pay(ms->ms_channel_id, ms->ms_amount, _tmp_is_success);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_balance(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_balance_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_balance_t* ms = SGX_CAST(ms_ecall_get_balance_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_balance = ms->ms_balance;



	ecall_get_balance(ms->ms_channel_id, _tmp_balance);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_close_channel(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_close_channel_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_close_channel_t* ms = SGX_CAST(ms_ecall_close_channel_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_signed_tx = ms->ms_signed_tx;
	unsigned int* _tmp_signed_tx_len = ms->ms_signed_tx_len;



	ecall_close_channel(ms->ms_nonce, ms->ms_channel_id, _tmp_signed_tx, _tmp_signed_tx_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_eject(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_eject_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_eject_t* ms = SGX_CAST(ms_ecall_eject_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_signed_tx = ms->ms_signed_tx;
	unsigned int* _tmp_signed_tx_len = ms->ms_signed_tx_len;



	ecall_eject(ms->ms_nonce, ms->ms_pn, _tmp_signed_tx, _tmp_signed_tx_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_receive_create_channel(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_receive_create_channel_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_receive_create_channel_t* ms = SGX_CAST(ms_ecall_receive_create_channel_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_owner = ms->ms_owner;
	size_t _len_owner = 40;
	unsigned char* _in_owner = NULL;
	unsigned char* _tmp_receiver = ms->ms_receiver;
	size_t _len_receiver = 40;
	unsigned char* _in_receiver = NULL;

	CHECK_UNIQUE_POINTER(_tmp_owner, _len_owner);
	CHECK_UNIQUE_POINTER(_tmp_receiver, _len_receiver);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_owner != NULL && _len_owner != 0) {
		if ( _len_owner % sizeof(*_tmp_owner) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_owner = (unsigned char*)malloc(_len_owner);
		if (_in_owner == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_owner, _len_owner, _tmp_owner, _len_owner)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_receiver != NULL && _len_receiver != 0) {
		if ( _len_receiver % sizeof(*_tmp_receiver) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_receiver = (unsigned char*)malloc(_len_receiver);
		if (_in_receiver == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_receiver, _len_receiver, _tmp_receiver, _len_receiver)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_receive_create_channel(ms->ms_channel_id, _in_owner, _in_receiver, ms->ms_deposit);

err:
	if (_in_owner) free(_in_owner);
	if (_in_receiver) free(_in_receiver);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_go_pre_update(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_go_pre_update_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_go_pre_update_t* ms = SGX_CAST(ms_ecall_go_pre_update_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_channel_id = ms->ms_channel_id;
	int* _tmp_amount = ms->ms_amount;



	ecall_go_pre_update(ms->ms_payment_num, _tmp_channel_id, _tmp_amount, ms->ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_go_post_update(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_go_post_update_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_go_post_update_t* ms = SGX_CAST(ms_ecall_go_post_update_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_channel_id = ms->ms_channel_id;
	int* _tmp_amount = ms->ms_amount;



	ecall_go_post_update(ms->ms_payment_num, _tmp_channel_id, _tmp_amount, ms->ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_go_idle(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_go_idle_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_go_idle_t* ms = SGX_CAST(ms_ecall_go_idle_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_go_idle(ms->ms_payment_num);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_register_comminfo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_register_comminfo_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_register_comminfo_t* ms = SGX_CAST(ms_ecall_register_comminfo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_ip = ms->ms_ip;



	ecall_register_comminfo(ms->ms_channel_id, _tmp_ip, ms->ms_ip_size, ms->ms_port);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_load_account_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_account_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_account_data_t* ms = SGX_CAST(ms_ecall_load_account_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_addr = ms->ms_addr;
	size_t _len_addr = 40;
	unsigned char* _in_addr = NULL;
	unsigned char* _tmp_seckey = ms->ms_seckey;
	size_t _len_seckey = 64;
	unsigned char* _in_seckey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_addr, _len_addr);
	CHECK_UNIQUE_POINTER(_tmp_seckey, _len_seckey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_addr != NULL && _len_addr != 0) {
		if ( _len_addr % sizeof(*_tmp_addr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_addr = (unsigned char*)malloc(_len_addr);
		if (_in_addr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_addr, _len_addr, _tmp_addr, _len_addr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_seckey != NULL && _len_seckey != 0) {
		if ( _len_seckey % sizeof(*_tmp_seckey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_seckey = (unsigned char*)malloc(_len_seckey);
		if (_in_seckey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_seckey, _len_seckey, _tmp_seckey, _len_seckey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_load_account_data(_in_addr, _in_seckey);

err:
	if (_in_addr) free(_in_addr);
	if (_in_seckey) free(_in_seckey);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_load_channel_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_channel_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_channel_data_t* ms = SGX_CAST(ms_ecall_load_channel_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_my_addr = ms->ms_my_addr;
	size_t _len_my_addr = 40;
	unsigned char* _in_my_addr = NULL;
	unsigned char* _tmp_other_addr = ms->ms_other_addr;
	size_t _len_other_addr = 40;
	unsigned char* _in_other_addr = NULL;
	unsigned char* _tmp_other_ip = ms->ms_other_ip;

	CHECK_UNIQUE_POINTER(_tmp_my_addr, _len_my_addr);
	CHECK_UNIQUE_POINTER(_tmp_other_addr, _len_other_addr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_my_addr != NULL && _len_my_addr != 0) {
		if ( _len_my_addr % sizeof(*_tmp_my_addr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_my_addr = (unsigned char*)malloc(_len_my_addr);
		if (_in_my_addr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_my_addr, _len_my_addr, _tmp_my_addr, _len_my_addr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_other_addr != NULL && _len_other_addr != 0) {
		if ( _len_other_addr % sizeof(*_tmp_other_addr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_other_addr = (unsigned char*)malloc(_len_other_addr);
		if (_in_other_addr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_other_addr, _len_other_addr, _tmp_other_addr, _len_other_addr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_load_channel_data(ms->ms_channel_id, ms->ms_type, ms->ms_channel_status, _in_my_addr, ms->ms_my_deposit, ms->ms_other_deposit, ms->ms_balance, ms->ms_locked_balance, _in_other_addr, _tmp_other_ip, ms->ms_ip_size, ms->ms_other_port);

err:
	if (_in_my_addr) free(_in_my_addr);
	if (_in_other_addr) free(_in_other_addr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_load_payment_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_load_payment_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_load_payment_data_t* ms = SGX_CAST(ms_ecall_load_payment_data_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_load_payment_data(ms->ms_payment_num, ms->ms_channel_id, ms->ms_amount);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[16];
} g_ecall_table = {
	16,
	{
		{(void*)(uintptr_t)sgx_ecall_preset_account, 0},
		{(void*)(uintptr_t)sgx_ecall_create_account, 0},
		{(void*)(uintptr_t)sgx_ecall_create_channel, 0},
		{(void*)(uintptr_t)sgx_ecall_onchain_payment, 0},
		{(void*)(uintptr_t)sgx_ecall_pay, 0},
		{(void*)(uintptr_t)sgx_ecall_get_balance, 0},
		{(void*)(uintptr_t)sgx_ecall_close_channel, 0},
		{(void*)(uintptr_t)sgx_ecall_eject, 0},
		{(void*)(uintptr_t)sgx_ecall_receive_create_channel, 0},
		{(void*)(uintptr_t)sgx_ecall_go_pre_update, 0},
		{(void*)(uintptr_t)sgx_ecall_go_post_update, 0},
		{(void*)(uintptr_t)sgx_ecall_go_idle, 0},
		{(void*)(uintptr_t)sgx_ecall_register_comminfo, 0},
		{(void*)(uintptr_t)sgx_ecall_load_account_data, 0},
		{(void*)(uintptr_t)sgx_ecall_load_channel_data, 0},
		{(void*)(uintptr_t)sgx_ecall_load_payment_data, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][16];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

