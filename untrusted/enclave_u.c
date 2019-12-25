#include "enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	1,
	{
		(void*)enclave_ocall_print_string,
	}
};
sgx_status_t ecall_preset_account(sgx_enclave_id_t eid, unsigned char* addr, unsigned char* seckey)
{
	sgx_status_t status;
	ms_ecall_preset_account_t ms;
	ms.ms_addr = addr;
	ms.ms_seckey = seckey;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_create_account(sgx_enclave_id_t eid, unsigned char* generated_addr)
{
	sgx_status_t status;
	ms_ecall_create_account_t ms;
	ms.ms_generated_addr = generated_addr;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_create_channel(sgx_enclave_id_t eid, unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int deposit, unsigned char* signed_tx, unsigned int* signed_tx_len)
{
	sgx_status_t status;
	ms_ecall_create_channel_t ms;
	ms.ms_nonce = nonce;
	ms.ms_owner = owner;
	ms.ms_receiver = receiver;
	ms.ms_deposit = deposit;
	ms.ms_signed_tx = signed_tx;
	ms.ms_signed_tx_len = signed_tx_len;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_onchain_payment(sgx_enclave_id_t eid, unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int amount, unsigned char* signed_tx, unsigned int* signed_tx_len)
{
	sgx_status_t status;
	ms_ecall_onchain_payment_t ms;
	ms.ms_nonce = nonce;
	ms.ms_owner = owner;
	ms.ms_receiver = receiver;
	ms.ms_amount = amount;
	ms.ms_signed_tx = signed_tx;
	ms.ms_signed_tx_len = signed_tx_len;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_pay(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int amount, int* is_success)
{
	sgx_status_t status;
	ms_ecall_pay_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_amount = amount;
	ms.ms_is_success = is_success;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_get_balance(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int* balance)
{
	sgx_status_t status;
	ms_ecall_get_balance_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_balance = balance;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_close_channel(sgx_enclave_id_t eid, unsigned int nonce, unsigned int channel_id, unsigned char* signed_tx, unsigned int* signed_tx_len)
{
	sgx_status_t status;
	ms_ecall_close_channel_t ms;
	ms.ms_nonce = nonce;
	ms.ms_channel_id = channel_id;
	ms.ms_signed_tx = signed_tx;
	ms.ms_signed_tx_len = signed_tx_len;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_eject(sgx_enclave_id_t eid, unsigned int nonce, unsigned int pn, unsigned char* signed_tx, unsigned int* signed_tx_len)
{
	sgx_status_t status;
	ms_ecall_eject_t ms;
	ms.ms_nonce = nonce;
	ms.ms_pn = pn;
	ms.ms_signed_tx = signed_tx;
	ms.ms_signed_tx_len = signed_tx_len;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_receive_create_channel(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* owner, unsigned char* receiver, unsigned int deposit)
{
	sgx_status_t status;
	ms_ecall_receive_create_channel_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_owner = owner;
	ms.ms_receiver = receiver;
	ms.ms_deposit = deposit;
	status = sgx_ecall(eid, 8, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_go_pre_update(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int* channel_id, int* amount, unsigned int size)
{
	sgx_status_t status;
	ms_ecall_go_pre_update_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_channel_id = channel_id;
	ms.ms_amount = amount;
	ms.ms_size = size;
	status = sgx_ecall(eid, 9, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_go_post_update(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int* channel_id, int* amount, unsigned int size)
{
	sgx_status_t status;
	ms_ecall_go_post_update_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_channel_id = channel_id;
	ms.ms_amount = amount;
	ms.ms_size = size;
	status = sgx_ecall(eid, 10, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_go_idle(sgx_enclave_id_t eid, unsigned int payment_num)
{
	sgx_status_t status;
	ms_ecall_go_idle_t ms;
	ms.ms_payment_num = payment_num;
	status = sgx_ecall(eid, 11, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_register_comminfo(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* ip, unsigned int ip_size, unsigned int port)
{
	sgx_status_t status;
	ms_ecall_register_comminfo_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_ip = ip;
	ms.ms_ip_size = ip_size;
	ms.ms_port = port;
	status = sgx_ecall(eid, 12, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_load_account_data(sgx_enclave_id_t eid, unsigned char* addr, unsigned char* seckey)
{
	sgx_status_t status;
	ms_ecall_load_account_data_t ms;
	ms.ms_addr = addr;
	ms.ms_seckey = seckey;
	status = sgx_ecall(eid, 13, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_load_channel_data(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int type, unsigned int channel_status, unsigned char* my_addr, unsigned int my_deposit, unsigned int other_deposit, unsigned int balance, unsigned int locked_balance, unsigned char* other_addr, unsigned char* other_ip, unsigned int ip_size, unsigned int other_port)
{
	sgx_status_t status;
	ms_ecall_load_channel_data_t ms;
	ms.ms_channel_id = channel_id;
	ms.ms_type = type;
	ms.ms_channel_status = channel_status;
	ms.ms_my_addr = my_addr;
	ms.ms_my_deposit = my_deposit;
	ms.ms_other_deposit = other_deposit;
	ms.ms_balance = balance;
	ms.ms_locked_balance = locked_balance;
	ms.ms_other_addr = other_addr;
	ms.ms_other_ip = other_ip;
	ms.ms_ip_size = ip_size;
	ms.ms_other_port = other_port;
	status = sgx_ecall(eid, 14, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_load_payment_data(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int channel_id, int amount)
{
	sgx_status_t status;
	ms_ecall_load_payment_data_t ms;
	ms.ms_payment_num = payment_num;
	ms.ms_channel_id = channel_id;
	ms.ms_amount = amount;
	status = sgx_ecall(eid, 15, &ocall_table_enclave, &ms);
	return status;
}

