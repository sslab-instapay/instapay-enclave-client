#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t ecall_preset_account(sgx_enclave_id_t eid, unsigned char* addr, unsigned char* seckey);
sgx_status_t ecall_create_account(sgx_enclave_id_t eid, unsigned char* generated_addr);
sgx_status_t ecall_create_channel(sgx_enclave_id_t eid, unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int deposit, unsigned char* signed_tx, unsigned int* signed_tx_len);
sgx_status_t ecall_onchain_payment(sgx_enclave_id_t eid, unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int amount, unsigned char* signed_tx, unsigned int* signed_tx_len);
sgx_status_t ecall_pay(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int amount, int* is_success);
sgx_status_t ecall_get_balance(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int* balance);
sgx_status_t ecall_close_channel(sgx_enclave_id_t eid, unsigned int nonce, unsigned int channel_id, unsigned char* signed_tx, unsigned int* signed_tx_len);
sgx_status_t ecall_eject(sgx_enclave_id_t eid, unsigned int nonce, unsigned int pn, unsigned char* signed_tx, unsigned int* signed_tx_len);
sgx_status_t ecall_receive_create_channel(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* owner, unsigned char* receiver, unsigned int deposit);
sgx_status_t ecall_go_pre_update(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int* channel_id, int* amount, unsigned int size);
sgx_status_t ecall_go_post_update(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int* channel_id, int* amount, unsigned int size);
sgx_status_t ecall_go_idle(sgx_enclave_id_t eid, unsigned int payment_num);
sgx_status_t ecall_register_comminfo(sgx_enclave_id_t eid, unsigned int channel_id, unsigned char* ip, unsigned int ip_size, unsigned int port);
sgx_status_t ecall_load_account_data(sgx_enclave_id_t eid, unsigned char* addr, unsigned char* seckey);
sgx_status_t ecall_load_channel_data(sgx_enclave_id_t eid, unsigned int channel_id, unsigned int type, unsigned int channel_status, unsigned char* my_addr, unsigned int my_deposit, unsigned int other_deposit, unsigned int balance, unsigned int locked_balance, unsigned char* other_addr, unsigned char* other_ip, unsigned int ip_size, unsigned int other_port);
sgx_status_t ecall_load_payment_data(sgx_enclave_id_t eid, unsigned int payment_num, unsigned int channel_id, int amount);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
