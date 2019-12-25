#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_preset_account(unsigned char* addr, unsigned char* seckey);
void ecall_create_account(unsigned char* generated_addr);
void ecall_create_channel(unsigned int nonce, unsigned char* owner, unsigned char* receiver, unsigned int deposit, unsigned char* signed_tx, unsigned int* signed_tx_len);
void ecall_pay(unsigned int channel_id, unsigned int amount, int* is_success);
void ecall_get_balance(unsigned int channel_id, unsigned int* balance);
void ecall_close_channel(unsigned int nonce, unsigned int channel_id, unsigned char* signed_tx, unsigned int* signed_tx_len);
void ecall_eject(unsigned int nonce, unsigned int pn, unsigned char* signed_tx, unsigned int* signed_tx_len);
void ecall_receive_create_channel(unsigned int channel_id, unsigned char* owner, unsigned char* receiver, unsigned int deposit);
void ecall_go_pre_update(unsigned int payment_num, unsigned int* channel_id, int* amount, unsigned int size);
void ecall_go_post_update(unsigned int payment_num, unsigned int* channel_id, int* amount, unsigned int size);
void ecall_go_idle(unsigned int payment_num);
void ecall_register_comminfo(unsigned int channel_id, unsigned char* ip, unsigned int ip_size, unsigned int port);
void ecall_load_account_data(unsigned char* addr, unsigned char* seckey);
void ecall_load_channel_data(unsigned int channel_id, unsigned int type, unsigned int channel_status, unsigned char* my_addr, unsigned int my_deposit, unsigned int other_deposit, unsigned int balance, unsigned int locked_balance, unsigned char* other_addr, unsigned char* other_ip, unsigned int ip_size, unsigned int other_port);
void ecall_load_payment_data(unsigned int payment_num, unsigned int channel_id, int amount);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
