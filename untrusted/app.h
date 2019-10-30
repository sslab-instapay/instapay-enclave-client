#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

int initialize_enclave(void);

/* command.cpp */
void ecall_register_account(unsigned char *, unsigned char *);
unsigned char* ecall_new_channel(unsigned int, unsigned char *, unsigned char *, unsigned int, unsigned int *);
int ecall_get_my_balance(unsigned int);

/* network.cpp */
void ecall_receive_agreement_request(unsigned int, unsigned int *, int *, unsigned int);
void ecall_receive_update_request(unsigned int, unsigned int *, int *, unsigned int);
void ecall_receive_payment_confirmation(unsigned int);

/* event.cpp */
void ecall_event_create_channel(unsigned int, unsigned char *, unsigned char *, unsigned int);

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
