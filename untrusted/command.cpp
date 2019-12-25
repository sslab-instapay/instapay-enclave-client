#include "app.h"
#include "enclave_u.h"


void ecall_preset_account_w(unsigned char *addr, unsigned char *seckey)
{
    ecall_preset_account(global_eid, addr, seckey);
}


unsigned char* ecall_create_account_w(void)
{
    unsigned char *generated_addr = new unsigned char[20];

    ecall_create_account(global_eid, generated_addr);

    return generated_addr;
}


unsigned char* ecall_create_channel_w(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int deposit, unsigned int *sig_len)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    ecall_create_channel(global_eid, nonce, owner, receiver, deposit, signed_tx, &signed_tx_len);
    *sig_len = signed_tx_len;
    
    return signed_tx;
}

unsigned char* ecall_onchain_payment_w(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int amount, unsigned int *sig_len)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    ecall_onchain_payment(global_eid, nonce, owner, receiver, amount, signed_tx, &signed_tx_len);
    *sig_len = signed_tx_len;
    
    return signed_tx;
}

int ecall_get_balance_w(unsigned int channel_id)
{
    unsigned int balance;

    ecall_get_balance(global_eid, channel_id, &balance);

    return balance;
}


unsigned char* ecall_close_channel_w(unsigned int nonce, unsigned int channel_id, unsigned int *sig_len)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    ecall_close_channel(global_eid, nonce, channel_id, signed_tx, &signed_tx_len);
    *sig_len = signed_tx_len;
    
    return signed_tx;
}


unsigned char* ecall_eject_w(unsigned int nonce, unsigned int pn, unsigned int *sig_len)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    ecall_eject(global_eid, nonce, pn, signed_tx, &signed_tx_len);
    *sig_len = signed_tx_len;
    
    return signed_tx;    
}