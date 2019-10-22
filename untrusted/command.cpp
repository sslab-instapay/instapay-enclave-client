#include <string>

#include "app.h"
#include "enclave_u.h"


using namespace std;


void ecall_register_account(unsigned char *addr, unsigned char *seckey)
{
    ecall_preset_account(global_eid, addr, seckey);
}


std::string ecall_new_channel(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int deposit)
{
    unsigned char *signed_tx = new unsigned char[700];
    unsigned int signed_tx_len;

    ecall_create_channel(global_eid, nonce, owner, receiver, deposit, signed_tx, &signed_tx_len);

    return std::string(signed_tx, signed_tx + signed_tx_len);
}


int ecall_get_my_balance(unsigned int channel_id)
{
    unsigned int balance;

    ecall_get_balance(global_eid, channel_id, &balance);

    return balance;
}