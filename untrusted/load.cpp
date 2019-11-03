#include "app.h"
#include "enclave_u.h"

#include <string.h>


void ecall_load_account_data_w(unsigned char *addr, unsigned char *seckey)
{
    ecall_load_account_data(global_eid, addr, seckey);    
}


void ecall_load_channel_data_w(
    unsigned int channel_id,
    unsigned int type,
    unsigned int channel_status,
    unsigned char *my_addr,
    unsigned int my_deposit,
    unsigned int other_deposit,
    unsigned int balance,
    unsigned int locked_balance,
    unsigned char *other_addr,
    unsigned char *other_ip,
    unsigned int other_port)
{
    ecall_load_channel_data(
        global_eid,
        channel_id,
        type,
        channel_status,
        my_addr,
        my_deposit,
        other_deposit,
        balance,
        locked_balance,
        other_addr,
        other_ip,
        strlen((char*)other_ip),
        other_port);
}


void ecall_load_payment_data_w(unsigned int payment_num, unsigned int channel_id, int amount)
{
    ecall_load_payment_data(global_eid, payment_num, channel_id, amount);
}