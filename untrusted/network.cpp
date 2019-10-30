#include "app.h"
#include "enclave_u.h"


void ecall_receive_agreement_request(unsigned int payment_num, unsigned int *channel_id, int *amount, unsigned int size)
{
    ecall_go_pre_update(global_eid, payment_num, channel_id, amount, size);
}


void ecall_receive_update_request(unsigned int payment_num, unsigned int *channel_id, int *amount, unsigned int size)
{
    ecall_go_post_update(global_eid, payment_num, channel_id, amount, size);
}


void ecall_receive_payment_confirmation(unsigned int payment_num)
{
    ecall_go_idle(global_eid, payment_num);
}