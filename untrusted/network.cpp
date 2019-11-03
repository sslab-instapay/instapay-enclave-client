#include "app.h"
#include "enclave_u.h"

#include <string.h>


void ecall_go_pre_update_w(unsigned int payment_num, unsigned int *channel_id, int *amount, unsigned int size)
{
    ecall_go_pre_update(global_eid, payment_num, channel_id, amount, size);
}


void ecall_go_post_update_w(unsigned int payment_num, unsigned int *channel_id, int *amount, unsigned int size)
{
    ecall_go_post_update(global_eid, payment_num, channel_id, amount, size);
}


void ecall_go_idle_w(unsigned int payment_num)
{
    ecall_go_idle(global_eid, payment_num);
}


void ecall_register_comminfo_w(unsigned int channel_id, unsigned char *ip, unsigned int port)
{
    ecall_register_comminfo(global_eid, channel_id, ip, strlen((char*)ip), port);
}