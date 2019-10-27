#include "app.h"
#include "enclave_u.h"


void ecall_event_create_channel(unsigned int channel_id, void *owner, void *receiver, unsigned int deposit)
{
    ecall_receive_create_channel(global_eid, channel_id, (unsigned char*)owner, (unsigned char*)receiver, deposit);
}
