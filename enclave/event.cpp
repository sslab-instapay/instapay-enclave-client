#include <string.h>
#include <stdint.h>
#include <cstring>

#include "sgx_trts.h"
#include "enclave.h"
#include "enclave_t.h"

#include <account.h>
#include <channel.h>
#include <transaction.h>
#include <util.h>


using namespace std;


void ecall_receive_create_channel(unsigned int channel_id, unsigned char *owner, unsigned char *receiver, unsigned int deposit)
{
    unsigned char *owner_addr_bytes = ::arr_to_bytes(owner, 40);
    unsigned char *receiver_addr_bytes = ::arr_to_bytes(receiver, 40);
    std::vector<unsigned char> owner_addr(owner_addr_bytes, owner_addr_bytes + 20);
    std::vector<unsigned char> receiver_addr(receiver_addr_bytes, receiver_addr_bytes + 20);

    if(accounts.find(owner_addr) == accounts.end() && accounts.find(receiver_addr) == accounts.end())
        return;

    bool is_in;

    if(accounts.find(owner_addr) != accounts.end()) {
        is_in = false;
    }
    else {
        is_in = true;
    }

    Channel channel(channel_id, owner, receiver, is_in, deposit);
    channels.insert(map_channel_value(channel_id, channel));

    return;
}