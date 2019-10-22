#include <string.h>
#include <stdint.h>
#include <cstring>

#include "sgx_trts.h"
#include "enclave.h"
#include "enclave_t.h"

#include <account.h>
#include <channel.h>
#include <transaction.h>
#include <payment.h>
#include <util.h>


using namespace std;


void ecall_go_pre_update(unsigned int payment_num, unsigned int *channel_id, int *amount, unsigned int size)
{
    payments.insert(map_payment_value(payment_num, Payment(payment_num)));

    for(int i = 0; i < size; i++) {
        payments.find(payment_num)->second.add_element(channel_id[i], amount[i]);
        channels.find(channel_id[i])->second.transition_to_pre_update();
    }

    return;
}


void ecall_go_post_update(unsigned int payment_num, unsigned int *channel_id, int *amount, unsigned int size)
{
    if(payments.find(payment_num) == payments.end()) {
        payments.insert(map_payment_value(payment_num, Payment(payment_num)));
        for(int i = 0; i < size; i++)
            payments.find(payment_num)->second.add_element(channel_id[i], amount[i]);
    }

    for(int i = 0; i < size; i++) {
        channels.find(channel_id[i])->second.pay(amount[i]);
        channels.find(channel_id[i])->second.transition_to_post_update();
    }

    return;
}


void ecall_go_idle(unsigned int payment_num)
{
    std::vector<Related> c = payments.find(payment_num)->second.m_related_channels;
    for(int i = 0; i < c.size(); i++)
        channels.find(c.at(i).channel_id)->second.transition_to_idle();

    return;
}
