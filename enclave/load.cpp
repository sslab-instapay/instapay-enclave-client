#include <account.h>
#include <channel.h>
#include <payment.h>
#include <util.h>

#include "enclave.h"
#include "enclave_t.h"


void ecall_load_account_data(unsigned char *addr, unsigned char *seckey)
{
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    unsigned char *seckey_bytes = ::arr_to_bytes(seckey, 64);

    std::vector<unsigned char> p(addr_bytes, addr_bytes + 20);
    std::vector<unsigned char> s(seckey_bytes, seckey_bytes + 32);

    accounts.insert(map_account_value(p, Account(s)));  
}


void ecall_load_channel_data(
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
    unsigned int ip_size,
    unsigned int other_port)
{
    Channel channel;

    channel.m_id = channel_id;
    channel.m_is_in = type;

    if(channel_status == PENDING)
        channel.m_status = PENDING;
    else if(channel_status == IDLE)
        channel.m_status = IDLE;
    else if(channel_status == PRE_UPDATE)
        channel.m_status = PRE_UPDATE;
    else if(channel_status == POST_UPDATE)
        channel.m_status = POST_UPDATE;

    channel.m_my_addr = ::arr_to_bytes(my_addr, 40);
    channel.m_my_deposit = my_deposit;
    channel.m_other_deposit = other_deposit;
    channel.m_balance = balance;
    channel.m_locked_balance = locked_balance;
    channel.m_other_addr = ::arr_to_bytes(other_addr, 40);
    channel.m_other_ip = ::copy_bytes(other_ip, ip_size);
    channel.m_other_port = other_port;

    channels.insert(map_channel_value(channel_id, channel));
}


void ecall_load_payment_data(unsigned int payment_num, unsigned int channel_id, int amount)
{
    if(payments.find(payment_num) == payments.end())
        payments.insert(map_payment_value(payment_num, Payment(payment_num)));
    
    payments.find(payment_num)->second.add_element(channel_id, amount);
}