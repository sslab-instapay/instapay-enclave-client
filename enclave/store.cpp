#include <account.h>
#include <channel.h>
#include <payment.h>

#include "enclave.h"
#include "enclave_t.h"


void ecall_store_account_data(unsigned char *addr, unsigned char *seckey)
{
    std::map<std::vector<unsigned char>, Account>::iterator iter;

    for (iter = accounts.begin(); iter != accounts.end(); ++iter);
}


void ecall_store_channel_data()
{

}


void ecall_store_payment_data()
{

}