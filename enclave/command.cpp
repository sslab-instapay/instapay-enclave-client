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


/* this function is only for debugging. it must be removed in the product */
void ecall_preset_account(unsigned char *addr, unsigned char *seckey)
{
    unsigned char *addr_bytes = ::arr_to_bytes(addr, 40);
    unsigned char *seckey_bytes = ::arr_to_bytes(seckey, 64);

    std::vector<unsigned char> p(addr_bytes, addr_bytes + 20);
    std::vector<unsigned char> s(seckey_bytes, seckey_bytes + 32);
    accounts.insert(map_account_value(p, Account(s)));

    return;
}


void ecall_create_account(unsigned char *generated_addr)
{
    /* generate a secret key */
    unsigned char *seckey = new unsigned char[32];
    sgx_read_rand(seckey, 32);

    /* secp256k1 */
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_pubkey pk;

    secp256k1_ecdsa_signature sig;

    unsigned char *msg32;
    unsigned char output[65];

    size_t outputlen = 65;

    /* sha3 (keccak256) */
    sha3_context sha3_ctx;

    /* get public key and serialize it */
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_ec_pubkey_create(secp256k1_ctx, &pk, seckey);
    secp256k1_ec_pubkey_serialize(secp256k1_ctx, output, &outputlen, &pk, SECP256K1_EC_UNCOMPRESSED);

    /* calculate public key hash */
    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, output + 1, outputlen-1);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    std::vector<unsigned char> p(msg32 + 12, msg32 + 32);
    std::vector<unsigned char> s(seckey, seckey + 32);
    accounts.insert(map_account_value(p, Account(s)));

    copy(msg32 + 12, msg32 + 32, generated_addr);

    return;
}


void ecall_create_channel(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int deposit, unsigned char *signed_tx, unsigned int *signed_tx_len)
{
    std::vector<unsigned char> data;

    /* encode ABI for calling "create_channel(address)" on the contract */
    sha3_context sha3_ctx;
    unsigned char *func = (unsigned char*)"create_channel(address)";
    unsigned char *msg32;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, func, strlen((char*)func));
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    unsigned char *addr = ::arr_to_bytes(receiver, 40);
    data.insert(data.end(), msg32, msg32 + 4);
    data.insert(data.end(), addr, addr + 20);

    /* generate a transaction creating a channel */
    Transaction tx(nonce, CONTRACT_ADDR, deposit, data.data(), data.size());

    // TODO: find the account's private key and sign on transaction using

    tx.sign((unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd");

    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();

    return;
}

void ecall_onchain_payment(unsigned int nonce, unsigned char *owner, unsigned char *receiver, unsigned int amount, unsigned char *signed_tx, unsigned int *signed_tx_len)
{
    /* encode ABI for calling "create_channel(address)" on the contract */
    sha3_context sha3_ctx;

    /* generate a transaction creating a channel */
    Transaction tx(nonce, receiver, amount, null, 0);

    // TODO: find the account's private key and sign on transaction using
    tx.sign((unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd");

    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();

    return;
}


void ecall_pay(unsigned int channel_id, unsigned int amount, int *is_success)
{
    if(channels.find(channel_id) == channels.end()) {
        *is_success = false;
        return;
    }

    *is_success = channels.find(channel_id)->second.pay(amount);
    return;
}


void ecall_get_balance(unsigned int channel_id, unsigned int *balance)
{
    *balance = channels.find(channel_id)->second.get_balance();
    return;
}