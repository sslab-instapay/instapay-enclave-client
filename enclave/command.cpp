#include <string.h>
#include <stdint.h>
#include <cstring>

#include "sgx_trts.h"
#include "enclave.h"
#include "enclave_t.h"

#include <account.h>
#include <channel.h>
#include <payment.h>
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


void ecall_close_channel(unsigned int nonce, unsigned int channel_id, unsigned char *signed_tx, unsigned int *signed_tx_len)
{
    std::vector<unsigned char> data;

    /* encode ABI for calling "close_channel(uint256,uint256,uint256)" on the contract */
    sha3_context sha3_ctx;
    unsigned char *func = (unsigned char*)"close_channel(uint256,uint256,uint256)";
    unsigned char *msg32;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, func, strlen((char*)func));
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);


    /* get owner(source) and receiver's(target) balances */
    unsigned int source_bal, target_bal;

    if(channels.find(channel_id)->second.m_is_in == 0) { // owner is me
        source_bal = channels.find(channel_id)->second.m_balance;
        target_bal = channels.find(channel_id)->second.m_my_deposit - channels.find(channel_id)->second.m_balance;
    }
    else {  // owner is not me
        source_bal = channels.find(channel_id)->second.m_other_deposit - channels.find(channel_id)->second.m_balance;
        target_bal = channels.find(channel_id)->second.m_balance;
    }

    data.insert(data.end(), msg32, msg32 + 4);
    data.insert(data.end(), channel_id, channel_id + 32);  // TODO: fix byte range ?
    data.insert(data.end(), source_bal, source_bal + 32);  // TODO: fix byte range ?
    data.insert(data.end(), target_bal, target_bal + 32);  // TODO: fix byte range ?


    /* generate a transaction creating a channel */
    Transaction tx(nonce, CONTRACT_ADDR, 0, data.data(), data.size());

    // TODO: find the account's private key and sign on transaction using

    tx.sign((unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd");

    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();

    return;
}


void ecall_eject(unsigned int nonce, unsigned int pn, unsigned char *signed_tx, unsigned int *signed_tx_len)
{
    std::vector<unsigned char> data;

    /* encode ABI for calling "close_channel(uint256,uint256,uint256)" on the contract */
    sha3_context sha3_ctx;
    unsigned char *func = (unsigned char*)"eject(uint256,uint8,uint256[],uint256[],uint256)";
    unsigned char *msg32;

    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, func, strlen((char*)func));
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);


    /* data encoding */
    unsigned int total_headsize = 32 * 5;
    unsigned int stage;
    unsigned int head_pn, head_stage, head_ids, head_bals, head_v;
    unsigned int ids_size, bals_size, e, source_bal, target_bal;

    e = payments.find(pn)->second.m_related_channels.at(0).channel_id;
    stage = channels.find(e)->second.m_status;

    if(stage == PRE_UPDATE) {
        stage = 0;    // PRE_UPDATE on contract is 0, but PRE_UPDATE in channel.h is 1
    }
    else {
        stage = 1;
    }

    head_pn = pn;
    head_stage = stage;
    head_ids = total_head_size;
    head_bals = total_head_size + 32 + 32 * payments.find(pn)->second.m_related_channels.size();
    head_v = abs(payments.find(pn)->second.m_related_channels.at(0).amount);


    data.insert(data.end(), msg32, msg32 + 4);

    data.insert(data.end(), head_pn, head_pn + 1);       // pn: head(pn) = enc(pn)
    data.insert(data.end(), head_stage, head_stage + 1); // stage: head(stage) = enc(stage)
    data.insert(data.end(), head_ids, head_ids + 1);       // ids: head(ids) = enc(len(head(pn) head(stage) head(ids) head(bals) head(v) tail(pn) tail(stage)))
    data.insert(data.end(), head_bals, head_bals + 1);       // bals: head(bals) = enc(len(head(pn) head(stage) head(ids) head(bals) head(v) tail(pn) tail(stage) tail(ids)))
    data.insert(data.end(), head_v, head_v + 1);       // v: head(v) = enc(v)

    ids_size = payments.find(pn)->second.m_related_channels.size();
    data.insert(data.end(), ids_size, ids_size + 1);
    for(int i = 0; i < ids_size; i++) {
        e = payments.find(pn)->second.m_related_channels.at(i).channel_id;
        data.insert(data.end(), e, e + 1);
    }

    bals_size = ids_size * 2;
    data.insert(data.end(), bals_size, bals_size + 1);
    for(int i = 0; i < ids_size; i++) {
        e = payments.find(pn)->second.m_related_channels.at(i).channel_id;
        if(channels.find(e)->second.m_is_in == 0) { // owner is me
            source_bal = channels.find(e)->second.m_balance;
            target_bal = channels.find(e)->second.m_my_deposit - channels.find(channel_id)->second.m_balance;
        }
        else {  // owner is not me
            source_bal = channels.find(e)->second.m_other_deposit - channels.find(channel_id)->second.m_balance;
            target_bal = channels.find(e)->second.m_balance;
        }
        data.insert(data.end(), source_bal, source_bal + 1);
        data.insert(data.end(), target_bal, target_bal + 1);
    }


    /* generate a transaction creating a channel */
    Transaction tx(nonce, CONTRACT_ADDR, 0, data.data(), data.size());

    // TODO: find the account's private key and sign on transaction using

    tx.sign((unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd");

    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();

    return;
}