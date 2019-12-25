#include <stdio.h>    // vsnprintf
#include <stdarg.h>   // va_list
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
    Transaction tx(nonce, receiver, amount, NULL, 0);

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


    /* convert to numbers which have leading zeros to use as contract function's arguments */
    unsigned char *channel_id_bytes, *source_bal_bytes, *target_bal_bytes;

    channel_id_bytes = create_uint256_argument(channel_id);
    source_bal_bytes = create_uint256_argument(source_bal);
    target_bal_bytes = create_uint256_argument(target_bal);
    
    data.insert(data.end(), channel_id_bytes, channel_id_bytes + 32);
    data.insert(data.end(), source_bal_bytes, source_bal_bytes + 32);
    data.insert(data.end(), target_bal_bytes, target_bal_bytes + 32);


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

    unsigned char *head_pn_bytes, *stage_bytes, *head_ids_bytes, *head_bals_bytes, *v_bytes;
    unsigned char *ids_size_bytes, *bals_size_bytes, *id_bytes, *source_bal_bytes, *target_bal_bytes;

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
    head_ids = total_headsize;
    head_bals = total_headsize + 32 + 32 * payments.find(pn)->second.m_related_channels.size();
    head_v = abs(payments.find(pn)->second.m_related_channels.at(0).amount);

    head_pn_bytes = create_uint256_argument(head_pn);
    stage_bytes = create_uint256_argument(head_stage);
    head_ids_bytes = create_uint256_argument(head_ids);
    head_bals_bytes = create_uint256_argument(head_bals);
    v_bytes = create_uint256_argument(head_v);


    data.insert(data.end(), msg32, msg32 + 4);

    data.insert(data.end(), head_pn_bytes, head_pn_bytes + 32);       // pn: head(pn) = enc(pn)
    data.insert(data.end(), stage_bytes, stage_bytes + 32); // stage: head(stage) = enc(stage)
    data.insert(data.end(), head_ids_bytes, head_ids_bytes + 32);       // ids: head(ids) = enc(len(head(pn) head(stage) head(ids) head(bals) head(v) tail(pn) tail(stage)))
    data.insert(data.end(), head_bals_bytes, head_bals_bytes + 32);       // bals: head(bals) = enc(len(head(pn) head(stage) head(ids) head(bals) head(v) tail(pn) tail(stage) tail(ids)))
    data.insert(data.end(), v_bytes, v_bytes + 32);       // v: head(v) = enc(v)

    ids_size = payments.find(pn)->second.m_related_channels.size();
    ids_size_bytes = create_uint256_argument(ids_size);
    data.insert(data.end(), ids_size_bytes, ids_size_bytes + 32);
    for(int i = 0; i < ids_size; i++) {
        e = payments.find(pn)->second.m_related_channels.at(i).channel_id;
        id_bytes = create_uint256_argument(e);
        data.insert(data.end(), id_bytes, id_bytes + 32);
    }

    bals_size = ids_size * 2;
    bals_size_bytes = create_uint256_argument(bals_size);
    data.insert(data.end(), bals_size_bytes, bals_size_bytes + 32);
    for(int i = 0; i < ids_size; i++) {
        e = payments.find(pn)->second.m_related_channels.at(i).channel_id;
        if(channels.find(e)->second.m_is_in == 0) { // owner is me
            source_bal = channels.find(e)->second.m_balance;
            target_bal = channels.find(e)->second.m_my_deposit - channels.find(e)->second.m_balance;
        }
        else {  // owner is not me
            source_bal = channels.find(e)->second.m_other_deposit - channels.find(e)->second.m_balance;
            target_bal = channels.find(e)->second.m_balance;
        }

        source_bal_bytes = create_uint256_argument(source_bal);
        target_bal_bytes = create_uint256_argument(target_bal);

        data.insert(data.end(), source_bal_bytes, source_bal_bytes + 32);
        data.insert(data.end(), target_bal_bytes, target_bal_bytes + 32);
    }


    /* generate a transaction creating a channel */
    Transaction tx(nonce, CONTRACT_ADDR, 0, data.data(), data.size());

    // TODO: find the account's private key and sign on transaction using

    tx.sign((unsigned char*)"e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd");

    memcpy(signed_tx, tx.signed_tx.data(), tx.signed_tx.size());
    *signed_tx_len = tx.signed_tx.size();

    return;
}