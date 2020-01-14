#include "enclave.h"
#include "enclave_t.h"

#include <message.h>


void sign_message(unsigned char *original_msg, unsigned int msg_size, unsigned char *seckey, unsigned char *signature)
{
    unsigned char *msg32;

    /* secp256k1 */
    secp256k1_context* secp256k1_ctx = NULL;
    secp256k1_ecdsa_signature sig;

    unsigned char output64[64];

    /* sha3 (keccak256) */
    sha3_context sha3_ctx;

    /* hashing the byte stream */
    sha3_Init256(&sha3_ctx);
    sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
    sha3_Update(&sha3_ctx, original_msg, msg_size);
    msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

    /* ECDSA sign on the message */
    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_sign(secp256k1_ctx, &sig, msg32, seckey, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, output64, &sig);

    memcpy(signature, output64, 32);  // copy r
    memcpy(signature + 32, output64 + 32, 32);  // copy s
}


int verify_message(unsigned int from, unsigned char *signature, unsigned char *original_msg, unsigned int msg_size, unsigned char *pubaddr)
{
    if(from == 0) {
        secp256k1_context* secp256k1_ctx = NULL;
        secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        secp256k1_ecdsa_recoverable_signature raw_sig;
        int v = 1;
        if(!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &raw_sig, signature, v))
            return -1;

        unsigned char *msg32;
        sha3_context sha3_ctx;

        sha3_Init256(&sha3_ctx);
        sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
        sha3_Update(&sha3_ctx, original_msg, msg_size);
        msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

        secp256k1_pubkey raw_pubkey;
        if(!secp256k1_ecdsa_recover(secp256k1_ctx, &raw_pubkey, &raw_sig, msg32))
            return -1;

        unsigned char pubkey[65];
        size_t pubkey_len = 65;

        secp256k1_ec_pubkey_serialize(secp256k1_ctx, pubkey, &pubkey_len, &raw_pubkey, SECP256K1_EC_UNCOMPRESSED);

        sha3_Init256(&sha3_ctx);
        sha3_SetFlags(&sha3_ctx, SHA3_FLAGS_KECCAK);
        sha3_Update(&sha3_ctx, pubkey + 1, pubkey_len - 1);
        msg32 = (unsigned char*)sha3_Finalize(&sha3_ctx);

        unsigned char sender[20];
        
        memcpy(sender, msg32 + 12, 20);
        pubaddr = ::arr_to_bytes(pubaddr, 40);

        if(memcmp(sender, pubaddr, 20) == 0)
            return 0;

        return 1;
    }
    else if(from == 1) {
        
    }
}