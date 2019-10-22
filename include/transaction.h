#ifndef TX_H
#define TX_H

#include <stdint.h>
#include <vector>
#include <util.h>
#include <rlpvalue.h>

#define CONTRACT_ADDR (unsigned char*)"b0920c523d582040f2bcb1bd7fb1c7c1ecebdb34"

#if defined(__cplusplus)
extern "C" {
#endif

#include <secp256k1.h>
#include <sha3.h>

#if defined(__cplusplus)
}
#endif

class Transaction {
    public:
        Transaction(unsigned int t_nonce,
                    unsigned char* t_to,
                    unsigned int t_value,
                    unsigned char* t_data,
                    unsigned int t_data_size
                    )
                    : m_nonce(t_nonce)
                    , m_gas_price(1000000000)
                    , m_gas_limit(10000000)
                    , m_value(t_value)
                    , m_v(0x01)
                    , m_data_size(t_data_size)
        {
            m_to = ::arr_to_bytes(t_to, 40);
            m_data = ::copy_bytes(t_data, t_data_size);
        };

        std::vector<unsigned char> signed_tx;
        // bool is_signed;

        std::vector<unsigned char> encode(bool);
        void sign(unsigned char*);
        
    private:
        unsigned int m_nonce;
        unsigned int m_gas_price;
        unsigned int m_gas_limit;
        unsigned char* m_to;
        unsigned int m_value;
        unsigned char* m_data;
        unsigned int m_v;
        unsigned char m_r[32];
        unsigned char m_s[32];

        unsigned int m_data_size;
};

#endif  // TX_H