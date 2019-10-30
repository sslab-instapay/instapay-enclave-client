#ifndef CHANNEL_H
#define CHANNEL_H

#include <map>
#include <util.h>

enum channel_status {
    PENDING     = 0,
	IDLE		= 1,
	PRE_UPDATE	= 2,
	POST_UPDATE	= 3,
};

class Channel {
    public:
        Channel(unsigned int t_id,
                unsigned char *t_from,
                unsigned char *t_to,
                bool t_is_in,
                unsigned int t_deposit
                )
                : m_id(t_id)
                , m_is_in(t_is_in)
        {
            m_to = ::arr_to_bytes(t_to, 40);
            m_from = ::arr_to_bytes(t_from, 40);

            m_status = (m_id == -1) ? PENDING:IDLE;

            if(m_is_in == true) {
                m_deposit = 0;
                m_balance = 0;
            }
            else {
                m_deposit = t_deposit;
                m_balance = t_deposit;
                m_locked_balance = 0;
            }
        };

        int pay(unsigned int amount);
        int paid(unsigned int amount);

        void transition_to_pre_update(void);
        void transition_to_post_update(void);
        void transition_to_idle(void);

        unsigned int get_balance(void);

    private:
        unsigned int m_id;
        unsigned char *m_from;
        unsigned char *m_to;
        bool m_is_in;
        channel_status m_status;
        unsigned int m_deposit;
        unsigned int m_balance;
        unsigned int m_locked_balance;
        unsigned char *m_other_ip;
        unsigned int m_other_port;
};

using namespace std;

typedef std::map<unsigned int, Channel> map_channel;
typedef map_channel::value_type map_channel_value;

extern map_channel channels;

#endif