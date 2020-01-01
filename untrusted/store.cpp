#include "app.h"
#include "enclave_u.h"

#include <stdio.h>
#include <string.h>


void ecall_store_account_data_w()
{
    ecall_store_account_data(global_eid);
}


void ocall_remove_key_file()
{
    if(remove("./data/key/a0") != 0)
        printf("error deleting file\n");
    else
        printf("removed file successfully\n");
}


void ocall_store_sealed_seckey(unsigned char *sealed_seckey)
{
    FILE *fp = fopen("./data/key/a0", "ab");
    int count;

    count = fwrite(sealed_seckey, sizeof(unsigned char), 592, fp);
    printf("write %d bytes to ./data/key/a0\n", count);

    fclose(fp);

    return;
}


void ecall_store_channel_data_w()
{
    ecall_store_channel_data(global_eid);
}


void ocall_remove_channel_file()
{
    if(remove("./data/channel/c0") != 0)
        printf("error deleting file\n");
    else
        printf("removed file successfully\n");
}


void ocall_store_sealed_channel_data(unsigned char *sealed_channel_data)
{
    FILE *fp = fopen("./data/channel/c0", "ab");
    int count;

    count = fwrite(sealed_channel_data, sizeof(unsigned char), 628, fp);
    printf("write %d bytes to ./data/channel/c0\n", count);

    fclose(fp);

    return;
}