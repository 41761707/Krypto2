#include <iostream>
#include <ctime>
#include <random>
#include <algorithm>
#include "md5.hpp"
#include "arrays.hpp"

using namespace std;


unsigned char* compute_hash(unsigned char* msg)
{
    unsigned char* hash = new unsigned char[16];
    Context ctx{};
    mbedtls_md5_procedure(&ctx, msg, 128, hash);
    return hash;
}


bool check_equality(unsigned char* msg0, unsigned char* msg1, unsigned char* msg0_prim, unsigned char* msg1_prim)
{
    unsigned char msg[128], msg_prim[128];
    for (int i = 0; i < 64; i++)
    {
        msg[i] = msg0[i];
        msg_prim[i] = msg0_prim[i];
    }
    for(int i=64;i<128;i++)
    {
        msg[i] = msg1[i-64];
        msg_prim[i] = msg1_prim[i-64];
    }
    unsigned char* hash1 = compute_hash(msg);
    unsigned char* hash2 = compute_hash(msg_prim);
    bool result = true;
    for (int i = 0; i < 16; i++)
    {
        if (hash1[i] != hash2[i])
            result = false;
            break;
    }
    for (int i = 0; i < 16; i++)
    {
        printf("%x", hash1[i]);
        if ((i+1) % 4 == 0)
            cout << " ";
    }
    cout << "\n";
    for (int i = 0; i < 16; i++)
    {
        printf("%x", hash2[i]);
        if ((i+1) % 4 == 0)
            cout << " ";
    }
    cout << "\n";
    if(result)
    {
        cout << "Hashe identyczne\n";
    }
    else
    {
        cout << "Hashe są rożne\n";
    }

    return result;
}


void interface()
{
    std::mt19937 mt(time(nullptr)); 
    unsigned char rand_m1[64], rand_m1_prim[64];
    for (int i = 0; i < 16; i++)
    {
        rand_m1[i] = mt();
        rand_m1_prim[i] = mt();
    }

    cout << "MD5(MD5(IV, M0), M1) vs MD5(MD5(IV, M0'), M1')\n";
    check_equality(m0, m1, m0_prim, m1_prim);
}


void textbook_attack()
{
    std::mt19937 mt(time(nullptr)); 
    unsigned char placeholder_m1[64], placeholder_m1_prim[64];
    for (int i = 0; i < 64; i++)
    {
        placeholder_m1[i] = m1[i];
    }

    unsigned char* hash1 = new unsigned char[16];
    Context ctx{};
    mbedtls_modified_md5_procedure(&ctx, placeholder_m1, 64, hash1, true);

    for (int i = 0; i < 64; i++)
    {
        placeholder_m1_prim[i] = placeholder_m1[i];
    }

    uint32_t m_4 = MBEDTLS_GET_UINT32_LE(placeholder_m1, 16) + 0x80000000;
    uint32_t m_11 = MBEDTLS_GET_UINT32_LE(placeholder_m1, 44) - 0x00008000;
    uint32_t m_14 = MBEDTLS_GET_UINT32_LE(placeholder_m1, 56) + 0x80000000;

    MBEDTLS_PUT_UINT32_LE(m_4, placeholder_m1_prim, 16);
    MBEDTLS_PUT_UINT32_LE(m_11, placeholder_m1_prim, 44);
    MBEDTLS_PUT_UINT32_LE(m_14, placeholder_m1_prim, 56);

    for (int i = 0; i < 64; i++)
    {
        printf("%x", placeholder_m1[i]);
        if ((i+1) % 4 == 0)
            cout << ' ';
    }
    cout << "\n";
    for (int i = 0; i < 64; i++)
    {
        printf("%x", placeholder_m1_prim[i]);
        if ((i+1) % 4 == 0)
            cout << ' ';
    }
    cout << "\n";
    unsigned char* hash2 = new unsigned char[16];
    mbedtls_modified_md5_procedure(&ctx, placeholder_m1_prim, 64, hash2, false);
    bool result = true; 

    for (int i = 0; i < 16; i++)
    {
        if (hash1[i] != hash2[i])
            result = false;
            break;
    }
    for (int i = 0; i < 16; i++)
    {
        printf("%x", hash1[i]);
        if ((i+1) % 4 == 0)
            cout << ' ';
    }
    cout << "\n";
    for (int i = 0; i < 16; i++)
    {
        printf("%x", hash2[i]);
        if ((i+1) % 4 == 0)
            cout << ' ';
    }
    cout << "\n";
    cout << "Wynik: " << result << "\n";
}


int main()
{
    interface();
    textbook_attack();
}