#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "md5.h"

void convert(unsigned char* array)
{
    for(int i=0;i<128;i+=4)
    {
        unsigned char temp_1=array[i];
        array[i] = array[i+3];
        array[i+3] = temp_1;
        unsigned char temp_2 = array[i+1];
        array[i+1] = array[i+2];
        array[i+2] = temp_2;
    }
}

bool check_hashes(unsigned char *m0, unsigned char *m1)
{
    for(int i=0;i<16;i++)
    {
        if(m0[i] != m1[i])
        {
            printf("0x%02x",m0[i]);
            printf("0x%02x",m1[i]);
            printf("Hashe są różne\n");
            return false;
        }
    }
    return true;
}

void print_hash(unsigned char *p){
    for( int i = 0; i < 16; i++){
        printf("%02x", p[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[])
{
    unsigned char m0[128];
    unsigned char m0_2[128];
    int tracker = 0;
    FILE* file;
    char* buffer = 0;
    unsigned char current;
    long length;

    file = fopen(argv[1],"rb");
    if(NULL == file)
    {
        printf("Nie udało się otworzyć pliku\n");
    }

    if(file)
    {
        fseek(file, 0, SEEK_END);
        length = ftell(file);
        fseek(file, 0, SEEK_SET);
        buffer = malloc(length);
        if(buffer)
        {
            fread(buffer, 1, length, file);
        }
        fclose(file);
    }
    if(buffer)
    {
        for(int i=0;i<length-1;i+=2)
        {
            char temp[] = {buffer[i],buffer[i+1]};
            current = (unsigned char) strtol (temp, (char **) NULL, 16);
            m0[tracker] = current;
            tracker = tracker+1;
        }
    }

    free(buffer);
    tracker = 0;

    file = fopen(argv[2],"rb");
    if(NULL == file)
    {
        printf("Nie udało się otworzyć pliku\n");
    }

    if(file)
    {
        fseek(file, 0, SEEK_END);
        length = ftell(file);
        fseek(file, 0, SEEK_SET);
        buffer = malloc(length);
        if(buffer)
        {
            fread(buffer, 1, length, file);
        }
        fclose(file);
    }
    if(buffer)
    {
        for(int i=0;i<length-1;i+=2)
        {
            char temp[] = {buffer[i],buffer[i+1]};
            current = (unsigned char) strtol (temp, (char **) NULL, 16);
            m0_2[tracker] = current;
            tracker = tracker+1;
        }
    }
    /*printf("M0:\n");
    for(int i=0;i<128;i++)
    {
        printf("0x%02x ",m0[i]);
        if(i%16==15)
        {
            printf("\n");
        }
    }
    printf("M0_2:\n");
    for(int i=0;i<128;i++)
    {
        printf("0x%02x ",m0_2[i]);
        if(i%16==15)
        {
            printf("\n");
        }
    }*/
    unsigned char md5sum_m0[16];
    unsigned char md5sum_m1[16];
    printf("MD5(MD5(IV, M0), M1):\n");
    convert(m0);
    mbedtls_md5(m0, 128, md5sum_m0 );
    print_hash(md5sum_m0);
    printf("MD5(MD5(IV, M0'), M1'):\n");
    convert(m0_2);
    mbedtls_md5(m0_2, 128, md5sum_m1);
    print_hash(md5sum_m1);
    if(check_hashes(md5sum_m0,md5sum_m1))
    {
        printf("Hashe są identyczne\n");
    }
    
}
