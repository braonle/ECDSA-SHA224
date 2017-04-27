#pragma once

#define RAND_SIZE 64
#define SHM_SIZE 8192

#define TEXT1 "text1"
#define TEXT2 "text2"
#define TEXT3 "text3"

#define FILEPATH "pub.key"

#define HEX(x) setw(2) << setfill('0') << hex << (unsigned)x << flush << dec
#define DEBUG cout << "DEBUG" << flush << endl;

#define SIGN_SIZE 132

enum ErrorCodes
{
    ok = 0, shmem, forkerr, txt1, txt3, hash, rcv_snd1, rcv_snd2, randerr
};

struct Message1
{
    int receiver;
    int sender;
    unsigned char Rb[RAND_SIZE];
    unsigned char text1[];
};

struct Message2
{
    int receiver;
    int sender;
    unsigned char Rb[RAND_SIZE];
    unsigned char Ra[RAND_SIZE];
    unsigned char signature[SIGN_SIZE];
    unsigned char text3[];
};

struct HashedInfo
{
    unsigned char Ra[RAND_SIZE];
    unsigned char Rb[RAND_SIZE];
    int verifier;
    unsigned char text2[];
};
