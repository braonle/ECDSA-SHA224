#pragma once
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"

class Verifier
{
public:
    Verifier(void* pk, int klen);
    bool verify(void* msg, int msglen);
};