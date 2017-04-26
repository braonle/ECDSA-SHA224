#pragma once
#include <cryptopp/osrng.h>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include <string.h>

using namespace CryptoPP;
using namespace std;

class Claimer
{
    CryptoPP::AutoSeededRandomPool* _pool = 0;
    ECDSA<ECP, SHA224>::Signer* _signer = 0;

public:
    Claimer();
    void get_pk(string filename);
    void sign(void* buffer, const void* msg, unsigned msglen);
    unsigned get_sign_len();
    ~Claimer();
};