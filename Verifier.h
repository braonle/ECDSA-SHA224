#pragma once
#include <cryptopp/osrng.h>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include "Const.h"

using namespace std;
using namespace CryptoPP;

class Verifier
{
    CryptoPP::AutoSeededRandomPool *_pool = 0;
    ECDSA<ECP, SHA224>::Verifier *_verifier = 0;
    ECDSA<ECP, SHA224>::PublicKey _public_key;
public:
    Verifier(char *filename);
    bool Verify(void *msg, int msglen, void *sig, int siglen);
    ~Verifier();
};