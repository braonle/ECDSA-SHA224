#pragma once
#include <cryptopp/osrng.h>
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/files.h>
#include "Const.h"

using namespace CryptoPP;
using namespace std;

class Claimer
{
    CryptoPP::AutoSeededRandomPool* _pool = 0;
    ECDSA<ECP, SHA224>::Signer* _signer = 0;

public:
    Claimer();
    void SavePublicKey(char *filename);
    //void PlaceChallenge(Message1 *ptr);
    void Sign(void* buffer, const void* msg, unsigned msglen);
    ~Claimer();
};