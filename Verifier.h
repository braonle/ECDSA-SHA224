#pragma once
#include <unistd.h>
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
    CryptoPP::AutoSeededRandomPool _pool;
    ECDSA<ECP, SHA224>::Verifier *_verifier = 0;
    ECDSA<ECP, SHA224>::PublicKey _public_key;
    unsigned char *_Rb = 0;
public:
    enum Error {ok, sender, receiver, sign, rerr, txt, no_pk};

    Verifier();
    void LoadKey(char *filename);
    void PlaceChallenge(Message1 *ptr, int src, int dst, string* text1);
    Verifier::Error Verify(Message2* msg, int src, int dest, string* text2, string* text3);
    ~Verifier();
};