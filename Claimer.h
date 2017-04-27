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
    CryptoPP::AutoSeededRandomPool _pool;
    ECDSA<ECP, SHA224>::Signer _signer;
public:
    enum Error {ok, sender, receiver, txt};

    Claimer();
    void SavePublicKey(char *filename);
    Claimer::Error Check(Message1* msg, int src, int dest, string* text1);
    void PlaceResponse(Message1* msg1, Message2 *msg2, int src, int dest, string* text2, string* text3);
};