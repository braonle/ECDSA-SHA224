#include "Claimer.h"

Claimer::Claimer()
{
    _pool = new AutoSeededRandomPool();
    _signer = new ECDSA<ECP, SHA224>::Signer();

    _signer->AccessKey().Initialize(*_pool, ASN1::secp521r1());
    if (!_signer->AccessKey().Validate(*_pool, 3))
        throw "Cannot create private key";
}

Claimer::~Claimer()
{
    if (!_pool)
        delete _pool;
    if (!_signer)
        delete _signer;
}

void Claimer::SavePublicKey(char *filename)
{
    ECDSA<ECP, SHA224>::PublicKey public_key;
    _signer->AccessKey().MakePublicKey(public_key);

    if (!public_key.Validate(*_pool, 3))
        throw "Cannot create public key";

    FileSink fs(filename, true);
    public_key.Save(fs);
}

void Claimer::Sign(void *buffer, const void *msg, unsigned msglen)
{
    _signer->SignMessage(*_pool, (byte*)(msg),
                                  msglen, (byte*)(buffer));
}