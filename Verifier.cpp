#include "Verifier.h"

Verifier::Verifier(char* filename)
{
    _pool = new AutoSeededRandomPool();
    FileSource fs(filename, true);
    _public_key.Load(fs);
    _verifier = new ECDSA<ECP, SHA224>::Verifier(_public_key);
}

Verifier::~Verifier()
{
    if (!_pool)
        delete _pool;
    if (!_verifier)
        delete _verifier;
}

bool Verifier::Verify(void *msg, int msglen, void *sig, int siglen)
{
    return _verifier->VerifyMessage((byte*)msg, msglen, (byte*)sig, siglen);
}