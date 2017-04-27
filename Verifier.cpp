#include "Verifier.h"

Verifier::Verifier()
{
    _Rb = new unsigned char[RAND_SIZE];
}

void Verifier::LoadKey(char *filename)
{
    FileSource fs(filename, true);
    _public_key.Load(fs);
    _verifier = new ECDSA<ECP, SHA224>::Verifier(_public_key);
}

Verifier::~Verifier()
{
    if (!_verifier)
        delete _verifier;
    if (!_Rb)
        delete _Rb;
}

Verifier::Error Verifier::Verify(Message2* msg, int src, int dest,  string* text2, string* text3)
{
    if (!_verifier)
        return no_pk;

    if (msg->receiver != dest)
        return receiver;

    if(msg->sender != src)
        return sender;

    if (0 != memcmp(msg->Rb, _Rb, RAND_SIZE))
        return rerr;

    if (text3->compare((char*)msg->text3) != 0)
        return txt;

    unsigned char buf[sizeof(HashedInfo) + text2->length() + 1];
    HashedInfo *info = (HashedInfo*) &buf;
    memcpy(info->Ra, msg->Ra, RAND_SIZE);
    memcpy(info->Rb, msg->Rb, RAND_SIZE);
    info->verifier = getpid();
    memcpy(info->text2, text2->c_str(), text2->length() + 1);

    if(_verifier->VerifyMessage((byte*)info, sizeof(HashedInfo) + text2->length() + 1, msg->signature, SIGN_SIZE))
        return ok;
    else
        return sign;
}

void Verifier::PlaceChallenge(Message1 *msg, int src, int dest, string* text1)
{
    msg->receiver = dest;
    msg->sender = src;
    _pool.GenerateBlock((byte*)(msg->Rb), RAND_SIZE);
    memcpy(_Rb, msg->Rb, RAND_SIZE);
    memcpy(msg->text1, text1->c_str(), text1->length() + 1);
}

