#include "Claimer.h"

using namespace std;

Claimer::Claimer()
{
    _signer.AccessKey().Initialize(_pool, ASN1::secp521r1());
}

void Claimer::SavePublicKey(char *filename)
{
    ECDSA<ECP, SHA224>::PublicKey public_key;
    _signer.AccessKey().MakePublicKey(public_key);
    FileSink fs(filename, true);
    public_key.Save(fs);
}

Claimer::Error Claimer::Check(Message1 *msg, int src, int dest, string* text1)
{
    if (msg->sender != src)
        return sender;
    if (msg->receiver != dest)
        return receiver;
    if (text1->compare((char*)msg->text1) != 0)
        return txt;
    return ok;
}

void Claimer::PlaceResponse(Message1* msg1, Message2 *msg2, int src, int dest, string* text2, string* text3)
{
    memmove(msg2->Rb, msg1->Rb, RAND_SIZE);
    msg2->sender = src;
    msg2->receiver = dest;
    _pool.GenerateBlock(msg2->Ra, RAND_SIZE);
    memcpy(msg2->text3, text3->c_str(), text3->length() + 1);

    unsigned char ptr[sizeof(HashedInfo) + text2->length() + 1];
    HashedInfo *info = (HashedInfo*) &ptr;
    memcpy(info->Ra, msg2->Ra, RAND_SIZE);
    memcpy(info->Rb, msg2->Rb, RAND_SIZE);
    info->verifier = dest;
    memcpy(info->text2, text2->c_str(), text2->length() + 1);
    _signer.SignMessage(_pool, (byte*)(info), sizeof(HashedInfo) + text2->length() + 1, (byte*)(msg2->signature));
}