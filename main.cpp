#include <iostream>
#include <unistd.h>
#include "Sync.h"
#include <sys/shm.h>
#include <iomanip>
#include "Verifier.h"
#include "Claimer.h"
#include "Const.h"

using namespace std;

void exit(void* shmem, int shmid, int exitcode)
{
    shmdt(shmem);
    shmctl(shmid, IPC_RMID, 0);
    exit(exitcode);
}

int main()
{
    int peer_pid = 0;
    int pid = 0;
    int shmid = 0;
    int *shmem = 0;
    Message1 *msg1 = 0;
    Message2 *msg2 = 0;
    CryptoPP::AutoSeededRandomPool pool;
    string text1(TEXT1);
    string text2(TEXT2);
    string text3(TEXT3);
    int br;

    //Initialization section
    if ((shmid = shmget(IPC_PRIVATE, SHM_SIZE, IPC_CREAT | IPC_PRIV)) == -1
            || *(shmem = (int*)shmat(shmid, 0, 0)) == -1)
    {
        cout << "Cannot obtain shared memory" << endl;
        return ErrorCodes::shmem;
    }

    msg1 = (Message1*) shmem;
    msg2 = (Message2*) shmem;

    if ((pid = fork()) == -1)
    {
        cout << "Unable to fork" << endl;
        return ErrorCodes::forkerr;
    }
    else if (pid)          //Verification section
    {
        peer_pid = pid;
        pid = getpid();

        //RNG --> Rb(a)
        msg1->receiver = peer_pid;
        msg1->sender = pid;
        pool.GenerateBlock((byte*)(msg1->Rb), RAND_SIZE);
        unsigned char *Rb = new unsigned char[RAND_SIZE];
        memcpy(Rb, msg1->Rb, RAND_SIZE);
        memcpy(msg1->text1, text1.c_str(), text1.length() + 1);

        cout << "Verification challenge: " << pid << " probes " << peer_pid << endl;
        cout << "Rb: 0x";
        for (int i = 0; i < RAND_SIZE; ++i)
            cout << HEX(msg1->Rb[i]);
        cout << endl;

        Sync::Instance().PlaceMessage();
        Sync::Instance().WaitMessage();

        if (pid != msg2->receiver)
        {
            cout << "Bad sender of recipient" << endl
                 << "Sender " << msg2->sender << endl
                 << "Recipient " << msg2->receiver << endl;
            exit(shmem, shmid, ErrorCodes::rcv_snd2);
        }

        if (0 != memcmp(msg2->Rb, Rb, RAND_SIZE))
        {
            cout << "Bad random number from challenge" << endl;
            exit(shmem, shmid, ErrorCodes::randerr);
        }

        if (text3.compare((char*)msg2->text3) != 0)
        {
            cout << "TEXT1 doesn't match: " << msg2->text3 << " vs " << text3 << endl;
            exit(shmem, shmid, ErrorCodes::txt1);
        }

        cout << "Response for challenge: " << peer_pid << " answered " << pid << flush << endl;
        cout << "Rb: 0x";
        for (int i = 0; i < RAND_SIZE; ++i)
            cout << HEX(msg2->Rb[i]);
        cout << endl;
        cout << "Ra: 0x";
        for (int i = 0; i < RAND_SIZE; ++i)
            cout << HEX(msg2->Ra[i]);
        cout << endl;

        Verifier verifier(FILEPATH);

        unsigned char *ptr = new unsigned char[sizeof(HashedInfo) + text2.length() + 1];
        HashedInfo *info = (HashedInfo*) ptr;
        memcpy(info->Ra, msg2->Ra, RAND_SIZE);
        memcpy(info->Rb, msg2->Rb, RAND_SIZE);
        info->verifier = pid;
        memcpy(info->text2, text2.c_str(), text2.length() + 1);

        if (verifier.Verify(ptr, sizeof(HashedInfo) + text2.length() + 1, msg2->signature, SIGN_SIZE))
            cout << "Authenticated" << endl;
        else
            cout << "Authentication failed" << endl;

        delete ptr;

        //Sync::Instance().PlaceMessage();

        exit(shmem, shmid, ErrorCodes::ok);
    }
    else                        //Authenticating section
    {
        peer_pid = getppid();
        pid = getpid();

        Claimer claimer;
        claimer.SavePublicKey(FILEPATH);

        Sync::Instance().ReadMessage();

        if (pid != msg1->receiver)
        {
            cout << "Bad sender of recipient" << endl
                 << "Sender " << msg1->sender << endl
                 << "Recipient " << msg1->receiver << endl;
            exit(shmem, shmid, ErrorCodes::rcv_snd1);
        }

        if (text1.compare((char*)msg1->text1) != 0)
        {
            cout << "TEXT1 doesn't match: " << msg1->text1 << " vs " << text1 << endl;
            exit(shmem, shmid, ErrorCodes::txt1);
        }

        memmove(msg2->Rb, msg1->Rb, RAND_SIZE);
        msg2->sender = pid;
        msg2->receiver = peer_pid;
        pool.GenerateBlock(msg2->Ra, RAND_SIZE);
        memcpy(msg2->text3, text3.c_str(), text3.length() + 1);


        unsigned char *ptr = new unsigned char[sizeof(HashedInfo) + text2.length() + 1];
        HashedInfo *info = (HashedInfo*) ptr;
        memcpy(info->Ra, msg2->Ra, RAND_SIZE);
        memcpy(info->Rb, msg2->Rb, RAND_SIZE);
        info->verifier = peer_pid;
        memcpy(info->text2, text2.c_str(), text2.length() + 1);
        claimer.Sign(msg2->signature, info, sizeof(HashedInfo) + text2.length() + 1);

        Sync::Instance().AckMessage();

        //Sync::Instance().ReadMessage();
        shmdt(shmem);

        return 0;
    }
}

