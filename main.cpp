#include <iostream>
#include <unistd.h>
#include "Sync.h"
#include <sys/shm.h>
#include <iomanip>
#include "Verifier.h"
#include "Claimer.h"
#include "cryptopp/integer.h"
#include "cryptopp/osrng.h"
#include "Const.h"

#define SHM_SIZE 8000

using namespace std;

int main()
{
    int peer_pid = 0;
    int pid = 0;
    int shmid = 0;
    unsigned char *shmem = 0;
    int *ushmem = 0;
    CryptoPP::AutoSeededRandomPool pool;
    unsigned offset = 0;
    string text1 = TEXT1;
    string text2 = TEXT2;
    string text3 = TEXT3;

    //Initialization section
    if ((shmid = shmget(IPC_PRIVATE, SHM_SIZE, IPC_CREAT | IPC_PRIV)) == -1
            || *(shmem = (unsigned char*)shmat(shmid, 0, 0)) == -1)
    {
        cout << "Cannot obtain shared memory" << endl;
        return -1;
    }

    ushmem = (int*)shmem;

    if ((pid = fork()) == -1)
    {
        cout << "Unable to fork" << endl;
        return -3;
    }
    else if (pid == 0)          //Verification section
    {
        peer_pid = getppid();
        pid = getpid();

        //RNG --> Rb(a)
        ushmem[0] = peer_pid;
        ushmem[1] = pid;
        offset = 2 * sizeof(int);
        memcpy(shmem + offset, text1.data(), text1.length() + 1);
        offset += text1.length() + 1;
        pool.GenerateBlock((byte*)(shmem + offset), RAND_SIZE);
        offset += RAND_SIZE;

        cout << "Verification challenge: " << pid << " probes " << peer_pid << endl;
        for (int i = offset - RAND_SIZE; i < offset; ++i)
            cout << HEX(shmem[i]);
        cout << endl;

        Sync::Instance().msg_place();
        Sync::Instance().msg_wait();

        cout << "Child exits " << endl;

        Sync::Instance().msg_place();
    }
    else                        //Authenticating section
    {
        peer_pid = pid;
        pid = getpid();

        Claimer claimer;
        claimer.get_pk(FILEPATH);

        Sync::Instance().msg_read();

        if (pid != ushmem[0])
            cout << "Bad sender of recipient" << endl
                 << "Sender " << ushmem[1] << endl
                 << "Recipient " << ushmem[0] << endl;

        offset = 2 * sizeof(int);

        char* buf = new char[text1.length() + 1];
        memcpy(buf, shmem + offset, text1.length() + 1);
        if (text1.compare(buf) != 0)
            cout << "TEXT1 doesn't match: " << text1 << " vs " << buf << endl;
        offset += text1.length() + 1;
        delete buf;

        buf =  new char[RAND_SIZE * 2 + text2.length() + 1 + sizeof(int)];
        pool.GenerateBlock((byte*)(buf), RAND_SIZE);
        int off = RAND_SIZE;
        memcpy(buf + RAND_SIZE, shmem + offset, RAND_SIZE);
        off += RAND_SIZE;
        *(int*)(buf + off) = ushmem[1];
        off += sizeof(int);
        memcpy(buf + off, text2.data(), text2.length() + 1);
        off += text2.length() + 1;

        cout << SHA224::DIGESTSIZE << endl;
        unsigned char* hash = new unsigned char[SHA224::DIGESTSIZE];
        SHA224().CalculateDigest(hash, (byte*)buf, off);


        for (int i = 0; i < SHA224::DIGESTSIZE; ++i)
            cout << HEX(hash[i]);
        cout << endl;

        delete buf;
        delete hash;

        Sync::Instance().msg_ack();
        Sync::Instance().msg_read();

        cout << "Parent exits " << endl;
    }

    shmdt(shmem);
    shmctl(shmid, IPC_RMID, 0);

    return 0;
}