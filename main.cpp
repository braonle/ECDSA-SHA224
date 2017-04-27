#include <iostream>
#include <iomanip>
#include <unistd.h>
#include "Sync.h"
#include <sys/shm.h>
#include "Verifier.h"
#include "Claimer.h"

using namespace std;

int main()
{
    int pid = 0;
    int shmid = 0;
    int *shmem = 0;
    string text1(TEXT1);
    string text2(TEXT2);
    string text3(TEXT3);

    //Initialization section
    if ((shmid = shmget(IPC_PRIVATE, SHM_SIZE, IPC_CREAT | IPC_PRIV)) == -1
            || *(shmem = (int*)shmat(shmid, 0, 0)) == -1)
    {
        cout << "Cannot obtain shared memory" << endl;
        return -1;
    }

    if ((pid = fork()) == -1)
    {
        cout << "Unable to fork" << endl;
        return -2;
    }
    else if (pid)          //Verification section
    {
        Verifier ver;

        ver.PlaceChallenge((Message1*)shmem, getpid(), pid, &text1);

        cout << "Verification challenge: " << getpid() << " probes " << pid << endl;
        cout << "Rb: 0x";
        for (int i = 0; i < RAND_SIZE; ++i)
            cout << HEX(((Message1*)shmem)->Rb[i]);
        cout << endl;

        Sync::Instance().PlaceMessage();
        Sync::Instance().WaitMessage();

        cout << "Response for challenge: " << pid << " answered " << getpid() << endl;
        cout << "Rb: 0x";
        for (int i = 0; i < RAND_SIZE; ++i)
            cout << HEX(((Message2*)shmem)->Rb[i]);
        cout << endl;
        cout << "Ra: 0x";
        for (int i = 0; i < RAND_SIZE; ++i)
            cout << HEX(((Message2*)shmem)->Ra[i]);
        cout << endl;

        ver.LoadKey(FILEPATH);
        Verifier::Error res = ver.Verify((Message2*)shmem, pid, getpid(), &text2, &text3);

        string msg;
        switch (res)
        {
            case Verifier::receiver:
                msg = "Bad receiver"; break;
            case Verifier::sender:
                msg = "Bad sender"; break;
            case Verifier::rerr:
                msg = "Bad random number from challenge"; break;
            case Verifier::txt:
                msg = "text3 mismatch"; break;
            case Verifier::ok:
                msg = "Authenticated"; break;
            case Verifier::sign:
                msg = "Authentication failed"; break;
            case Verifier::no_pk:
                msg = "Public key not loaded";
            default:
                msg = "Unknown result"; break;
        }
        cout << msg << endl;

        shmdt(shmem);
        shmctl(shmid, IPC_RMID, 0);
        remove(FILEPATH);
        return res;
    }
    else                        //Authenticating section
    {
        Claimer claimer;
        claimer.SavePublicKey(FILEPATH);

        Sync::Instance().ReadMessage();

        Claimer::Error res = claimer.Check((Message1*)shmem, getppid(), getpid(), &text1);

        string msg;
        switch (res)
        {
            case Claimer::sender:
                msg = "Bad sender"; break;
            case Claimer::receiver:
                msg = "Bad receiver"; break;
            case Claimer::txt:
                msg = "text1 mismatch"; break;
            case Claimer::ok: break;
            default:
                msg = "Unknown result"; break;
        }
        if (res !=  Claimer::ok)
        {
            cout << msg << endl;
            shmdt(shmem);
            shmctl(shmid, IPC_RMID, 0);
            return -1;
        }

        claimer.PlaceResponse((Message1*) shmem, (Message2*) shmem, getpid(), getppid(), &text2, &text3);

        Sync::Instance().AckMessage();

        shmdt(shmem);
    }
    return 0;
}

