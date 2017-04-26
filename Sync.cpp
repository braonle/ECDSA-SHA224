#include "Sync.h"

Sync::Sync() throw(int)
{
    semid = semget(ftok(IPC_KEY, 0), 1, IPC_CREAT | IPC_PRIV);
    if (semid == -1)
        throw errno;
}

Sync& Sync::Instance()
{
    static Sync s;
    return s;
}

void Sync::msg_place()
{
    sops.sem_op = 2;
    semop(semid, &sops, 1);
}

void Sync::msg_read()
{
    sops.sem_op = -1;
    semop(semid, &sops, 1);
}

void Sync::msg_ack()
{
    sops.sem_op = -1;
    semop(semid, &sops, 1);
}

void Sync::msg_wait()
{
    sops.sem_op = 0;
    semop(semid, &sops, 1);
}

Sync::~Sync()
{
    if (semid != 0)
        semctl(semid, 0, IPC_RMID);
}