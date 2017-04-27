#pragma once
#include <iostream>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <errno.h>

#define IPC_KEY "ISO_ECDSA_SHA224"
#define IPC_PRIV 0666

class Sync
{
    int semid = 0;
    struct sembuf sops;

    Sync() throw(int);

    ~Sync();
public:
    Sync(const Sync&) = delete;
    Sync& operator=(const Sync&) = delete;

    static Sync& Instance();

    void PlaceMessage();
    void WaitMessage();

    void ReadMessage();
    void AckMessage();

};