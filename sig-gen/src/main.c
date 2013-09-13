/*
 ============================================================================
 Name        : main.c
 Author      : Yufei Gu
 Version     :
 Copyright   : Copyright 2012 by UTD. all rights reserved. This material may
 be freely copied and distributed subject to inclusion of this
 copyright notice and our World Wide Web URL http://www.utdallas.edu
 Description : Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include "memload.h"
#include "memory.h"


extern long long timeval_diff(struct timeval *difference,
                              struct timeval *end_time,
                              struct timeval *start_time);

unsigned getPgd(char *mem, int mem_size);

void usage(int argc, char *argv[])
{
   if (argc < 5)
    {
        fprintf(stderr, "%s OPTION(-g|-s) SNAPSHOT PAGE_TO_PRINT /proc/modules \n", argv[0]);
        exit(1);
    }
}

//get current time
int get_current_time(struct timeval * current_time)
{
    if (gettimeofday(current_time, NULL)) {
        perror("gettimeofday() error");
        exit(1);
    }
    return 0;
}

Mem *initMem(char *snapshot)
{
   //load memory file
    struct timeval earlier;
    struct timeval later;
    get_current_time(&earlier);

    char *mem;
    unsigned long mem_size;
    mem = mem_load(snapshot, &mem_size);
    if (mem == NULL)
        return NULL;
    else
        printf("mem '%s' load success! size is %ld\n", snapshot, mem_size);


    get_current_time(&later);
    int loadTime = timeval_diff(NULL, &later, &earlier) / 1000;
    printf("Load mem time cost is %d milliseconds\n", loadTime);
    FILE *out_data;
    out_data = fopen("loadMemTime", "a+");
    fprintf(out_data, "%d\t%s\n", loadTime, snapshot);
    fclose(out_data);

    //get pgd
    unsigned pgd = getPgd(mem, mem_size);
    printf("pgd is 0x%x\n", pgd);

    //construct a struct Mem
    Mem *mem1 = (Mem *) malloc(sizeof(Mem));
    mem1->mem = mem;
    mem1->mem_size = mem_size;
    mem1->pgd = pgd;

    return mem1;
}

//get signature from a memory snapshot
void genSignature(char *snapshot1)
{
    xed2_init();
    Mem *mem = initMem(snapshot1);

    //traverse memory
    if (mem != NULL) {
        gen_md5_signature(mem);
    }
    //free memory
    free_mem(mem);
}




unsigned out_pc;
FILE *out_code;
struct timeval programStart;
char *snapshot;
char *modules;
int isGenerator = 0;
int main(int argc, char *argv[])
{
    get_current_time(&programStart); //record start time
    
    //handle Command Line Arguments
    usage(argc, argv);

    char *argument = argv[1];
    snapshot = argv[2];

    char * out_code_file = argv[3];
    sscanf(out_code_file, "%x", &out_pc);
    out_code = fopen(out_code_file, "w");

    //modules
    modules = argv[4];

    extern char *strchr(const char *s, int c);
    //g is generate signature
    char *pch = strchr(argument, 'g');
    if (pch != NULL)
        isGenerator = 1;


    //generate signature
    genSignature(snapshot);

    struct timeval later;
    get_current_time(&later);

    printf("Total time cost is %lld milliseconds\n",
           timeval_diff(NULL, &later, &programStart) / 1000);
    return EXIT_SUCCESS;
}


