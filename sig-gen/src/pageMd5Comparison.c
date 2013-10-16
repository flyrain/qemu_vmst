/*
 * pageMd5Comparison.c
 *
 *  Created on: Dec 18, 2011
 *      Author: Yufei Gu
 *  Copyright : Copyright 2012 by UTD. all rights reserved. This material may
 *	 	 	 	be freely copied and distributed subject to inclusion of this
 *              copyright notice and our World Wide Web URL http://www.utdallas.edu
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "memory.h"
#include "mddriver.c"
#include <sys/times.h>
#include <stdint.h>

extern int potential_pgd;
extern int real_pgd;
extern char *snapshot;
extern long long timeval_diff(struct timeval *difference,
                              struct timeval *end_time,
                              struct timeval *start_time);
extern int get_current_time(struct timeval * current_time);

FILE *kernel_code_sig;
/*determine whether a value is a valid non-empty kernel point */
int isKernelAddress(unsigned vaddr, char *mem, unsigned mem_size,
                    unsigned pgd, int isWindows)
{
    unsigned kernleStartAddr;
    if (isWindows)
        kernleStartAddr = 0x80000000;
    else
        kernleStartAddr = 0xc0000000;
    if (vaddr > kernleStartAddr) {
        unsigned pAddr = vtop(mem, mem_size, pgd, vaddr);
        if (pAddr > 0 && pAddr < mem_size)
            return 1;
    }
    return 0;
}

//generate md5 and print virtual address and md5
void genMd5(void *startAdress, int pageSize, unsigned vaddr)
{
    unsigned char md5digest[16];
    MDMem(startAdress, pageSize, md5digest);
//      printf("%x ", vaddr); //print vaddr
    MDPrint(md5digest);
    printf(" %x ", vaddr);      //print vaddr
    printf("\n");
}

//generate md5 and print virtual address and md5
void genMd5WithOffset(void *startAdress, int pageSize, unsigned vaddr,
                      unsigned offset)
{
    unsigned char md5digest[16];
    MDMem(startAdress, pageSize, md5digest);
    //print md5 and vaddr
    MDPrint(md5digest);

    printf(" %x %u", vaddr, offset / 4096);
    printf("\n");

    /*
      int i;
      for (i = 0; i < 16; i++)
      fprintf(kernel_code_sig, "%02x", md5digest[i]);
      fprintf(kernel_code_sig, " %x %u", vaddr, offset / 4096);
      fprintf(kernel_code_sig, "\n");
    */
}

extern unsigned out_pc;
extern range ranges[];
extern unsigned range_index;
extern int newstart;
cluster clusters[1 << 16];

//if there are some kernel address in the range
int containKernelAddres(cluster range, unsigned cr3address[])
{
    int ret = -1;
    int i = 0;
    int cr3No = 0;
    while (cr3address[i] != 0) {
        if (cr3address[i] >= range.start && cr3address[i] <= range.end) {
//                      ret = 0;
//                      break;
            cr3No++;
        }
        i++;
    }
    if (cr3No > 0)
        return cr3No;
    return ret;
}

int containKernelAddresForRange(range range, unsigned cr3address[])
{
    int ret = -1;
    int i = 0;
    while (cr3address[i] != 0) {
        if (cr3address[i] >= range.start && cr3address[i] <= range.end) {
            ret = 0;
            break;
        }
        i++;
    }
    return ret;
}

//recorde performance to file "outTime"
void recordPerformance(unsigned kdi_time, int sigGen_time, int match_time)
{
    //record performance
    extern int potential_pgd_time;
    extern int real_pgd_time;
    FILE *out_time;
    out_time = fopen("outTime", "a+");
    fprintf(out_time, "%d\t%d\t%d\t%d\t%d\t%s\n",
            potential_pgd_time + real_pgd_time, kdi_time, sigGen_time,
            match_time,
            (potential_pgd_time + real_pgd_time + kdi_time + sigGen_time +
             match_time), snapshot);
    fclose(out_time);
}

//signatures match
void sigMatch(range range, Mem * mem, int pageSize, int *dsmPages,
              int *match_time)
{
    int i;
    struct timeval earlier;
    struct timeval later;
    //begin match
    int osNumber = initDb();
    extern fingerprint fingerprints[FINGERPRINT_NO];
    if (gettimeofday(&earlier, NULL)) {
        perror("gettimeofday() error");
        exit(1);
    }
    int availableOs[FINGERPRINT_NO], matchCounts[FINGERPRINT_NO];
    for (i = 0; i < FINGERPRINT_NO; i++) {
        availableOs[i] = 1;
        matchCounts[i] = 0;
    }
    unsigned startVirtualAddr = range.start;
    int match_no = 0;
    for (; startVirtualAddr <= range.end; startVirtualAddr += 0x1000) {
        unsigned pAddr =
            vtop(mem->mem, mem->mem_size, mem->pgd, startVirtualAddr);
        if (pAddr == -1 || pAddr > mem->mem_size)
            continue;

        int pageIndex = pAddr / pageSize;
        if (dsmPages[pageIndex] == 1) {
            int offset = (startVirtualAddr - range.start) / 4096;
            void *startAdress =
                (void *) ((unsigned) mem->mem + pageIndex * pageSize);
            unsigned char md5digest[16];
            MDMem(startAdress, pageSize, md5digest);
            //      printf("%x ", vaddr); //print vaddr
            MDPrint(md5digest);
            printf("  offset %d\n", offset);
            int ret =
                matchByIndex(osNumber, md5digest, offset, availableOs,
                             matchCounts);
            if (ret == 1 || ret == 0)
                match_no++;
            printf("Number of page matching is %d\n", match_no);
        }
    }

    int maxIndex = -1;
    int maxMatch = 0;
    for (i = 0; i < FINGERPRINT_NO; i++) {
        if (matchCounts[i] > maxMatch) {
            maxIndex = i;
            maxMatch = matchCounts[i];
        }
    }
    if (maxMatch > 0)
        printf("Os is %s, match count is %d\n",
               fingerprints[maxIndex].osVersion, maxMatch);

    else
        puts("Unknown OS!");

    if (gettimeofday(&later, NULL)) {
        perror("gettimeofday() error");
        exit(1);
    }

    *match_time = timeval_diff(NULL, &later, &earlier) / 1000;
    printf("match time cost is %d milliseconds\n", *match_time);
}

//record data to file
void recordData(int allPages, unsigned cluster_index, int cr3ClusterNo,
                int cr3PageNo, unsigned finalTotalPageNo,
                unsigned disasPageNo, float byerate)
{
    FILE *out_data;
    float pageRate = (float) disasPageNo / (float) finalTotalPageNo * 100;
    out_data = fopen("outData", "a+");
    fprintf(out_data,
            "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%.2f\t%.2f\t%d\t%s\n",
            real_pgd, allPages, cluster_index, cr3ClusterNo, cr3PageNo,
            range_index, finalTotalPageNo, disasPageNo, pageRate,
            byerate * 100, disasPageNo, snapshot);
    fclose(out_data);
}

int findClusterHasMaxCr3(unsigned cluster_index, cluster clusters[],
                         unsigned cr3Pages[], int *cr3ClusterNo)
{
    int i;
    int maxcr3Index = -1;
    int maxLen = 0;
    for (i = 1; i <= cluster_index; i++) {
        int cr3No = containKernelAddres(clusters[i], cr3Pages);
        if (cr3No == -1) {
            continue;
        }
        (*cr3ClusterNo)++;
        if (cr3No > maxLen) {
            maxLen = cr3No;
            maxcr3Index = i;
        }
    }

    printf("CR3 cluster: %d\n", *cr3ClusterNo);
    return maxcr3Index;
}

void findKernelCodePageByCr3(unsigned startVirtualAddr, Mem * mem,
                             int pageSize, unsigned cr3Pages[])
{
    unsigned startVirtual = startVirtualAddr;
    int cr3PageIndex = 0;
    for (; startVirtual > startVirtualAddr - 1; startVirtual += 0x1000) {
        //      for (; startVirtual < 0x818f0000; startVirtual += 0x1000) {
        unsigned vAddr = startVirtual;

        int rw = 0;             //read or write
        int us = 0;             //use or system
        int g = 0;              //global(no move out of TLB) or not global
        int ps = 0;             //page size
        unsigned pAddr =
            vtopPageProperty(mem->mem, mem->mem_size, mem->pgd, vAddr, &rw,
                             &us, &g,
                             &ps);

        // IS PHYSICAL ADDRESS VALID?
        if (pAddr == -1 || pAddr > mem->mem_size)
            continue;

        //collect pages which are system access, and global pages
        if (us == 0 && g == 256) {
            if (find_kernel(mem, vAddr, pageSize) == 0) {
                //record kernel address (contain cr3: 0f 20 d8, 0f 22 d8)
                cr3Pages[cr3PageIndex++] = vAddr;
                printf("kernel start at %x\n", vAddr);
            }
        }
    }
}

//kernel code identification
int getClusters(unsigned startVirtualAddr, Mem * mem, int pageSize,
                int *allPages)
{
    clusters[0].end = 0;
    int pre_rw = -1;            //read or write
    int pre_us = -1;            //use or system
    int pre_g = -1;             //global, no move out of TLB
    int pre_ps = -1;            //page size
    unsigned cluster_index = 0;
    newstart = 1;
//              int allPhysicalPages = 0;

    unsigned vAddr = startVirtualAddr;
    for (; vAddr > startVirtualAddr - 1; vAddr += 0x1000) {
        int rw = 0;             //read or write
        int us = 0;             //use or system
        int g = 0;              //global, no move out of TLB
        int ps = 0;             //page size 4M or 4k
        unsigned pAddr =
            vtopPageProperty(mem->mem, mem->mem_size, mem->pgd, vAddr, &rw,
                             &us, &g,
                             &ps);

//                      extern FILE *pte_data;
        if (pAddr >= 0 && pAddr < mem->mem_size && us == 0 && g == 256) {
//                      if (pAddr >= 0 && pAddr < mem->mem_size) {
            (*allPages)++;
//                              if (pAddrs[pAddr / 4096] == 0)
//                                      allPhysicalPages++;
//                              pAddrs[pAddr / 4096] = 1;
            //                      printf("vaddr:%x,pAddr: %x, allpages is %d\n", vAddr,pAddr,allPages);
            //                      fprintf(pte_data,"%08x vaddr:%x, kernel code\n",pAddr, vAddr);
        }
        //if PHYSICAL ADDRESS is not VALID, then start a new cluster
        if (pAddr < 0 || pAddr > mem->mem_size || us != 0 || g != 256) {
            if (newstart == 0) {
                clusters[cluster_index].end = vAddr - 1;
                newstart = 1;
            }
            continue;
        }
        //if any property changes, then start a new cluster
        if (rw != pre_rw || us != pre_us || g != pre_g || ps != pre_ps) {
            if (newstart == 0) {
                clusters[cluster_index].end = vAddr - 1;
                newstart = 1;
            }
        }
        //update pre properties
        pre_rw = rw;
        pre_us = us;
        pre_g = g;
        pre_ps = ps;

        //collect pages  with continuous properties;
        if (newstart) {
            clusters[++cluster_index].start = vAddr;
            clusters[cluster_index].end = vAddr + pageSize - 1;
            newstart = 0;
            if (ps == 1)
                clusters[cluster_index].pageSize = 0x400000;
            else
                clusters[cluster_index].pageSize = 0x1000;
        } else
            clusters[cluster_index].end = vAddr + pageSize - 1;
    }

    return cluster_index;
}


//construct range from cluster
range gen_range(cluster c)
{
    range r;
    r.start = c.start;
    r.end = c.end;
    r.len = r.end - r.start;
    if(r.len < 0 )
        r.len = 0;
    r.disasBytes = 0;
    return r;
}

//read modules information from file /proc/modules, return length of
//the array
int read_modules_info(char *filename)
{
    //read file
    struct stat fstat;
    if (stat(filename, &fstat) != 0) {
        printf("No /proc/modules file : %s\n", filename);
        exit(1);
    }

    FILE *file = fopen(filename, "r");
    if ( file == NULL){
        perror(filename);       /* why didn't the file open? */
        return -1;
    }
    
    char line[100];
    int cluster_len =0;
    while (fgets(line, sizeof line, file) != NULL) {        /* read a
                                                               line */
//      printf("%s", line);
        int k;
        int space_count = 0;
        unsigned start_addr;
        int module_size = 0;
        int size_start_idx = -1;
        line[strlen(line)-1] = '\0'; //get rid of '\n'

        for (k = 0; k < 100; k++){
            if(line[k]== ' ')
                space_count ++;

            //printf("%d---\n", space_count);

            if(space_count == 1 && size_start_idx == -1)
                size_start_idx = k +1;

            if(space_count == 2){
                line[k] = '\0';
            }
          
            if(space_count == 5){
                sscanf(line+k+1, "%x", &start_addr);
                break;
            }
        }

        module_size = atoi(line + size_start_idx);

        char * name = malloc(size_start_idx + 1);
        name[size_start_idx] = '\0';
        memcpy(name, line, size_start_idx);

        clusters[cluster_len].name = name;
        clusters[cluster_len].start = start_addr;
        clusters[cluster_len].end = start_addr + module_size;
        clusters[cluster_len].pageSize = 4096;

//      printf("cluster start:%x, end:%x\n",  clusters[cluster_len].start, clusters[cluster_len].end);
        cluster_len ++;
    }

    fclose(file);
    return cluster_len;
}

/******************************************************************
 * Generate md5 signatures for the snapshot
 * traverse page by page 
 *****************************************************************/
void gen_md5_signature(Mem * mem)
{
    int i;
    int pageSize = 4 * 1024;    //4k
    int totalPageNumber = mem->mem_size / (4 * 1024);  //assume page size is 4k
    unsigned startVirtualAddr = 0x80000000;

    int calledPages[totalPageNumber];
    int dsmPages[totalPageNumber];
    //record virtual address
    unsigned virtualAddrs[totalPageNumber];
    for (i = 0; i < totalPageNumber; i++) {
        calledPages[i] = 0;
        dsmPages[i] = 0;
        virtualAddrs[i] = 0;
    }

    //step1. give clusters by modules information
    int cluster_idx = 0 ;
    int all_page(){
        clusters[0].start = 0xd0000000;
        clusters[0].end = 0xe0000000;
        clusters[0].name = "all";
        clusters[0].pageSize = 4096;
        return 1;
    }
  
    extern char *modules;
    extern int isGenerator;
    int cluster_len = 0;
    if (isGenerator == 1)
        cluster_len = read_modules_info(modules);
    else
        cluster_len = all_page();

    for(cluster_idx = 0; cluster_idx < cluster_len; cluster_idx++){

        int page_no= (clusters[cluster_idx].end - clusters[cluster_idx].start) / 0x1000;
        printf("%x ~ %x, %s, %d\n",  clusters[cluster_idx].start, clusters[cluster_idx].end, clusters[cluster_idx].name, page_no);

        range range_item = gen_range(clusters[cluster_idx]);

        unsigned codePageNo = 0;
        unsigned vAddr;
        for (vAddr = clusters[cluster_idx].start;
             vAddr < clusters[cluster_idx].end; vAddr += 0x1000) {
            unsigned pAddr = vtop(mem->mem, mem->mem_size, mem->pgd, vAddr);
#if 0
            if( pAddr != -1)
                printf("vaddr: %x, paddr: %x\n", vAddr, pAddr);
#endif

            if (vAddr == out_pc)
                code_init(mem, vAddr, pageSize, dsmPages, virtualAddrs, 1,
                          calledPages, &codePageNo);
            else
                code_init(mem, vAddr, pageSize, dsmPages, virtualAddrs, 0,
                          calledPages, &codePageNo);
        }

        //print md5 of pages that can be disassembled
        for (startVirtualAddr = range_item.start; startVirtualAddr <= range_item.end;
             startVirtualAddr += 0x1000) {
            unsigned pAddr =
                vtop(mem->mem, mem->mem_size, mem->pgd, startVirtualAddr);
            //      printf("paddr %x\n", pAddr);
            if (pAddr == -1 || pAddr > mem->mem_size)
                continue;
      
            int pageIndex = pAddr / pageSize;
            //printf("page index: %d, dsmPages[pageIndex]: %d, vaddr: %x\n", pageIndex, dsmPages[pageIndex], startVirtualAddr);
            if (dsmPages[pageIndex] == 1) { 

                unsigned offset = startVirtualAddr - range_item.start;
                void *startAdress =
                    (void *) ((unsigned) mem->mem + pageIndex * pageSize);
                genMd5WithOffset(startAdress, pageSize, startVirtualAddr,
                                 offset);
            }
        }


//    float byerate = (float) range_item.disasBytes / (4096 * disasPageNo);
/*
  printf
  ("Success pages: %u/%u disassembled bytes rate: %f, page rate: %f\n",
  disasPageNo, totalPageNo,
  (float) range_item.disasBytes / (4096 * disasPageNo),
  (float) disasPageNo / totalPageNo);
*/
    }
}
