/*
 *  Software MMU support
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu-timer.h"

#define DATA_SIZE (1 << SHIFT)

#if DATA_SIZE == 8
#define SUFFIX q
#define USUFFIX q
#define DATA_TYPE uint64_t
#elif DATA_SIZE == 4
#define SUFFIX l
#define USUFFIX l
#define DATA_TYPE uint32_t
#elif DATA_SIZE == 2
#define SUFFIX w
#define USUFFIX uw
#define DATA_TYPE uint16_t
#elif DATA_SIZE == 1
#define SUFFIX b
#define USUFFIX ub
#define DATA_TYPE uint8_t
#else
#error unsupported data size
#endif

#ifdef SOFTMMU_CODE_ACCESS
#define READ_ACCESS_TYPE 2
#define ADDR_READ addr_code
#else
#define READ_ACCESS_TYPE 0
#define ADDR_READ addr_read
#endif

//#define DEBUG_VMMI

extern target_ulong module_revise(target_ulong snapshot_addr);//yufei

//zlin.begin

static inline uint32_t glue(glue(is_io_read,SUFFIX), MMUSUFFIX)(target_ulong addr, int mmu_idx)
{
    int index;
    target_ulong tlb_addr;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    void *retaddr;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);

	//yang
 redo:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
			if(is_ins_log())
				qemu_log(" addr is io");
            return 0;
        }
        else
        {
			return 0;
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
        vmmi_tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo;
    }
}
static inline uint32_t glue(glue(is_io_write,SUFFIX), MMUSUFFIX)(target_ulong addr, int mmu_idx)
{
    int index;
    target_ulong tlb_addr;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    void *retaddr;
//yang
    
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
			if(is_ins_log())
				qemu_log(" addr is io");
			return 0;
        }
        else
        {
			return 0;
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
        vmmi_tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo;
    }
}
//zlin.end

static DATA_TYPE glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                        int mmu_idx,
                                                        void *retaddr);
#ifndef MMUSUFFIX_kmmu 
static inline DATA_TYPE glue(io_read, SUFFIX)(target_phys_addr_t physaddr,
                                              target_ulong addr,
                                              void *retaddr)
{

			if(is_ins_log())
				qemu_log(" addr is io 2");
    DATA_TYPE res;
    int index;
    index = (physaddr >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;
    env->mem_io_pc = (unsigned long)retaddr;
    if (index > (IO_MEM_NOTDIRTY >> IO_MEM_SHIFT)
            && !can_do_io(env)) {
        cpu_io_recompile(env, retaddr);
    }

    env->mem_io_vaddr = addr;
#if SHIFT <= 2
    res = io_mem_read[index][SHIFT](io_mem_opaque[index], physaddr);
#else
#ifdef TARGET_WORDS_BIGENDIAN
    res = (uint64_t)io_mem_read[index][2](io_mem_opaque[index], physaddr) << 32;
    res |= io_mem_read[index][2](io_mem_opaque[index], physaddr + 4);
#else
    res = io_mem_read[index][2](io_mem_opaque[index], physaddr);
    res |= (uint64_t)io_mem_read[index][2](io_mem_opaque[index], physaddr + 4) << 32;
#endif
#endif /* SHIFT > 2 */
    return res;
}
#endif


/* handle all cases except unaligned access which span two pages */
DATA_TYPE REGPARM glue(glue(__ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                      int mmu_idx)
{
    DATA_TYPE res;
    int index;
    target_ulong tlb_addr;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    void *retaddr;
 

//////////////////////////////////////////////////////////////////////////////////////
	//zlin.begin
//	vmmi_test(addr);
	
#ifdef MMUSUFFIX_mmu 
    if(is_monitored_vmmi_kernel_data_read(addr) ){

    /* test if there is match for unaligned or IO access */
    /* XXX: could done more in memory macro in a non portable way */
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
       if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access1;
            retaddr = GETPC();
            ioaddr = env->vmmi_iotlb[mmu_idx][index];
            set_io_need_red(); //yufei

            res = glue(io_read, SUFFIX)(ioaddr, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            /* slow unaligned access (it spans two pages or IO) */
 do_unaligned_access1:
         retaddr = GETPC();
				res = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr,
                                                         mmu_idx, retaddr);
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in LD vmmi paddr %x, old paddr %x, esp %x\n",(uint32_t)(addr+addend-(uint64_t)vmmi_mem_shadow), vmmi_vtop(addr), env->regs[4]);
			#endif
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
            res = module_revise(res);//yufei
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();

        vmmi_tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo1;
    }
    return res;

	}
#endif 

	//zlin.end
//////////////////////////////////////////////////////////////////////////////////////

    /* test if there is match for unaligned or IO access */
    /* XXX: could done more in memory macro in a non portable way */
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            retaddr = GETPC();
            ioaddr = env->iotlb[mmu_idx][index];
            res = glue(io_read, SUFFIX)(ioaddr, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            /* slow unaligned access (it spans two pages or IO) */
        do_unaligned_access:
            retaddr = GETPC();
#ifdef ALIGNED_ONLY
            do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
#endif
            res = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr,
                                                         mmu_idx, retaddr);
        } else {
            /* unaligned/aligned access in the same page */
#ifdef ALIGNED_ONLY
            if ((addr & (DATA_SIZE - 1)) != 0) {
                retaddr = GETPC();
                do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
            }
#endif
            addend = env->tlb_table[mmu_idx][index].addend;
		if(0){
//		if(is_ins_log()){
			uint32_t phyaddr= vmmi_vtop(addr);
			if(phyaddr !=0xffffffff){
			uint64_t newphyaddr=(uint64_t)vmmi_mem_shadow + (uint64_t)phyaddr;
			qemu_log("old:%x\nnew:%x\n", *(uint8_t*)((uint64_t)addr+addend), *(uint8_t *)newphyaddr);
			}else
				qemu_log("not exit");
		}
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
            
            //yufei.begin
            extern uint32_t sys_need_red;
            if(sys_need_red)
                 res = module_revise(res);
            //yufei.end
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0)
            do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
#endif
        tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo;
    }
    return res;
}

/* handle all unaligned cases */
static DATA_TYPE glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                        int mmu_idx,
                                                        void *retaddr)
{
    DATA_TYPE res, res1, res2;
    int index, shift;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr, addr1, addr2;



//////////////////////////////////////////////////////////////////
//zlin.begin

	#ifdef MMUSUFFIX_mmu
	if(is_monitored_vmmi_kernel_data_read(addr) )
	{


    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
         if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access1;
            ioaddr = env->vmmi_iotlb[mmu_idx][index];
            set_io_need_red(); //yufei
            res = glue(io_read, SUFFIX)(ioaddr, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access1:
            /* slow unaligned access (it spans two pages) */
            addr1 = addr & ~(DATA_SIZE - 1);
            addr2 = addr1 + DATA_SIZE;
            res1 = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr1,
                                                          mmu_idx, retaddr);
            res2 = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr2,
                                                          mmu_idx, retaddr);
            shift = (addr & (DATA_SIZE - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
            res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
#else
            res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
#endif
            res = (DATA_TYPE)res;
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in SLOW LD vmmi paddr %x, old paddr %x esp %x\n",(uint32_t)(addr+addend-(uint64_t)vmmi_mem_shadow),vmmi_vtop(addr), env->regs[4]);
			#endif
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));

            res = module_revise(res);//yufei
        }
    } else {
        /* the page is not in the TLB : fill it */
        vmmi_tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo1;
    }


    return res;
    }
#endif
//zlin.end
//////////////////////////////////////////////////////////////////

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            ioaddr = env->iotlb[mmu_idx][index];
            res = glue(io_read, SUFFIX)(ioaddr, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            /* slow unaligned access (it spans two pages) */
            addr1 = addr & ~(DATA_SIZE - 1);
            addr2 = addr1 + DATA_SIZE;
            res1 = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr1,
                                                          mmu_idx, retaddr);
            res2 = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr2,
                                                          mmu_idx, retaddr);
            shift = (addr & (DATA_SIZE - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
            res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
#else
            res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
#endif
            res = (DATA_TYPE)res;
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->tlb_table[mmu_idx][index].addend;
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
            //yufei.begin
            extern uint32_t sys_need_red;
            if(sys_need_red)
                 res = module_revise(res);
            //yufei.end
        }
    } else {
        /* the page is not in the TLB : fill it */
        tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo;
    }
    return res;
}

#ifndef SOFTMMU_CODE_ACCESS

static void glue(glue(slow_st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                   DATA_TYPE val,
                                                   int mmu_idx,
                                                   void *retaddr);

#ifndef MMUSUFFIX_kmmu
static inline void glue(io_write, SUFFIX)(target_phys_addr_t physaddr,
                                          DATA_TYPE val,
                                          target_ulong addr,
                                          void *retaddr)
{
	
    int index;
    index = (physaddr >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);
    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;

    if(is_ins_log())
        qemu_log(" addr is io 2, index %d, phy %x \n", index, physaddr);

    if (index > (IO_MEM_NOTDIRTY >> IO_MEM_SHIFT)
            && !can_do_io(env)) {
        cpu_io_recompile(env, retaddr);
    }

    env->mem_io_vaddr = addr;
    env->mem_io_pc = (unsigned long)retaddr;
//    qemu_log(" fun: %x\n", io_mem_write[index][SHIFT]); //yufei
#if SHIFT <= 2
    
    io_mem_write[index][SHIFT](io_mem_opaque[index], physaddr, val);
#else
#ifdef TARGET_WORDS_BIGENDIAN
    io_mem_write[index][2](io_mem_opaque[index], physaddr, val >> 32);
    io_mem_write[index][2](io_mem_opaque[index], physaddr + 4, val);
#else
    io_mem_write[index][2](io_mem_opaque[index], physaddr, val);
    io_mem_write[index][2](io_mem_opaque[index], physaddr + 4, val >> 32);
#endif
#endif /* SHIFT > 2 */
}
#endif

void REGPARM glue(glue(__st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                 DATA_TYPE val,
                                                 int mmu_idx)
{
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr;
    void *retaddr;
    int index;


    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
//////////////////////////////////////////////////////////////////////////////////
//zlin.begin
//if(is_ins_log)
//		qemu_log(" MMUST:0x%08x", addr);
#ifdef MMUSUFFIX_mmu

	if(is_monitored_vmmi_kernel_data_write(addr))
	{

		//yang.begin

#ifdef VMMI_COW
        if (do_copy_page_if_necessary(addr)){
			void * retaddr;

			retaddr = GETPC();
			vmmi_tlb_fill(addr, 1, mmu_idx, retaddr);
        	if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE){
				do_copy_page_if_necessary(addr+DATA_SIZE-1);
				vmmi_tlb_fill((addr+DATA_SIZE -1)&TARGET_PAGE_MASK, 1, mmu_idx, retaddr);
			}
		}
#endif
		//yang.end
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
         if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access1;
            retaddr = GETPC();
            ioaddr = env->vmmi_iotlb[mmu_idx][index];
            set_io_need_red();//yufei
            glue(io_write, SUFFIX)(ioaddr, val, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
         do_unaligned_access1:
            retaddr = GETPC();
            glue(glue(slow_st, SUFFIX), MMUSUFFIX)(addr, val,
                                                   mmu_idx, retaddr);
        } else {

            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in ST vmmi paddr %lx, old paddr %x value %x\n",addr+addend, vmmi_vtop(addr), val);
			#endif
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"after %x %x\n", *(uint32_t *)(addend+addr), vmmi_vtop2(addr,4));
			#endif
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
        vmmi_tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo1;
    }

	return;
    }
#endif 
//zlin.end
//////////////////////////////////////////////////////////////////////////////////

 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            retaddr = GETPC();
            ioaddr = env->iotlb[mmu_idx][index];
            glue(io_write, SUFFIX)(ioaddr, val, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            retaddr = GETPC();
#ifdef ALIGNED_ONLY
            do_unaligned_access(addr, 1, mmu_idx, retaddr);
#endif
            glue(glue(slow_st, SUFFIX), MMUSUFFIX)(addr, val,
                                                   mmu_idx, retaddr);
        } else {
            /* aligned/unaligned access in the same page */
#ifdef ALIGNED_ONLY
            if ((addr & (DATA_SIZE - 1)) != 0) {
                retaddr = GETPC();
                do_unaligned_access(addr, 1, mmu_idx, retaddr);
            }
#endif
            addend = env->tlb_table[mmu_idx][index].addend;
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0)
            do_unaligned_access(addr, 1, mmu_idx, retaddr);
#endif
        tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo;
    }


}

/* handles all unaligned cases */
static void glue(glue(slow_st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                   DATA_TYPE val,
                                                   int mmu_idx,
                                                   void *retaddr)
{
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr;
    int index, i;


    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);

//////////////////////////////////////////////////////////////////////////////////
//zlin.begin
   #ifdef MMUSUFFIX_mmu
    if(is_monitored_vmmi_kernel_data_write(addr)) 
	{
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
         if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access1;
            ioaddr = env->vmmi_iotlb[mmu_idx][index];
            set_io_need_red();//yufei
            glue(io_write, SUFFIX)(ioaddr, val, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
 do_unaligned_access1:
            /* XXX: not efficient, but simple */
            /* Note: relies on the fact that tlb_fill() does not remove the
             * previous page from the TLB cache.  */
            for(i = DATA_SIZE - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
                glue(slow_stb, MMUSUFFIX)(addr + i, val >> (((DATA_SIZE - 1) * 8) - (i * 8)),
                                          mmu_idx, retaddr);
#else
                glue(slow_stb, MMUSUFFIX)(addr + i, val >> (i * 8),
                                          mmu_idx, retaddr);
#endif
            }
        } else {
            /* aligned/unaligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in STraw vmmi paddr %x, old paddr %x, esp %x\n",addr+addend-(uint64_t)vmmi_mem_shadow,vmmi_vtop(addr), env->regs[4]);
			#endif
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        vmmi_tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo1;
    }
	return;
    }
#endif
//zlin.end
//////////////////////////////////////////////////////////////////////////////////

 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            ioaddr = env->iotlb[mmu_idx][index];
            glue(io_write, SUFFIX)(ioaddr, val, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            /* XXX: not efficient, but simple */
            /* Note: relies on the fact that tlb_fill() does not remove the
             * previous page from the TLB cache.  */
            for(i = DATA_SIZE - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
                glue(slow_stb, MMUSUFFIX)(addr + i, val >> (((DATA_SIZE - 1) * 8) - (i * 8)),
                                          mmu_idx, retaddr);
#else
                glue(slow_stb, MMUSUFFIX)(addr + i, val >> (i * 8),
                                          mmu_idx, retaddr);
#endif
            }
        } else {
            /* aligned/unaligned access in the same page */
            addend = env->tlb_table[mmu_idx][index].addend;
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo;
    }
}

#endif /* !defined(SOFTMMU_CODE_ACCESS) */

#if 0
static DATA_TYPE glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                        int mmu_idx,
                                                        void *retaddr);

/* handle all cases except unaligned access which span two pages */
DATA_TYPE REGPARM glue(glue(vmmi__ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                      int mmu_idx)
{
    DATA_TYPE res;
    int index;
    target_ulong tlb_addr;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    void *retaddr;

//////////////////////////////////////////////////////////////////////////////////////
	//zlin.begin
//	vmmi_test(addr);
	
	#ifndef MMUSUFFIX_cmmu
	if(is_monitored_vmmi_kernel_data_read() && (!(glue(glue(is_io_read, SUFFIX), MMUSUFFIX))(addr, mmu_idx)))
	{
    /* test if there is match for unaligned or IO access */
    /* XXX: could done more in memory macro in a non portable way */
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            /* slow unaligned access (it spans two pages or IO) */
		        retaddr = GETPC();
				res = glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(addr,
                                                         mmu_idx, retaddr);
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in LD vmmi paddr %x, old paddr %x, esp %x\n",(uint32_t)(addr+addend-(uint64_t)vmmi_mem), vmmi_vtop(addr), env->regs[4]);
			#endif
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();

        vmmi_tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo1;
    }
    return res;

	}else
		return glue(glue(__ld, SUFFIX), MMUSUFFIX)(addr, mmu_idx);

#endif 

	//zlin.end
//////////////////////////////////////////////////////////////////////////////////////

}

/* handle all unaligned cases */
static DATA_TYPE glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                        int mmu_idx,
                                                        void *retaddr)
{
    DATA_TYPE res, res1, res2;
    int index, shift;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr, addr1, addr2;

//////////////////////////////////////////////////////////////////
//zlin.begin

	#ifndef MMUSUFFIX_cmmu
	if(is_monitored_vmmi_kernel_data_read() && (!(glue(glue(is_io_read, SUFFIX), MMUSUFFIX))(addr, mmu_idx)))
	{

	vmmi_vtop(addr);

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access1:
            /* slow unaligned access (it spans two pages) */
            addr1 = addr & ~(DATA_SIZE - 1);
            addr2 = addr1 + DATA_SIZE;
            res1 = glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(addr1,
                                                          mmu_idx, retaddr);
            res2 = glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(addr2,
                                                          mmu_idx, retaddr);
            shift = (addr & (DATA_SIZE - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
            res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
#else
            res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
#endif
            res = (DATA_TYPE)res;
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in SLOW LD vmmi paddr %x, old paddr %x esp %x\n",(uint32_t)(addr+addend-(uint64_t)vmmi_mem),vmmi_vtop(addr), env->regs[4]);
			#endif
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
        }
    } else {
        /* the page is not in the TLB : fill it */
        vmmi_tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo1;
    }


    return res;
    }else
		return glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr,mmu_idx,retaddr);

#endif
//zlin.end
//////////////////////////////////////////////////////////////////
}

#ifndef SOFTMMU_CODE_ACCESS

static void glue(glue(vmmi_slow_st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                   DATA_TYPE val,
                                                   int mmu_idx,
                                                   void *retaddr);


void REGPARM glue(glue(vmmi__st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                 DATA_TYPE val,
                                                 int mmu_idx)
{
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr;
    void *retaddr;
    int index;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
//////////////////////////////////////////////////////////////////////////////////
//zlin.begin
//if(is_ins_log)
//		qemu_log(" MMUST:0x%08x", addr);
	if(is_monitored_vmmi_kernel_data_write() && (!(glue(glue(is_io_write, SUFFIX), MMUSUFFIX))(addr, mmu_idx)))
	{
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            retaddr = GETPC();
            glue(glue(vmmi_slow_st, SUFFIX), MMUSUFFIX)(addr, val,
                                                   mmu_idx, retaddr);
        } else {

            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in ST vmmi paddr %x, old paddr %x esp %x\n",addr+addend-(uint64_t)vmmi_mem,vmmi_vtop(addr), env->regs[4]);
			#endif
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
        vmmi_tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo1;
    }

    }else
		glue(glue(__st, SUFFIX), MMUSUFFIX)(addr,val,mmu_idx);

//zlin.end
//////////////////////////////////////////////////////////////////////////////////

}

/* handles all unaligned cases */
static void glue(glue(vmmi_slow_st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                   DATA_TYPE val,
                                                   int mmu_idx,
                                                   void *retaddr)
{
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr;
    int index, i;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);

//////////////////////////////////////////////////////////////////////////////////
//zlin.beging
	if(is_monitored_vmmi_kernel_data_write() && (!(glue(glue(is_io_write, SUFFIX), MMUSUFFIX))(addr, mmu_idx)))
	{
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            /* XXX: not efficient, but simple */
            /* Note: relies on the fact that tlb_fill() does not remove the
             * previous page from the TLB cache.  */
            for(i = DATA_SIZE - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
                glue(vmmi_slow_stb, MMUSUFFIX)(addr + i, val >> (((DATA_SIZE - 1) * 8) - (i * 8)),
                                          mmu_idx, retaddr);
#else
                glue(vmmi_slow_stb, MMUSUFFIX)(addr + i, val >> (i * 8),
                                          mmu_idx, retaddr);
#endif
            }
        } else {
            /* aligned/unaligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in STraw vmmi paddr %x, old paddr %x, esp %x\n",addr+addend-(uint64_t)vmmi_mem,vmmi_vtop(addr), env->regs[4]);
			#endif
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        vmmi_tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo1;
    }
    }
	else
         glue(glue(slow_st, SUFFIX), MMUSUFFIX)(addr,val, mmu_idx,retaddr);


//zlin.end
//////////////////////////////////////////////////////////////////////////////////
}
#endif /* !defined(SOFTMMU_CODE_ACCESS) */
static DATA_TYPE glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                        int mmu_idx,
                                                        void *retaddr);

/* handle all cases except unaligned access which span two pages */
DATA_TYPE REGPARM glue(glue(vmmi__ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                      int mmu_idx)
{
    DATA_TYPE res;
    int index;
    target_ulong tlb_addr;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    void *retaddr;

//////////////////////////////////////////////////////////////////////////////////////
	//zlin.begin
//	vmmi_test(addr);
	
	#ifndef MMUSUFFIX_cmmu
	if(is_monitored_vmmi_kernel_data_read() && (!(glue(glue(is_io_read, SUFFIX), MMUSUFFIX))(addr, mmu_idx)))
	{
    /* test if there is match for unaligned or IO access */
    /* XXX: could done more in memory macro in a non portable way */
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            /* slow unaligned access (it spans two pages or IO) */
		        retaddr = GETPC();
				res = glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(addr,
                                                         mmu_idx, retaddr);
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in LD vmmi paddr %x, old paddr %x, esp %x\n",(uint32_t)(addr+addend-(uint64_t)vmmi_mem), vmmi_vtop(addr), env->regs[4]);
			#endif
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();

        vmmi_tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo1;
    }
    return res;

	}
#endif 

	//zlin.end
//////////////////////////////////////////////////////////////////////////////////////

    /* test if there is match for unaligned or IO access */
    /* XXX: could done more in memory macro in a non portable way */
    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            retaddr = GETPC();
            ioaddr = env->iotlb[mmu_idx][index];
            res = glue(io_read, SUFFIX)(ioaddr, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            /* slow unaligned access (it spans two pages or IO) */
        do_unaligned_access:
            retaddr = GETPC();
#ifdef ALIGNED_ONLY
            do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
#endif
            res = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr,
                                                         mmu_idx, retaddr);
        } else {
            /* unaligned/aligned access in the same page */
#ifdef ALIGNED_ONLY
            if ((addr & (DATA_SIZE - 1)) != 0) {
                retaddr = GETPC();
                do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
            }
#endif
            addend = env->tlb_table[mmu_idx][index].addend;
		if(is_ins_log()){
			uint32_t phyaddr= vmmi_vtop(addr);
			if(phyaddr !=0xffffffff){
			uint64_t newphyaddr=(uint64_t)vmmi_mem + (uint64_t)phyaddr;
			qemu_log("old:%x\nnew:%x\n", *(uint8_t*)((uint64_t)addr+addend), *(uint8_t *)newphyaddr);
			}else
				qemu_log("not exit");
		}
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0)
            do_unaligned_access(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
#endif
        tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo;
    }
    return res;
}

/* handle all unaligned cases */
static DATA_TYPE glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                        int mmu_idx,
                                                        void *retaddr)
{
    DATA_TYPE res, res1, res2;
    int index, shift;
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr, addr1, addr2;

//////////////////////////////////////////////////////////////////
//zlin.begin

	#ifndef MMUSUFFIX_cmmu
	if(is_monitored_vmmi_kernel_data_read() && (!(glue(glue(is_io_read, SUFFIX), MMUSUFFIX))(addr, mmu_idx)))
	{

	vmmi_vtop(addr);

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access1:
            /* slow unaligned access (it spans two pages) */
            addr1 = addr & ~(DATA_SIZE - 1);
            addr2 = addr1 + DATA_SIZE;
            res1 = glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(addr1,
                                                          mmu_idx, retaddr);
            res2 = glue(glue(vmmi_slow_ld, SUFFIX), MMUSUFFIX)(addr2,
                                                          mmu_idx, retaddr);
            shift = (addr & (DATA_SIZE - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
            res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
#else
            res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
#endif
            res = (DATA_TYPE)res;
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in SLOW LD vmmi paddr %x, old paddr %x esp %x\n",(uint32_t)(addr+addend-(uint64_t)vmmi_mem),vmmi_vtop(addr), env->regs[4]);
			#endif
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
        }
    } else {
        /* the page is not in the TLB : fill it */
        vmmi_tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo1;
    }


    return res;
    }
#endif
//zlin.end
//////////////////////////////////////////////////////////////////

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            ioaddr = env->iotlb[mmu_idx][index];
            res = glue(io_read, SUFFIX)(ioaddr, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            /* slow unaligned access (it spans two pages) */
            addr1 = addr & ~(DATA_SIZE - 1);
            addr2 = addr1 + DATA_SIZE;
            res1 = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr1,
                                                          mmu_idx, retaddr);
            res2 = glue(glue(slow_ld, SUFFIX), MMUSUFFIX)(addr2,
                                                          mmu_idx, retaddr);
            shift = (addr & (DATA_SIZE - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
            res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
#else
            res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
#endif
            res = (DATA_TYPE)res;
        } else {
            /* unaligned/aligned access in the same page */
            addend = env->tlb_table[mmu_idx][index].addend;
            res = glue(glue(ld, USUFFIX), _raw)((uint8_t *)(long)(addr+addend));
        }
    } else {
        /* the page is not in the TLB : fill it */
        tlb_fill(addr, READ_ACCESS_TYPE, mmu_idx, retaddr);
        goto redo;
    }
    return res;
}

#ifndef SOFTMMU_CODE_ACCESS

static void glue(glue(vmmi_slow_st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                   DATA_TYPE val,
                                                   int mmu_idx,
                                                   void *retaddr);



void REGPARM glue(glue(vmmi__st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                 DATA_TYPE val,
                                                 int mmu_idx)
{
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr;
    void *retaddr;
    int index;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
//////////////////////////////////////////////////////////////////////////////////
//zlin.begin
//if(is_ins_log)
//		qemu_log(" MMUST:0x%08x", addr);
	if(is_monitored_vmmi_kernel_data_write() && (!(glue(glue(is_io_write, SUFFIX), MMUSUFFIX))(addr, mmu_idx)))
	{
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            retaddr = GETPC();
            glue(glue(vmmi_slow_st, SUFFIX), MMUSUFFIX)(addr, val,
                                                   mmu_idx, retaddr);
        } else {

            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in ST vmmi paddr %x, old paddr %x esp %x\n",addr+addend-(uint64_t)vmmi_mem,vmmi_vtop(addr), env->regs[4]);
			#endif
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
        vmmi_tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo1;
    }

    }
//zlin.end
//////////////////////////////////////////////////////////////////////////////////

 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            retaddr = GETPC();
            ioaddr = env->iotlb[mmu_idx][index];
            glue(io_write, SUFFIX)(ioaddr, val, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            retaddr = GETPC();
#ifdef ALIGNED_ONLY
            do_unaligned_access(addr, 1, mmu_idx, retaddr);
#endif
            glue(glue(slow_st, SUFFIX), MMUSUFFIX)(addr, val,
                                                   mmu_idx, retaddr);
        } else {
            /* aligned/unaligned access in the same page */
#ifdef ALIGNED_ONLY
            if ((addr & (DATA_SIZE - 1)) != 0) {
                retaddr = GETPC();
                do_unaligned_access(addr, 1, mmu_idx, retaddr);
            }
#endif
            addend = env->tlb_table[mmu_idx][index].addend;
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        retaddr = GETPC();
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0)
            do_unaligned_access(addr, 1, mmu_idx, retaddr);
#endif
        tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo;
    }


}

/* handles all unaligned cases */
static void glue(glue(vmmi_slow_st, SUFFIX), MMUSUFFIX)(target_ulong addr,
                                                   DATA_TYPE val,
                                                   int mmu_idx,
                                                   void *retaddr)
{
    target_phys_addr_t ioaddr;
    unsigned long addend;
    target_ulong tlb_addr;
    int index, i;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);

//////////////////////////////////////////////////////////////////////////////////
//zlin.begin
	if(is_monitored_vmmi_kernel_data_write() && (!(glue(glue(is_io_write, SUFFIX), MMUSUFFIX))(addr, mmu_idx)))
	{
 redo1:
    tlb_addr = env->vmmi_tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
            /* XXX: not efficient, but simple */
            /* Note: relies on the fact that tlb_fill() does not remove the
             * previous page from the TLB cache.  */
            for(i = DATA_SIZE - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
                glue(vmmi_slow_stb, MMUSUFFIX)(addr + i, val >> (((DATA_SIZE - 1) * 8) - (i * 8)),
                                          mmu_idx, retaddr);
#else
                glue(vmmi_slow_stb, MMUSUFFIX)(addr + i, val >> (i * 8),
                                          mmu_idx, retaddr);
#endif
            }
        } else {
            /* aligned/unaligned access in the same page */
            addend = env->vmmi_tlb_table[mmu_idx][index].addend;
			#ifdef DEBUG_VMMI
			fprintf(vmmi_log,"in STraw vmmi paddr %x, old paddr %x, esp %x\n",addr+addend-(uint64_t)vmmi_mem,vmmi_vtop(addr), env->regs[4]);
			#endif
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        vmmi_tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo1;
    }
    }

//zlin.end
//////////////////////////////////////////////////////////////////////////////////

 redo:
    tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
        if (tlb_addr & ~TARGET_PAGE_MASK) {
            /* IO access */
            if ((addr & (DATA_SIZE - 1)) != 0)
                goto do_unaligned_access;
            ioaddr = env->iotlb[mmu_idx][index];
            glue(io_write, SUFFIX)(ioaddr, val, addr, retaddr);
        } else if (((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1) >= TARGET_PAGE_SIZE) {
        do_unaligned_access:
            /* XXX: not efficient, but simple */
            /* Note: relies on the fact that tlb_fill() does not remove the
             * previous page from the TLB cache.  */
            for(i = DATA_SIZE - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
                glue(slow_stb, MMUSUFFIX)(addr + i, val >> (((DATA_SIZE - 1) * 8) - (i * 8)),
                                          mmu_idx, retaddr);
#else
                glue(slow_stb, MMUSUFFIX)(addr + i, val >> (i * 8),
                                          mmu_idx, retaddr);
#endif
            }
        } else {
            /* aligned/unaligned access in the same page */
            addend = env->tlb_table[mmu_idx][index].addend;
            glue(glue(st, SUFFIX), _raw)((uint8_t *)(long)(addr+addend), val);
        }
    } else {
        /* the page is not in the TLB : fill it */
        tlb_fill(addr, 1, mmu_idx, retaddr);
        goto redo;
    }
}
#endif
#endif

#undef READ_ACCESS_TYPE
#undef SHIFT
#undef DATA_TYPE
#undef SUFFIX
#undef USUFFIX
#undef DATA_SIZE
#undef ADDR_READ
