/**********************************************************************************************
*      This file is part of X-Force, A Brute Force Execution Approach for Malware Analysis    *
*                                                                                             *
*      X-Force is owned and copyright (C) by Lab FRIENDS at Purdue University, 2009-2011.     *
*      All rights reserved.                                                                   *
*      Do not copy, disclose, or distribute without explicit written                          *
*      permission.                                                                            *
*                                                                                             *
*      Author: Zhiqiang Lin <zlin@cs.purdue.edu>                                              *
**********************************************************************************************/


/* 
*/
#include <stdio.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <assert.h>
//#include <xed-interface.h>
#include "hook_inst.h"
#include "qemu-common.h"
#include "cpu.h"
#include "taint.h"
#include "sys_hook.h"
#include "qemu-log.h"

/* Map from XED register numbers to
    0) Base register
    1) Offset
    2) Size
*/
int xed_regmapping[][3] = {
/* XED_REG_INVALID */ {-1, -1, -1},
/* XED_REG_ERROR */ {-1, -1, -1},
/* XED_REG_RAX */ {-1, -1, -1},
/* XED_REG_EAX */ {R_EAX, 0, 4},
/* XED_REG_AX */ {R_EAX, 0, 2},
/* XED_REG_AH */ {R_EAX, 1, 1},
/* XED_REG_AL */ {R_EAX, 0, 1},
/* XED_REG_RCX */ {-1, -1, -1},
/* XED_REG_ECX */ {R_ECX, 0, 4},
/* XED_REG_CX */ {R_ECX, 0, 2},
/* XED_REG_CH */ {R_ECX, 1, 1},
/* XED_REG_CL */ {R_ECX, 0, 1},
/* XED_REG_RDX */ {-1, -1, -1},
/* XED_REG_EDX */ {R_EDX, 0, 4},
/* XED_REG_DX */ {R_EDX, 0, 2},
/* XED_REG_DH */ {R_EDX, 1, 1},
/* XED_REG_DL */ {R_EDX, 0, 1},
/* XED_REG_RBX */ {-1, -1, -1},
/* XED_REG_EBX */ {R_EBX, 0, 4},
/* XED_REG_BX */ {R_EBX, 0, 2},
/* XED_REG_BH */ {R_EBX, 1, 1},
/* XED_REG_BL */ {R_EBX, 0, 1},
/* XED_REG_RSP */ {-1, -1, -1},
/* XED_REG_ESP */ {R_ESP, 0, 4},
/* XED_REG_SP */ {R_ESP, 0, 2},
/* XED_REG_SPL */ {-1, -1, -1},
/* XED_REG_RBP */ {-1, -1, -1},
/* XED_REG_EBP */ {R_EBP, 0, 4},
/* XED_REG_BP */ {R_EBP, 0, 2},
/* XED_REG_BPL */ {-1, -1, -1},
/* XED_REG_RSI */ {-1, -1, -1},
/* XED_REG_ESI */ {R_ESI, 0, 4},
/* XED_REG_SI */ {R_ESI, 0, 2},
/* XED_REG_SIL */ {-1, -1, -1},
/* XED_REG_RDI */ {-1, -1, -1},
/* XED_REG_EDI */ {R_EDI, 0, 4},
/* XED_REG_DI */ {R_EDI, 0, 2},
/* XED_REG_DIL */ {-1, -1, -1},
/* XED_REG_R8 */ {-1, -1, -1},
/* XED_REG_R8D */ {-1, -1, -1},
/* XED_REG_R8W */ {-1, -1, -1},
/* XED_REG_R8B */ {-1, -1, -1},
/* XED_REG_R9 */ {-1, -1, -1},
/* XED_REG_R9D */ {-1, -1, -1},
/* XED_REG_R9W */ {-1, -1, -1},
/* XED_REG_R9B */ {-1, -1, -1},
/* XED_REG_R10 */ {-1, -1, -1},
/* XED_REG_R10D */ {-1, -1, -1},
/* XED_REG_R10W */ {-1, -1, -1},
/* XED_REG_R10B */ {-1, -1, -1},
/* XED_REG_R11 */ {-1, -1, -1},
/* XED_REG_R11D */ {-1, -1, -1},
/* XED_REG_R11W */ {-1, -1, -1},
/* XED_REG_R11B */ {-1, -1, -1},
/* XED_REG_R12 */ {-1, -1, -1},
/* XED_REG_R12D */ {-1, -1, -1},
/* XED_REG_R12W */ {-1, -1, -1},
/* XED_REG_R12B */ {-1, -1, -1},
/* XED_REG_R13 */ {-1, -1, -1},
/* XED_REG_R13D */ {-1, -1, -1},
/* XED_REG_R13W */ {-1, -1, -1},
/* XED_REG_R13B */ {-1, -1, -1},
/* XED_REG_R14 */ {-1, -1, -1},
/* XED_REG_R14D */ {-1, -1, -1},
/* XED_REG_R14W */ {-1, -1, -1},
/* XED_REG_R14B */ {-1, -1, -1},
/* XED_REG_R15 */ {-1, -1, -1},
/* XED_REG_R15D */ {-1, -1, -1},
/* XED_REG_R15W */ {-1, -1, -1},
/* XED_REG_R15B */ {-1, -1, -1},
/* XED_REG_RIP */ {-1, -1, -1},
/* XED_REG_EIP */ {-1, -1, -1},
///* XED_REG_EIP */ {-1, -1, -1}
/* XED_REG_IP */ {-1, -1, -1},
/* XED_REG_FLAGS */ {-1, -1, -1},
/* XED_REG_EFLAGS */ {-1, -1, -1},
/* XED_REG_RFLAGS */ {-1, -1, -1},
/* XED_REG_CS */ {R_CS, -1, -1},
/* XED_REG_DS */ {R_DS, -1, -1},
/* XED_REG_ES */ {R_ES, -1, -1},
/* XED_REG_SS */ {R_SS, -1, -1},
/* XED_REG_FS */ {R_FS, -1, -1},
/* XED_REG_GS */ {R_GS, -1, -1},
/* XED_REG_XMM0 */ {-1, -1, -1},
/* XED_REG_XMM1 */ {-1, -1, -1},
/* XED_REG_XMM2 */ {-1, -1, -1},
/* XED_REG_XMM3 */ {-1, -1, -1},
/* XED_REG_XMM4 */ {-1, -1, -1},
/* XED_REG_XMM5 */ {-1, -1, -1},
/* XED_REG_XMM6 */ {-1, -1, -1},
/* XED_REG_XMM7 */ {-1, -1, -1},
/* XED_REG_XMM8 */ {-1, -1, -1},
/* XED_REG_XMM9 */ {-1, -1, -1},
/* XED_REG_XMM10 */ {-1, -1, -1},
/* XED_REG_XMM11 */ {-1, -1, -1},
/* XED_REG_XMM12 */ {-1, -1, -1},
/* XED_REG_XMM13 */ {-1, -1, -1},
/* XED_REG_XMM14 */ {-1, -1, -1},
/* XED_REG_XMM15 */ {-1, -1, -1},
/* XED_REG_MMX0 */ {-1, -1, -1},
/* XED_REG_MMX1 */ {-1, -1, -1},
/* XED_REG_MMX2 */ {-1, -1, -1},
/* XED_REG_MMX3 */ {-1, -1, -1},
/* XED_REG_MMX4 */ {-1, -1, -1},
/* XED_REG_MMX5 */ {-1, -1, -1},
/* XED_REG_MMX6 */ {-1, -1, -1},
/* XED_REG_MMX7 */ {-1, -1, -1},
/* XED_REG_ST0 */ {-1, -1, -1},
/* XED_REG_ST1 */ {-1, -1, -1},
/* XED_REG_ST2 */ {-1, -1, -1},
/* XED_REG_ST3 */ {-1, -1, -1},
/* XED_REG_ST4 */ {-1, -1, -1},
/* XED_REG_ST5 */ {-1, -1, -1},
/* XED_REG_ST6 */ {-1, -1, -1},
/* XED_REG_ST7 */ {-1, -1, -1},
/* XED_REG_CR0 */ {-1, -1, -1},
/* XED_REG_CR1 */ {-1, -1, -1},
/* XED_REG_CR2 */ {-1, -1, -1},
/* XED_REG_CR3 */ {-1, -1, -1},
/* XED_REG_CR4 */ {-1, -1, -1},
/* XED_REG_CR5 */ {-1, -1, -1},
/* XED_REG_CR6 */ {-1, -1, -1},
/* XED_REG_CR7 */ {-1, -1, -1},
/* XED_REG_CR8 */ {-1, -1, -1},
/* XED_REG_CR9 */ {-1, -1, -1},
/* XED_REG_CR10 */ {-1, -1, -1},
/* XED_REG_CR11 */ {-1, -1, -1},
/* XED_REG_CR12 */ {-1, -1, -1},
/* XED_REG_CR13 */ {-1, -1, -1},
/* XED_REG_CR14 */ {-1, -1, -1},
/* XED_REG_CR15 */ {-1, -1, -1},
/* XED_REG_DR0 */ {-1, -1, -1},
/* XED_REG_DR1 */ {-1, -1, -1},
/* XED_REG_DR2 */ {-1, -1, -1},
/* XED_REG_DR3 */ {-1, -1, -1},
/* XED_REG_DR4 */ {-1, -1, -1},
/* XED_REG_DR5 */ {-1, -1, -1},
/* XED_REG_DR6 */ {-1, -1, -1},
/* XED_REG_DR7 */ {-1, -1, -1},
/* XED_REG_DR8 */ {-1, -1, -1},
/* XED_REG_DR9 */ {-1, -1, -1},
/* XED_REG_DR10 */ {-1, -1, -1},
/* XED_REG_DR11 */ {-1, -1, -1},
/* XED_REG_DR12 */ {-1, -1, -1},
/* XED_REG_DR13 */ {-1, -1, -1},
/* XED_REG_DR14 */ {-1, -1, -1},
/* XED_REG_DR15 */ {-1, -1, -1},
/* XED_REG_ONE */ {-1, -1, -1},
/* XED_REG_STACKPUSH */ {-1, -1, -1},
/* XED_REG_STACKPOP */ {-1, -1, -1},
/* XED_REG_GDTR */ {-1, -1, -1},
/* XED_REG_LDTR */ {-1, -1, -1},
/* XED_REG_IDTR */ {-1, -1, -1},
/* XED_REG_TR */ {-1, -1, -1},
/* XED_REG_TSC */ {-1, -1, -1},
/* XED_REG_TSCAUX */ {-1, -1, -1},
/* XED_REG_MSRS */ {-1, -1, -1},
/* XED_REG_X87CONTROL */ {-1, -1, -1},
/* XED_REG_X87STATUS */ {-1, -1, -1},
/* XED_REG_X87TOP */ {-1, -1, -1},
/* XED_REG_X87TAG */ {-1, -1, -1},
/* XED_REG_X87PUSH */ {-1, -1, -1},
/* XED_REG_X87POP */ {-1, -1, -1},
/* XED_REG_X87POP2 */ {-1, -1, -1},
/* XED_REG_MXCSR */ {-1, -1, -1},
/* XED_REG_TMP0 */ {-1, -1, -1},
/* XED_REG_TMP1 */ {-1, -1, -1},
/* XED_REG_TMP2 */ {-1, -1, -1},
/* XED_REG_TMP3 */ {-1, -1, -1},
/* XED_REG_TMP4 */ {-1, -1, -1},
/* XED_REG_TMP5 */ {-1, -1, -1},
/* XED_REG_TMP6 */ {-1, -1, -1},
/* XED_REG_TMP7 */ {-1, -1, -1},
/* XED_REG_TMP8 */ {-1, -1, -1},
/* XED_REG_TMP9 */ {-1, -1, -1},
/* XED_REG_TMP10 */ {-1, -1, -1},
/* XED_REG_TMP11 */ {-1, -1, -1},
/* XED_REG_TMP12 */ {-1, -1, -1},
/* XED_REG_TMP13 */ {-1, -1, -1},
/* XED_REG_TMP14 */ {-1, -1, -1},
/* XED_REG_TMP15 */ {-1, -1, -1},
/* XED_REG_LAST */ {-1, -1, -1},
};

uint32_t global_time_stamp = 0;
extern xed_decoded_inst_t xedd_g;
static uint32_t num_stack_address;
target_ulong stack_address[1024];
uint32_t is_ret, is_call;
uint32_t is_kernel_stack(target_ulong);
void set_kernel_stack_address(target_ulong addr);

typedef void (*fun)();
extern uint32_t is_syscall;
extern uint32_t cond_res;
extern fun iret_handle;
xed_reg_enum_t basereg;
extern uint32_t current_pc;


int operand_is_mem(const xed_operand_enum_t op_name, uint32_t * mem_addr,
		   int operand_i, UChar * taint)
{

    *taint = 0;
    switch (op_name) {
        /* Memory */
    case XED_OPERAND_AGEN:
    case XED_OPERAND_MEM0:
    case XED_OPERAND_MEM1:{
        unsigned long base = 0;
        unsigned long index = 0;
        unsigned long scale = 1;
        unsigned long segbase = 0;
        unsigned short segsel = 0;
        unsigned long displacement = 0;
        unsigned int j;
        size_t remaining = 0;

        /* Set memory index */
        int mem_idx = 0;
        if (op_name == XED_OPERAND_MEM1)
            mem_idx = 1;

        unsigned int memlen =
            xed_decoded_inst_operand_length(&xedd_g, operand_i);

        /* Initialization */
        base = 0;
        index = 0;
        scale = 1;
        segbase = 0;
        segsel = 0;
        displacement = 0;

        // Get Segment register
        xed_reg_enum_t seg_regid =
            xed_decoded_inst_get_seg_reg(&xedd_g, mem_idx);

        if (seg_regid != XED_REG_INVALID) {
            const xed_operand_values_t *xopv =
                xed_decoded_inst_operands_const(&xedd_g);
            xed_bool_t default_segment =
                xed_operand_values_using_default_segment
                (xopv, mem_idx);

            if (!default_segment) {
                int segmentreg =
                    xed_regmapping[seg_regid][0];

                segbase =
                    cpu_single_env->segs[segmentreg].base;
                segsel =
                    cpu_single_env->segs[segmentreg].selector;
            }

        }

        // Get Base register
        xed_reg_enum_t base_regid =
            xed_decoded_inst_get_base_reg(&xedd_g, mem_idx);
			
        basereg = base_regid;
			
			
        if (base_regid != XED_REG_INVALID) {
            int basereg =
                xed_regmapping[base_regid][0];

            base = cpu_single_env->regs[basereg];
				
            *taint =  *taint | get_reg_taint(base_regid);
#ifdef DEBUG_VMMI
            if(is_ins_log())
                qemu_log("(reg %x taint %x)", base_regid, *taint);
#endif
//          fprintf(tracelog,"BASE_REG %d %s, base %x ",base_regid, xed_reg_enum_t2str(base_regid), base);
        }
        // Get Index register and Scale
        xed_reg_enum_t index_regid =
            xed_decoded_inst_get_index_reg(&xedd_g, mem_idx);
        if (mem_idx == 0 && index_regid != XED_REG_INVALID) {
            int indexreg =
                xed_regmapping[index_regid][0];

            index = cpu_single_env->regs[indexreg];

            // Get Scale (AKA width) (only have a scale if the index exists)
            if (xed_decoded_inst_get_scale
                (&xedd_g, operand_i) != 0) {
                scale =
                    (unsigned long)
                    xed_decoded_inst_get_scale(&xedd_g,
                                               mem_idx);
            }
            //	*taint =  *taint | get_reg_taint(index_regid);
        }

        // Get displacement (AKA offset)
        displacement =
            (unsigned long)
            xed_decoded_inst_get_memory_displacement(&xedd_g,
                                                     mem_idx);

        // Calculate memory address accessed
        *mem_addr =
            segbase + base + index * scale + displacement;

        return 1;
    }

    default:
        return 0;
    }

}

int operand_is_relbr(const xed_operand_enum_t op_name, uint32_t * branch) {
	switch (op_name) {
		/* Jumps */
	case XED_OPERAND_PTR:	// pointer (always in conjunction with a IMM0)
	case XED_OPERAND_RELBR:{
				// branch displacements

			xed_uint_t disp =
			    xed_decoded_inst_get_branch_displacement(&xedd_g);
			*branch = disp;
			 return 1;

		} default:return 0;
	}

}

int operand_is_float(const xed_operand_enum_t op_name) {
	switch (op_name) {
		/* Floating point registers */
	case XED_REG_X87CONTROL:
	case XED_REG_X87STATUS:
	case XED_REG_X87TOP:
	case XED_REG_X87TAG:
	case XED_REG_X87PUSH:
	case XED_REG_X87POP:
	case XED_REG_X87POP2:
		return 1;

		default:return 0;
	}
}

int operand_is_reg(const xed_operand_enum_t op_name, xed_reg_enum_t * reg_id) {
	switch (op_name) {
		/* Register */
	case XED_OPERAND_REG0:
	case XED_OPERAND_REG1:
	case XED_OPERAND_REG2:
	case XED_OPERAND_REG3:
	case XED_OPERAND_REG4:
	case XED_OPERAND_REG5:
	case XED_OPERAND_REG6:
	case XED_OPERAND_REG7:
	case XED_OPERAND_REG8:
	case XED_OPERAND_REG9:
	case XED_OPERAND_REG10:
	case XED_OPERAND_REG11:
	case XED_OPERAND_REG12:
	case XED_OPERAND_REG13:
	case XED_OPERAND_REG14:
	case XED_OPERAND_REG15:{
			*reg_id = xed_decoded_inst_get_reg(&xedd_g, op_name);
			return 1;
		} default:return 0;
	}
}

int operand_is_imm(const xed_operand_enum_t op_name, uint32_t * value) {
	switch (op_name) {
		/* Immediate */
	case XED_OPERAND_IMM0:{
			if (xed_decoded_inst_get_immediate_is_signed(&xedd_g)) {
				xed_int32_t signed_imm_val =
				    xed_decoded_inst_get_signed_immediate
				    (&xedd_g);
				*value = (uint32_t) signed_imm_val;
			} else {
				xed_uint64_t unsigned_imm_val =
				    xed_decoded_inst_get_unsigned_immediate
				    (&xedd_g);
				*value = (uint32_t) unsigned_imm_val;
			}
			return 1;
		}
		/* Special immediate only used in ENTER instruction */
	case XED_OPERAND_IMM1:{
			xed_uint8_t unsigned_imm_val =
			    xed_decoded_inst_get_second_immediate(&xedd_g);
			*value = (uint32_t) unsigned_imm_val;
			return 1;
		}

	default:
		return 0;
	}

}

static void Instrument_MOV(INS xi) {
}

static void Instrument_MUL(INS);

static void UnimplementedInstruction(INS ins) {

#ifdef DEBUG_TAINT
	fprintf(tracelog, "unimplemented: eip=0x%08x \n", *TEMU_cpu_eip);
#endif
	return;
}

static void Instrument_AND(INS ins);

static void Instrument_ADC(INS ins) {
	Instrument_AND(ins);
}

// This is a good example of how instructions are modeled and taint is
// propagated.

// To implement one of these functions the first thing to do is decide
// how taint marks should be propagated.

// In this instance, for ADD, the destination operand and the eflags register
// are tainted with the union of the taint marks associated with the
// destination and source operands.

// dest, eflags <- union(dest, src)

// Then the general implementation goes like this
// 1. load the taint marks associated with the operands on the right hand
//    side of the equation (dest, src)
// 2. figure out the union
// 3. assign the union to the operands on the left hand side (dest, eflags)
int replace_reg;
void replace_esp()
{
	cpu_single_env->regs[replace_reg] = vmmi_esp & 0xffffe000;

}

static void Instrument_AND(INS xi) {
}

static void Instrument_ADD(INS xi) {
}

static void Instrument_BSWAP(INS ins) {
}

static void Instrument_CALL_NEAR(INS ins) {
	is_call = 1;
 
/*
	const xed_operand_t *op = xed_inst_operand(ins, 0);
	xed_operand_enum_t op_name  = xed_operand_name(op);
	uint32_t mem_addr;
	UChar taint;
	unsigned int pc;
	xed_reg_enum_t reg_id;

	if (operand_is_mem(op_name, &mem_addr, 0, &taint)) {
		char buf[4];
		cpu_memory_rw_debug(cpu_single_env, mem_addr, buf,4, 0);
		pc = *( uint32_t *)buf;
	}else if (operand_is_reg(op_name, &reg_id)){
		int reg  = xed_regmapping[reg_id][0];
		pc = cpu_single_env->regs[reg];
	}else {
		pc = xed_decoded_inst_get_branch_displacement(&xedd_g)+current_pc+5;
	}
	
#ifdef DEBUG_VMMI	
	find_kernel_call(pc);
#endif
*/
}

static void Instrument_CALL_FAR(INS ins) {
    is_call = 1;
}

static void Instrument_CDQ(INS ins) {
}

static void Instrument_CLD(INS ins) {
}

static void Instrument_CMOVcc(INS ins) {
}

static void Instrument_CMP(INS ins) {
 
}

static void Instrument_CMPSB(INS ins) {
}

static void Instrument_CMPXCHG(INS ins) {
}

static void Instrument_CWDE(INS ins) {
}

static void Instrument_DEC(INS ins) {
}

static void Instrument_DIV(INS ins) {

}

static void Instrument_FLDCW(INS ins) {	//TODO: Floating point instruction
}

static void Instrument_FNSTCW(INS ins) {
}

static void Instrument_HLT(INS ins) {
}

static void Instrument_IDIV(INS ins) {

}

static void Instrument_IMUL(INS ins) {
}

static void Instrument_INC(INS ins) {
}

static void Instrument_INT(INS ins) {
}

uint32_t jmp_target_ins_addr;
uint32_t next_ins_addr;
unsigned char is_cond_jmp_inst;
unsigned char is_jmp_table_inst;
unsigned char is_jmp_inst;

static void Instrument_Jcc(INS ins) {
    is_call =1;	
}

static void Instrument_JMP(INS ins) {
    /*
    const xed_operand_t *op = xed_inst_operand(ins, 0);
    xed_operand_enum_t op_name  = xed_operand_name(op);
    uint32_t mem_addr;
    UChar taint;
    unsigned int pc;
    xed_reg_enum_t reg_id;

    if (operand_is_mem(op_name, &mem_addr, 0, &taint)) {
        char buf[4];
        cpu_memory_rw_debug(cpu_single_env, mem_addr, buf,4, 0);
        pc = *( uint32_t *)buf;

    }else if (operand_is_reg(op_name, &reg_id)){
        int reg  = xed_regmapping[reg_id][0];
        pc = cpu_single_env->regs[reg];
    }else {
        pc = xed_decoded_inst_get_branch_displacement(&xedd_g)+current_pc+5;
    }
    */
}

static void Instrument_LEA(INS xi) {
}

static void Instrument_LEAVE(INS ins) {	
}

static void Instrument_LDMXCSR(INS ins) {
}


static void Instrument_MOVSD(INS ins) {
}

static void Instrument_MOVSW(INS ins) {
}

static void Instrument_MOVSB(INS ins) {
}

static void Instrument_MOVSX(INS ins) {
}

static void Instrument_MOVZX(INS ins) {	// movzx r/m, r
}

static void Instrument_MUL(INS ins) {

}

static void Instrument_NEG(INS ins) {
}

static void Instrument_NOT(INS ins) {
}

static void Instrument_OR(INS ins) {
}

static void Instrument_PAUSE(INS ins) {
}

static void Instrument_POP(INS ins) {
}

static void Instrument_POPFD(INS ins) {
}

static void Instrument_POPAD(INS ins){ 
}

static void Instrument_PUSH(INS ins) {
}

static void Instrument_PUSHFD(INS ins) {
}

static void Instrument_PUSHAD(INS ins) {
}

static void Instrument_RDTSC(INS ins) {
}

static void Instrument_RET(INS ins) {
	is_ret = 1;
}

static void Instrument_SAR(INS ins) {
}

static void Instrument_SBB(INS ins) {
}

static void Instrument_SCASB(INS ins) {
}

static void Instrument_SETcc(INS ins) {
}

static void Instrument_SHL(INS ins) {
}

static void Instrument_SHLD(INS ins) {
}

static void Instrument_SHR(INS ins) {
}

static void Instrument_SHRD(INS ins) {
}

static void Instrument_STD(INS ins) {
}

static void Instrument_STMXCSR(INS ins) {
	
}
static void Instrument_LODSB(INS ins){
}

static void Instrument_LODSD(INS ins){
}

static void Instrument_LODSW(INS ins){
}

static void Instrument_STOSB(INS ins) {
}

static void Instrument_STOSD(INS ins) {
}

static void Instrument_STOSW(INS ins) {
}

static void Instrument_SUB(INS ins) {
}

static void Instrument_TEST(INS ins) {
}

static void Instrument_XADD(INS ins) {
}

static void Instrument_XCHG(INS ins) {
}

static void Instrument_XOR(INS xi) {
}

static void Instrument_DAA(INS ins) {
}

static void Instrument_DAS(INS ins) {
}

static void Instrument_AAA(INS ins) {
}

static void Instrument_AAS(INS ins) {
}

static void Instrument_ROL(INS ins) {
}

static void Instrument_BT(INS ins){
}

void update_esp()
{

#ifdef DEBUG_VMMI
	qemu_log("return old esp");
#endif
    cpu_single_env->regs[R_ESP] =vmmi_save_esp;
}

static void Instrument_IRETD(INS ins)
{
    if(is_interrupt){
        vmmi_interrupt_stack--;
        if(vmmi_interrupt_stack == 0){
            is_interrupt=0;
			
#ifdef DEBUG_VMMI
            if(qemu_log_enabled())
                qemu_log("exit interrupt\n");
#endif
            if(!is_syscall)
                cond_res=0;
        }
    }else{
        if(is_sysenter)
            return;


		
        if(current_syscall == 5 || current_syscall ==102){
#ifdef DEBUG_VMMI
            if(qemu_log_enabled())
                qemu_log("open file (%x %u)\n",cpu_single_env->regs[R_EAX], file_flag);
#endif
            set_file_flag(cpu_single_env->regs[R_EAX], file_flag);
			
            if(file_flag)
                set_reg_taint_fd(XED_REG_EAX, FDTAINTED);
        }

#ifdef DEBUG_VMMI
        if(current_syscall == 3){
            char buf[4192];
            int maxnum;
            if(cpu_single_env->regs[R_EAX]<4192)
                maxnum = cpu_single_env->regs[R_EAX];
            else
                maxnum = 4191;

            cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_ECX] , buf, maxnum, 0);
            buf[maxnum]='\0';
            if(qemu_log_enabled())
                qemu_log("Fd %x: data:%s",cpu_single_env->regs[R_EBX],buf);
			
        }
#endif

        is_syscall=0;
        cond_res=0;
#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("iret\n");
        show_time(0);
#endif
        set_sys_need_red(0);
    }

#ifdef DEBUG_VMMI	
    uint32_t stack= cpu_single_env->regs[R_ESP]&0xffffe000;
    uint32_t task;
    uint32_t pid;
    char comm[128];
    cpu_memory_rw_debug(cpu_single_env, stack, &task, 4,0);
    cpu_memory_rw_debug(cpu_single_env, task+0x224, comm, 128,0);
    cpu_memory_rw_debug(cpu_single_env, task+0x12c, &pid, 4,0);
    comm[127]='\0';
    if(qemu_log_enabled())
        qemu_log("task is  %x  %x %s\n", cpu_single_env->cr[3],pid, comm);
#endif

}

static void Instrument_SYSENTER(INS ins)
{
#ifdef DEBUG_VMMI
	if(qemu_log_enabled())
		qemu_log("SYSenter call");
#endif
	
	is_sysenter=1;
	
	syscall_hook(cpu_single_env->regs[R_EAX]);
}

extern void show_time(int syscall); //yufei

char  inst_buff[16];
static void Instrument_SYSEXIT(INS ins)
{
#ifdef DEBUG_VMMI	
    uint32_t stack= cpu_single_env->regs[R_ESP]&0xffffe000;
    uint32_t task;
    uint32_t pid;
    char comm[128];
    cpu_memory_rw_debug(cpu_single_env, stack, &task, 4,0);
    cpu_memory_rw_debug(cpu_single_env, task+0x224, comm, 128,0);
    cpu_memory_rw_debug(cpu_single_env, task+0x12c, &pid, 4,0);
    comm[127]='\0';
    if(qemu_log_enabled())
        qemu_log("task is  %x  %x %s\n", cpu_single_env->cr[3],pid, comm);
#endif

    is_syscall=0;
    cond_res=0;
    is_sysenter = 0;
    is_pipe =0;


#ifdef DEBUG_VMMI
    if(qemu_log_enabled())
        qemu_log("sys exit\n");
    show_time(0);
#endif
    if(current_syscall == 5 || current_syscall ==102){
        cpu_single_env->regs[R_EAX] |= 1024;//yufei

#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("open file (%u %u)\n",cpu_single_env->regs[R_EAX], file_flag);
#endif
        set_file_flag(cpu_single_env->regs[R_EAX], file_flag);
    }


#ifdef DEBUG_VMMI
    if(current_syscall == 3){
        char buf[4192];
        int maxnum;
        if(cpu_single_env->regs[R_EAX]<4192)
            maxnum = cpu_single_env->regs[R_EAX];
        else
            maxnum = 4191;

        cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_ECX] , buf, maxnum, 0);
        buf[maxnum]='\0';
        if(qemu_log_enabled())
            qemu_log("Fd %x:data:%s",cpu_single_env->regs[R_EBX],buf);
    }
#endif

}

InstrumentFunction instrument_functions[XED_ICLASS_LAST];

void setup_inst_hook() {
    // set a default handling function that aborts.  This makes sure I don't
    // miss instructions in new applications
    int i;
    for (i = 0; i < XED_ICLASS_LAST; i++) {
        instrument_functions[i] = &UnimplementedInstruction;
    }
    instrument_functions[XED_ICLASS_ADD] = &Instrument_ADD;	// 1
    instrument_functions[XED_ICLASS_PUSH] = &Instrument_PUSH;	// 2
    instrument_functions[XED_ICLASS_POP] = &Instrument_POP;	// 3
    instrument_functions[XED_ICLASS_OR] = &Instrument_OR;	// 4

    instrument_functions[XED_ICLASS_ADC] = &Instrument_ADC;	// 6
    instrument_functions[XED_ICLASS_SBB] = &Instrument_SBB;	// 7
    instrument_functions[XED_ICLASS_AND] = &Instrument_AND;	// 8

    //  instrument_functions[XED_ICLASS_DAA] = &Instrument_DAA; // 11
    instrument_functions[XED_ICLASS_SUB] = &Instrument_SUB;	// 12

    //  instrument_functions[XED_ICLASS_DAS] = &Instrument_DAS; // 14
    instrument_functions[XED_ICLASS_XOR] = &Instrument_XOR;	// 15

    //  instrument_functions[XED_ICLASS_AAA] = &Instrument_AAA; // 17
    instrument_functions[XED_ICLASS_CMP] = &Instrument_CMP;	// 18

    //  instrument_functions[XED_ICLASS_AAS] = &Instrument_AAS; // 20
    instrument_functions[XED_ICLASS_INC] = &Instrument_INC;	// 21
    instrument_functions[XED_ICLASS_DEC] = &Instrument_DEC;	// 22

    instrument_functions[XED_ICLASS_PUSHAD] = &Instrument_PUSHAD; // 25
    instrument_functions[XED_ICLASS_POPAD] = &Instrument_POPAD; // 27
    //  instrument_functions[XED_ICLASS_BOUND] = &Instrument_BOUND; // 28
    //  instrument_functions[XED_ICLASS_ARPL] = &Instrument_ARPL; // 29

    instrument_functions[XED_ICLASS_IMUL] = &Instrument_IMUL;	// 35
    //  instrument_functions[XED_ICLASS_INSB] = &Instrument_INSB; // 36

    //  instrument_functions[XED_ICLASS_INSD] = &Instrument_INSD; // 38
    //  instrument_functions[XED_ICLASS_OUTSB] = &Instrument_OUTSB; // 39

    //  instrument_functions[XED_ICLASS_OUTSD] = &Instrument_OUTSD; // 41
    instrument_functions[XED_ICLASS_JO] = &Instrument_Jcc;	//42
    instrument_functions[XED_ICLASS_JNO] = &Instrument_Jcc;	//43
    instrument_functions[XED_ICLASS_JB] = &Instrument_Jcc;	//43
    instrument_functions[XED_ICLASS_JNB] = &Instrument_Jcc;	//45
    instrument_functions[XED_ICLASS_JZ] = &Instrument_Jcc;	//46
    instrument_functions[XED_ICLASS_JNZ] = &Instrument_Jcc;	//47
    instrument_functions[XED_ICLASS_JBE] = &Instrument_Jcc;	//48
    instrument_functions[XED_ICLASS_JNBE] = &Instrument_Jcc;	//49
    instrument_functions[XED_ICLASS_JS] = &Instrument_Jcc;	//50
    instrument_functions[XED_ICLASS_JNS] = &Instrument_Jcc;	//51
    instrument_functions[XED_ICLASS_JP] = &Instrument_Jcc;	//52
    instrument_functions[XED_ICLASS_JNP] = &Instrument_Jcc;	//53
    instrument_functions[XED_ICLASS_JL] = &Instrument_Jcc;	//54
    instrument_functions[XED_ICLASS_JNL] = &Instrument_Jcc;	//55
    instrument_functions[XED_ICLASS_JLE] = &Instrument_Jcc;	//56
    instrument_functions[XED_ICLASS_JNLE] = &Instrument_Jcc;	//57
    instrument_functions[XED_ICLASS_JRCXZ] = &Instrument_Jcc;	//57

    instrument_functions[XED_ICLASS_TEST] = &Instrument_TEST;	//59
    instrument_functions[XED_ICLASS_XCHG] = &Instrument_XCHG;	//60
    instrument_functions[XED_ICLASS_MOV] = &Instrument_MOV;	//61
    instrument_functions[XED_ICLASS_LEA] = &Instrument_LEA;	//62

    instrument_functions[XED_ICLASS_PAUSE] = &Instrument_PAUSE;	//64

    instrument_functions[XED_ICLASS_CWDE] = &Instrument_CWDE;	//67

    instrument_functions[XED_ICLASS_CDQ] = &Instrument_CDQ;	//70
    instrument_functions[XED_ICLASS_CALL_FAR] = &Instrument_CALL_FAR;	//71
    //  instrument_functions[XED_ICLASS_WAIT] = &Instrument_WAIT; //72

    instrument_functions[XED_ICLASS_PUSHFD] = &Instrument_PUSHFD;	//74

    instrument_functions[XED_ICLASS_POPFD] = &Instrument_POPFD;	//77

    //  instrument_functions[XED_ICLASS_POPFD] = &Instrument_SAHF; //79
    //  instrument_functions[XED_ICLASS_POPFD] = &Instrument_LAHF; //80
    instrument_functions[XED_ICLASS_MOVSB] = &Instrument_MOVSB;	//81
    instrument_functions[XED_ICLASS_MOVSW] = &Instrument_MOVSW;	//82
    instrument_functions[XED_ICLASS_MOVSD] = &Instrument_MOVSD;	//83

    instrument_functions[XED_ICLASS_CMPSB] = &Instrument_CMPSB;	//85

    //  instrument_functions[XED_ICLASS_CMPSD] = &Instrument_CMPSD; //87

    instrument_functions[XED_ICLASS_STOSB] = &Instrument_STOSB;	//89
    instrument_functions[XED_ICLASS_STOSW] = &Instrument_STOSW; //90
    instrument_functions[XED_ICLASS_STOSD] = &Instrument_STOSD;	//91

    instrument_functions[XED_ICLASS_LODSB] = &Instrument_LODSB; //93

    instrument_functions[XED_ICLASS_LODSD] = &Instrument_LODSD; //95
    instrument_functions[XED_ICLASS_LODSD] = &Instrument_LODSW; //95

    instrument_functions[XED_ICLASS_SCASB] = &Instrument_SCASB;	//97

    //  instrument_functions[XED_ICLASS_SCASD] = &Instrument_SCASD; //99

    instrument_functions[XED_ICLASS_RET_NEAR] = &Instrument_RET;	//102
    //  instrument_functions[XED_ICLASS_LES] = &Instrument_LES; //103
    //  instrument_functions[XED_ICLASS_LDS] = &Instrument_LDS; //104

    //  instrument_functions[XED_ICLASS_ENTER] = &Instrument_ENTER; //106
    instrument_functions[XED_ICLASS_LEAVE] = &Instrument_LEAVE;	//107
    instrument_functions[XED_ICLASS_RET_FAR] = &Instrument_RET; //108
    //  instrument_functions[XED_ICLASS_INT3] = &Instrument_INT3; //109
    instrument_functions[XED_ICLASS_INT] = &Instrument_INT;	//110
    //  instrument_functions[XED_ICLASS_INT0] = &Instrument_INT0; //111

    instrument_functions[XED_ICLASS_IRETD] = &Instrument_IRETD; //113

    //  instrument_functions[XED_ICLASS_AAM] = &Instrument_AAM; //115
    //  instrument_functions[XED_ICLASS_AAD] = &Instrument_AAD; //116
    //  instrument_functions[XED_ICLASS_SALC] = &Instrument_SALC; //117
    //  instrument_functions[XED_ICLASS_XLAT] = &Instrument_XLAT; //118

    //  instrument_functions[XED_ICLASS_LOOPNE] = &Instrument_LOOPNE; //120
    //  instrument_functions[XED_ICLASS_LOOPE] = &Instrument_LOOPE; //121
    //  instrument_functions[XED_ICLASS_LOOP] = &Instrument_LOOP; //122
    instrument_functions[XED_ICLASS_JRCXZ] = &Instrument_Jcc;	//123
    //  instrument_functions[XED_ICLASS_IN] = &Instrument_IN; //124
    //  instrument_functions[XED_ICLASS_OUT] = &Instrument_OUT; //125
    instrument_functions[XED_ICLASS_CALL_NEAR] = &Instrument_CALL_NEAR;	//126
    instrument_functions[XED_ICLASS_JMP] = &Instrument_JMP;	//127
    instrument_functions[XED_ICLASS_JMP_FAR] = &Instrument_JMP; //128

    //  instrument_functions[XED_ICLASS_INT_l] = &Instrument_INT_l; //130

    instrument_functions[XED_ICLASS_HLT] = &Instrument_HLT;	//133
    //  instrument_functions[XED_ICLASS_CMC] = &Instrument_CMC; //134

    //  instrument_functions[XED_ICLASS_CLC] = &Instrument_CLC; //136
    //  instrument_functions[XED_ICLASS_STC] = &Instrument_STC; //137
    //  instrument_functions[XED_ICLASS_CLI] = &Instrument_CLI; //138
    //  instrument_functions[XED_ICLASS_STI] = &Instrument_STI; //139
    instrument_functions[XED_ICLASS_CLD] = &Instrument_CLD;	//140
    instrument_functions[XED_ICLASS_STD] = &Instrument_STD;	//141

    instrument_functions[XED_ICLASS_RDTSC] = &Instrument_RDTSC;	//169

    instrument_functions[XED_ICLASS_CMOVB] = &Instrument_CMOVcc;	//177
    instrument_functions[XED_ICLASS_CMOVNB] = &Instrument_CMOVcc;	//178
    instrument_functions[XED_ICLASS_CMOVZ] = &Instrument_CMOVcc;	//179
    instrument_functions[XED_ICLASS_CMOVNZ] = &Instrument_CMOVcc;	//180
    instrument_functions[XED_ICLASS_CMOVBE] = &Instrument_CMOVcc;	//181
    instrument_functions[XED_ICLASS_CMOVNBE] = &Instrument_CMOVcc;	//182

    //  instrument_functions[XED_ICLASS_EMMS] = &Instrument_EMMS; //216

    instrument_functions[XED_ICLASS_SETB] = &Instrument_SETcc;	//222
    instrument_functions[XED_ICLASS_SETNB] = &Instrument_SETcc;	//223
    instrument_functions[XED_ICLASS_SETZ] = &Instrument_SETcc;	//224
    instrument_functions[XED_ICLASS_SETNZ] = &Instrument_SETcc;	//225
    instrument_functions[XED_ICLASS_SETBE] = &Instrument_SETcc;	//226
    instrument_functions[XED_ICLASS_SETNBE] = &Instrument_SETcc;	//227
    //  instrument_functions[XED_ICLASS_CPUID] = &Instrument_CPUID; //228
    instrument_functions[XED_ICLASS_BT] = &Instrument_BT; //229
    instrument_functions[XED_ICLASS_SHLD] = &Instrument_SHLD;	//230
    instrument_functions[XED_ICLASS_CMPXCHG] = &Instrument_CMPXCHG;	//231

    instrument_functions[XED_ICLASS_BTR] = &Instrument_BT; //233

    instrument_functions[XED_ICLASS_MOVZX] = &Instrument_MOVZX;	//236
    instrument_functions[XED_ICLASS_XADD] = &Instrument_XADD;	//237

    //  instrument_functions[XED_ICLASS_PSRLQ] = &Instrument_PSRLQ; //250  
    //  instrument_functions[XED_ICLASS_PADDQ] = &Instrument_PADDQ; //251  

    //  instrument_functions[XED_ICLASS_MOVQ] = &Instrument_MOVQ; //255  

    //  instrument_functions[XED_ICLASS_MOVQ2Q] = &Instrument_MOVDQ2Q; //258

    //  instrument_functions[XED_ICLASS_PSLLQ] = &Instrument_PSLLQ; //272
    //  instrument_functions[XED_ICLASS_PMULUDQ] = &Instrument_PMULUDQ; //273

    //  instrument_functions[XED_ICLASS_UD2] = &Instrument_UD2; //281

    instrument_functions[XED_ICLASS_CMOVS] = &Instrument_CMOVcc;	//307
    instrument_functions[XED_ICLASS_CMOVNS] = &Instrument_CMOVcc;	//308

    instrument_functions[XED_ICLASS_CMOVL] = &Instrument_CMOVcc;	//311
    instrument_functions[XED_ICLASS_CMOVNL] = &Instrument_CMOVcc;	//312
    instrument_functions[XED_ICLASS_CMOVLE] = &Instrument_CMOVcc;	//313
    instrument_functions[XED_ICLASS_CMOVNLE] = &Instrument_CMOVcc;	//314

    //  instrument_functions[XED_ICLASS_MOVD] = &Instrument_MOVD; //350
    //  instrument_functions[XED_ICLASS_MOVDQU] = &Instrument_MOVDQU; //351

    //  instrument_functions[XED_ICLASS_MOVDQA] = &Instrument_MOVDQA; //354

    instrument_functions[XED_ICLASS_SETS] = &Instrument_SETcc;	//361

    instrument_functions[XED_ICLASS_SETL] = &Instrument_SETcc;	//365
    instrument_functions[XED_ICLASS_SETNL] = &Instrument_SETcc;	//366
    instrument_functions[XED_ICLASS_SETLE] = &Instrument_SETcc;	//367/ire
    instrument_functions[XED_ICLASS_SETNLE] = &Instrument_SETcc;	//368

    instrument_functions[XED_ICLASS_BTS] = &Instrument_BT; //370
    instrument_functions[XED_ICLASS_BTC] = &Instrument_BT; //370
    instrument_functions[XED_ICLASS_SHRD] = &Instrument_SHRD;	//371

    //  instrument_functions[XED_ICLASS_BSF] = &Instrument_BSF; //376
    //  instrument_functions[XED_ICLASS_BSR] = &Instrument_BSR; //377
    instrument_functions[XED_ICLASS_MOVSX] = &Instrument_MOVSX;	//378
    instrument_functions[XED_ICLASS_BSWAP] = &Instrument_BSWAP;	//379

    //  instrument_functions[XED_ICLASS_PAND] = &Instrument_PAND; //383

    //  instrument_functions[XED_ICLASS_PSUBSW] = &Instrument_PSUBSW; //389

    //  instrument_functions[XED_ICLASS_POR] = &Instrument_POR; //391

    //  instrument_functions[XED_ICLASS_PXOR] = &Instrument_PXOR; //395

    //  instrument_functions[XED_ICLASS_ROL] = &Instrument_ROL; //472
    //  instrument_functions[XED_ICLASS_ROR] = &Instrument_ROR; //473
    //  instrument_functions[XED_ICLASS_RCL] = &Instrument_RCL; //474
    //  instrument_functions[XED_ICLASS_RCR] = &Instrument_RCR; //475
    instrument_functions[XED_ICLASS_SHL] = &Instrument_SHL;	//476
    instrument_functions[XED_ICLASS_SHR] = &Instrument_SHR;	//477
    instrument_functions[XED_ICLASS_SAR] = &Instrument_SAR;	//478
    instrument_functions[XED_ICLASS_NOT] = &Instrument_NOT;	//479
    instrument_functions[XED_ICLASS_NEG] = &Instrument_NEG;	//480
    instrument_functions[XED_ICLASS_MUL] = &Instrument_MUL;	//481
    instrument_functions[XED_ICLASS_DIV] = &Instrument_DIV;	//482
    instrument_functions[XED_ICLASS_IDIV] = &Instrument_IDIV;	//483

    instrument_functions[XED_ICLASS_LDMXCSR] = &Instrument_LDMXCSR;	//507
    instrument_functions[XED_ICLASS_STMXCSR] = &Instrument_STMXCSR;	//508

    instrument_functions[XED_ICLASS_FLDCW] = &Instrument_FLDCW;	//527

    instrument_functions[XED_ICLASS_FNSTCW] = &Instrument_FNSTCW;	//529
    instrument_functions[XED_ICLASS_SYSENTER] = &Instrument_SYSENTER;	//652
    instrument_functions[XED_ICLASS_SYSEXIT] = &Instrument_SYSEXIT;	//653
//	instrument_functions[XED_ICLASS_BTS] = &Instrument_BT;	//653
}

void taint_reset()
{
    num_stack_address=0;
    is_ret=0;
    is_call=0;
}

void Instrument(INS ins)
{
    xed_reg_enum_t reg_id;
    uint32_t mem_addr;
    UChar   taint;
    uint32_t nop;

    taint_reset();
    nop = xed_decoded_inst_noperands(&xedd_g);
	
    xed_iclass_enum_t opcode = xed_decoded_inst_get_iclass(&xedd_g);

    if (opcode == XED_ICLASS_SYSENTER || opcode == XED_ICLASS_SYSEXIT || opcode == XED_ICLASS_IRETD)
    {
        (*instrument_functions[opcode]) (ins);
        return ;
    }
	

    if(
        !is_interrupt
     	&& sys_need_red 
	)
    {
/*
        const xed_operand_t *op = xed_inst_operand(ins, 0);
        xed_operand_enum_t op_name = xed_operand_name(op);
		

        if (operand_is_mem(op_name, &mem_addr, 0, &taint)) {
            if(taint == TAINTED){
                if(opcode == XED_ICLASS_POP &&basereg == XED_REG_ESP)
                    mem_addr+=4;
                set_kernel_stack_address(mem_addr);
            }
		
        } 
		
        const xed_operand_t *op0 = xed_inst_operand(ins, 1);
        xed_operand_enum_t op0_name = xed_operand_name(op0);
		

        if (operand_is_mem(op0_name, &mem_addr, 1, &taint)) {
            if(taint == TAINTED)
                set_kernel_stack_address(mem_addr);
#ifdef VMMI_ALL_REDIRCTION
            if(!is_interrupt&&is_sysenter&&vmmi_profile&&vmmi_start&&sys_need_red){
                uint64_t phaddr = (uint64_t)vmmi_mem_shadow+vmmi_vtop(mem_addr);
                vmmi_esp2 = *(uint32_t *)phaddr;
            }
#endif
        }

*/
#ifdef DEBUG_VMMI
  	if(qemu_log_enabled())
            qemu_log(" op:%s", xed_iclass_enum_t2str(opcode));
#endif
   	(*instrument_functions[opcode]) (ins);

    }
}


void set_kernel_stack_address(target_ulong addr)
{

#ifdef DEBUG_VMMI
    qemu_log("set kernel stack address %x",addr);
#endif

    stack_address[num_stack_address++]=addr;
}

uint32_t is_kernel_stack(target_ulong addr)
{
    uint32_t i=0;
    uint32_t res;
	
    res =0;
	
    if(num_stack_address >0)
        for(i=0; i<num_stack_address; i++)
            if(stack_address[i] == addr)
                res = 1;	
	
#ifdef DEBUG_VMMI
    if(qemu_log_enabled())
        qemu_log("check addrss %x %x %x %x",addr, num_stack_address, stack_address[0], res);
    if(get_reg_taint(XED_REG_ESP)){
        if(((cpu_single_env->regs[R_ESP]&0xffffe000)==(addr&0xffffe000))^(res==1))
            if(qemu_log_enabled())
                qemu_log("translate error(%x, %x, %x)", cpu_single_env->regs[R_ESP], addr, res);
    }else if(res==1){
        if(qemu_log_enabled())
            qemu_log("translate error(%x, %x, %x)", cpu_single_env->regs[R_ESP], addr, res);

    }
#endif

    return res;
}

int is_pc_redirect()
{

	return (num_stack_address==0);
}
