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
#include "qemu-common.h"
#include "cpu.h"
#include "taint.h"
#include "qemu-log.h"
#include "hook_inst.h"

/* Map from XED register numbers to
    0) Base register
    1) Offset
    2) Size
*/

extern xed_decoded_inst_t xedd_g;
extern int xed_regmapping[][3];




static void FD_Instrument_MOV(INS xi) {
	xed_reg_enum_t reg_id;
	uint32_t value;
	uint32_t mem_addr;
	UChar taint = 0, taint1=0;

	/* Only check the second operand, whether it is register
	   memory, or immediate value
	 */

	const xed_operand_t *op = xed_inst_operand(xi, 1);
	xed_operand_enum_t op_name = xed_operand_name(op);
	
#ifdef DEBUG_VMMI2
	if(operand_is_mem(op_name, &mem_addr, 1, &taint1)){
		if(qemu_log_enabled())
			qemu_log("XED address is 0x%08x\n", mem_addr);
	}
#endif
	
	taint = 0;
	taint1=0;

	if (operand_is_reg(op_name, &reg_id)) {
		
		taint = get_reg_taint_fd(reg_id);

		const xed_operand_t *op0 = xed_inst_operand(xi, 0);
		xed_operand_enum_t op_name0 = xed_operand_name(op0);
		xed_uint_t width =
		    xed_decoded_inst_get_operand_width(&xedd_g);
		
		if (operand_is_mem(op_name0, &mem_addr, 0, &taint1)) {
			set_mem_taint_bysize(mem_addr, taint, width/8);
		}
		else if (operand_is_reg(op_name0, &reg_id)) {
			set_reg_taint_fd(reg_id, taint);
		}
	} else if (operand_is_imm(op_name, &value)) {


		const xed_operand_t *op0 = xed_inst_operand(xi, 0);
		xed_operand_enum_t op_name0 = xed_operand_name(op0);
		xed_uint_t width =
		    xed_decoded_inst_get_immediate_width(&xedd_g);

		if (operand_is_reg(op_name0, &reg_id)) {
				set_reg_taint_fd(reg_id, UNTAINTED);
		}
		else if (operand_is_mem(op_name0, &mem_addr, 0, &taint1)) {
			set_mem_taint_bysize(mem_addr, UNTAINTED, width);
		}
	}

	else if (operand_is_mem(op_name, &mem_addr, 1, &taint)) {
		xed_uint_t width =
		    xed_decoded_inst_get_operand_width(&xedd_g);
		
		taint = get_mem_taint(mem_addr);

		const xed_operand_t *op0 = xed_inst_operand(xi, 0);
		xed_operand_enum_t op_name0 = xed_operand_name(op0);

		if (operand_is_reg(op_name0, &reg_id)) 
			set_reg_taint_fd(reg_id, taint);

	} else {
		#ifdef DEBUG_TAINT
		fprintf(tracelog, "%d unknown\n", 1);
		#endif
	}
}

static void FD_Instrument_MUL(INS);

static void UnimplementedInstruction(INS ins) {

#ifdef DEBUG_TAINT
	fprintf(tracelog, "unimplemented: eip=0x%08x \n", *TEMU_cpu_eip);
#endif

	return;
}

static void FD_Instrument_AND(INS ins);

static void FD_Instrument_ADC(INS ins) {
	FD_Instrument_AND(ins);
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

static void FD_Instrument_AND(INS xi) {

}

static void FD_Instrument_ADD(INS xi) {
	

}

static void FD_Instrument_BSWAP(INS ins) {
}

static void FD_Instrument_CALL_NEAR(INS ins) {
}

static void FD_Instrument_CALL_FAR(INS ins) {

}

static void FD_Instrument_CDQ(INS ins) {
}

static void FD_Instrument_CLD(INS ins) {
}

static void FD_Instrument_CMOVcc(INS ins) {
}

static void FD_Instrument_CMP(INS ins) {


}

static void FD_Instrument_CMPSB(INS ins) {
}

static void FD_Instrument_CMPXCHG(INS ins) {
}

static void FD_Instrument_CWDE(INS ins) {
}

static void FD_Instrument_DEC(INS ins) {
}

static void FD_Instrument_DIV(INS ins) {

}

static void FD_Instrument_FLDCW(INS ins) {	//TODO: Floating point instruction
}

static void FD_Instrument_FNSTCW(INS ins) {
}

static void FD_Instrument_HLT(INS ins) {
}

static void FD_Instrument_IDIV(INS ins) {

}

static void FD_Instrument_IMUL(INS ins) {

}

static void FD_Instrument_INC(INS ins) {
}

static void FD_Instrument_INT(INS ins) {

}


static void FD_Instrument_Jcc(INS ins) {

}

static void FD_Instrument_JMP(INS ins) {

}

static void FD_Instrument_LEA(INS xi) {
	xed_reg_enum_t reg_id;
	uint32_t value;
	uint32_t mem_addr;
	UChar taint = 0;


	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);

	if (operand_is_reg(op_name, &reg_id)) {

		set_reg_taint_fd(reg_id, UNTAINTED);

	}

}

static void FD_Instrument_LEAVE(INS ins) {	//Stack variable life time ends
	


}

static void FD_Instrument_LDMXCSR(INS ins) {
//float point instruction
//pass
}


static void FD_Instrument_MOVSD(INS ins) {
}

static void FD_Instrument_MOVSW(INS ins) {

}

static void FD_Instrument_MOVSB(INS ins) {

}

static void FD_Instrument_MOVSX(INS ins) {
	
}

static void FD_Instrument_MOVZX(INS ins) {	

}

static void FD_Instrument_MUL(INS ins) {
}

static void FD_Instrument_NEG(INS ins) {
}

static void FD_Instrument_NOT(INS ins) {
//pass
}

static void FD_Instrument_OR(INS ins) {
}

static void FD_Instrument_PAUSE(INS ins) {
}

static void FD_Instrument_POP(INS ins) {
	
	xed_reg_enum_t reg_id;
	uint32_t mem_addr, addr;
	UChar taint, taint1;
	

	mem_addr = cpu_single_env->regs[R_ESP];
	taint = get_mem_taint(mem_addr);

	const xed_operand_t *op = xed_inst_operand(ins, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
	
	if(operand_is_reg(op_name, &reg_id)){
		set_reg_taint_fd(reg_id, taint);		
	}
	else if (operand_is_mem(op_name, &addr, 0, &taint1)) {
		set_mem_taint(mem_addr, taint);	
	}
	
	uint32_t i;
	for(i=0; i< 4;i++)
		set_mem_taint(mem_addr+i, UNTAINTED);

}

static void FD_Instrument_POPFD(INS ins) {
}

static void FD_Instrument_PUSH(INS ins) {
	
	xed_reg_enum_t reg_id;
	uint32_t mem_addr;
	UChar   taint=0;

	const xed_operand_t *op = xed_inst_operand(ins, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);
			
	uint32_t value;
	uint32_t addr;
	int i;


    mem_addr = cpu_single_env->regs[R_ESP]-4;

	if (operand_is_reg(op_name, &reg_id)) {
		taint=get_reg_taint_fd(reg_id);
	
	} else if (operand_is_imm(op_name, &value)) {
		taint= UNTAINTED;
	
	}else if (operand_is_mem(op_name, &addr, 0, &taint)) {
		taint=get_mem_taint(addr);	
	
	} else {
		#ifdef DEBUG_TAINT
		fprintf(tracelog, "%d unknown\n", 1);
		#endif
		return;
	}

	
	for(i=0; i< 4; i++)
	set_mem_taint(mem_addr+i, taint);			
}

static void FD_Instrument_PUSHFD(INS ins) {

}
static void FD_Instrument_RDTSC(INS ins) {
}

static void FD_Instrument_RET(INS ins) {
}

static void FD_Instrument_SAR(INS ins) {
}

static void FD_Instrument_SBB(INS ins) {
}

static void FD_Instrument_SCASB(INS ins) {
}

static void FD_Instrument_SETcc(INS ins) {
}

static void FD_Instrument_SHL(INS ins) {
}

static void FD_Instrument_SHLD(INS ins) {

}

static void FD_Instrument_SHR(INS ins) {
}

static void FD_Instrument_SHRD(INS ins) {
}

static void FD_Instrument_STD(INS ins) {
}

static void FD_Instrument_STMXCSR(INS ins) {
	
}
static void FD_Instrument_LODSB(INS ins){
}

static void FD_Instrument_LODSD(INS ins){
}
static void FD_Instrument_LODSW(INS ins){
}

static void FD_Instrument_STOSB(INS ins) {

}

static void FD_Instrument_STOSD(INS ins) {
}
static void FD_Instrument_STOSW(INS ins) {
}

static void FD_Instrument_SUB(INS ins) {

}

static void FD_Instrument_TEST(INS ins) {

}

static void FD_Instrument_XADD(INS ins) {


}

static void FD_Instrument_XCHG(INS ins) {
	
	xed_reg_enum_t reg_id, reg_id0;

	const xed_operand_t * op = xed_inst_operand(ins, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);

	if (operand_is_reg(op_name, &reg_id)){
		const xed_operand_t * op0 = xed_inst_operand(ins, 1);
		xed_operand_enum_t op0_name = xed_operand_name(op0);

		if (operand_is_reg(op0_name, &reg_id0)){
			UChar taint = get_reg_taint_fd(reg_id);

			set_reg_taint_fd(reg_id, get_reg_taint_fd(reg_id0));
			set_reg_taint_fd(reg_id0, taint);
		}

	}
		

}

static void FD_Instrument_XOR(INS xi) {


	xed_reg_enum_t reg_id;
	uint32_t value;
	target_ulong mem_addr;


	const xed_operand_t *op = xed_inst_operand(xi, 0);
	xed_operand_enum_t op_name = xed_operand_name(op);

	if (operand_is_reg(op_name, &reg_id)) {
		op = xed_inst_operand(xi, 1);
		op_name = xed_operand_name(op);

		xed_reg_enum_t reg_id2;

		if (operand_is_reg(op_name, &reg_id2))
		{
			if(reg_id == reg_id2)
			{
				set_reg_taint_fd(reg_id, UNTAINTED);
			}
		}
	}
}
static void FD_Instrument_DAA(INS ins) {

}

static void FD_Instrument_DAS(INS ins) {

}

static void FD_Instrument_AAA(INS ins) {

}

static void FD_Instrument_AAS(INS ins) {

}

static void FD_Instrument_ROL(INS ins) {
}

static void FD_Instrument_BT(INS ins)
{
}
static void FD_Instrument_IRETD(INS ins)
{
}

static void FD_Instrument_SYSENTER(INS ins)
{
}

static void FD_Instrument_SYSEXIT(INS ins)
{
	
}

static InstrumentFunction FD_instrument_functions[XED_ICLASS_LAST];

void setup_inst_hook_fd() {
	// set a default handling function that aborts.  This makes sure I don't
	// miss instructions in new applications
	int i;
	for (i = 0; i < XED_ICLASS_LAST; i++) {
		FD_instrument_functions[i] = &UnimplementedInstruction;
	}
	FD_instrument_functions[XED_ICLASS_ADD] = &FD_Instrument_ADD;	// 1
	FD_instrument_functions[XED_ICLASS_PUSH] = &FD_Instrument_PUSH;	// 2
	FD_instrument_functions[XED_ICLASS_POP] = &FD_Instrument_POP;	// 3
	FD_instrument_functions[XED_ICLASS_OR] = &FD_Instrument_OR;	// 4

	FD_instrument_functions[XED_ICLASS_ADC] = &FD_Instrument_ADC;	// 6
	FD_instrument_functions[XED_ICLASS_SBB] = &FD_Instrument_SBB;	// 7
	FD_instrument_functions[XED_ICLASS_AND] = &FD_Instrument_AND;	// 8

	//  FD_instrument_functions[XED_ICLASS_DAA] = &FD_Instrument_DAA; // 11
	FD_instrument_functions[XED_ICLASS_SUB] = &FD_Instrument_SUB;	// 12

	//  FD_instrument_functions[XED_ICLASS_DAS] = &FD_Instrument_DAS; // 14
	FD_instrument_functions[XED_ICLASS_XOR] = &FD_Instrument_XOR;	// 15

	//  FD_instrument_functions[XED_ICLASS_AAA] = &FD_Instrument_AAA; // 17
	FD_instrument_functions[XED_ICLASS_CMP] = &FD_Instrument_CMP;	// 18

	//  FD_instrument_functions[XED_ICLASS_AAS] = &FD_Instrument_AAS; // 20
	FD_instrument_functions[XED_ICLASS_INC] = &FD_Instrument_INC;	// 21
	FD_instrument_functions[XED_ICLASS_DEC] = &FD_Instrument_DEC;	// 22

	//  FD_instrument_functions[XED_ICLASS_PUSHAD] = &FD_Instrument_PUSHAD; // 25
	//  FD_instrument_functions[XED_ICLASS_POPAD] = &FD_Instrument_POPAD; // 27
	//  FD_instrument_functions[XED_ICLASS_BOUND] = &FD_Instrument_BOUND; // 28
	//  FD_instrument_functions[XED_ICLASS_ARPL] = &FD_Instrument_ARPL; // 29

	FD_instrument_functions[XED_ICLASS_IMUL] = &FD_Instrument_IMUL;	// 35
	//  FD_instrument_functions[XED_ICLASS_INSB] = &FD_Instrument_INSB; // 36

	//  FD_instrument_functions[XED_ICLASS_INSD] = &FD_Instrument_INSD; // 38
	//  FD_instrument_functions[XED_ICLASS_OUTSB] = &FD_Instrument_OUTSB; // 39

	//  FD_instrument_functions[XED_ICLASS_OUTSD] = &FD_Instrument_OUTSD; // 41
	FD_instrument_functions[XED_ICLASS_JO] = &FD_Instrument_Jcc;	//42
	FD_instrument_functions[XED_ICLASS_JNO] = &FD_Instrument_Jcc;	//43
	FD_instrument_functions[XED_ICLASS_JB] = &FD_Instrument_Jcc;	//43
	FD_instrument_functions[XED_ICLASS_JNB] = &FD_Instrument_Jcc;	//45
	FD_instrument_functions[XED_ICLASS_JZ] = &FD_Instrument_Jcc;	//46
	FD_instrument_functions[XED_ICLASS_JNZ] = &FD_Instrument_Jcc;	//47
	FD_instrument_functions[XED_ICLASS_JBE] = &FD_Instrument_Jcc;	//48
	FD_instrument_functions[XED_ICLASS_JNBE] = &FD_Instrument_Jcc;	//49
	FD_instrument_functions[XED_ICLASS_JS] = &FD_Instrument_Jcc;	//50
	FD_instrument_functions[XED_ICLASS_JNS] = &FD_Instrument_Jcc;	//51
	FD_instrument_functions[XED_ICLASS_JP] = &FD_Instrument_Jcc;	//52
	FD_instrument_functions[XED_ICLASS_JNP] = &FD_Instrument_Jcc;	//53
	FD_instrument_functions[XED_ICLASS_JL] = &FD_Instrument_Jcc;	//54
	FD_instrument_functions[XED_ICLASS_JNL] = &FD_Instrument_Jcc;	//55
	FD_instrument_functions[XED_ICLASS_JLE] = &FD_Instrument_Jcc;	//56
	FD_instrument_functions[XED_ICLASS_JNLE] = &FD_Instrument_Jcc;	//57
	FD_instrument_functions[XED_ICLASS_JRCXZ] = &FD_Instrument_Jcc;	//57

	FD_instrument_functions[XED_ICLASS_TEST] = &FD_Instrument_TEST;	//59
	FD_instrument_functions[XED_ICLASS_XCHG] = &FD_Instrument_XCHG;	//60
	FD_instrument_functions[XED_ICLASS_MOV] = &FD_Instrument_MOV;	//61
	FD_instrument_functions[XED_ICLASS_LEA] = &FD_Instrument_LEA;	//62

	FD_instrument_functions[XED_ICLASS_PAUSE] = &FD_Instrument_PAUSE;	//64

	FD_instrument_functions[XED_ICLASS_CWDE] = &FD_Instrument_CWDE;	//67

	FD_instrument_functions[XED_ICLASS_CDQ] = &FD_Instrument_CDQ;	//70
	FD_instrument_functions[XED_ICLASS_CALL_FAR] = &FD_Instrument_CALL_FAR;	//71
	//  FD_instrument_functions[XED_ICLASS_WAIT] = &FD_Instrument_WAIT; //72

	FD_instrument_functions[XED_ICLASS_PUSHFD] = &FD_Instrument_PUSHFD;	//74

	FD_instrument_functions[XED_ICLASS_POPFD] = &FD_Instrument_POPFD;	//77

	//  FD_instrument_functions[XED_ICLASS_POPFD] = &FD_Instrument_SAHF; //79
	//  FD_instrument_functions[XED_ICLASS_POPFD] = &FD_Instrument_LAHF; //80
	FD_instrument_functions[XED_ICLASS_MOVSB] = &FD_Instrument_MOVSB;	//81
	FD_instrument_functions[XED_ICLASS_MOVSW] = &FD_Instrument_MOVSW;	//82
	FD_instrument_functions[XED_ICLASS_MOVSD] = &FD_Instrument_MOVSD;	//83

	FD_instrument_functions[XED_ICLASS_CMPSB] = &FD_Instrument_CMPSB;	//85

	//  FD_instrument_functions[XED_ICLASS_CMPSD] = &FD_Instrument_CMPSD; //87

	FD_instrument_functions[XED_ICLASS_STOSB] = &FD_Instrument_STOSB;	//89
	  FD_instrument_functions[XED_ICLASS_STOSW] = &FD_Instrument_STOSW; //90
	FD_instrument_functions[XED_ICLASS_STOSD] = &FD_Instrument_STOSD;	//91

	  FD_instrument_functions[XED_ICLASS_LODSB] = &FD_Instrument_LODSB; //93

	  FD_instrument_functions[XED_ICLASS_LODSD] = &FD_Instrument_LODSD; //95
	  FD_instrument_functions[XED_ICLASS_LODSD] = &FD_Instrument_LODSW; //95

	FD_instrument_functions[XED_ICLASS_SCASB] = &FD_Instrument_SCASB;	//97

	//  FD_instrument_functions[XED_ICLASS_SCASD] = &FD_Instrument_SCASD; //99

	FD_instrument_functions[XED_ICLASS_RET_NEAR] = &FD_Instrument_RET;	//102
	//  FD_instrument_functions[XED_ICLASS_LES] = &FD_Instrument_LES; //103
	//  FD_instrument_functions[XED_ICLASS_LDS] = &FD_Instrument_LDS; //104

	//  FD_instrument_functions[XED_ICLASS_ENTER] = &FD_Instrument_ENTER; //106
	FD_instrument_functions[XED_ICLASS_LEAVE] = &FD_Instrument_LEAVE;	//107
	  FD_instrument_functions[XED_ICLASS_RET_FAR] = &FD_Instrument_RET; //108
	//  FD_instrument_functions[XED_ICLASS_INT3] = &FD_Instrument_INT3; //109
	FD_instrument_functions[XED_ICLASS_INT] = &FD_Instrument_INT;	//110
	//  FD_instrument_functions[XED_ICLASS_INT0] = &FD_Instrument_INT0; //111

	  FD_instrument_functions[XED_ICLASS_IRETD] = &FD_Instrument_IRETD; //113

	//  FD_instrument_functions[XED_ICLASS_AAM] = &FD_Instrument_AAM; //115
	//  FD_instrument_functions[XED_ICLASS_AAD] = &FD_Instrument_AAD; //116
	//  FD_instrument_functions[XED_ICLASS_SALC] = &FD_Instrument_SALC; //117
	//  FD_instrument_functions[XED_ICLASS_XLAT] = &FD_Instrument_XLAT; //118

	//  FD_instrument_functions[XED_ICLASS_LOOPNE] = &FD_Instrument_LOOPNE; //120
	//  FD_instrument_functions[XED_ICLASS_LOOPE] = &FD_Instrument_LOOPE; //121
	//  FD_instrument_functions[XED_ICLASS_LOOP] = &FD_Instrument_LOOP; //122
	FD_instrument_functions[XED_ICLASS_JRCXZ] = &FD_Instrument_Jcc;	//123
	//  FD_instrument_functions[XED_ICLASS_IN] = &FD_Instrument_IN; //124
	//  FD_instrument_functions[XED_ICLASS_OUT] = &FD_Instrument_OUT; //125
	FD_instrument_functions[XED_ICLASS_CALL_NEAR] = &FD_Instrument_CALL_NEAR;	//126
	FD_instrument_functions[XED_ICLASS_JMP] = &FD_Instrument_JMP;	//127
	  FD_instrument_functions[XED_ICLASS_JMP_FAR] = &FD_Instrument_JMP; //128

	//  FD_instrument_functions[XED_ICLASS_INT_l] = &FD_Instrument_INT_l; //130

	FD_instrument_functions[XED_ICLASS_HLT] = &FD_Instrument_HLT;	//133
	//  FD_instrument_functions[XED_ICLASS_CMC] = &FD_Instrument_CMC; //134

	//  FD_instrument_functions[XED_ICLASS_CLC] = &FD_Instrument_CLC; //136
	//  FD_instrument_functions[XED_ICLASS_STC] = &FD_Instrument_STC; //137
	//  FD_instrument_functions[XED_ICLASS_CLI] = &FD_Instrument_CLI; //138
	//  FD_instrument_functions[XED_ICLASS_STI] = &FD_Instrument_STI; //139
	FD_instrument_functions[XED_ICLASS_CLD] = &FD_Instrument_CLD;	//140
	FD_instrument_functions[XED_ICLASS_STD] = &FD_Instrument_STD;	//141

	FD_instrument_functions[XED_ICLASS_RDTSC] = &FD_Instrument_RDTSC;	//169

	FD_instrument_functions[XED_ICLASS_CMOVB] = &FD_Instrument_CMOVcc;	//177
	FD_instrument_functions[XED_ICLASS_CMOVNB] = &FD_Instrument_CMOVcc;	//178
	FD_instrument_functions[XED_ICLASS_CMOVZ] = &FD_Instrument_CMOVcc;	//179
	FD_instrument_functions[XED_ICLASS_CMOVNZ] = &FD_Instrument_CMOVcc;	//180
	FD_instrument_functions[XED_ICLASS_CMOVBE] = &FD_Instrument_CMOVcc;	//181
	FD_instrument_functions[XED_ICLASS_CMOVNBE] = &FD_Instrument_CMOVcc;	//182

	//  FD_instrument_functions[XED_ICLASS_EMMS] = &FD_Instrument_EMMS; //216

	FD_instrument_functions[XED_ICLASS_SETB] = &FD_Instrument_SETcc;	//222
	FD_instrument_functions[XED_ICLASS_SETNB] = &FD_Instrument_SETcc;	//223
	FD_instrument_functions[XED_ICLASS_SETZ] = &FD_Instrument_SETcc;	//224
	FD_instrument_functions[XED_ICLASS_SETNZ] = &FD_Instrument_SETcc;	//225
	FD_instrument_functions[XED_ICLASS_SETBE] = &FD_Instrument_SETcc;	//226
	FD_instrument_functions[XED_ICLASS_SETNBE] = &FD_Instrument_SETcc;	//227
	//  FD_instrument_functions[XED_ICLASS_CPUID] = &FD_Instrument_CPUID; //228
	FD_instrument_functions[XED_ICLASS_BT] = &FD_Instrument_BT; //229
	FD_instrument_functions[XED_ICLASS_SHLD] = &FD_Instrument_SHLD;	//230
	FD_instrument_functions[XED_ICLASS_CMPXCHG] = &FD_Instrument_CMPXCHG;	//231

	FD_instrument_functions[XED_ICLASS_BTR] = &FD_Instrument_BT; //233

	FD_instrument_functions[XED_ICLASS_MOVZX] = &FD_Instrument_MOVZX;	//236
	FD_instrument_functions[XED_ICLASS_XADD] = &FD_Instrument_XADD;	//237

	//  FD_instrument_functions[XED_ICLASS_PSRLQ] = &FD_Instrument_PSRLQ; //250  
	//  FD_instrument_functions[XED_ICLASS_PADDQ] = &FD_Instrument_PADDQ; //251  

	//  FD_instrument_functions[XED_ICLASS_MOVQ] = &FD_Instrument_MOVQ; //255  

	//  FD_instrument_functions[XED_ICLASS_MOVQ2Q] = &FD_Instrument_MOVDQ2Q; //258

	//  FD_instrument_functions[XED_ICLASS_PSLLQ] = &FD_Instrument_PSLLQ; //272
	//  FD_instrument_functions[XED_ICLASS_PMULUDQ] = &FD_Instrument_PMULUDQ; //273

	//  FD_instrument_functions[XED_ICLASS_UD2] = &FD_Instrument_UD2; //281

	FD_instrument_functions[XED_ICLASS_CMOVS] = &FD_Instrument_CMOVcc;	//307
	FD_instrument_functions[XED_ICLASS_CMOVNS] = &FD_Instrument_CMOVcc;	//308

	FD_instrument_functions[XED_ICLASS_CMOVL] = &FD_Instrument_CMOVcc;	//311
	FD_instrument_functions[XED_ICLASS_CMOVNL] = &FD_Instrument_CMOVcc;	//312
	FD_instrument_functions[XED_ICLASS_CMOVLE] = &FD_Instrument_CMOVcc;	//313
	FD_instrument_functions[XED_ICLASS_CMOVNLE] = &FD_Instrument_CMOVcc;	//314

	//  FD_instrument_functions[XED_ICLASS_MOVD] = &FD_Instrument_MOVD; //350
	//  FD_instrument_functions[XED_ICLASS_MOVDQU] = &FD_Instrument_MOVDQU; //351

	//  FD_instrument_functions[XED_ICLASS_MOVDQA] = &FD_Instrument_MOVDQA; //354

	FD_instrument_functions[XED_ICLASS_SETS] = &FD_Instrument_SETcc;	//361

	FD_instrument_functions[XED_ICLASS_SETL] = &FD_Instrument_SETcc;	//365
	FD_instrument_functions[XED_ICLASS_SETNL] = &FD_Instrument_SETcc;	//366
	FD_instrument_functions[XED_ICLASS_SETLE] = &FD_Instrument_SETcc;	//367/ire
	FD_instrument_functions[XED_ICLASS_SETNLE] = &FD_Instrument_SETcc;	//368

	FD_instrument_functions[XED_ICLASS_BTS] = &FD_Instrument_BT; //370
	FD_instrument_functions[XED_ICLASS_BTC] = &FD_Instrument_BT; //370
	FD_instrument_functions[XED_ICLASS_SHRD] = &FD_Instrument_SHRD;	//371

	//  FD_instrument_functions[XED_ICLASS_BSF] = &FD_Instrument_BSF; //376
	//  FD_instrument_functions[XED_ICLASS_BSR] = &FD_Instrument_BSR; //377
	FD_instrument_functions[XED_ICLASS_MOVSX] = &FD_Instrument_MOVSX;	//378
	FD_instrument_functions[XED_ICLASS_BSWAP] = &FD_Instrument_BSWAP;	//379

	//  FD_instrument_functions[XED_ICLASS_PAND] = &FD_Instrument_PAND; //383

	//  FD_instrument_functions[XED_ICLASS_PSUBSW] = &FD_Instrument_PSUBSW; //389

	//  FD_instrument_functions[XED_ICLASS_POR] = &FD_Instrument_POR; //391

	//  FD_instrument_functions[XED_ICLASS_PXOR] = &FD_Instrument_PXOR; //395

	//  FD_instrument_functions[XED_ICLASS_ROL] = &FD_Instrument_ROL; //472
	//  FD_instrument_functions[XED_ICLASS_ROR] = &FD_Instrument_ROR; //473
	//  FD_instrument_functions[XED_ICLASS_RCL] = &FD_Instrument_RCL; //474
	//  FD_instrument_functions[XED_ICLASS_RCR] = &FD_Instrument_RCR; //475
	FD_instrument_functions[XED_ICLASS_SHL] = &FD_Instrument_SHL;	//476
	FD_instrument_functions[XED_ICLASS_SHR] = &FD_Instrument_SHR;	//477
	FD_instrument_functions[XED_ICLASS_SAR] = &FD_Instrument_SAR;	//478
	FD_instrument_functions[XED_ICLASS_NOT] = &FD_Instrument_NOT;	//479
	FD_instrument_functions[XED_ICLASS_NEG] = &FD_Instrument_NEG;	//480
	FD_instrument_functions[XED_ICLASS_MUL] = &FD_Instrument_MUL;	//481
	FD_instrument_functions[XED_ICLASS_DIV] = &FD_Instrument_DIV;	//482
	FD_instrument_functions[XED_ICLASS_IDIV] = &FD_Instrument_IDIV;	//483

	FD_instrument_functions[XED_ICLASS_LDMXCSR] = &FD_Instrument_LDMXCSR;	//507
	FD_instrument_functions[XED_ICLASS_STMXCSR] = &FD_Instrument_STMXCSR;	//508

	FD_instrument_functions[XED_ICLASS_FLDCW] = &FD_Instrument_FLDCW;	//527

	FD_instrument_functions[XED_ICLASS_FNSTCW] = &FD_Instrument_FNSTCW;	//529
	FD_instrument_functions[XED_ICLASS_SYSENTER] = &FD_Instrument_SYSENTER;	//652
	FD_instrument_functions[XED_ICLASS_SYSEXIT] = &FD_Instrument_SYSEXIT;	//653

}

void FD_Instrument(INS ins)
{
	xed_iclass_enum_t opcode = xed_decoded_inst_get_iclass(&xedd_g);
   	(*FD_instrument_functions[opcode]) (ins);
}
uint32_t get_file_taint()
{
	if(get_reg_taint_fd(XED_REG_EBX)==FDTAINTED)
		return 1;
	else
		return 0;
}



