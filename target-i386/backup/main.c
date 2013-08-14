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


#include <stdio.h>
#include <sys/resource.h>

#include "cpu.h"
#include "cpu-all.h"
#include "exec-all.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include "config.h"
#include "TEMU_lib.h"
#include "shared/procmod.h"
#include "shared/read_linux.h"
#include "shared/procmod.h"
#include "shared/hookapi.h"
#include "shared/hooks/function_map.h"
#include "ko_monitor.h"

#include <xed-interface.h>

#include "trace.h"
#include "conditions.h"

#include "load_hook_wrapper.h"
#include "hook_plugin_loader.h"

#include "rewards_hook_helper.h"

#include "hash_helper.h"
#include "bb_helper.h"
#include "write_list.h"

static plugin_interface_t rewards_interface;

int skip_decode_address = 0;
/* Environment variables */
/*
static int conf_ignore_dns = 0;
static int conf_tainted_only = 0;
static int conf_single_thread_only = 0;
static int conf_tracing_kernel_all = 0;
static int conf_tracing_kernel_tainted = 0;
static int conf_tracing_kernel_partial = 0;
*/

uint32_t tracecr3 = 0;

uint32_t fst_inst;

FILE *tracelog = 0;
FILE *tracenetlog = 0;
FILE *tracehooklog = 0;
FILE *calllog = 0;
FILE *alloclog = 0;

/* Filename for functions file */
char functionsname[128] = "";

/* Filename for trace file */
char tracename[128] = "";
char *tracename_p = tracename;

/* Start usage */
struct rusage startUsage;

char current_mod[32] = "";
char current_proc[32] = "";

uint32_t current_tid = 0;	// Current thread id
char tracefile[256];

static int taint_sendkey_id = 0;
int keystroke_offset = 0;	// Global counter for keystrokes, used for offset
uint32_t current_eip = 0;
FILE *testlog = NULL;

T_Type prev_basic_block_start_type;
T_Type prev_basic_block_end_type;

T_Type curr_basic_block_start_type;
T_Type curr_basic_block_end_type;

static uint32_t prev_basic_block_addr;
static uint32_t curr_basic_block_addr;

char basic_block_inst[1024 * 4];

static uint32_t starting_eip;
static uint32_t starting_esp;
static uint32_t next_library_call_addr;
unsigned char in_initial_exec = 0;
unsigned char in_force_exec = 0;
unsigned char is_library_call;
unsigned char is_ret_inst;
unsigned char illegal_inst;
unsigned char ill_int_inst;
unsigned char is_lea_inst;
unsigned char is_call_inst;
uint32_t restore_eip, restore_esp, ret_value, restore_ebp;
uint32_t restore_eax;
uint32_t restore_ebx;
uint32_t restore_ecx;
uint32_t restore_edx;
uint32_t restore_esi;
uint32_t restore_edi;

inline int keep_emulation()
{
	uint32_t esp;
	TEMU_read_register(esp_reg, &esp);
	if (esp < starting_esp)
		return 1;

	uint32_t eip;
	TEMU_read_register(esp, &eip);

	if (eip == starting_eip && esp == starting_esp) {
		return 1;
	}

	return 0;
}

void start_emulation()
{
	TEMU_read_register(esp_reg, &starting_esp);
	TEMU_read_mem(starting_esp, 4, &starting_eip);
	term_printf("the returned eip %x, and esp %x\n", starting_eip,
		    starting_esp);

	in_force_exec = 0;
	in_initial_exec = 1;
	fst_inst = *TEMU_cpu_eip;
	starting_eip = fst_inst;
	prev_basic_block_addr = starting_eip;

	fprintf(tracelog, "STARTED emulation...............%x\n", fst_inst);

}
static void stop_emulation()
{
	in_force_exec = 0;
}

#define	RESTORE_CONTEXT_TO_NEXT_EIP(new_pc) \
	do {\
		uint32_t local_ebp = GetEBP(); \
		uint32_t *local_ret_addr=local_ebp; \
		uint32_t *local_mem_addr=(*local_ret_addr + 4); \
		*local_mem_addr=create_tb_for_pc(new_pc); \
		return; \
	}while(0);

#define PATCH_VICTIM_INST_FOR_NEXT_EIP(victim_pc, new_pc) \
	do {\
	if(*TEMU_cpu_eip == victim_pc){\
		uint32_t local_ebp = GetEBP(); \
		uint32_t *local_ret_addr=local_ebp; \
		uint32_t *local_mem_addr=(*local_ret_addr + 4); \
		*local_mem_addr=create_tb_for_pc(new_pc); \
		return; \
		} \
	}while(0);

#define PATCH_BEGIN_VICTIM_INST_FOR_NEXT_EIP(victim_pc, new_pc) \
	do {\
	if(*TEMU_cpu_eip == victim_pc){\
		uint32_t local_ebp = GetEBP(); \
		uint32_t *local_mem_addr=(local_ebp + 4); \
		*local_mem_addr=create_tb_for_pc(new_pc); \
		return; \
		} \
	}while(0);

#define PATCH_END_VICTIM_INST_FOR_NEXT_EIP(victim_pc, new_pc) \
	do {\
	if(*TEMU_cpu_eip == victim_pc){\
		uint32_t local_ebp = GetEBP(); \
		uint32_t *local_ret_addr=local_ebp; \
		uint32_t *local_mem_addr=(*local_ret_addr + 4); \
		*local_mem_addr=create_tb_for_pc(new_pc); \
		return; \
		} \
	}while(0);

static term_cmd_t rewards_info_cmds[] = {
	{NULL, NULL},
};

static dump_tb()
{
	TranslationBlock *tb;
	if (cpu_single_env != NULL) {
		fprintf(tracelog, "cpu_status eip %x, exception_next_eip %x\n",
			cpu_single_env->eip,
			cpu_single_env->exception_next_eip);
	} else {
		fprintf(tracelog, "cannot dump cpu_state\n");
		return;
	}
	tb = cpu_single_env->current_tb;
	if (tb != NULL) {
		fprintf(tracelog,
			"tb %x pc %x, cs_base %x flags %x size %x, tc_ptr %x, jmp_next %x, jmp_next[2] %x, jmp_first %x\n",
			tb, tb->pc, tb->cs_base, tb->flags, tb->size,
			tb->tc_ptr, tb->jmp_next[0], tb->jmp_next[1],
			tb->jmp_first);
	} else {
		fprintf(tracelog, "cannot dump tb\n");
	}
}

int tracing_start(uint32_t pid, const char *filename)
{

#ifdef INSN_INFO
	char infoname[128];
	if (infolog)
		fclose(infolog);
	snprintf(infoname, 128, "%s.log", filename);
	infolog = fopen(infoname, "w");
	if (0 == infolog) {
		perror("tracing_start");
		tracepid = 0;
		tracecr3 = 0;
		return -1;
	}
#endif

	if (conf_log_external_calls) {
		trace_do_not_write = 1;
	}

	/* Initialize disassembler */
	xed2_init();

	strncpy(tracename, filename, 128);

	strncpy(tracefile, filename, 256);

	if (tracelog)
		fclose(tracelog);

	if (tracenetlog)
		fclose(tracenetlog);

	tracelog = fopen(filename, "w");
	if (0 == tracelog) {
		perror("tracing_start");
		tracepid = 0;
		tracecr3 = 0;
		return -1;
	}
//      setvbuf(tracelog, filebuf, _IOFBF, FILEBUFSIZE);

	char netname[128];
	int e;
	struct stat sb;

	sprintf(netname,"/tmp/%d",pid);
	read_reg(esp_reg, &begin_stack_esp);

	e = stat(netname, &sb);
	if (e != 0) //doesn't exist
	{
		if (errno = ENOENT)
		{
			e = mkdir(netname, S_IRWXU|S_IRWXO|S_IRWXG);
			if (e != 0)
			{
				printf("mkdir failed; %s errno=%d\n",netname, errno);
				exit(1);
			}
		}
	}

	snprintf(netname, 128, "%s.%d.netlog", filename, pid);
	tracenetlog = fopen(netname, "w");
	if (0 == tracenetlog) {
		perror("tracing_start");
		tracepid = 0;
		tracecr3 = 0;
		do_tracing_stop();
		do_disable_emulation();
		return -1;
	}
	// Set name for functions file
	snprintf(functionsname, 128, "%s.functions", filename);

	if (conf_log_external_calls) {
		char callname[128];
		if (calllog)
			fclose(calllog);
		snprintf(callname, 128, "%s.calls", filename);
		calllog = fopen(callname, "w");
		if (0 == calllog) {
			perror("tracing_start");
			tracepid = 0;
			tracecr3 = 0;
			return -1;
		}
		setvbuf(calllog, filebuf, _IOFBF, FILEBUFSIZE);
	}

	term_printf("init hash table %x\n", bbg);

	tracepid = pid;
	tracecr3 = find_cr3(pid);
	if (0 == tracecr3) {
		term_printf
		    ("CR3 for PID %d not found. Tracing all processes!\n", pid);
	}
	term_printf("PID: %d CR3: 0x%08x\n", tracepid, tracecr3);

	/* Initialize hooks only for this process */
	temu_plugin->monitored_cr3 = tracecr3;

	/* Get system start usage */
	if (getrusage(RUSAGE_SELF, &startUsage) != 0)
		term_printf("Could not get start usage\n");

	return 0;
}

static void rewards_taint_disk(uint64_t addr, uint8_t * record, void *opaque)
{
	return;
}

static void rewards_guest_message(char *message)
{
	handle_message(message);
	switch (message[0]) {
	case 'P':
		parse_process(message);
		break;
	case 'M':
		parse_module(message);
		break;
	}
}

void do_tracing(uint32_t pid, const char *filename)
{
	/* if pid = 0, stop trace */
	if (0 == pid)
		tracing_stop();
	else {
		int retval = tracing_start(pid, filename);
		if (retval < 0)
			term_printf("Unable to open log file '%s'\n", filename);
	}

	/* Print configuration variables */
	print_conf_vars();
}

void do_keep_execution()
{
	fflush(tracelog);

}

void do_tracing_stop()
{
//      free_thread_info_record_list();
	tracing_stop();
	stop_emulation();
}

void do_load_hooks(const char *hooks_dirname, const char *plugins_filename)
{
	return;

#if 0
	if (strcmp(plugins_filename, "") != 0)
		strncpy(hook_plugins_filename, plugins_filename, 256);
	if (strcmp(hooks_dirname, "") != 0)
		strncpy(hook_dirname, hooks_dirname, 256);

	// Load hooks if requested via TEMU monitor
	load_hook_plugins(&(temu_plugin->monitored_cr3),
			  hook_plugins_filename,
			  hook_dirname, &g_plugin_info, ini);
#endif
}

inline int tracing_single_thread_only()
{
	return conf_single_thread_only;
}

void set_kernel_all(int state)
{
	if (state) {
		conf_tracing_kernel_all = 1;
		term_printf("Kernel-all flag on.\n");

	} else {
		conf_tracing_kernel_all = 0;
		term_printf("Kernel-all flag off.\n");
	}
}

inline int tracing_kernel_all()
{
	return conf_tracing_kernel_all;
}

void set_kernel_tainted(int state)
{
	if (state) {
		conf_tracing_kernel_tainted = 1;
		term_printf("Kernel-tainted flag on.\n");
	} else {
		conf_tracing_kernel_tainted = 0;
		term_printf("Kernel-tainted flag off.\n");
	}
}

inline int tracing_kernel_tainted()
{
	return conf_tracing_kernel_tainted;
}

void set_kernel_partial(int state)
{
	if (state) {
		conf_tracing_kernel_partial = 1;
		term_printf("Kernel-partial flag on.\n");
	} else {
		conf_tracing_kernel_partial = 0;
		term_printf("Kernel-partial flag off.\n");
	}
}

inline int tracing_kernel_partial()
{
	return conf_tracing_kernel_partial;
}

inline int tracing_kernel()
{
	return conf_tracing_kernel_all || conf_tracing_kernel_partial ||
	    conf_tracing_kernel_tainted;
}
static int rewards_block_begin()
{
	if (is_kernel_instruction() && !tracing_kernel())
		return 0;

	tmodinfo_t *mi;
	mi = locate_module(*TEMU_cpu_eip, TEMU_cpu_cr[3], current_proc);
	strncpy(current_mod, mi ? mi->name : "unknown", 31);
	current_mod[31] = '\0';

	if (procname_is_set()) {
		char temp[64];
		uint32_t pid;

		find_process(TEMU_cpu_cr[3], temp, &pid);
		if (procname_match(temp)) {
			do_tracing(pid, tracefile);
			term_printf("Tracing %s\n", procname_get());
			procname_clear();
		}
	}

	if (modname_is_set()) {
		if (modname_match(current_mod) &&
		    (temu_plugin->monitored_cr3 == TEMU_cpu_cr[3])) {
			tracing_start_condition = 1;
			modname_clear();
		}
	}

	if (temu_plugin->monitored_cr3 != TEMU_cpu_cr[3])
		return 0;

	uint32_t eip = *TEMU_cpu_eip;
	if (eip > LIBRARY_BOUNDARY) {
		struct names_t *names = query_name(eip);
		uint32_t curr_tid = get_current_tid();
		if ((names != NULL)) {
			if ((names->fun_name != NULL)
			    && (names->mod_name != NULL)) {
				fprintf(tracelog,
					"Process %d TID: %d -> %s::%s @ EIP: 0x%08x\n",
					tracepid, curr_tid, names->mod_name,
					names->fun_name, eip);
			} else {
				fprintf(tracelog,
					"Process %d TID: %d -> ?::? @ EIP: 0x%08x\n",
					tracepid, curr_tid, eip);
			}
		}
	}

	current_tid = get_current_tid();

// tracelog=get_tracelog_by_pt_id(tracepid, current_tid);

	if (in_force_exec || in_initial_exec) {
		curr_basic_block_addr = *TEMU_cpu_eip;

		fprintf(tracelog, "insert bb %x\n", prev_basic_block_addr);
		if (prev_basic_block_addr < LIBRARY_BOUNDARY) {
			if (is_call_inst) {
				insert_or_update_bb(prev_basic_block_addr,
						    curr_basic_block_addr,
						    basic_block_inst,
						    prev_basic_block_start_type,
						    curr_basic_block_end_type,
						    next_ins_addr);
			} else if (is_cond_jmp_inst) {
				insert_or_update_bb(prev_basic_block_addr,
						    jmp_target_ins_addr,
						    basic_block_inst,
						    prev_basic_block_start_type,
						    curr_basic_block_end_type,
						    next_ins_addr);

			} else {
				insert_or_update_bb(prev_basic_block_addr,
						    curr_basic_block_addr,
						    basic_block_inst,
						    prev_basic_block_start_type,
						    curr_basic_block_end_type,
						    0);
			}

		}
		basic_block_inst[0] = '\0';
		prev_basic_block_start_type = curr_basic_block_end_type;
		prev_basic_block_addr = curr_basic_block_addr;

		if (*TEMU_cpu_eip > LIBRARY_BOUNDARY
		    && prev_basic_block_addr < LIBRARY_BOUNDARY) {
			fprintf(tracelog, "insert api %x\n", *TEMU_cpu_eip);
			insert2_api_list(prev_basic_block_addr, *TEMU_cpu_eip);
		}
	}

	hookapi_check_call(1);

	return 0;
}

static void rewards_send_keystroke(int reg)
{
	if (taint_sendkey_id) {
		taint_sendkey_id = 0;
	}
}

static void rewards_bdrv_open(int index, void *opaque)
{
}

static void rewards_nic_recv(uint8_t * buf, int size, int index, int start,
			     int stop)
{
	return;
}

static void rewards_nic_send(uint32_t addr, int size, uint8_t * buf)
{
	return;
}

void do_guest_modules(uint32_t pid)
{
	list_guest_modules(pid);
}

void do_tracing_by_name(const char *progname, const char *filename)
{
	/* If process already running, start tracing */
	uint32_t pid = find_pid_by_name(progname);
	uint32_t minus_one = (uint32_t) (-1);
	if (pid != minus_one) {
		do_tracing(pid, filename);
		return;
	}

	/* Otherwise, start monitoring for process start */
	procname_set(progname);
	strncpy(tracefile, filename, 256);
	term_printf("Waiting for process %s to start\n", progname);

#if 0
	/* Print configuration variables */
	print_conf_vars();
#endif
}

void do_save_state(uint32_t pid, uint32_t address, const char *filename)
{
	int err;
	err = save_state_at_addr(pid, address, filename);
	if (err)
		term_printf("Invalid pid or unable to open log file '%s'\n",
			    filename);
}

void do_load_config(const char *config_filepath)
{
	int err = 0;

	// Parse configuration file
	err = check_ini(config_filepath);
	if (err) {
		term_printf("Could not find INI file: %s\nTry again.\n",
			    config_filepath);
	}
}

xed_decoded_inst_t xedd_g;
extern xed_state_t dstate;
uint32_t skipped_addr;

void skip_to_next_inst()
{
	TranslationBlock *tb;
	uint8_t *tc_ptr;
	void (*gen_func) (void);
	unsigned long pc;
//      do_tracing_stop();

	skipped_addr = savedeip;
	term_printf("in exceitpion to bad inst %x jmp_target_ins\n",
		    skipped_addr);
//      fprintf(tracelog, "current eip %x in exceitpion to bad inst %x jmp_target_ins\n",
//      cpu_single_env->current_tb->pc, skipped_addr);

	if (is_cond_jmp_inst) {
		pc = jmp_target_ins_addr;
		fprintf(tracelog, "in exceitpion skip to jmp_target_ins %x\n",
			pc);
//              push_shadow_stack(next_ins_addr);
	} else {
		pc = next_ins_addr;
		fprintf(tracelog, "in exception take next addr %x\n", pc);
	}
#if 0
	tb = tb_find_pc(pc);
	fprintf(tracelog, "in exception tb %x\n", tb);
	if (tb) {
		/* the PC is inside the translated code. It means that we have
		   a virtual CPU fault */
		int ret = cpu_restore_state(tb, cpu_single_env, pc, NULL);
//              if(ret==0)
//                      fprintf(tracelog,"successfully take next addr\n");
	}
	tb = tb_find_pc(prev_basic_block_addr);

	fprintf(tracelog, "in exception tb %x basic block\n", tb);
	fprintf(tracelog, "current tb->cs_base %x tc->ptr %x\n",
		cpu_single_env->current_tb->cs_base,
		cpu_single_env->current_tb->tc_ptr);
	if (tb) {
		/* the PC is inside the translated code. It means that we have
		   a virtual CPU fault */
		//cpu_single_env->current_tb=tb;
		cpu_single_env->current_tb->tc_ptr = tb->tc_ptr;

//              int ret=cpu_restore_state(tb, cpu_single_env, prev_basic_block_addr, NULL);
//              if(ret==0)
		term_printf("successfully restore next addr\n");
	}
#endif
	uint64_t flags;
	uint32_t cs_base;
	flags = cpu_single_env->hflags;
	flags |= (cpu_single_env->eflags & (IOPL_MASK | TF_MASK | VM_MASK));
	flags |= cpu_single_env->intercept;
	cs_base = cpu_single_env->segs[R_CS].base;

//      *TEMU_cpu_eip = pc;
	pc = TEMU_get_phys_addr(pc);
	tb = tb_find_slow(pc, cs_base, flags);

	cpu_restore_state(tb, cpu_single_env, next_ins_addr, NULL);
//tb_phys_invalidate(tb, -1); 
	cpu_resume_from_signal(cpu_single_env, NULL);
//      tc_ptr = tb->tc_ptr;

//      cpu_single_env->current_tb = tb;
//      gen_func=(void*)tc_ptr;
//      gen_func();

//      cpu_single_env->current_tb->tc_ptr = tb->tc_ptr;
	//         int ret=cpu_restore_state(tb, cpu_single_env, next_ins_addr, NULL);
	//          if(ret==0)
	//      term_printf("successfully restore next addr\n");
//      tlb_flush_page(cpu_single_env, pc);
//      tb_flush(cpu_single_env);
//*TEMU_cpu_eip = prev_basic_block_addr;

}

static void dynamic_disas_inst()
{
	uint8_t buf[15];
	char str[128];

	TEMU_read_mem(*TEMU_cpu_eip, 15, buf);

	xed_decoded_inst_zero_set_mode(&xedd_g, &dstate);

	xed_error_enum_t xed_error = xed_decode(&xedd_g,
						STATIC_CAST(const xed_uint8_t *,
							    buf),
						15);

	if (xed_error == XED_ERROR_NONE) {
		xed_decoded_inst_dump_intel_format(&xedd_g, str, sizeof(str),
						   0);
//#ifdef DEBUG_TAINT

		if (in_force_exec )
		{
			fprintf(tracelog, "%s!%s: eip=%08x %s\n", current_proc,
				current_mod, *TEMU_cpu_eip, str);
		}

//#endif
		illegal_inst = 0;
		ill_int_inst = 0;

		if (in_force_exec) {
			if (strstr(str, "add byte ptr")
			    || strstr(str, "add dword ptr")
			    || strstr(str, "and byte ptr")) {
				illegal_inst = 1;
			}

			if (strstr(str, "int") || strstr(str,"arpl")
			|| strstr(str,"clts")
			|| strstr(str,"lgdt")
			|| strstr(str,"lahf")
			|| strstr(str,"insb")
			|| strstr(str,"outsd")
			|| strstr(str,"arpl")
			|| strstr(str,"lidt")
			|| strstr(str,"lldt")
			|| strstr(str,"lmsw")
			|| strstr(str,"ltr")
			|| strstr(str,"sgdt")
			|| strstr(str,"sldt")
			|| strstr(str,"sidt")
			|| strstr(str,"smsw")
			|| strstr(str,"str"))
			{
				ill_int_inst = 1;
			}
		}

		if (in_force_exec || in_initial_exec) {
			strcat(basic_block_inst, str);
			strcat(basic_block_inst, "\n");
		}
	} else {
		return;
	}

	xed_iclass_enum_t opcode = xed_decoded_inst_get_iclass(&xedd_g);
	const xed_inst_t *xi = xed_decoded_inst_inst(&xedd_g);
	is_ret_inst = 0;
	is_lea_inst = 0;
	is_cond_jmp_inst = 0;
	is_jmp_inst = 0;
	is_call_inst = 0;

//      if(in_force_exec)
	{
		next_ins_addr = xed_decoded_inst_get_length(&xedd_g) + savedeip;
	}

	if (savedeip == skipped_addr) {
		*TEMU_cpu_eip = next_ins_addr;
	}

	(*instrument_functions[opcode]) (xi);

	if (is_library_call) {
		is_library_call = 0;
		next_library_call_addr = next_ins_addr;
	}

	if (in_force_exec && is_call_inst && (next_ins_addr < LIBRARY_BOUNDARY)) {
		uint32_t esp, ebp;
		uint32_t mem_addr;
		uint32_t time_stamp;
		read_reg(esp_reg, &esp);
		read_reg(ebp_reg, &ebp);

		time_stamp = get_mem_write_time_stamp(next_ins_addr);
		fprintf(tracelog,
			"push return addr in shadow stack, time_stamp %x\n",
			time_stamp);
		push_shadow_stack(next_ins_addr, time_stamp);
	}
	return;

//#ifdef DEBUG_TAINT
	fprintf(tracelog, "opcode %d\n", opcode);

	int op_idx = -1;
	int xed_ops = xed_inst_noperands(xi);
	if (op_idx >= MAX_NUM_OPERANDS)
		return;

	xed_reg_enum_t reg_id;
	uint32_t value;
	uint32_t mem_addr;
	uint32_t branch;
	int i;

	/* Iterate over the XED operands */
	for (i = 0; i < xed_ops; i++) {
		//assert(op_idx < MAX_NUM_OPERANDS);
		/* Get operand */
		const xed_operand_t *op = xed_inst_operand(xi, i);
		xed_operand_enum_t op_name = xed_operand_name(op);

		if (operand_is_reg(op_name, &reg_id)) {
			int regnum = xed2chris_regmapping[reg_id][1];
			value = TEMU_cpu_regs[regnum];

			if (reg_id == XED_REG_STACKPUSH) {
//                      is_stackpush = 1;
				fprintf(tracelog, "%d R %d %s %x PUSH\n", i,
					reg_id, xed_reg_enum_t2str(reg_id),
					value);
			} else if (reg_id == XED_REG_STACKPOP) {
//                      is_stackpop = 1;
				fprintf(tracelog, "%d R %d %s %x POP\n", i,
					reg_id, xed_reg_enum_t2str(reg_id),
					value);
			} else
				fprintf(tracelog, "%d R %d %s %x\n", i, reg_id,
					xed_reg_enum_t2str(reg_id), value);
#if 0
			taint_record_t record[4];
			uint64_t taint = get_reg_taint(reg_id, &record);
			if (taint) {
				fprintf(tracelog,
					"shadow R %08x %08x %d with %08x has taint = %d\n",
					record[0].value_tag,
					record[0].time_stamp,
					record[0].taint_size, savedeip, taint);
			}
			//      cpu_dump_state(cpu_single_env,tracelog,fprintf,0);

#endif
		} else if (operand_is_imm(op_name, &value)) {
			fprintf(tracelog, "%d I %x\n", i, value);
		} else if (operand_is_mem(op_name, &mem_addr, i)) {
			read_mem(mem_addr, 4, &value);
			fprintf(tracelog, "%d M %x V %x\n", i, mem_addr, value);

#if 0
			taint_record_t record[4];

			uint64_t taint =
			    get_virtmem_taint(mem_addr, 1, &record);
			if (taint) {
				fprintf(tracelog,
					"shadow M %08x %08x %d with %08x has taint = %d\n",
					record[0].value_tag,
					record[0].time_stamp,
					record[0].taint_size, savedeip, taint);
			}
#endif

		} else if (operand_is_relbr(op_name, &branch)) {
			fprintf(tracelog, "%d B %x\n", i, branch);
		} else if (operand_is_float(op_name)) {

			fprintf(tracelog, "%d float\n", i);
		} else {
			fprintf(tracelog, "%d unknown\n", i);
		}
	}
//#endif //DEBUG_TAINT

}

static void rewards_taint_propagate(int nr_src,
				    taint_operand_t * src_oprnds,
				    taint_operand_t * dst_oprnd, int mode)
{

	return;

	if (temu_plugin->monitored_cr3 != TEMU_cpu_cr[3])
		return;

	/* If tracing start condition not satisified, or not tracing return */
	if ((!tracing_start_condition) || (tracepid == 0))
		return;

	/* If not tracing kernel and kernel instruction , return */
	if (is_kernel_instruction() && !tracing_kernel())
		return;

	if (is_lea_inst == 1)	//No propagation
		return;

#ifdef DEBUG_TAINT
	int i;
	for (i = 0; i < nr_src; i++) {
		fprintf(tracelog,
			"src[%d]: type=%d size=%d taint=%u addr=%p records=%p\n",
			i, src_oprnds[i].type, src_oprnds[i].size,
			src_oprnds[i].taint, src_oprnds[i].addr,
			src_oprnds[i].records);
		taint_record_t *p = (taint_record_t *) (src_oprnds[i].records);
		if ((src_oprnds[i].taint == (1 << src_oprnds[i].size) - 1)
		    && p != NULL)
			fprintf(tracelog, "src value_tag=%p, time_stamp=%p\n",
				p->value_tag, p->time_stamp);
	}

	fprintf(tracelog,
		"dst: type=%d dst_size=%d dst_taint=%u dst_addr=%p dst_records=%p\n",
		dst_oprnd->type, dst_oprnd->size, dst_oprnd->taint,
		dst_oprnd->addr, dst_oprnd->records);

	taint_record_t *p2 = (taint_record_t *) (dst_oprnd->records);
	if ((dst_oprnd->taint == (1 << dst_oprnd->size) - 1) && p2 != NULL)
		fprintf(tracelog, "dst value_tag=%p, time_stamp=%p\n",
			p2->value_tag, p2->time_stamp);

	//disable table lookup
	if (mode == PROP_MODE_MOVE) {
		if (src_oprnds[0].taint != (1 << src_oprnds[0].size) - 1)
			goto _clean_dst;
		if (nr_src == 2)
			nr_src = 1;
	}
#endif

	default_taint_propagate(nr_src, src_oprnds, dst_oprnd, mode);

#ifdef DEBUG_TAINT
	p2 = (taint_record_t *) (dst_oprnd->records);
	if ((dst_oprnd->taint == (1 << dst_oprnd->size) - 1) && p2 != NULL)
		fprintf(tracelog, "after dst value_tag=%p, time_stamp=%p\n",
			p2->value_tag, p2->time_stamp);
#endif

	return;

      _clean_dst:
	if (dst_oprnd->type == OPERAND_REG)
		taintcheck_reg_clean2(dst_oprnd->addr, dst_oprnd->size);
	else if (dst_oprnd->type == OPERAND_MEM)
		taintcheck_clean_memory(dst_oprnd->addr, dst_oprnd->size);
	insn_tainted = 0;
}

void do_flush_log()
{
	fflush(testlog);
	if (tracelog)
		fflush(tracelog);
}

static void do_xforce(void)
{
	in_force_exec = 1;
}
static term_cmd_t rewards_term_cmds[] = {
	/* operating system information */
	{"guest_ps", "", list_procs,
	 "", "list the processes on guest system"},
	{"guest_modules", "i", do_guest_modules,
	 "pid", "list the modules of the process with <pid>"},
	{"linux_ps", "", do_linux_ps,
	 "", "list the processes on linux guest system"},

	{"type_inference", "", do_type_inference,
	 "", "perform type inference"},

	{"flush_log", "", do_flush_log,
	 "", "flush trace log file"},

	/* Rewareds added */

	/* operations to record instruction trace */
	{"trace", "iF", do_tracing,
	 "pid filepath",
	 "save the execution trace of a process into the specified file"},
	{"tracebyname", "sF", do_tracing_by_name,
	 "name filepath",
	 "save the execution trace of a process into the specified file"},
	{"trace_stop", "", do_tracing_stop,
	 "", "stop tracing current process(es)"},
	{"keep_exec", "", do_keep_execution,
	 "", "keep executing current process(es)"},
	{"tc_modname", "s", tc_modname,
	 "modulename", "start saving execution trace upon entering the "
	 "specified module"},
	{"tc_address", "i", tc_address,
	 "codeaddress", "start saving execution trace upon reaching the "
	 "specified virtual address"},
	{"tc_address_start", "ii", tc_address_start,
	 "codeaddress timehit", "start saving execution trace upon reaching "
	 "the specified virtual address for the (timehit+1)th times since "
	 "the call of this tc_address_start command"},
	{"tc_address_stop", "ii", tc_address_stop,
	 "codeaddress timehit", "stop saving execution trace upon reaching the "
	 "specified virtual address for the (timehit+1)th times since the "
	 "storing of execution trace"},

	{"filter_kernel_all", "i", set_kernel_all,
	 "state", "set flag to trace all kernel instructions in addition to "
	 "user instructions"},
	{"filter_kernel_partial", "i", set_kernel_partial,
	 "state", "set flag to trace kernel instructions that modify user "
	 "space memory"},

	/* operations to record memory state */
	{"save_state", "iis", do_save_state,
	 "pid address filepath",
	 "save the state (register and memory) of a process when its execution "
	 "hits the specified address "
	 "(address needs to be the first address in a basic block)"},

	/* operations for hooks */
	{"load_hooks", "FF", do_load_hooks,
	 "hooks_dirname  plugins_filepath",
	 "change hooks paths (hook directory and plugins.active)"},

	/* load a configuration file */
	{"load_config", "F", do_load_config,
	 "configuration_filepath", "load configuration info from given file"},

    { "do_xforce", "", do_xforce,
      "", "start xforce..."},
	/*  end */

	{NULL, NULL},
};

void rewards_loadmodule_notify(uint32_t pid, uint32_t cr3, char *name,
			       uint32_t base, uint32_t size)
{
	if (base < 0x80000000)
		return;

	insert_mem_object(base, size, name);	//insert a static memory object
}

typedef struct {
	char image_name[512];
	uint32_t stack[8];
	uint32_t hook_handle;
} hook_context_t;

static int MmLoadSystemImage_ret(void *opaque)
{
	hook_context_t *ctx = opaque;
	hookapi_remove_hook(ctx->hook_handle);
	if (TEMU_cpu_regs[R_EAX] != 0)	// return value is an error
		return 0;

	uint32_t base;
	TEMU_read_mem(ctx->stack[6], 4, &base);

	int offset;
	for (offset = strlen(ctx->image_name); offset >= 0; offset--) {
		if (ctx->image_name[offset] == '\\')
			break;
	}
	assert(offset >= 0);

	term_printf("MmLoadSystemImage: %s base=0x%08x\n",
		    ctx->image_name, base);
	//TODO:

	free(ctx);
	return 0;
}

static int MmLoadSystemImage_call(void *opaque)
{
	uint32_t esp;
	hook_context_t *ctx = malloc(sizeof(hook_context_t));
	TEMU_read_register(esp_reg, &esp);
	TEMU_read_mem(esp, 32, ctx->stack);
	uint16_t wchar;
	uint32_t addr;
	int i = 0;
	TEMU_read_mem(ctx->stack[1] + 4, 4, &addr);
	if (addr == 0) {
		free(ctx);
		return 0;
	}

	TEMU_read_mem(addr, 2, &wchar);
	ctx->image_name[i] = (char)wchar;
	while (wchar != 0) {
		++i;
		TEMU_read_mem(addr + 2 * i, 2, &wchar);
		ctx->image_name[i] = (char)wchar;
	}

	ctx->hook_handle =
	    hookapi_hook_return(ctx->stack[0], MmLoadSystemImage_ret, ctx,
				sizeof(hook_context_t));
	return 0;
}

static int rewards_init()
{
	function_map_init();
	init_hookapi();
	procmod_init();
	ko_monitor_init();

	hookapi_hook_function(1, 0x805a5c9f, MmLoadSystemImage_call, NULL, 0);
	testlog = fopen("test.log", "w");
	if (testlog == NULL) {
		term_printf("Cannot open test.log!\n");
		exit(1);
	}

	rewards_load_hooks("hook_plugin.ini", ".");
	do_enable_emulation();	//we just enable it from start    

	add_log("rewardsplugin", "rewards_plugin.log", 1);

	xed_decoded_inst_set_mode(&xedd_g, XED_MACHINE_MODE_LEGACY_32,
				  XED_ADDRESS_WIDTH_32b);

	setup_inst_hook();
	xed2_init();

	init_shadow_stack_record();

	init_shadow_mem_write_memory();	//tracking unpacking code

	init_bb_hash_table();

	return 0;
}

static void rewards_cleanup()
{
	ko_monitor_cleanup();

	if (tracelog)
		fclose(tracelog);

	fclose(testlog);

	procmod_cleanup();
	hookapi_cleanup();

	function_map_cleanup();

	destroy_and_dump_bb_hash_table_for_pid_tid(tracepid, current_tid);
	free_next_branch_hash_table();

	free_shadow_mem_write_memory();	//clean up the unpacking tracking code
}

char mod_func_name[128];

char *get_func_name_by_addr(uint32_t eip)
{
	struct names_t *names = query_name(eip);
	if ((names != NULL)) {
		if ((names->fun_name != NULL)
		    && (names->mod_name != NULL)) {
			sprintf(mod_func_name, "%s.%s", names->mod_name,
				names->fun_name);
			return mod_func_name;

		} else {
			return "Unresolved";
		}
	}
}

void rewards_insn_begin()
{
	/* If tracing start condition not satisified, or not tracing return */
	if ((!tracing_start_condition) || (tracepid == 0))
		return;

	/* If not tracing kernel and kernel instruction , return */
	if (is_kernel_instruction() && !tracing_kernel())
		return;

	if (temu_plugin->monitored_cr3 != TEMU_cpu_cr[3])
		return;

	/* Check if this is a system call */
	if (conf_log_external_calls) {
		uint32_t eip = *TEMU_cpu_eip;
		struct names_t *names = query_name(eip);
		uint32_t curr_tid = get_current_tid();
		if ((names != NULL) && (calllog)) {
			if ((names->fun_name != NULL)
			    && (names->mod_name != NULL)) {
				fprintf(calllog,
					"Process %d TID: %d -> %s::%s @ EIP: 0x%08x\n",
					tracepid, curr_tid, names->mod_name,
					names->fun_name, eip);
			} else {
				fprintf(calllog,
					"Process %d TID: %d -> ?::? @ EIP: 0x%08x\n",
					tracepid, curr_tid, eip);
			}
		}
	}
//      dump_tb();

	savedeip = *TEMU_cpu_eip;

//      PATCH_BEGIN_VICTIM_INST_FOR_NEXT_EIP(0x401003, 0x401044);

	if (savedeip <= LIBRARY_BOUNDARY) {
//      if (savedeip <= LIBRARY_BOUNDARY) {
//              set_kernel_all(1);      
		//      start_emulation();
		if (!in_initial_exec && !in_force_exec) {
			start_emulation();
		}
	}
#if 0
	if (savedeip == 0x40100a) {
//              restore_to_new_eip(0x401036);
//              patch_inst_for_next_eip(0x40100a,0x401036);
		fprintf(tracelog, "patch to next eip\n");
//              set_kernel_all(1);      
		//      start_emulation();
	}
#endif

	dynamic_disas_inst();

#if 0
	if (ill_int_inst)
    {
			if (shadow_stack_is_empty()) {
				fprintf(tracelog, "FINISHED, over\n");
				return do_tracing_stop();
			}
			ret_value =
			    pop_shadow_stack(&restore_eip, &restore_esp,
					     &restore_ebp);

            fprintf(tracelog, "after pop shadow stack\n");
			if (ret_value == 0) {
				fprintf(tracelog, "FINISHED, over\n");
				return do_tracing_stop();
			}

			TEMU_write_register(esp_reg, &restore_esp);
			TEMU_write_register(ebp_reg, &restore_ebp);
			TEMU_write_register(eax_reg, &restore_eax);
			TEMU_write_register(ebx_reg, &restore_ebx);
			TEMU_write_register(ecx_reg, &restore_ecx);
			TEMU_write_register(edx_reg, &restore_edx);
			TEMU_write_register(esi_reg, &restore_esi);
			TEMU_write_register(edi_reg, &restore_edi);

			fprintf(tracelog,
				"ILLegal inst RESTOREING context to eip %x esp %x\n",
				restore_eip, restore_esp);
			RESTORE_CONTEXT_TO_NEXT_EIP(restore_eip);
	}
#endif

}

uint32_t keep_exception;
uint32_t inst_count;

uint32_t fault_count;
uint32_t continued_fault;
uint32_t begin_fault_count;

uint32_t retry_count;
uint32_t continued_retry;
uint32_t begin_retry_count;

void check_and_update_fault_count()
{
	if (fault_count == 0) {
		begin_fault_count = inst_count;
		fault_count++;
		continued_fault = 0;
	} else {
		if (fault_count + begin_fault_count == inst_count) {
			continued_fault++;
			fprintf(tracelog, "continued fault %d\n",
				continued_fault);
		} else {
			fprintf(tracelog, "new_fault fault %d\n",
				continued_fault);
			continued_fault = 0;
			fault_count = -1;
		}
		fault_count++;
	}
}

void check_and_update_retry_count()
{
	if (retry_count == 0) {
		begin_retry_count = inst_count;
		retry_count++;
		continued_retry = 0;
	} else {
		if (retry_count + begin_retry_count == inst_count) {
			continued_retry++;
			fprintf(tracelog, "continued retry %d\n",
				continued_retry);
		} else {
			fprintf(tracelog, "new_fault retry %d\n",
				continued_retry);
			continued_retry = 0;
			retry_count = -1;
		}
		retry_count++;
	}
}

void rewards_insn_end()
{
	/* If tracing start condition not satisified, or not tracing return */
	if ((!tracing_start_condition) || (tracepid == 0))
		return;

	/* If not tracing kernel and kernel instruction , return */
	if (is_kernel_instruction() && !tracing_kernel())
		return;

	if (temu_plugin->monitored_cr3 != TEMU_cpu_cr[3])
		return;

	/* If partially tracing kernel but did not access user memory, return */
	if (is_kernel_instruction()) {
		if (tracing_kernel_partial() && (!access_user_mem))
			return;
#if TAINT_ENABLED
		if (tracing_kernel_tainted() && (!insn_tainted))
			return;
#endif
	}


	//Normal execution
//      return;

	inst_count++;
    if (in_force_exec)
		fprintf(tracelog, "ins end, and next eip = %x, inst_count %d\n", *TEMU_cpu_eip, inst_count);
#if 0
	if (in_force_exec)
		if (savedeip == 0x407c69) {
			fprintf(tracelog, "the stopped eip called\n");
			goto NORMAL_RESTORE;
		}
#endif
	if (is_ret_inst == 1) {
		uint32_t esp;
		uint32_t mem_addr;
		read_reg(esp_reg, &esp);
		//pop_call_stack(p_call_stack_g, esp);
		fprintf(tracelog, "POP_STACK R 0x%08x\n", esp);
		curr_basic_block_end_type = T_RET;
/*
		if(in_initial_exec)
		if (esp > starting_esp) {
			in_initial_exec = 0;
			in_force_exec = 1;
			fprintf(tracelog, "NOW ENTERING FORCING MODE\n");
			term_printf("entering forcing mode\n");

			uint32_t restore_eip, restore_esp, restore_ebp;
			if(pop_shadow_stack(&restore_eip, &restore_esp, &restore_ebp))
			{
				TEMU_write_register(ebp_reg, &restore_ebp);
				TEMU_write_register(esp_reg, &restore_esp);
			}
			else
			{
				fprintf(tracelog, "FINISHED, over\n");
				return do_tracing_stop();
			}

			fprintf(tracelog, "BEGIN_RESTOREING context to eip %x esp %x\n", restore_eip, restore_esp);
			RESTORE_CONTEXT_TO_NEXT_EIP(restore_eip);
		}
*/

		if (in_force_exec)
			if (*TEMU_cpu_eip < 0x400000) {
				fprintf(tracelog,
					"return to heap or stack to eip %x\n",
					*TEMU_cpu_eip);
				goto NORMAL_RESTORE;
			}
	}

	if (is_cond_jmp_inst) {
		if (*TEMU_cpu_eip <= LIBRARY_BOUNDARY) {
			//      fprintf(tracelog, "in lib space, return\n");

			uint32_t esp, ebp;
			uint32_t mem_addr;
			uint32_t time_stamp;

			if (*TEMU_cpu_eip == jmp_target_ins_addr) {
				time_stamp =
				    get_mem_write_time_stamp(next_ins_addr);
				fprintf(tracelog,
					"take target addr, time_stamp %x\n",
					time_stamp);
				push_shadow_stack(next_ins_addr,
						  time_stamp);
			} else {
				time_stamp =
				    get_mem_write_time_stamp
				    (jmp_target_ins_addr);
				push_shadow_stack(jmp_target_ins_addr,
						  time_stamp);
				fprintf(tracelog,
					"take next addr, time_stamp %x\n",
					time_stamp);
			}
		}
	}

	if (*TEMU_cpu_eip == 0x7c90eaec)	//Exception
	{
		fprintf(tracelog,
			"begin happened an exception inst_count %x fault_count %x begin_fault %x\n",
			inst_count, fault_count, begin_fault_count);

		check_and_update_fault_count();

		if (continued_fault == 10) {
			fprintf(tracelog, "happened a continued exception\n");
			fault_count = 0;
			goto NORMAL_RESTORE;
		} else {
			fprintf(tracelog,
				"end happened an exception inst_count %x fault_count %x begin_fault %x\n",
				inst_count, fault_count, begin_fault_count);
			fprintf(tracelog, "happened an exception\n");
			RESTORE_CONTEXT_TO_NEXT_EIP(next_ins_addr);
		}
	}
///////////////////////////////////////////////////////////////////////////
	if(in_force_exec)
	{
		if(ill_int_inst || illegal_inst)
		{
				fprintf(tracelog,
					"encounter illegal instruction illegal\n");
				ill_int_inst = 0;
				illegal_inst = 0;

			goto NORMAL_RESTORE;
		}

	}

	if (in_force_exec)
		if (*TEMU_cpu_eip < STACK_BOUNDARY) {

			if (continued_retry <= 20 && restore_eip !=0 ) {
				fprintf(tracelog,
					"happened a continued retry illegal %d\n", continued_retry);
				retry_count = 0;

				fprintf(tracelog,
					"invalid context restore next %p, curr %p, and retry\n",
					next_ins_addr, *TEMU_cpu_eip);
				TEMU_write_register(esp_reg, &restore_esp);
				TEMU_write_register(ebp_reg, &restore_ebp);
				TEMU_write_register(eax_reg, &restore_eax);
				TEMU_write_register(ebx_reg, &restore_ebx);
				TEMU_write_register(ecx_reg, &restore_ecx);
				TEMU_write_register(edx_reg, &restore_edx);
				TEMU_write_register(esi_reg, &restore_esi);
				TEMU_write_register(edi_reg, &restore_edi);


				fprintf(tracelog,
					"RESTOREING context to eip %x esp %x again\n",
					restore_eip, restore_esp);
				RESTORE_CONTEXT_TO_NEXT_EIP(restore_eip);
			} else {
				fprintf(tracelog,
					"eip = %x goes to stack or library or heap or somewhere\n",
					*TEMU_cpu_eip);
				goto NORMAL_RESTORE;
			}
	}

	//skip all library call in exec mode
	if (in_force_exec)
		if (*TEMU_cpu_eip > LIBRARY_BOUNDARY) {

		if ((!is_ret_inst) && (!is_jmp_inst) && (!is_call_inst) && (!is_cond_jmp_inst) && (restore_eip !=0))
		{
				if (restore_eip>LIBRARY_BOUNDARY)
				{
					goto NORMAL_RESTORE;
				}

				fprintf(tracelog,
					"invalid context restore next %p, curr %p, and retry %d, continued retry %d\n",
					next_ins_addr, *TEMU_cpu_eip, retry_count, continued_retry);
				TEMU_write_register(esp_reg, &restore_esp);
				TEMU_write_register(ebp_reg, &restore_ebp);
				TEMU_write_register(eax_reg, &restore_eax);
				TEMU_write_register(ebx_reg, &restore_ebx);
				TEMU_write_register(ecx_reg, &restore_ecx);
				TEMU_write_register(edx_reg, &restore_edx);
				TEMU_write_register(esi_reg, &restore_esi);
				TEMU_write_register(edi_reg, &restore_edi);

				restore_write_mem(p_current_write_head_restore);

				fprintf(tracelog,
					"RESTOREING context to eip %x esp %x again\n",
					restore_eip, restore_esp);
				RESTORE_CONTEXT_TO_NEXT_EIP(restore_eip);
		}

			fprintf(tracelog,
				"current eip %p next_library_call_addr %p\n",
				*TEMU_cpu_eip, next_library_call_addr);
			if (next_library_call_addr < LIBRARY_BOUNDARY
			    &&
			    !next_block_has_been_visited
			    (next_library_call_addr)) {
				RESTORE_CONTEXT_TO_NEXT_EIP
				    (next_library_call_addr);
			} else
				goto NORMAL_RESTORE;
	}

#if 0
	if (exception_call_is_set && keep_exception > 2) {
		exception_call_is_set = 0;
		keep_exception = 0;
		goto NORMAL_RESTORE;
	}

	if (skip_call_is_set) {
		skip_call_is_set = 0;
		uint32_t restore_eip, restore_esp;
		read_reg(esp_reg, &restore_esp);
		restore_esp = restore_esp + 4;
		TEMU_write_register(esp_reg, &restore_esp);

		fprintf(tracelog,
			"BEGIN_RESTOREING HOOK_API_SIKP context to eip %x esp %x\n",
			next_skipped_call_insn_addr, restore_esp);
		RESTORE_CONTEXT_TO_NEXT_EIP(next_skipped_call_insn_addr);
	}
//#endif
	if (exception_call_is_set) {
		exception_call_is_set = 0;
		if (next_exception_insn_addr < LIBRARY_BOUNDARY) {
			fprintf(tracelog,
				"BEGIN_RESTOREING EXCEPTION_SKIP context to eip %x and keep original esp\n",
				next_exception_insn_addr);
			RESTORE_CONTEXT_TO_NEXT_EIP(next_exception_insn_addr);
		} else {
			goto NORMAL_RESTORE;
		}
	}
//#if 0
	if (savedeip == 0x401008) {
		uint32_t ebp = GetEBP();
		uint32_t *ret_addr = ebp;
		uint32_t *mem_addr = (*ret_addr + 4);

		*mem_addr = create_tb_for_pc(0x401036);
		*TEMU_cpu_eip = 0x401036;
//              restore_to_new_eip(0x401036);
//              patch_inst_for_next_eip(0x40100a,0x401036);
	}
#endif
//      PATCH_VICTIM_INST_FOR_NEXT_EIP(0x401003, 0x401044);

	if (in_force_exec) {
		fprintf(tracelog, "current eip %p\n", *TEMU_cpu_eip);

		if ((!is_ret_inst) && (!is_jmp_inst) && (!is_call_inst) && (!is_cond_jmp_inst)
		    && (next_ins_addr != *TEMU_cpu_eip)) {
			check_and_update_retry_count();

			if (continued_retry == 20) {
				fprintf(tracelog,
					"happened a continued retry %d\n", continued_retry);
				retry_count = 0;

				goto NORMAL_RESTORE;
			}

			if( restore_eip !=0 )
			{
				fprintf(tracelog,
					"invalid context restore next %p, curr %p, and retry %d, continued retry %d\n",
					next_ins_addr, *TEMU_cpu_eip, retry_count, continued_retry);
				TEMU_write_register(esp_reg, &restore_esp);
				TEMU_write_register(ebp_reg, &restore_ebp);
				TEMU_write_register(eax_reg, &restore_eax);
				TEMU_write_register(ebx_reg, &restore_ebx);
				TEMU_write_register(ecx_reg, &restore_ecx);
				TEMU_write_register(edx_reg, &restore_edx);
				TEMU_write_register(esi_reg, &restore_esi);
				TEMU_write_register(edi_reg, &restore_edi);

				restore_write_mem(p_current_write_head_restore);

				fprintf(tracelog,
					"RESTOREING context to eip %x esp %x again\n",
					restore_eip, restore_esp);
				RESTORE_CONTEXT_TO_NEXT_EIP(restore_eip);
			}
			else
			{
				goto NORMAL_RESTORE;
			}

		}

		if (is_call_inst || is_cond_jmp_inst) {
			insert_or_update_bb(curr_basic_block_addr,
					    *TEMU_cpu_eip, basic_block_inst,
					    prev_basic_block_start_type,
					    curr_basic_block_end_type,
					    next_ins_addr);
			basic_block_inst[0] = '\0';
			prev_basic_block_start_type = curr_basic_block_end_type;
			prev_basic_block_addr = curr_basic_block_addr;
		}

		if (next_block_has_been_visited(*TEMU_cpu_eip)) {
			fprintf(tracelog, "update bb2 for bbaddr %p eip %p\n",
				curr_basic_block_addr, *TEMU_cpu_eip);
			update_bb_to(curr_basic_block_addr, *TEMU_cpu_eip);

NORMAL_RESTORE:
			if (shadow_stack_is_empty()) {
				fprintf(tracelog, "FINISHED, over\n");
				return do_tracing_stop();
			}
			ret_value =
			    pop_shadow_stack(&restore_eip, &restore_esp,
					     &restore_ebp);

			next_ins_addr = restore_eip;
            fprintf(tracelog, "after pop shadow stack\n");
			if (ret_value == 0) {
				fprintf(tracelog, "FINISHED, over\n");
				return do_tracing_stop();
			}

			restore_write_mem(p_current_write_head_restore);

			TEMU_write_register(esp_reg, &restore_esp);
			TEMU_write_register(ebp_reg, &restore_ebp);
			TEMU_write_register(eax_reg, &restore_eax);
			TEMU_write_register(ebx_reg, &restore_ebx);
			TEMU_write_register(ecx_reg, &restore_ecx);
			TEMU_write_register(edx_reg, &restore_edx);
			TEMU_write_register(esi_reg, &restore_esi);
			TEMU_write_register(edi_reg, &restore_edi);

			fprintf(tracelog,
				"RESTOREING context to eip %x esp %x\n",
				restore_eip, restore_esp);
			RESTORE_CONTEXT_TO_NEXT_EIP(restore_eip);
		}
	}

}

#ifdef MEM_CHECK
void tracing_mem_read(uint32_t virt_addr, uint32_t phys_addr, int size)
{
	if (temu_plugin->monitored_cr3 != TEMU_cpu_cr[3])
		return;

	/* If tracing start condition not satisified, or not tracing return */
	if ((!tracing_start_condition) || (tracepid == 0))
		return;

	/* If not tracing kernel and kernel instruction , return */
	if (is_kernel_instruction() && !tracing_kernel())
		return;

#ifdef DEBUG_TAINT
	fprintf(tracelog, "mem_read virt_addr %x phys_addr %x\n", virt_addr,
		phys_addr);
#endif

	return;

	taint_record_t record[8];
	uint64_t taint = get_virtmem_taint(virt_addr, size, &record);
	if (taint) {
		fprintf(tracelog,
			"M 0x%08x 0x%02d 0x%08x 0x%08x %02d r\n", virt_addr,
			size, record[0].value_tag, record[0].time_stamp,
			record[0].taint_size);

		int i;
		for (i = 0; i < size; i++)
			if (record[i].network_offset) {
				fprintf(tracelog,
					"N 0x%08x %08d r\n", virt_addr + i,
					record[i].network_offset);

				fprintf(tracenetlog,
					"%08d N 0x%08x %08d %s\n", current_tid,
					virt_addr + i, record[i].network_offset,
					p_call_string_g);
			}
	}
}

void tracing_mem_write(uint32_t virt_addr, uint32_t phys_addr, int size)
{

	if (temu_plugin->monitored_cr3 != TEMU_cpu_cr[3])
		return;
	/* If tracing start condition not satisified, or not tracing return */
	if ((!tracing_start_condition) || (tracepid == 0))
		return;

	/* If not tracing kernel and kernel instruction , return */
	if (is_kernel_instruction() && !tracing_kernel())
		return;

	fprintf(tracelog, "mem_write virt_addr %x time_stamp %x\n",
		virt_addr, global_time_stamp);

	uint32_t i;

	read_mem(virt_addr, 4, &i);
	insert_addr_value(virt_addr, i);

	for (i = 0; i < size; i++) {
		set_mem_write_time_stamp(virt_addr + i, global_time_stamp);
	}

#ifdef DEBUG_TAINT
	fprintf(tracelog, "mem_write virt_addr %x phys_addr %x size %d\n",
		virt_addr, phys_addr, size);
#endif

	taint_record_t record[8];
	uint64_t taint = get_virtmem_taint(virt_addr, size, &record);
	if (taint) {
		fprintf(tracelog,
			"M 0x%08x 0x%02d 0x%08x 0x%08x 0x%02d w\n", virt_addr,
			size, record[0].value_tag, record[0].time_stamp,
			record[0].taint_size);
	}

}
#endif				/* #ifdef MEMCHECK */

#ifdef REG_CHECK

void tracing_reg_read(uint32_t regidx, int size)
{
	return;

	if (temu_plugin->monitored_cr3 != TEMU_cpu_cr[3])
		return;

	/* If tracing start condition not satisified, or not tracing return */
	if ((!tracing_start_condition) || (tracepid == 0))
		return;

	/* If not tracing kernel and kernel instruction , return */
	if (is_kernel_instruction() && !tracing_kernel())
		return;

	fprintf(tracelog, "reg_read idx %d size %d\n", regidx, size);

}

void tracing_reg_write(uint32_t regidx, int size)
{
	return;

	if (temu_plugin->monitored_cr3 != TEMU_cpu_cr[3])
		return;

	/* If tracing start condition not satisified, or not tracing return */
	if ((!tracing_start_condition) || (tracepid == 0))
		return;

	/* If not tracing kernel and kernel instruction , return */
	if (is_kernel_instruction() && !tracing_kernel())
		return;

	fprintf(tracelog, "reg_write idx %d size %d\n", regidx, size);
}

#endif

plugin_interface_t *init_plugin()
{
	rewards_interface.plugin_cleanup = rewards_cleanup;
	rewards_interface.taint_record_size = sizeof(taint_record_t);

	rewards_interface.taint_propagate = rewards_taint_propagate;

	rewards_interface.guest_message = rewards_guest_message;

	rewards_interface.block_begin = rewards_block_begin;
	rewards_interface.insn_begin = rewards_insn_begin;
	rewards_interface.insn_end = rewards_insn_end;

	rewards_interface.term_cmds = rewards_term_cmds;
	rewards_interface.info_cmds = rewards_info_cmds;
	rewards_interface.send_keystroke = rewards_send_keystroke;
	rewards_interface.bdrv_open = rewards_bdrv_open;
	rewards_interface.taint_disk = rewards_taint_disk;

	rewards_interface.nic_recv = rewards_nic_recv;
	rewards_interface.nic_send = rewards_nic_send;

	loadmodule_notify = rewards_loadmodule_notify;

#ifdef MEM_CHECK
	rewards_interface.mem_read = tracing_mem_read;
	rewards_interface.mem_write = tracing_mem_write;
#endif				/* #ifdef MEM_CHECK */

#ifdef REG_CHECK
	rewards_interface.reg_read = tracing_reg_read;
	rewards_interface.reg_write = tracing_reg_write;
#endif

	rewards_init();
	return &rewards_interface;
}

void restore_to_new_eip(uint32_t pc)
{
	TranslationBlock *tb;

	dump_tb();
	if (cpu_single_env == NULL) {
		fprintf(tracelog, "cpu_single_env NULL\n");
		return;
	}

	fprintf(tracelog, "before tb invalidate\n");
//      if(cpu_single_env->current_tb !=NULL)
//              tb_phys_invalidate(cpu_single_env->current_tb, -1);

	fprintf(tracelog, "before tb flush\n");
//      tb_flush(cpu_single_env);
	fprintf(tracelog, "after tb flush\n");

	uint64_t flags;
	uint32_t cs_base;
	flags = cpu_single_env->hflags;
	flags |= (cpu_single_env->eflags & (IOPL_MASK | TF_MASK | VM_MASK));
	flags |= cpu_single_env->intercept;
	cs_base = cpu_single_env->segs[R_CS].base;

	cpu_single_env->eip = pc;
//
//      tb_gen_code(cpu_single_env, pc, cs_base, flags);
//      *TEMU_cpu_eip = pc;

//      tb=tb_find_fast();

//      pc = TEMU_get_phys_addr(pc);
	uint32_t code_size;

//	while(1)
	{
		tb = my_tb_find_slow(pc, cs_base, flags, &code_size);
		fprintf(tracelog, "restore to new code_ptr %x, code_size %x\n",
			tb->tc_ptr, code_size);
//		if(code_size!=0)
//			break;
	}

	cpu_restore_state(tb, cpu_single_env, tb->tc_ptr, NULL);
/*
	if(cpu_single_env->current_tb !=NULL)
	{
		memcpy(cpu_single_env->current_tb->tc_ptr, tb->tc_ptr, code_size);
		fprintf(tracelog, "restore to new eip %x, tb %x tb->pc %x\n", \
			 pc, tb, tb->pc);
		cpu_single_env->regs[8] = 0;
		cpu_single_env->current_tb->tc_ptr = tb->tc_ptr;
		cpu_single_env->eip = pc;

	}
	else
		fprintf(tracelog, "cannot restore to new eip %x, tb %x tb->pc %x\n", \
		 pc, tb, tb->pc);
*/

/*
	cpu_single_env->current_tb = tb;
	uint8_t *tc_ptr;
	void (*gen_func)(void);

	tc_ptr = tb->tc_ptr;
*/
//      fprintf(tracelog, "restore to new eip %x, tb %x tb->pc %x\n", \
//               pc, tb, tb->pc);

//      cpu_single_env->current_tb = tb;
//      gen_func=(void*)tc_ptr;
//      gen_func();
#if 0
//      do_tracing_stop();
	if (tb != NULL) {
		fprintf(tracelog, "restore to new eip %x, tb %x tb->pc %x\n",
			pc, tb, tb->pc);
		if (cpu_restore_state(tb, cpu_single_env, pc, NULL) == -1)
			fprintf(tracelog, "unsuccessful\n");

	} else
		fprintf(tracelog, "didn't find the tb\n");
#endif

}

uint32_t GetEBP()
{
	uint32_t ebp;
	__asm__ __volatile__("movl (%%ebp), %0":"=a"(ebp)
	    );
	return ebp;
}

uint8_t *create_tb_for_pc(uint32_t pc)
{
	TranslationBlock *tb;

	if (cpu_single_env == NULL) {
		fprintf(tracelog, "cpu_single_env NULL\n");
		return;
	}

	fprintf(tracelog, "called tb_for_pc\n");

	fprintf(tracelog, "before tb invalidate\n");
//      if(cpu_single_env->current_tb !=NULL)
//              tb_phys_invalidate(cpu_single_env->current_tb, -1);

	fprintf(tracelog, "before tb flush\n");
//      tb_flush(cpu_single_env);
	fprintf(tracelog, "after tb flush\n");

	uint64_t flags;
	uint32_t cs_base;
	flags = cpu_single_env->hflags;
	flags |= (cpu_single_env->eflags & (IOPL_MASK | TF_MASK | VM_MASK));
	flags |= cpu_single_env->intercept;
	cs_base = cpu_single_env->segs[R_CS].base;

	//cpu_single_env->eip = pc;
//
//      tb_gen_code(cpu_single_env, pc, cs_base, flags);

//      *TEMU_cpu_eip = pc;

//      tb=tb_find_fast();

//      pc = TEMU_get_phys_addr(pc);
	uint32_t code_size;
	tb = my_tb_find_slow(pc, cs_base, flags, &code_size);

	/*
	while(1)
	{
		tb = my_tb_find_slow(pc, cs_base, flags, &code_size);
		fprintf(tracelog, "restore to new code_ptr %x, code_size %x\n",
			tb->tc_ptr, code_size);
		if(code_size!=0)
			break;
	}

	*/
	fprintf(tracelog,
		"restore to new code_ptr %x, code_size %x, for pc %x\n",
		tb->tc_ptr, code_size, pc);

	*TEMU_cpu_eip = pc;

	return tb->tc_ptr;

//      cpu_restore_state(tb, cpu_single_env, tb->tc_ptr, NULL);
/*
	if(cpu_single_env->current_tb !=NULL)
	{
		memcpy(cpu_single_env->current_tb->tc_ptr, tb->tc_ptr, code_size);
		fprintf(tracelog, "restore to new eip %x, tb %x tb->pc %x\n", \
			 pc, tb, tb->pc);
		cpu_single_env->regs[8] = 0;
		cpu_single_env->current_tb->tc_ptr = tb->tc_ptr;
		cpu_single_env->eip = pc;

	}
	else
		fprintf(tracelog, "cannot restore to new eip %x, tb %x tb->pc %x\n", \
		 pc, tb, tb->pc);
*/

/*
	cpu_single_env->current_tb = tb;
	uint8_t *tc_ptr;
	void (*gen_func)(void);

	tc_ptr = tb->tc_ptr;
*/
//      fprintf(tracelog, "restore to new eip %x, tb %x tb->pc %x\n", \
//               pc, tb, tb->pc);

//      cpu_single_env->current_tb = tb;
//      gen_func=(void*)tc_ptr;
//      gen_func();
#if 0
//      do_tracing_stop();
	if (tb != NULL) {
		fprintf(tracelog, "restore to new eip %x, tb %x tb->pc %x\n",
			pc, tb, tb->pc);
		if (cpu_restore_state(tb, cpu_single_env, pc, NULL) == -1)
			fprintf(tracelog, "unsuccessful\n");

	} else
		fprintf(tracelog, "didn't find the tb\n");
#endif

}
