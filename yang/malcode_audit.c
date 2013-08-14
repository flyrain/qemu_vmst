/* Audit malicious code execution 
   Zhiqiang Lin 
   zlin@cs.purdue.edu
   copy(c) 2008 SRI International 
*/
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <assert.h>

#include "cpu.h"
#include "exec-all.h"
#include "disas.h"
#include "dis-asm.h"
#include "malcode_audit.h"
#include "bb_helper.h"



static uint32_t tid;
static uint32_t ppid;
static uint32_t pid;
static uint32_t start_log;
int monitored_eip;
target_ulong monitored_esp=0;
char inst_g[64];
uint32_t jmp_target;
uint32_t call_target;

mon_pid_tid_list *p_mon_pid_tid_list_head=NULL;
mon_pid_list *p_mon_pid_list_head=NULL;
static int num_pid_tid_list_node=0;
static int num_pid_list_node=0;


/*---------------------------------------------------------------------------------
 * following functions are used to manage thread level audit					  *
 * -------------------------------------------------------------------------------*/
int is_audited_pid_tid(uint32_t pid, uint32_t tid)
{
	mon_pid_tid_list *p;


	if(num_pid_tid_list_node==0)
		return 0;

	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid)&&(tid==p->tid))
			return 1;
		p=p->next;
	}
	return 0;
}

int is_parent_process_audited(uint32_t ppid)
{
	mon_pid_tid_list *p;

	if(num_pid_tid_list_node==0)
		return 0;

	p=p_mon_pid_tid_list_head;

	while(p!=NULL)
	{
		if((ppid==p->pid))
			return 1;
		p=p->next;
	}
	return 0;
}



void traverse_mon_pid_tid_list()
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	printf("\nbegin traverse\n");
	while(p!=NULL)
	{
		printf("pid=%d tid=%d, hash_table=%p, image_name=%s\n",p->pid,p->tid, p->bbht,p->image_name);
		p=p->next;
	}
	printf("end traverse\n");
	return NULL;
}

void dump_mon_pid_list2()
{
	mon_pid_list *p;
	p=p_mon_pid_list_head;
	while(p!=NULL)
	{
		printf("pid=%d image_name=%s image_buffer %p\n",p->pid, p->image_name,p->image_buffer);
		p=p->next;
	}
}

void dump_mon_pid_tid_list2()
{
	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		printf("pid=%d tid=%d, image_name=%s\n",p->pid,p->tid, p->image_name);
		p=p->next;
	}
}

void dump_mon_pid_list()
{
	mon_pid_list *p;
	p=p_mon_pid_list_head;
	while(p!=NULL)
	{
		term_printf("pid=%d image_name=%s image_buffer %p\n",p->pid, p->image_name,p->image_buffer);
		p=p->next;
	}
}

void dump_mon_pid_tid_list()
{
	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		term_printf("pid=%d tid=%d, image_name=%s hash_table=%p\n",p->pid,p->tid, p->image_name,p->bbht);
		p=p->next;
	}
}

void insert2_mon_pid_tid_list(mon_pid_tid_list *p);
void insert2_mon_pid_list(mon_pid_list *p);

char* get_image_buffer_by_pid(uint32_t pid)
{

	mon_pid_list *p;
	p=p_mon_pid_list_head;

	while(p!=NULL)
	{
		if((pid==p->pid))
		{
			return p->image_buffer;
		}
		p=p->next;
	}
	return NULL;
}

int is_monitored_pid(uint32_t pid)
{

	mon_pid_list *p;
	p=p_mon_pid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid))
		{
			return 1;
		}
		p=p->next;
	}
	return 0;
}
char* get_image_name_by_pid(uint32_t pid)
{

	mon_pid_list *p;
	p=p_mon_pid_list_head;

	while(p!=NULL)
	{
		if((pid==p->pid))
		{
			return p->image_name;
		}
		p=p->next;
	}
	return NULL;
}

extern uint32_t terminated_process_id;
void allocate_a_mon_pid_tid_list_node(uint32_t pid, uint32_t tid, uint32_t ppid, char *fname, uint32_t image_base, uint32_t image_size)
{
	mon_pid_tid_list *p;
	mon_pid_list *q;
	int already_monitored_pid=0;
	int already_monitored_pid_tid=0;

	p=p_mon_pid_tid_list_head;
	q=p_mon_pid_list_head;

	if(pid==terminated_process_id)
		return;

	while(q!=NULL)
	{
		if(pid==q->pid)
		{
			already_monitored_pid=1;
			break;
		}
		q=q->next;
	}

	while(p!=NULL)
	{
		if((pid==p->pid) && (tid==p->tid))
		{
			already_monitored_pid_tid=1;
			break;
		}
		p=p->next;
	}

	if(!already_monitored_pid_tid)
	{
		p=(mon_pid_tid_list*) malloc(sizeof(mon_pid_tid_list));
		if(p!=NULL)
		{
			memset(p,0,sizeof(mon_pid_tid_list));

			p->pid=pid;
			p->tid=tid;
			p->ppid=ppid;
			strncpy(p->image_name,fname,15);
			p->image_name[15]='\0';
			if(is_basic_block_count)
				p->bbht=HT_construct(BASIC_BLOCK_CHAIN_NO);				//basic block hash table
			p->image_base = image_base;
			p->image_size = image_size;
			p->next=NULL;
			p->fst_inst=0;
			p->inst_buf=NULL;
			p->inst_type_prev=T_UNKNOWN;
			p->from_bb=0;

			if(is_inst_space_profiling)
			{
				char filename[120];
				sprintf(filename,"%s/%s_%04d_%04d_inst_space",INST_SPACE_DIRECTORY,fname,pid,tid);
				p->logspace=fopen(filename,"a+");
				if (p->logspace==NULL)
				{
					perror(NULL);
					printf("Cannot create file %s for writing.\n\n",filename);
				}
			}

			insert2_mon_pid_tid_list(p);
		}
	}

	if(!already_monitored_pid)
	{
		printf("allocate pid %d image_name %s\n",pid, fname);
		q=(mon_pid_list*) malloc(sizeof(mon_pid_list));
		if(q!=NULL)
		{
			q->pid=pid;
			q->maxium_bigram=0;
			q->is_mem_addr_tracking=0;
			q->cr3=cpu_single_env->cr[3];
			q->image_base = image_base;
			q->image_size = image_size;
			strncpy(q->image_name,fname,15);
			q->image_name[15]='\0';
			q->epl=NULL;													//entry point list
			q->next=NULL;
			q->image_buffer=(char*) malloc(image_size * sizeof(image_inst_t));
			q->cpu_env = cpu_single_env;

			if(q->image_buffer==NULL)										//0. image_buffer (specified in PE header)
			{
				perror(NULL);
				printf("error while allocate the image_buffer memory\n");
			}
			memset(q->image_buffer,0, image_size * sizeof(image_inst_t));

			q->pdyna_image_buffer=NULL;										//track dynamic allocated buffer
			if(is_code_unpacking || is_inst_disassembling)
			{
				q->target_pc=HT_construct(TARGET_PC_CHAIN_NO);					//1. target_pc hash table
				if(q->target_pc==NULL)
				{
					perror(NULL);
					printf("Cannot allocate hash table for target pc checking\n");
				}

				q->dynamic_pc=HT_construct(DYNA_PC_CHAIN_NO);					//2. dynamic_pc hash table
				if(q->dynamic_pc==NULL)
				{
					perror(NULL);
					printf("Cannot allocate hash table for dynamic pc checking\n");
				}
				q->data_pool=HT_construct(DATA_POOL_CHAIN_NO);					//3. data pool hash table
				if(q->data_pool==NULL)
				{
					perror(NULL);
					printf("Cannot allocate hash table for data pool checking\n");
				}
				q->sys_entry_pc=HT_construct(WIN_SYS_ENTRY_PC_CHAIN_NO);		//4. sys entry pc hash table
				if(q->sys_entry_pc==NULL)
				{
					perror(NULL);
					printf("Cannot allocate hash table for sysenter pc checking\n");
				}
			}

			insert2_mon_pid_list(q);
		}
	}

}


mon_pid_tid_list* get_a_mon_pid_tid_list_node(uint32_t pid, uint32_t tid, uint32_t ppid, char *fname)
{
	mon_pid_tid_list *p;

	if(pid==terminated_process_id)
		return;

	p=(mon_pid_tid_list*) malloc(sizeof(mon_pid_tid_list));
	if(p==NULL)
		return NULL;

	p->pid=pid;
	p->tid=tid;
	p->ppid=ppid;
	strncpy(p->image_name,fname,15);
	p->image_name[15]='\0';
	p->bbht=HT_construct(99997);
	p->next=NULL;
	p->fst_inst=0;
	p->inst_buf=NULL;
	p->inst_type_prev=T_UNKNOWN;

	p->from_bb=0;


	return p;
}

T_Type get_lst_inst_type_by_pid_tid(uint32_t pid, uint32_t tid)
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;

	while(p!=NULL)
	{
		if((pid==p->pid) && (tid==p->tid))
		{
			return p->inst_type;
		}
		p=p->next;
	}
	return T_UNKNOWN;
}

T_Type get_inst_type_by_pid_tid(uint32_t pid, uint32_t tid)
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	T_Type tmp;
	while(p!=NULL)
	{
		if((pid==p->pid) && (tid==p->tid))
		{
			tmp=p->inst_type_prev;
			p->inst_type_prev=p->inst_type;
			return tmp;
		}
		p=p->next;
	}
	return T_UNKNOWN;
}


void set_inst_type_by_pid_tid(uint32_t pid, uint32_t tid, T_Type type)
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid) && (tid==p->tid))
		{
			p->inst_type=type;
			return;
		}
		p=p->next;
	}
}
void set_prev_inst_type_by_pid_tid(uint32_t pid, uint32_t tid, T_Type type)
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid) && (tid==p->tid))
		{
			p->inst_type_prev=type;
			return;
		}
		p=p->next;
	}
}

uint32_t get_tid_by_pid_in_list(uint32_t pid)
{
	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid))
			return p->tid;
		p=p->next;
	}
	return NULL;
}

uint32_t get_cr3_by_pid(uint32_t pid)
{
	mon_pid_list *p;
	p=p_mon_pid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid))
			return p->cr3;
		p=p->next;
	}
	return NULL;
}

mon_pid_list* get_handle_in_pid_list_by_pid(uint32_t pid)
{

	mon_pid_list *p;
	p=p_mon_pid_list_head;

	while(p!=NULL)
	{
		if(pid==p->pid)
			return p;
		p=p->next;
	}
	return NULL;
}

mon_pid_tid_list* get_handle_by_pid(uint32_t pid)
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;

	while(p!=NULL)
	{
		if(pid==p->pid)
			return p;

		p=p->next;
	}
	return NULL;
}

mon_pid_tid_list* get_handle_by_pid_tid(uint32_t pid,uint32_t tid)
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;

	while(p!=NULL)
	{
		if((pid==p->pid) && (tid==p->tid))
			return p;

		p=p->next;
	}
	return NULL;
}

uint32_t get_fst_inst_by_pid_tid(uint32_t pid,uint32_t tid)
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid) && (tid==p->tid))
			return p->fst_inst;
		p=p->next;
	}
	return NULL;
}
char* get_image_name_by_pid_tid(uint32_t pid,uint32_t tid)
{

	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid) && (tid==p->tid))
			return p->image_name;
		p=p->next;
	}
	return NULL;
}

HashTable get_pid_tid_hash_table(uint32_t pid, uint32_t tid)
{
	mon_pid_tid_list *p;

	p=p_mon_pid_tid_list_head;
	while(p!=NULL)
	{
		if((pid==p->pid)&&(tid==p->tid)){
			return p->bbht;
		}

		p=p->next;
	}
	return NULL;
}

void insert2_mon_pid_list(mon_pid_list *p)
{
	if(p!=NULL)
	{
		if(p_mon_pid_list_head==NULL)
		{
			p_mon_pid_list_head=p;
		}
		else
		{
			p->next=p_mon_pid_list_head;
			p_mon_pid_list_head=p;
		}
		num_pid_list_node ++;
	}
}

void insert2_mon_pid_tid_list(mon_pid_tid_list *p)
{
	if(p!=NULL)
	{
		if(p_mon_pid_tid_list_head==NULL)
		{
			p_mon_pid_tid_list_head=p;
		}
		else
		{
			p->next=p_mon_pid_tid_list_head;
			p_mon_pid_tid_list_head=p;
		}
		num_pid_tid_list_node ++;
	}
}

void delete_from_mon_pid_list(uint32_t pid)
{
	mon_pid_list *p, *q;
	uint32_t entry_pc;

	p=p_mon_pid_list_head;
	term_printf("delete pid %d \n",pid);
	printf("delete pid %d #node %d\n",pid, num_pid_list_node);

	if(num_pid_list_node==0)
		return;


	if(p!=NULL)
	{
		q=p->next;
		//The head is the one to be deleted
		if((p->pid==pid))
		{
			entry_pc=get_entry_point_from_entry_point_list(p->epl);
			if(entry_pc!=NULL)
			{
				dis_image_inst_from_pc_in_image_buffer(p->cr3, entry_pc, pid);
				traverse_DynaPC_hash_table(p->cr3, p->dynamic_pc, pid);

				dump_image_code_and_data_for_pid(pid);
				dump_data_pool_for_pid(pid);

				free_target_pc_hash_table(p->target_pc);
				free_SYS_PC_hash_table(p->sys_entry_pc);
				free_DynaPC_hash_table(p->dynamic_pc);
				free_data_pool(p->data_pool);
				free_entry_point_list(p->epl);
				free_image_buffer_for_pid(pid);
			}
			else
			{
//				dump_mon_pid_list2();
//				HT_destruct(p->sys_entry_pc);
//				HT_destruct(p->dynamic_pc);
			}
				p_mon_pid_list_head=q;
				printf("deleted %d and return \n",pid);
				free(p);
				term_printf("deleted %d \n",pid);
				num_pid_list_node --;

			if(num_pid_list_node==0)
			{
				p_mon_pid_list_head = NULL;
			}

			return;
		}
	}
	else
	{
		return;					//No data in the list
	}

	while(q!=NULL)
	{
		if((q->pid==pid))
		{
			p->next=q->next;

			entry_pc=get_entry_point_from_entry_point_list(q->epl);
			if(entry_pc!=NULL)
			{
				dis_image_inst_from_pc_in_image_buffer(q->cr3, entry_pc, pid);
				traverse_DynaPC_hash_table(q->cr3, q->dynamic_pc, pid);

				dump_image_code_and_data_for_pid(pid);
				dump_data_pool_for_pid(pid);

				free_target_pc_hash_table(q->target_pc);
				free_SYS_PC_hash_table(q->sys_entry_pc);
				free_DynaPC_hash_table(q->dynamic_pc);
				free_data_pool(q->data_pool);
				free_entry_point_list(q->epl);
				free_image_buffer_for_pid(pid);
			}
				printf("deleted %d \n",pid);
				free(q);
				term_printf("deleted %d \n",pid);
				num_pid_list_node --;

			if(num_pid_list_node==0)
			{
				p_mon_pid_list_head = NULL;
			}
			return;
		}
		else
		{
			p=q;
			q=q->next;
		}
	}
}

void delete_from_mon_pid_tid_list(uint32_t pid, uint32_t tid)
{
	mon_pid_tid_list *p, *q;

	p=p_mon_pid_tid_list_head;

	printf("delete in pid tid list for %d %di #pidtid node %d\n",pid,tid, num_pid_tid_list_node);

	if(num_pid_tid_list_node==0)
		return;

	if(p!=NULL)
	{
		q=p->next;
		//The head is the one to be deleted
		if((p->pid==pid) && (p->tid == tid))
		{
			p_mon_pid_tid_list_head=q;
			free(p);
			num_pid_tid_list_node --;
			if(num_pid_tid_list_node==0)
			{
				p_mon_pid_tid_list_head = NULL;
			}
			return;
		}
	}
	else
	{
		return;								//No data in the list
	}

	while(q!=NULL)
	{
		if((q->pid==pid) && (q->tid == tid))
		{
			p->next=q->next;
			free(q);

			num_pid_tid_list_node --;

			if(num_pid_tid_list_node==0)
			{
				p_mon_pid_tid_list_head = NULL;
			}
			return;
		}
		else
		{
			p=q;
			q=q->next;
		}
	}
}

void get_image_name(char* image_name)
{

	uint32_t paddr;
    uint32_t eprocess;

    bzero(image_name,16);
    cpu_memory_rw_debug(cpu_single_env, 0xffdff124, &paddr,4,0);
    cpu_memory_rw_debug(cpu_single_env, paddr+0x220, &eprocess,4,0);
    cpu_memory_rw_debug(cpu_single_env, eprocess+0x174, image_name,16,0);
}

/*---------------------------------------------------------------------------------*/

uint32_t get_current_process(uint32_t fs, uint32_t *tid, uint32_t *ppid, char *buf)
{
	uint32_t paddr;
	uint32_t pid;
	uint32_t eprocess;
	CPUState *env;
	env=cpu_single_env;

	fs=0xffdff000;											//that's how windows code, to get pid, and tid

	{
			cpu_memory_rw_debug(env, fs+0x124, &paddr,4,0);
			cpu_memory_rw_debug(env, paddr+0x220, &eprocess,4,0);
	        cpu_memory_rw_debug(env, paddr+0x1ec, &pid,4,0);
			cpu_memory_rw_debug(env, paddr+0x1f0, tid,4,0);
			cpu_memory_rw_debug(env, eprocess+0x14c, ppid,4,0);
			bzero(buf,16);
			cpu_memory_rw_debug(env, eprocess+0x174, buf,16,0);

	}

	return pid;
}

void get_ppid_imagename(uint32_t fs, uint32_t *ppid, char *buf)
{
	uint32_t paddr;
	uint32_t pid;
	uint32_t eprocess;
	CPUState *env;

	env=cpu_single_env;

	if(fs==0xffdff000)
	{
		cpu_memory_rw_debug(env, fs+0x124, &paddr,4,0);
		cpu_memory_rw_debug(env, paddr+0x220, &eprocess,4,0);
		cpu_memory_rw_debug(env, eprocess+0x14c, ppid,4,0);
		bzero(buf,16);
		cpu_memory_rw_debug(env, eprocess+0x174, buf,16,0);
	}
}

uint32_t get_pid_tid(CPUState *env, uint32_t *tid)
{
	uint32_t paddr;
	uint32_t pid;
	uint32_t fs;

	fs=(uint32_t) env->segs[4].base;

	if(fs == 0xffdff000)
	{
		paddr=cpu_get_phys_page_debug(env, 0xffdff124);
		cpu_physical_memory_read(paddr+0x1ec, &pid, 4);
		cpu_physical_memory_read(paddr+0x1f0, tid, 4);
	}
	else
	{
		paddr=cpu_get_phys_page_debug(env, fs);
		cpu_physical_memory_read(paddr+0x20, &pid, 4);
		cpu_physical_memory_read(paddr+0x24, tid, 4);
	}

	return pid;
}

uint32_t get_pid()
{
	uint32_t paddr;
	uint32_t pid;
	uint32_t fs;

	fs=(uint32_t) cpu_single_env->segs[4].base;

	if(fs == 0xffdff000)
	{
		paddr=cpu_get_phys_page_debug(cpu_single_env, 0xffdff124);
		cpu_physical_memory_read(paddr+0x1ec, &pid, 4);
	}
	else
	{
		paddr=cpu_get_phys_page_debug(cpu_single_env, fs);
		cpu_physical_memory_read(paddr+0x20, &pid, 4);
	}
	return pid;
}

void clear_audit()
{
	is_audit_all_process=0;
	is_library_code_filtered=1;
	is_basic_block_count=0;
	is_code_unpacking=0;
	is_inst_disassembling=0;
	is_inst_space_profiling=0;
	return;
}

static void monitor_ins_disas(CPUState *env,
                   target_ulong pc )
{
    struct disassemble_info disasm_info;
    int (*print_insn)(bfd_vma pc, disassemble_info *info);

    INIT_DISASSEMBLE_INFO(disasm_info, logfile,fprintf);
    monitor_disas_is_physical = 0;
    monitor_disas_env=env;
    disasm_info.read_memory_func = monitor_read_memory;
    disasm_info.buffer_vma = (void*)pc;
    disasm_info.endian = BFD_ENDIAN_LITTLE;
    disasm_info.mach = bfd_mach_i386_i386;
    print_insn = print_insn_i386;

    print_insn(pc, &disasm_info);
}



target_ulong get_current_esp()
{
	return cpu_single_env->regs[R_ESP];
}

static char* get_ins_disas(CPUState *env,
                   target_ulong pc )
{
    struct disassemble_info disasm_info;
    int (*print_insn)(bfd_vma pc, disassemble_info *info);
    mon_pid_tid_list *p;

    char buf[64];
    bzero(buf,64);
    p=get_handle_by_pid_tid(pid,tid);

    INIT_DISASSEMBLE_INFO(disasm_info, 0, fprintf);
    monitor_disas_is_physical = 0;
    monitor_disas_env=env;
    disasm_info.read_memory_func = monitor_read_memory;
    disasm_info.buffer_vma = (void*)pc;

    my_print_insn(pc, &disasm_info,buf);

    if(buf[0]=='j')
    {
		p->inst_type=T_JMP;
		p->new_bb=1;
		p->pc1=pc;
    }
    else
    {
		jmp_target=0;

	    if(!strncmp(buf,"ret",3))
		{
			p->inst_type=T_RET;
			p->new_bb=1;
			p->pc1=pc;
		}
	    else
		if(!strncmp(buf,"call",4))
		{
			p->inst_type=T_CALL;
			p->new_bb=1;
			p->pc1=pc;
		}
		else if(!strncmp(buf,"loop",4))
		{
			p->inst_type=T_UNKNOWN;
			p->new_bb=1;
			p->pc1=pc;
		}
    }

    sprintf(p->inst_g,"0x%08x:\t%s\n",pc,buf);
    return p->inst_g;
}

static int my_strncmp(const char *s1, const char *s2, uint32_t len)
{
    unsigned char uc1, uc2;
    uint32_t i=0;
    while (*s1 != '\0' && *s1 == *s2) {
        s1++;
        s2++;
	if((i++)==len)
		return 0;
    }
    uc1 = (*(unsigned char *) s1);
    uc2 = (*(unsigned char *) s2);
    return ((uc1 < uc2) ? -1 : (uc1 > uc2));
}

static uint32_t from_bb;
static uint32_t lst_ubb;
static uint32_t fst_lbb;


#define BB_INST_SIZE 64
char *inst_buf=NULL;

uint32_t append_inst_buf(char *buf,uint32_t len)
{
    mon_pid_tid_list *p;

    p=get_handle_by_pid_tid(pid,tid);
	if(p->inst_buf==NULL)
	{
		p->bb_inst_size=len;
		p->inst_buf=(char*)malloc(BB_INST_SIZE);
		memset(p->inst_buf,0,BB_INST_SIZE);
	}
	else
	{
		p->bb_inst_size += len;
		if(p->bb_inst_size>BB_INST_SIZE)
		{
			p->inst_buf=(char*) realloc(p->inst_buf, p->bb_inst_size);
			memset(p->inst_buf + p->bb_inst_size - len, 0, len);
		}
	}
	strcat(p->inst_buf,buf);
}

uint32_t prev_pc=0;

uint32_t inst_dumped(uint32_t pc)
{
	BBHashNode *bb;

	bb=HT_lookup(bbg,pc);

	if(bb!=NULL)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


void helper_cfg_log(uint32_t pc,uint32_t fs, uint32_t eip, uint32_t pid, uint32_t tid);

void finish_last_block()
{
    BBHashNode *bb;

	bb=HT_lookup(bbg,from_bb);

	if(bb==NULL)
	{
		insert_bb(from_bb,0,inst_buf,get_inst_type_by_pid_tid(pid,tid), T_UNKNOWN);
	}
	else
	{
		update_bb(bb,from_bb,0);
	}

}

mon_pid_list* is_in_checked_context()
{
	uint32_t local_pid;
	mon_pid_list *p;

    if ((loglevel & CPU_LOG_INS_PC)||(is_basic_block_count) || (is_code_unpacking) || (is_inst_disassembling))
	{
		local_pid=get_pid();
		p=p_mon_pid_list_head;
		while(p!=NULL)
		{
			if((local_pid==p->pid))
			{
				return p;
			}
			p=p->next;
		}
	}

	return NULL;

}

void helper_bbs_log(uint32_t pc,uint32_t fs, uint32_t eip)
{
	    char fname[16];
	    fname[0]=0;
	    uint32_t local_pid, local_tid;
	    uint32_t inst_len;
	    BBHashNode *bb;
	    mon_pid_tid_list *mptl,*p;
	    mon_pid_list *q;


		//---------------------------------------------------------------
		//1. check whether or not the instruciton can be filterd or not
		//---------------------------------------------------------------

		if(prev_pc == pc ) //filter like repz movsb instructions
		{
			return;
		}
		else
		{
			prev_pc=pc;
		}

		//---------------------------------------------------------------
		//2. check pid and tid, to ensure only audit necessary process
		//---------------------------------------------------------------

		local_pid=get_pid_tid(cpu_single_env,&local_tid);

		if(local_pid!=pid && local_tid!=tid)
		{
			pid=local_pid;
			tid=local_tid;
		}

		if((is_kernel_code_filtered) && ((uint32_t) pc > (uint32_t) KERNEL_BOUNDARY))
			return;

		p=get_handle_by_pid_tid(pid,tid);
		if(p!=NULL)
		{
			if((p->prev_pc < LIBRARY_BOUNDARY) && (pc > LIBRARY_BOUNDARY))
			{																//jump to library space
				if(p->disased==0)
				{
					p->lib_pc=pc;
				}
				else														//insert or update the list
				{
					insert2_api_list(p->pc0,pc);
				}
			}
			p->prev_pc=pc;
		}


		if(!is_audited_pid_tid(pid,tid))
		{
				pid=get_current_process(fs,&tid,&ppid,fname);

				if(!strncmp(fname,user_input_file_name,15))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname,image_base,image_size);
				}

				if(is_parent_process_audited(pid))
				{
					if((!is_audited_pid_tid(pid,tid))){
						allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
					}
				}

				if(is_parent_process_audited(ppid))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
				}
		}


		if((is_library_code_filtered) && ((uint32_t) pc > (uint32_t) LIBRARY_BOUNDARY))
			return;

		//-------------------------------------------------------------------
		//3. do log
		//-------------------------------------------------------------------

		if((!is_audited_pid_tid(pid,tid))){
			if ((!is_audit_all_process))
				return;
		}

		if(is_basic_block_count)
		{
			helper_cfg_log(pc, fs, eip, pid, tid);
		}
}

/*-------------------------------------------------------------------------------------------
 * Log at basic block level
------------------------------------------------------------------------------------------*/

//basic block statistics(bbs) log
void helper_cfg_log(uint32_t pc,uint32_t fs, uint32_t eip, uint32_t pid, uint32_t tid) 
{
    uint32_t inst_len;
    BBHashNode *bb;
    mon_pid_tid_list * p;
    T_Type type;

    p=get_handle_by_pid_tid(pid,tid);

    if(p==NULL)
		return; // non exist for this pid, tid

    if(p->fst_inst==0)
    {
		p->new_bb=0;
		p->fst_inst=pc;
		p->disased = 0; 
		p->pc0 = pc;
	}

	bbg=get_pid_tid_hash_table(pid,tid); //it will re-initialize global vairalbe

	if(bbg==NULL) // not guarded process
		return;

	if(p->new_bb)
	{
		bb=HT_lookup(bbg,p->pc0);
		if(bb==NULL)
		{//insert
			insert_bb2(p->pc0, pc, p->inst_buf, get_inst_type_by_pid_tid(pid,tid), p->pc1);
			insert2_api_list(p->pc0,p->lib_pc);
			p->lib_pc=0;
			p->	inst_buf=NULL;
		}
		else
		{//update
			update_bb(bb,p->pc0, pc);
		}

		//check the new basic block is already dumped or not
		bb=HT_lookup(bbg,pc);

		p->new_bb = 0;
		p->pc0 = pc;

		if(bb==NULL)
		{//
			p->disased = 0; 
			get_ins_disas(cpu_single_env,pc);
			append_inst_buf(p->inst_g, strlen(p->inst_g)+1);
			//update pc1, and new_bb
		}
		else
		{//update
			p->disased = 1;
			p->pc1 = bb->bbend;

		}

		if(pc==p->pc1)//only one inst in a block case
			p->new_bb=1;
	}
	else
	{
		if(!p->disased) // not disassembed yet
		{
			get_ins_disas(cpu_single_env,pc);
			append_inst_buf(p->inst_g, strlen(p->inst_g)+1);
			//p->pc1=pc; getupdated at get_ins_disas;
		}
		else
		{
			if (pc == p->pc1)
			{
				p->new_bb=1;
			}
		}
	}
}

void dump_cfg_for_pid(unsigned int pid)
{
	mon_pid_tid_list *p;
	p=p_mon_pid_tid_list_head;

	while(p!=NULL)
	{
		if((pid==p->pid))
			dump_cfg_for_pid_tid(pid,p->tid);
		p=p->next;
	}
}


void destroy_pid_tid_bb_hash_table(unsigned int pid, unsigned int tid)
{
	HashTable table;
	FILE *html, *cfg, *cg;
	int   i;
	char fname[64];
	ToList *fl;
	APIList *api_list;
	int summary;
	static int count=0;
	char image_name[16];
	static int already_dumped_pid=0;
	mon_pid_tid_list *pmon;

	BBHashNode *node, *node_next;

	if(is_inst_space_profiling)
	{
		pmon=get_handle_by_pid_tid(pid,tid);
		if(pmon->logspace!=NULL)
		{
			printf("close the file pid %d tid %d \n",pid,tid);
			fclose(pmon->logspace);
		}
	}

	if(get_fst_inst_by_pid_tid(pid,tid)==0)
	{
		delete_from_mon_pid_tid_list(pid,tid);
		return;
	}

	strcpy(image_name,get_image_name_by_pid_tid(pid,tid));

	if(is_library_code_filtered)
	{
		sprintf(fname,"%s/%s_%04d_%04d.wolib.html_%d",HTML_DIRECTORY,image_name,pid,tid,count);
	}
	else
	{
		sprintf(fname,"%s/%s_%04d_%04d.wilib.html_%d",HTML_DIRECTORY,image_name,pid,tid,count);
	}

	html=fopen(fname,"a+");

	sprintf(fname,"%s/%s_%04d_%04d_cfg.dot_%d",DOT_DIRECTORY,image_name,pid,tid,count++);
	cfg=fopen(fname,"a+");

	if(already_dumped_pid!=pid)
	{
		dump_entire_proc_image_by_pid(pid);
		//dump_entire_proc_image_by_pid_and_image_name(pid,image_name);
		already_dumped_pid=pid;
	}

	html_begin(html,pid,tid);
	init_cfg_dot_header(cfg);

	table=get_pid_tid_hash_table(pid,tid);


	if(table==NULL)
		return;

	traverse_mon_pid_tid_list();


	for (i = 0; i < table->n_chains; i++) {
		for (node = (BBHashNode*) table->chains[i]; node != NULL; node = node_next) {

				summary=0;

				for(fl=node->to; fl!=NULL; fl=fl->next){
					summary+=fl->count;
				}


				assign_html_node_begin(html,node->key,summary,node->inst, node->type);
				assign_cfg_node(cfg,node->key);

				for(api_list=node->api_list; api_list!=NULL; api_list=api_list->next){
					assign_html_api_node(html,api_list->inst,get_func_name_by_addr(api_list->inst));
				}

				for(fl=node->to; fl!=NULL; fl=fl->next){
					assign_html_node_edge(html,fl->to,fl->count);
					assign_cfg_edge(cfg,node->key,fl->to,fl->count);
				}

				free_api_list(node->api_list);
				free_tolist(node->to);
				free(node->inst);

				node_next=node->next;
				free(node);
		}
	}
	free(table);

	html_end(html);
	init_cfg_dot_end(cfg);

	delete_from_mon_pid_tid_list(pid,tid);

}


//log the entire instruction happend for a particular process
void helper_ins_log(uint32_t pc,uint32_t fs, uint32_t eip)
{
	    char fname[16];
	    uint32_t local_pid, local_tid;
	    uint32_t inst_len;
	    mon_pid_tid_list *mptl,*p;
	    mon_pid_list *q;
		char image_name[16];
	    fname[0]=0;


		//---------------------------------------------------------------
		//1. check whether or not the instruciton can be filterd or not
		//---------------------------------------------------------------

		if(prev_pc == pc ) //filter like repz movsb instructions
		{
			return;
		}
		else
		{
			prev_pc=pc;
		}

		//---------------------------------------------------------------
		//2. check pid and tid, to ensure only audit necessary process
		//---------------------------------------------------------------

		local_pid=get_pid_tid(cpu_single_env,&local_tid);

		if(local_pid!=pid && local_tid!=tid)
		{
			pid=local_pid;
			tid=local_tid;
		}

		if((is_kernel_code_filtered) && ((uint32_t) pc > (uint32_t) KERNEL_BOUNDARY))
			return;

		p=get_handle_by_pid_tid(pid,tid);


		if(!is_audited_pid_tid(pid,tid))
		{
				pid=get_current_process(fs,&tid,&ppid,fname);

				if(!strncmp(fname,user_input_file_name,15))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname,image_base,image_size);
				}

				if(is_parent_process_audited(pid))
				{
					if((!is_audited_pid_tid(pid,tid))){
						allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
					}
				}

				if(is_parent_process_audited(ppid))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
				}
		}


		if((is_library_code_filtered) && ((uint32_t) pc > (uint32_t) LIBRARY_BOUNDARY))
			return;

		//-------------------------------------------------------------------
		//3. do log
		//-------------------------------------------------------------------

		if((!is_audited_pid_tid(pid,tid))){
			if ((!is_audit_all_process))
				return;
		}

		get_image_name(image_name);
		fprintf(logfile, "PID %04d TID %04d PPID %04d ImageName %-15s eip 0x%08x 0x%08x: ",pid,tid,ppid, image_name,eip & 0xffffffff,pc & 0xffffffff);
		monitor_ins_disas(cpu_single_env,pc);
        fprintf(logfile, "\n");

}



void helper_unpacker(uint32_t pc,uint32_t fs, uint32_t eip)
{
	    char fname[16];
	    fname[0]=0;
	    uint32_t local_pid, local_tid;
	    uint32_t inst_len;
	    mon_pid_tid_list *mptl,*p;
		mon_pid_list *q;

		//---------------------------------------------------------------
		//1. check whether or not the instruciton can be filterd or not
		//---------------------------------------------------------------

		if(prev_pc == pc ) //filter like repz movsb instructions
		{
			return;
		}
		else
		{
			prev_pc=pc;
		}

		//---------------------------------------------------------------
		//2. check pid and tid, to ensure only audit necessary process
		//---------------------------------------------------------------

		local_pid=get_pid_tid(cpu_single_env,&local_tid);

		if(local_pid!=pid && local_tid!=tid)
		{
			pid=local_pid;
			tid=local_tid;
		}

		if((is_kernel_code_filtered) && ((uint32_t) pc > (uint32_t) KERNEL_BOUNDARY))
			return;

		p=get_handle_by_pid_tid(pid,tid);

		if(!is_audited_pid_tid(pid,tid))
		{
				pid=get_current_process(fs,&tid,&ppid,fname);

				if(!strncmp(fname,user_input_file_name,15))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname,image_base,image_size);
				}

				if(is_parent_process_audited(pid))
				{
					if((!is_audited_pid_tid(pid,tid))){
						allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
					}
				}

				if(is_parent_process_audited(ppid))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
				}
		}


		if((is_library_code_filtered) && ((uint32_t) pc > (uint32_t) LIBRARY_BOUNDARY))
			return;

		if((!is_audited_pid_tid(pid,tid))){
			return;
		}


		if(monitored_eip == pc)
		{
			q=get_handle_in_pid_list_by_pid(pid);
			q->start_esp=get_current_esp();
		}
		if(pc == 0x100739d)
		{
			printf("@entry point %p esp=%x\n",pc,get_current_esp());
//			dump_proc_image_by_pid(pid);
		}

		return;

}

void helper_inst_disassemble(uint32_t pc,uint32_t fs, uint32_t eip)
{
	    char fname[16];
	    fname[0]=0;
	    uint32_t local_pid, local_tid;
	    uint32_t inst_len;
	    BBHashNode *bb;
		mon_pid_list *p,*q;


		//---------------------------------------------------------------
		//1. check whether or not the instruciton can be filterd or not
		//---------------------------------------------------------------

		if(prev_pc == pc ) //filter like repz movsb instructions
		{
			return;
		}
		else
		{
			prev_pc=pc;
		}

		//---------------------------------------------------------------
		//2. check pid and tid, to ensure only audit necessary process
		//---------------------------------------------------------------

		local_pid=get_pid_tid(cpu_single_env,&local_tid);

		if(local_pid!=pid && local_tid!=tid)
		{
			pid=local_pid;
			tid=local_tid;
		}

		if((is_kernel_code_filtered) && ((uint32_t) pc > (uint32_t) KERNEL_BOUNDARY))
			return;


		if(!is_audited_pid_tid(pid,tid))
		{
				pid=get_current_process(fs,&tid,&ppid,fname);

				if(!strncmp(fname,user_input_file_name,15))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname,image_base,image_size);
				}

				if(is_parent_process_audited(pid))
				{
					if((!is_audited_pid_tid(pid,tid))){
						allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
					}
				}

				if(is_parent_process_audited(ppid))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
				}
		}


		if((is_library_code_filtered) && ((uint32_t) pc > (uint32_t) LIBRARY_BOUNDARY))
			return;

		if((!is_audited_pid_tid(pid,tid))){
			return;
		}

		if(monitored_eip == pc)
		{
			q=get_handle_in_pid_list_by_pid(pid);
			if(q!=NULL)
				q->start_esp=get_current_esp();
			printf("begin pc = %p esp=%x \n",pc,q->start_esp);
		}
/*
		if(get_current_esp() == monitored_esp)
		{
			printf("found a pc = %p esp=%x \n",pc,monitored_esp);
//			dump_proc_image_by_pid(pid);
		}
*/

		if(pc == 0x100739d)
		{
			printf("@entry point %p esp=%x\n",pc,get_current_esp());
//			dump_proc_image_by_pid(pid);
		}

		p=get_handle_in_pid_list_by_pid(pid);
		if((p!=NULL) &&(pc<LIBRARY_BOUNDARY) &&(p->is_mem_addr_tracking==1))
		{
			set_inst_executed_in_image_buffer(pc, pid, p->image_base, p->image_size, p->image_buffer, p->pdyna_image_buffer);
		}
		return;
}//end disassemble

void helper_inst_space_profile(uint32_t pc,uint32_t fs, uint32_t eip)
{
	    char fname[16];
	    fname[0]=0;
	    uint32_t local_pid, local_tid;
	    uint32_t inst_len;
	    mon_pid_tid_list *mptl,*p;
		mon_pid_list *q;


		//---------------------------------------------------------------
		//1. check whether or not the instruciton can be filterd or not
		//---------------------------------------------------------------

		if(prev_pc == pc ) //filter like repz movsb instructions
		{
			return;
		}
		else
		{
			prev_pc=pc;
		}

		//---------------------------------------------------------------
		//2. check pid and tid, to ensure only audit necessary process
		//---------------------------------------------------------------

		local_pid=get_pid_tid(cpu_single_env,&local_tid);

		if(local_pid!=pid && local_tid!=tid)
		{
			pid=local_pid;
			tid=local_tid;
		}

		if((is_kernel_code_filtered) && ((uint32_t) pc > (uint32_t) KERNEL_BOUNDARY))
			return;

		p=get_handle_by_pid_tid(pid,tid);


		if(!is_audited_pid_tid(pid,tid))
		{
				pid=get_current_process(fs,&tid,&ppid,fname);

				if(!strncmp(fname,user_input_file_name,15))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname,image_base,image_size);
				}

				if(is_parent_process_audited(pid))
				{
					if((!is_audited_pid_tid(pid,tid))){
						allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
					}
				}

				if(is_parent_process_audited(ppid))
				{
				    allocate_a_mon_pid_tid_list_node(pid,tid,ppid,fname, image_base, image_size);
				}
		}


		if((is_library_code_filtered) && ((uint32_t) pc > (uint32_t) LIBRARY_BOUNDARY))
			return;

		if((!is_audited_pid_tid(pid,tid))){
			return;
		}
		//-------------------------------------------------------------------
		//3. do log
		//-------------------------------------------------------------------

		//profile the instruction space
		check_inst_space(pc,p->image_base,p->image_size,pid,tid);
}

