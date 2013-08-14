void sys_hook_init();
void interrupt_hook(int intno, int is_int, target_ulong next_eip);
void syscall_hook(uint32_t syscall_op);

extern uint32_t sys_need_red;
extern uint32_t is_interrupt;
extern int current_syscall;
extern uint32_t vmmi_interrupt_stack ;
extern char vmmi_process_name[];
extern uint32_t file_flag;
extern uint32_t vmmi_save_esp;
extern uint32_t vmmi_esp2;
extern uint32_t origin_esp;
extern uint32_t is_sysenter;
void change_esp();
extern uint32_t is_pipe;
extern	uint32_t vmmi_mon_start;
extern 	uint32_t vmmi_mon_end;
extern uint32_t current_pc;
