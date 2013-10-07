#include "qemu-common.h"
#include "cpu.h"
#include "sys_hook.h"
#include "qemu-log.h"
#define KERNEL_STACK  (8192-1)
#define KERNEL_STACK_MASK (~KERNEL_STACK)

uint32_t file_flag ;
uint32_t sys_need_red ;
uint32_t io_need_red;
uint32_t is_interrupt;
int current_syscall;
int files[1024];
uint32_t vmmi_interrupt_stack ;
char vmmi_process_name[1024]= {0};

uint32_t is_syscall;
extern uint32_t int_con;
extern uint32_t sys_con;
extern uint32_t other;
extern uint32_t sys_con_w;
extern uint32_t excep_con;
target_ulong vmmi_save_esp;
target_ulong origin_esp;
target_ulong vmmi_esp2;
extern uint32_t start_trace;

uint32_t is_sysenter;
struct syscall_table_
{
    target_ulong pc;
    char fname[128];
} syscall_table[21000];
uint32_t syscall_num=0;

//yufei.begin
void set_sys_need_red(int flag){
  sys_need_red = flag;
}
//yufei.end

void init_syscall_table()
{
    return;
    if(syscall_num!=0)return;
    FILE *fp =fopen("kall","r");
    if(fp!=NULL)
    {
        char c;
        char buf[1024];
        //	while(!feof(fp)&&fscanf(fp, "%x %c %s\n", &syscall_table[syscall_num].pc, &c, syscall_table[syscall_num].fname)!=0){
        while(fgets(buf,1024, fp)!=NULL)
        {
            sscanf(buf,"%x %c %s", &syscall_table[syscall_num].pc, &c, syscall_table[syscall_num].fname);
            syscall_num++;
        }
        fclose(fp);
    }
    else
        printf("can't inital syscall table\n");
}
void find_kernel_call(target_ulong pc)
{
    uint32_t i;
    if(!qemu_log_enabled())
        return;
    for(i=0; i< syscall_num; i++)
        if(pc==syscall_table[i].pc)
            qemu_log("call is %s\n", syscall_table[i].fname);
}


typedef void (*fun)();
extern fun iret_handle;
void change_esp()
{
#ifdef DEBUG_VMMI
    if(qemu_log_enabled())
        qemu_log("esp is %x\n", cpu_single_env->regs[R_ESP]);
#endif
    origin_esp = cpu_single_env->regs[R_ESP];

    if(!is_sysenter)
        cpu_single_env->regs[R_ESP] = (vmmi_esp&KERNEL_STACK_MASK)+(origin_esp&KERNEL_STACK);
    else
        cpu_single_env->regs[R_ESP] =vmmi_esp2;

#ifdef DEBUG_VMMI
    if(qemu_log_enabled())
        qemu_log("esp(%x, %x)", origin_esp, cpu_single_env->regs[R_ESP]);
#endif

    if(is_sysenter)
    {
        char addr[4];
        cpu_memory_rw_debug(cpu_single_env,origin_esp-0x1fdc,addr,4, 0);
        uint64_t phaddr = (uint64_t)vmmi_mem_shadow+vmmi_vtop(cpu_single_env->regs[R_ESP]-0x1fdc);
        *(uint32_t *)phaddr = *(uint32_t*)addr;
    }

}

void sys_hook_init()
{
    int i;
    for(i=0 ; i <1024; i++)
        files[i]=0;
    init_syscall_table();
    set_sys_need_red(0);
    file_flag = 0;
    is_interrupt = 0;
    vmmi_interrupt_stack = 0;
    is_sysenter = 0;

    memcpy(vmmi_mem_shadow, vmmi_mem, snapshot_size);
    pc_taintInit();
}

int get_file_flag(uint32_t fd)
{
    if(fd <1024)
        return files[fd];

    return 0;
}

set_file_flag(uint32_t fd, int flag)
{
    if(fd<1024)
        files[fd]=flag;
}

int need_interrupt =0;
void interrupt_hook(int intno, int is_int, target_ulong next_eip)
{
    //yufei.begin
    if ( sys_need_red == 1 && intno == 0x3e)
      need_interrupt = 1;
    else
      need_interrupt = 0;
    //yufei.end

    if (intno != 0x80)
    {
      //yufei.begin
      if(intno == 0x3e)
        return;
      //yufei.end
#ifdef VMMI_ALL_REDIRCTION
        if(vmmi_profile&&sys_need_red&&is_interrupt==0&&vmmi_start)
        {
            if(qemu_log_enabled())
                qemu_log("stack esp is %x\n", cpu_single_env->regs[R_ESP]);
            if(((origin_esp-1)&KERNEL_STACK_MASK)!= (cpu_single_env->regs[R_ESP]&KERNEL_STACK_MASK))
            {
                vmmi_save_esp = cpu_single_env->regs[R_ESP];
                cpu_single_env->regs[R_ESP] = (vmmi_save_esp&KERNEL_STACK)+((origin_esp-1)&KERNEL_STACK_MASK);
            }
        }
#endif

        vmmi_interrupt_stack++;
        is_interrupt = 1;
#ifdef DEBUG_VMMI
        if(qemu_log_enabled()&&vmmi_interrupt_stack==1)
            qemu_log(" enter interrupt\n");
#endif
    }
    else
        syscall_hook(cpu_single_env->regs[R_EAX]);
}

void run_timer();
void pit_send();
extern char inst_buff[];
char inst_buff2[16];
char inst_buff3[16];
extern int patch_modules(CPUState *env); //yufei
extern target_ulong current_task; //yufei
extern int is_insert_work;

void syscall_hook(uint32_t syscall_op)
{

#ifdef DEBUG_VMMI
    if(qemu_log_enabled())
        qemu_log("sys enter %u \n", syscall_op);
#endif
    is_syscall=1;

    set_sys_need_red(1);
    current_syscall = syscall_op;
    switch (syscall_op)
    {

    case 0 : // sys_ni_syscall
        break;
    case 1 : // sys_exit
#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log(" monitor exit");
#endif
        //yufei.begin
        if (sys_need_red ==1)  
           patch_modules(cpu_single_env); 
        //yufei.end

        set_sys_need_red(0);
        vmmi_start = 0;
        vmmi_main_start = 0;
        is_insert_work = 0;
        sys_hook_init();
        run_timer();
        pit_resend();

        break;
    case 2 : // sys_fork
        set_sys_need_red(0);
        break;
    case 3 : // sys_read

#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("read file %u flag %u\n", cpu_single_env->regs[R_EBX], get_file_flag(cpu_single_env->regs[R_EBX]));
#endif
        if(cpu_single_env->regs[R_EBX] == 6)
            is_pipe = 1;

        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 4 : // sys_write
#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("write file %u flag %u\n", cpu_single_env->regs[R_EBX], get_file_flag(cpu_single_env->regs[R_EBX]));
#endif
        set_sys_need_red(get_file_taint());
        break;
    case 5 : // sys_open
    {
        char buf[1024];
        memset(buf,0,1024);
        file_flag=0;
        set_sys_need_red(0);
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 1024, 0)!=0)
            break;

#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("open file %s\n", buf);
#endif
        buf[1023]='\0';

        //filename is the name of target file       
        //char * target_file = "lab/test";
        char * target_file = "test/log";
        if(strcmp(buf, target_file) ==0)
        {
            file_flag = 1;
            set_sys_need_red(1);
            patch_modules(cpu_single_env); //yufei
            
            vmac_memory_read(0xc1801454, &current_task, 4);//yufei
        }

    }
    break;
    case 6 : // sys_close
#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("read file %u flag %u\n", cpu_single_env->regs[R_EBX], get_file_flag(cpu_single_env->regs[R_EBX]));
#endif
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_file_flag(cpu_single_env->regs[R_EBX],0);
        set_sys_need_red(get_file_taint());
        break;
    case 7 : // sys_waitpid

        //			vmmi_main_start = 0;
        set_sys_need_red(0);
        //		run_timer();
        break;
    case 8 : // sys_creat
        set_sys_need_red(0);
        break;
    case 10 : // sys_unlink
        set_sys_need_red(0);
        break;
    case 11: // sys_execve
    {
        set_sys_need_red(0);
        break;
        char buf[1024];
        char fname[1024];

        memset(buf,0,1024);
        file_flag=0;
        
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 1024, 0)!=0)
            break;

        get_process_name(buf, fname);
        printf("process name is %s\n", fname);
//#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("process name %s\n",fname);
        uint32_t stack=  0xc1801454;
        uint32_t task;
        uint32_t pid;
        char comm[128];
        cpu_memory_rw_debug(cpu_single_env, stack, &task, 4,0);
        cpu_memory_rw_debug(cpu_single_env, task+0x218, comm, 128,0);
        cpu_memory_rw_debug(cpu_single_env, task+0x120, &pid, 4,0);
        comm[127]='\0';
        //			if(qemu_log_enabled())
        printf("task is  %x  %x %s\n", cpu_single_env->cr[3],pid, comm);


//#endif
        {
            int i=0;
            CPUX86State *env=cpu_single_env;
            uint32_t stack= 0xc1801454;
            uint32_t task;
            uint32_t pid;
            uint32_t mm;
            uint32_t pgd;
            uint32_t next;
            uint32_t list;
            char comm[128];
            cpu_memory_rw_debug(env, stack, &task, 4,0);
            next=task;
            do
            {
                cpu_memory_rw_debug(env, next+0x218, comm, 128,0);
                comm[127]='\0';
                cpu_memory_rw_debug(env, next+0x120, &pid, 4,0);
                cpu_memory_rw_debug(env, next+0x100, &mm, 4,0);
                //print the task
                if(mm!=0)
                {
                    cpu_memory_rw_debug(env, mm+0x24, &pgd, 4,0);
                    printf("scan process %x %s %x\n", next, comm, pgd+0x40000000);
                }
                cpu_memory_rw_debug(env, next+0xe4, &list, 4, 0);
                next=list-0xe4;
                i++;
                if(i>100)
                    break;
            }
            while(next!=task);
        }

        if(strcmp(fname, vmmi_process_name) == 0)
        {

#ifdef DEBUG_VMMI
            if(qemu_log_enabled())
                qemu_log("process name %s\n",fname);
#endif
            vmmi_process_cr3 = cpu_single_env->cr[3];
            vmmi_main_start = 1;
#ifdef KERNEL_OLD
            vmmi_start = 1;
#endif

#ifdef DEBUG_VMMI
            if(qemu_log_enabled())
                qemu_log("process cr3  %x\n",vmmi_process_cr3);
#endif

        }
        set_sys_need_red(0);
    }
    break;
    case 12 : // sys_chdir
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 13 : // sys_time
        //	set_sys_need_red(0);
        break;
    case 14 : // sys_mknod
        set_sys_need_red(0);
        break;
    case 15 : // sys_chmod
        set_sys_need_red(0);
        break;
    case 16 : // sys_lchown16
        break;
    case 17 : // sys_ni_syscall
        break;
    case 18 : // sys_stat
    {
        char buf[6];
        memset(buf,0,6);
        file_flag=0;
        set_sys_need_red(0);
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 1024, 0)!=0)
            break;
        buf[5]='\0';

        if(strcmp(buf, "/proc") != 0)
        {
            file_flag = 0;
            set_sys_need_red(0);
        }
        else
        {
            file_flag = 1;
            set_sys_need_red(1);
        }
    }

    break;
    case 19 : // sys_lseek
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 20 : // sys_getpid
        break;
    case 21: // sys_mount
        break;
    case 22 : // sys_oldumount
        break;
    case 23 : // sys_setuid16
        break;
    case 24 : // sys_getuid16
        break;
    case 25 : // sys_stime
        break;
    case 26 : // sys_ptrace
        break;
    case 27 : // sys_alarm
        set_sys_need_red(0);
        break;
    case 28 : // sys_fstat
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 29 : // sys_pause
        break;
    case 30 : // sys_utime
        break;
    case 31 : // sys_ni_syscall
        break;
    case 32 : // sys_ni_syscall
        break;
    case 33 : // sys_access
    {
        char buf[1024];
        memset(buf,0,1024);
        file_flag=0;
        set_sys_need_red(0);
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 1024, 0)!=0)
            break;
        buf[5]='\0';

        if(strcmp(buf, "/proc") != 0||strcmp(buf, "/"))
        {
            file_flag = 0;
            set_sys_need_red(0);
        }
        else
        {
            file_flag = 1;
            set_sys_need_red(1);
        }
    }
    break;
    case 34 : // sys_nice
        break;
    case 35 : // sys_ni_syscall
        break;
    case 36 : // sys_sync
        set_sys_need_red(0);
        break;
    case 37 : // sys_kill
        break;
#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("vmmi process%x\n", cpu_single_env->cr[3]);
#endif

        if(!vmmi_start)
        {
            vmmi_process_cr3 = cpu_single_env->cr[3];
            vmmi_main_start = 1;
            vmmi_start=1;
            set_sys_need_red(1);
            start_trace=1;
        }
        set_sys_need_red(1);

        break;
    case 38: // sys_rename
        break;
    case 39: // sys_mkdir
        set_sys_need_red(0);
        break;
    case 40: // sys_rmdir
        set_sys_need_red(0);
        break;
    case 41: // sys_dup
        break;
    case 42: // sys_pipe
        set_sys_need_red(0);
        break;
    case 43 : // sys_times
        break;
    case 44 : // sys_ni_syscall
        break;
    case 45 : // sys_brk
        set_sys_need_red(0);
        break;
    case 46 : // sys_setgid16
        break;
    case 47 : // sys_getgid16
        break;
    case 48 : // sys_signal
        set_sys_need_red(0);
        break;
    case 49 : // sys_geteuid16
        break;
    case 50 : // sys_getegid16
        break;
    case 51 : // sys_acct
        break;
    case 52 : // sys_umount2
        break;
    case 53 : // sys_lock
        break;
    case 54 : // sys_ioctl
    {
        char new_inst[]="\xb8\x00\x00\x00\x00";

        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());

    }
    break;
    case 55 : // sys_fcntl
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 56 : // sys_mpx
        break;
    case 57 : // sys_setpgid
        break;
    case 58 : // sys_ulimit
        break;
    case 59 : // sys_oldolduname
        break;
    case 60 : // sys_umask
        break;
    case 61 : // sys_chroot
        break;
    case 62 : // sys_ustat
        break;
    case 63 : // sys_dup2
        break;
    case 64 : // sys_getppid
        break;
    case 65 : // sys_getpgrp
        break;
    case 66 : // sys_setsid
        break;
    case 67 : // sys_sigaction
        break;
    case 68 : // sys_sgetmask
        break;
    case 69 : // sys_ssetmask
        break;
    case 70 : // sys_setreuid
        break;
    case 71 : // sys_setregid
        break;
    case 72 : // sys_sigsuspend
        break;
    case 73 : // sys_sigpending
        break;
    case 74 : // sys_sethostname
        break;
    case 75 : // sys_setrlimit
        break;
    case 76 : // sys_getrlimit
        break;
    case 77 : // sys_getrusage
        break;
    case 78 : // sys_gettimeofday
        //				set_sys_need_red(0);
        break;
    case 79 : // sys_settimeofday
        //				set_sys_need_red(0);
        break;
    case 80 : // sys_getgroups
        break;
    case 81 : // sys_setgroups
        break;
    case 82 : // sys_select
        break;
    case 84 : // sys_oldlstat
        break;
    case 85 : // sys_readlink
        break;
    case 86 : // sys_uselib
        break;
    case 87 : // sys_swapon
        break;
    case 88 : // sys_reboot
        break;
    case 89 : // sys_readdir
        break;
    case 90 : // sys_mmap
        set_sys_need_red(0);
        break;
    case 91 : // sys_munmap
        set_sys_need_red(0);
        break;
    case 92 : // sys_truncate
        break;
    case 93 : // sys_ftruncate
        break;
    case 94 : // sys_fchmod
        break;
    case 95 : // sys_fchown
        break;
    case 96 : // sys_getpriority
        break;
    case 97 : // sys_setpriority
        break;
    case 98 : // sys_profil
        break;
    case 99 : // sys_statfs
    {
        char buf[6];
        memset(buf,0,6);
        file_flag=0;
        set_sys_need_red(0);
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 1024, 0)!=0)
            break;

        buf[5]='\0';

        if(strcmp(buf, "/proc") != 0||strcmp(buf, "/"))
        {
            file_flag = 0;
            set_sys_need_red(0);
        }
        else
        {
            file_flag = 1;
            set_sys_need_red(1);
        }
    }

    break;
    case 100 : // sys_fstatfs
        break;
    case 101 : // sys_ioperm
        break;
    case 102 : // sys_socketcall
        set_sys_need_red(1);
        file_flag = 1;
        break;

        break;
    case 103 : // sys_syslog
        break;
    case 104 : // sys_setitimer
        break;
    case 105 : // sys_getitimer
        break;
    case 106 : // sys_stat
    {
        char buf[6];
        memset(buf,0,6);
        file_flag=0;
        set_sys_need_red(0);
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 1024, 0)!=0)
            break;

        buf[5]='\0';

        if(strcmp(buf, "/proc") != 0||strcmp(buf, "/"))
        {
            file_flag = 0;
            set_sys_need_red(0);
        }
        else
        {
            file_flag = 1;
            set_sys_need_red(1);
        }
    }

    break;
    case 107 : // sys_lstat
    {
        char buf[6];
        memset(buf,0,6);
        file_flag=0;
        set_sys_need_red(0);
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 1024, 0)!=0)
            break;

        buf[5]='\0';

        if(strcmp(buf, "/proc") != 0)
        {
            file_flag = 0;
            set_sys_need_red(0);
        }
        else
        {
            file_flag = 1;
            set_sys_need_red(1);
        }
    }
    break;
    case 108 : // sys_fstat
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 109 : // sys_olduname
        break;
    case 110 : // sys_iopl
        break;
    case 111 : // sys_vhangup
        break;
    case 112 : // sys_idle
        break;
    case 113 : // sys_vm86old
        break;
    case 114 : // sys_wait4
#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log(" wait4 to exit");
#endif

        set_sys_need_red(0);
        //		vmmi_main_start = 0;
        //		run_timer();
        break;
    case 116 : // sys_sysinfo
        break;
    case 117 : // sys_ipc
        // call first second third ptr fifth
        //->EBX  ECX  EDX   ESI   EDI  EBP
        break;
    case 118 : // sys_fsync
        break;
    case 119 : // sys_sigreturn
        set_sys_need_red(0);
        break;
    case 120 : // sys_clone

#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
            qemu_log("clone child");
#endif
        set_sys_need_red(0);
        //		vmmi_main_start = 0;
        //			run_timer();
        break;
    case 121 : // sys_setdomainname
        break;
    case 122 : // sys_uname
        break;
    case 123 : // sys_modify_ldt
        break;
    case 124 : // sys_adjtimex
        break;
    case 125 : // sys_mprotect
        set_sys_need_red(0);
        break;
    case 126 : // sys_sigprocmask
        break;
    case 127 : // sys_create_module
        break;
    case 128 : // sys_init_module
        break;
    case 129 : // sys_delete_module
    {
        set_sys_need_red(1);
#ifdef DEBUG_VMMI
        char new_inst[]="\xb8\x00\x00\x00\x00";
        cpu_memory_rw_debug(cpu_single_env, 0xc1055e3f, inst_buff, 5, 0);
        cpu_memory_rw_debug(cpu_single_env, 0xc1055efc, inst_buff2, 5, 0);
        cpu_memory_rw_debug(cpu_single_env, 0xc1055cca, inst_buff3, 5, 0);
        cpu_memory_rw_debug(cpu_single_env, 0xc1055e3f, new_inst, 5,1);
        //		cpu_memory_rw_debug(cpu_single_env, 0xc1055efc, new_inst, 5,1);
        //		cpu_memory_rw_debug(cpu_single_env, 0xc1055cca, new_inst, 5,1);
        if(qemu_log_enabled())
            qemu_log("change %x\n", *(int *)inst_buff);
#endif
    }
    break;
    case 130 : // sys_get_kernel_syms
        break;
    case 131 : /// sys_quotactl
        break;
    case 132 : // sys_getpgid
        break;
    case 133 : // sys_fchdir
        break;
    case 134 : // sys_bdflush
        break;
    case 135 : // sys_sysfs
        break;
    case 136 : // sys_personality
        break;
    case 137 : // sys_afs_syscall
        break;
    case 138 : // sys_setfsuid
        break;
    case 139 : // sys_setfsgid
        break;
    case 140: //sys_llseek
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 141 : // sys_getdents
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 142 : // sys_select
        break;
    case 143:  // sys_flock
        break;
    case 144:  //sys_msync
        break;
    case 145: //sys_readv
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 146: //sys_writev
        set_sys_need_red(0);
        break;
    case 147 : // sys_getsid
        break;
    case 148 : // sys_fdatasync
        break;
    case 149 : // sys_sysctl
        break;
    case 150 : // sys_mlock
        break;
    case 151 : // sys_munlock
        break;
    case 152 : // sys_mlockall
        break;
    case 153 : // sys_munlockall
        break;
    case 154 : // sys_sched_setparam
        break;
    case 155 : // sys_sched_getparam
        break;
    case 156 : // sys_sched_setscheduler
        break;
    case 157 : // sys_sched_getscheduler
        break;
    case 158 : // sys_sched_yield
        break;
    case 159 : // sys_sched_get_priority_max
        break;
    case 160 : // sys_sched_get_priority_min
        break;
    case 161 : // sys_sched_rr_get_interval
        break;
    case 162 : // sys_nanosleep
        break;
    case 163 : // sys_mremap
        break;
    case 164 : // sys_setresuid
        break;
    case 165 : // sys_getresuid
        break;
    case 166 : // sys_vm86
        break;
    case 167 : // sys_query_module
        break;
    case 168:
        set_sys_need_red(0);
        break;
    case 169 : // sys_nfsservctl
        break;
    case 170 : // sys_setresgid
        break;
    case 171 : // sys_getresgid
        break;
    case 172 : // sys_prctl
        break;
    case 173 : // sys_rt_sigreturn
        set_sys_need_red(0);
        break;
    case 174 : // sys_rt_sigaction
        set_sys_need_red(0);
        break;
    case 175 : // sys_rt_sigprocmask
        set_sys_need_red(0);
        break;
    case 176 : // sys_rt_sigpending
        set_sys_need_red(0);
        break;
    case 177 : // sys_rt_sigtimedwait
        set_sys_need_red(0);
        break;
    case 178 : // sys_rt_sigqueueinfo
        set_sys_need_red(0);
        break;
    case 179 : // sys_rt_sigsuspend
        set_sys_need_red(0);
        break;
    case 180 : // sys_pread64
        break;
    case 181 : // sys_pwrite64
        break;
    case 182 : // sys_chown
        break;
    case 183 : // sys_getcwd
        break;
    case 184 : // sys_capget
        break;
    case 185 : // sys_capset
        break;
    case 186 : // sys_sigaltstack
        set_sys_need_red(0);
        break;
    case 187 : // sys_sendfile
        break;
    case 188 : // sys_getpmsg
        break;
    case 189 : // sys_putpmsg
        break;
    case 190 : // sys_vfork
        set_sys_need_red(0);
        break;
    case 191 : // sys_getrlimit
        break;
    case 192 : // sys_mmap2
        set_sys_need_red(0);
        break;
    case 193 : // sys_truncate64
        break;
    case 194 : // sys_ftruncate64
        break;
    case 195 : // sys_stat64
        //fprintf(logfile,"PID %3d (%16s)[sys_stat64  195]\n", pid, command);
    {
        char buf[256];
        memset(buf,0,256);
        file_flag=0;
        set_sys_need_red(0);
        if(qemu_log_enabled())
            qemu_log("statfs64\n");
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 256, 0)!=0)
            break;

        if(qemu_log_enabled())
            qemu_log("stat64 file %s\n", buf);

        buf[5]='\0';

        if(strcmp(buf, "/proc") !=0 )
        {
            buf[4]='\0';
            if(strcmp(buf, "/")==0 || strcmp(buf, "/sys")==0 || strcmp(buf, "/dev")==0)
            {
                file_flag = 1;
                set_sys_need_red(1);

            }
            else
            {
                file_flag = 0;
                set_sys_need_red(0);
            }
        }
        else
        {
            file_flag = 1;
            set_sys_need_red(1);
        }
    }
    break;
    case 196 : // sys_lstat64
        break;
    case 197 : // sys_fstat64
        //fprintf(logfile,"PID %3d (%16s)[sys_fstat64 197]\n", pid, command);
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 198 : // sys_lchown32
        break;
    case 199 : // sys_getuid32
        break;
    case 200 : // sys_getgid32
        break;
    case 201 : // sys_geteuid32

        break;
    case 202 : // sys_getegid32
        break;
    case 203 : // sys_setreuid32
        break;
    case 204 : // sys_setregid32
        break;
    case 205 : // sys_getgroups32
        break;
    case 206 : // sys_setgroups32
        break;
    case 207 : // sys_fchown32
        break;
    case 208 : // sys_setresuid32
        break;
    case 209 : // sys_getresuid32
        break;
    case 210 : // sys_setresgid32
        break;
    case 211 : // sys_getresgid32
        break;
    case 212 : // sys_chown32
        break;
    case 213 : // sys_setuid32
        break;
    case 214 : // sys_setgid32
        break;
    case 215 : // sys_setfsuid32
        break;
    case 216 : // sys_setfsgid32
        break;
    case 217 : // sys_pivot_root
        break;
    case 218 : // sys_mincore
        break;
    case 219 : // sys_madvise
        break;
    case 220 : // sys_getdents64
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 221 : // sys_fcntl64
        set_sys_need_red(get_file_flag(cpu_single_env->regs[R_EBX]));
        set_sys_need_red(get_file_taint());
        break;
    case 224 : // sys_gettid
        break;
    case 225 : // sys_readahead
        break;
    case 226 : // sys_setxattr
        break;
    case 227 : // sys_lsetxattr
        break;
    case 228 : // sys_fsetxattr
        break;
    case 229 : // sys_getxattr
        break;
    case 230 : // sys_lgetxattr
        break;
    case 231 : // sys_fgetxattr
        break;
    case 232 : // sys_listxattr
        break;
    case 233 : // sys_llistxattr
        break;
    case 234 : // sys_flistxattr
        break;
    case 235 : // sys_removexattr
        break;
    case 236 : // sys_lremovexattr
        break;
    case 237 : // sys_fremovexattr
        break;
    case 238 : // sys_tkill
        break;
    case 239 : // sys_sendfile64
        break;
    case 240 : // sys_futex
        set_sys_need_red(0);
        break;
    case 241 : // sys_sched_setaffinity
        break;
    case 242 : // sys_sched_getaffinity
        break;
    case 243 : // sys_set_thread_area
        set_sys_need_red(0);
        break;
    case 244 : // sys_get_thread_area
        set_sys_need_red(0);
        break;
    case 245 : // sys_io_setup
        set_sys_need_red(0);
        break;
    case 246 : // sys_io_destroy
        set_sys_need_red(0);
        break;
    case 247 : // sys_io_getevents
        set_sys_need_red(0);
        break;
    case 248 : // sys_io_submit
        set_sys_need_red(0);
        break;
    case 249 : // sys_io_cancel
        set_sys_need_red(0);
        break;
    case 250 : // sys_fadvise64
        break;
    case 252 : // sys_exit_group
    {
#ifdef DEBUG_VMMI
        if(qemu_log_enabled())
        {
            qemu_log(" monitor group exit");
            qemu_log(" context switch (%u  %u  %u %u)", int_con, sys_con, sys_con_w,excep_con);
        }
#endif


        //	 cpu_memory_rw_debug(cpu_single_env, vmmi_mon_start, inst_buff, 5, 1);
        /*delete module
        cpu_memory_rw_debug(cpu_single_env, 0xc1055efc, inst_buff2, 5, 1);
         cpu_memory_rw_debug(cpu_single_env, 0xc1055cca, inst_buff3, 5, 1);
         */
        vmmi_start = 0;
        vmmi_main_start = 0;
        set_sys_need_red(0);
        run_timer();
        pit_resend();
        //		sys_hook_init();
        break;
    }
    case 253 : // sys_lookup_dcookie
        break;
    case 254 : // sys_epoll_create
        set_sys_need_red(0);
        break;
    case 255 : // sys_epoll_ctl
        set_sys_need_red(0);
        break;
    case 256 : // sys_epoll_wait
        set_sys_need_red(0);
        break;
    case 257 : // sys_remap_file_pages
        break;
    case 258 : // sys_set_tid_address
        set_sys_need_red(0);
        break;
    case 259 : // sys_timer_create
        break;
    case 260: //sys_set_time
        break;
    case 261: //sys_get_time
        break;
    case 262: //sys_getoverrun
        break;
    case 263: //sys_delete
        break;
    case 264: //sys_set_time
        break;
    case 265: //sys_get_time
        set_sys_need_red(0);
        break;
    case 268:  //statfs64
    {
        char buf[256];
        memset(buf,0,256);
        file_flag=0;
        set_sys_need_red(0);
        if(qemu_log_enabled())
            qemu_log("statfs64\n");
        if(cpu_memory_rw_debug(cpu_single_env, cpu_single_env->regs[R_EBX] , buf, 256, 0)!=0)
            break;

        if(qemu_log_enabled())
            qemu_log("statfs64 file %s\n", buf);

        buf[5]='\0';

        if(strcmp(buf, "/proc") !=0 )
        {
            buf[4]='\0';
            if(strcmp(buf, "/")==0 || strcmp(buf, "/sys")==0 || strcmp(buf, "/dev")==0)
            {
                file_flag = 1;
                set_sys_need_red(1);

            }
            else
            {
                file_flag = 0;
                set_sys_need_red(0);
            }
        }
        else
        {
            file_flag = 1;
            set_sys_need_red(1);
        }
    }

    break;
    case 269:  //fstatfs64
        set_sys_need_red(get_file_taint());
        break;
    case 311: //set_robust_list
        set_sys_need_red(0);
        break;
    case 312: //set_robust_list
        set_sys_need_red(0);
        break;

    default:
        break;
    }  //switch

//	if(sys_need_red){
//		qemu_log("set vmmi_main_start");
//		vmmi_main_start = 1;
//	}

#ifdef VMMI_ALL_REDIRCTION
    if(!is_sysenter&&vmmi_profile&&vmmi_start&&sys_need_red)
    {
        if(qemu_log_enabled())
            qemu_log("start change esp");
        iret_handle = change_esp;
    }
#endif
}


void get_process_name(char * buf, char *fname)
{
    int len = strlen(buf);
    do
    {
        len--;
    }
    while(len>=0&&buf[len]!='/');

    len++;
    strcpy(fname, buf+len);

}
