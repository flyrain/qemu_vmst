#include <xed-interface.h>


typedef const xed_inst_t * INS;
typedef void (*InstrumentFunction)(INS ins);
void Instrument(INS ins);
void taint_reset();
void FD_Instrument(INS ins);
uint32_t get_file_taint();
int operand_is_mem(const xed_operand_enum_t op_name, uint32_t * mem_addr, int operand_i, unsigned char * taint);
int operand_is_reg(const xed_operand_enum_t op_name, xed_reg_enum_t * reg_id);
int operand_is_imm(const xed_operand_enum_t op_name, uint32_t * value);

