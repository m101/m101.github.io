// @author  m_101
// @year    2011
// @desc    GCHQ Challenge level 2
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

// if you want to debug and see all CPU states
//#define GCHQ_VM_DEBUG
// if you want to see (selected) disassembly
//#define GCHQ_DISAS
// if you want to see memory dumps
//#define GCHQ_MEMDUMP

// decrypted string should be: "GET /da75370fe15c4148bd4ceec861fbdaa5.exe HTTP/1.0"
//
/*  disasm
0x0000: movr r1, 4              r1 = 4
0x0002: movr r3, 170            r3 = 170
0x0004: movm r0, [ds:r2]        r0 = [ds:r2]
0x0006: xor r0, r3              r0 = r0 ^ r3
0x0008: movm [ds:r2], r0        [ds:r2] = r0
0x000a: add r2, 1               r2++
0x000c: add r3, 1               r3++
0x000e: cmp r2, 80              r2 == 80 ?
0x0010: movr r0, 20             r0 = 20
0x0012: jmpe r0                 jmp r0 if (r2 == 80)
0x0013: jmp r1                  jmp r1
0x0014: xor r0, r0              r0 = 0
0x0016: jmp r0:r0
0x0018: jmp r0
0x0019: jmp r0
0x001a: jmp r0
0x001b: jmp r0
//*/

uint8_t memory[] = {
    0x31, 0x04, 0x33, 0xaa, 0x40, 0x02, 0x80, 0x03, 0x52, 0x00, 0x72, 0x01, 0x73, 0x01, 0xb2, 0x50,
    0x30, 0x14, 0xc0, 0x01, 0x80, 0x00, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    
    0x98, 0xab, 0xd9, 0xa1, 0x9f, 0xa7, 0x83, 0x83, 0xf2, 0xb1, 0x34, 0xb6, 0xe4, 0xb7, 0xca, 0xb8,
    0xc9, 0xb8, 0x0e, 0xbd, 0x7d, 0x0f, 0xc0, 0xf1, 0xd9, 0x03, 0xc5, 0x3a, 0xc6, 0xc7, 0xc8, 0xc9,
    0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
    0xda, 0xdb, 0xa9, 0xcd, 0xdf, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
    0x26, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    0x7d, 0x1f, 0x15, 0x60, 0x4d, 0x4d, 0x52, 0x7d, 0x0e, 0x27, 0x6d, 0x10, 0x6d, 0x5a, 0x06, 0x56,
    0x47, 0x14, 0x42, 0x0e, 0xb6, 0xb2, 0xb2, 0xe6, 0xeb, 0xb4, 0x83, 0x8e, 0xd7, 0xe5, 0xd4, 0xd9,
    0xc3, 0xf0, 0x80, 0x95, 0xf1, 0x82, 0x82, 0x9a, 0xbd, 0x95, 0xa4, 0x8d, 0x9a, 0x2b, 0x30, 0x69,
    0x4a, 0x69, 0x65, 0x55, 0x1c, 0x7b, 0x69, 0x1c, 0x6e, 0x04, 0x74, 0x35, 0x21, 0x26, 0x2f, 0x60,
    0x03, 0x4e, 0x37, 0x1e, 0x33, 0x54, 0x39, 0xe6, 0xba, 0xb4, 0xa2, 0xad, 0xa4, 0xc5, 0x95, 0xc8,
    0xc1, 0xe4, 0x8a, 0xec, 0xe7, 0x92, 0x8b, 0xe8, 0x81, 0xf0, 0xad, 0x98, 0xa4, 0xd0, 0xc0, 0x8d,
    0xac, 0x22, 0x52, 0x65, 0x7e, 0x27, 0x2b, 0x5a, 0x12, 0x61, 0x0a, 0x01, 0x7a, 0x6b, 0x1d, 0x67,
    0x75, 0x70, 0x6c, 0x1b, 0x11, 0x25, 0x25, 0x70, 0x7f, 0x7e, 0x67, 0x63, 0x30, 0x3c, 0x6d, 0x6a,
    0x01, 0x51, 0x59, 0x5f, 0x56, 0x13, 0x10, 0x43, 0x19, 0x18, 0xe5, 0xe0, 0xbe, 0xbf, 0xbd, 0xe9,
    0xf0, 0xf1, 0xf9, 0xfa, 0xab, 0x8f, 0xc1, 0xdf, 0xcf, 0x8d, 0xf8, 0xe7, 0xe2, 0xe9, 0x93, 0x8e,
    0xec, 0xf5, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    
    0x37, 0x7a, 0x07, 0x11, 0x1f, 0x1d, 0x68, 0x25, 0x32, 0x77, 0x1e, 0x62, 0x23, 0x5b, 0x47, 0x55,
    0x53, 0x30, 0x11, 0x42, 0xf6, 0xf1, 0xb1, 0xe6, 0xc3, 0xcc, 0xf8, 0xc5, 0xe4, 0xcc, 0xc0, 0xd3,
    0x85, 0xfd, 0x9a, 0xe3, 0xe6, 0x81, 0xb5, 0xbb, 0xd7, 0xcd, 0x87, 0xa3, 0xd3, 0x6b, 0x36, 0x6f,
    0x6f, 0x66, 0x55, 0x30, 0x16, 0x45, 0x5e, 0x09, 0x74, 0x5c, 0x3f, 0x29, 0x2b, 0x66, 0x3d, 0x0d,
    0x02, 0x30, 0x28, 0x35, 0x15, 0x09, 0x15, 0xdd, 0xec, 0xb8, 0xe2, 0xfb, 0xd8, 0xcb, 0xd8, 0xd1,
    0x8b, 0xd5, 0x82, 0xd9, 0x9a, 0xf1, 0x92, 0xab, 0xe8, 0xa6, 0xd6, 0xd0, 0x8c, 0xaa, 0xd2, 0x94,
    0xcf, 0x45, 0x46, 0x67, 0x20, 0x7d, 0x44, 0x14, 0x6b, 0x45, 0x6d, 0x54, 0x03, 0x17, 0x60, 0x62,
    0x55, 0x5a, 0x4a, 0x66, 0x61, 0x11, 0x57, 0x68, 0x75, 0x05, 0x62, 0x36, 0x7d, 0x02, 0x10, 0x4b,
    0x08, 0x22, 0x42, 0x32, 0xba, 0xe2, 0xb9, 0xe2, 0xd6, 0xb9, 0xff, 0xc3, 0xe9, 0x8a, 0x8f, 0xc1,
    0x8f, 0xe1, 0xb8, 0xa4, 0x96, 0xf1, 0x8f, 0x81, 0xb1, 0x8d, 0x89, 0xcc, 0xd4, 0x78, 0x76, 0x61,
    0x72, 0x3e, 0x37, 0x23, 0x56, 0x73, 0x71, 0x79, 0x63, 0x7c, 0x08, 0x11, 0x20, 0x69, 0x7a, 0x14,
    0x68, 0x05, 0x21, 0x1e, 0x32, 0x27, 0x59, 0xb7, 0xcf, 0xab, 0xdd, 0xd5, 0xcc, 0x97, 0x93, 0xf2,
    0xe7, 0xc0, 0xeb, 0xff, 0xe9, 0xa3, 0xbf, 0xa1, 0xab, 0x8b, 0xbb, 0x9e, 0x9e, 0x8c, 0xa0, 0xc1,
    0x9b, 0x5a, 0x2f, 0x2f, 0x4e, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// defines for instructions
#define INST_JMP    0x0
#define INST_MOVR   0x1
#define INST_MOVM   0x2
#define INST_ADD    0x3
#define INST_XOR    0x4
#define INST_CMP    0x5
#define INST_JMPE   0x6
#define INST_HLT    0x7

/*! @desc   Structure for VM CPU */
struct vm_proc_s {
    // program counter
    uint32_t pc;
    // registers
    union {
        struct {
            /* general registers */
            uint8_t r0, r1, r2, r3;
            /* segment registers */
            union {
                struct {
                    uint8_t r4, r5;
                };
                struct {
                    uint8_t cs, ds;
                };
            };
        };
        uint8_t r[7];
    };
    // flag register
    uint8_t fl;
} __attribute__ ((packed));

// instruction
struct vm_inst_s {
    union {
        // big endian
        /*
           struct {
           uint8_t opcode:3;
           uint8_t mod:1;
           uint8_t operand1:4;
           };
        //*/
        // little endian
        struct {
            uint8_t operand1:4;
            uint8_t mod:1;
            uint8_t opcode:3;
        };
        uint8_t byte1;
    };
    uint8_t operand2; // optionnal (depend on mod)
    // instruction size
    int sz;
    // repr
    char *repr;
    int lenRepr;
    int szRepr;
};

// memory related
// get a linear address
int vm_addr_linear(uint8_t segment, int offset);
void memory_set(int segment, int offset, uint8_t value);
uint8_t memory_get(int segment, int offset);

// == instruction related
// check for operand2 presence
int vm_inst_has_operand2(struct vm_inst_s *inst);
// decode an instruction
struct vm_inst_s* vm_inst_decode (struct vm_inst_s **inst, uint8_t *bytes, int len);
// disassemble an instruction
int vm_inst_repr (struct vm_inst_s *inst);
// print disassembly
void vm_inst_disasm_show (uint8_t *bytes, int len, int nInstruction);

// VM execution
// exec instruction in mod0
int vm_exec_mod0(struct vm_inst_s *inst);
// exec instruction in mod1
int vm_exec_mod1(struct vm_inst_s *inst);
// exec vm code
int vm_exec(uint8_t *bytes, int len);

// == DEBUG related
// show CPU state
void vm_cpu_show (void);
// dump an instruction
void vm_inst_dump (struct vm_inst_s *inst);
// dump a byte (showing its bits)
void dump_byte(uint8_t byte);
// dump
int dump (const unsigned char *bytes, const int nbytes, const size_t align);

// vm cpu
static struct vm_proc_s vm_cpu = {0};

// asm translation table
static char *op_repr[] = { "jmp", "movr", "movm", "add", "xor", "cmp", "jmpe", "hlt" };
static char *reg_repr[] = { "r0", "r1", "r2", "r3", "cs", "ds", "unk1", "unk2" };

// get a linear address
int vm_addr_linear(uint8_t segment, int offset) {
    return segment * 16 + offset;
}

// set memory
void memory_set(int segment, int offset, uint8_t value) {
    int linear = vm_addr_linear(segment, offset);

    // set
    *(memory + linear) = value;
}

// get memory cell
uint8_t memory_get(int segment, int offset) {
    int linear = vm_addr_linear(segment, offset);

    // set
    return *(memory + linear);
}

// check for operand2 presence
int vm_inst_has_operand2(struct vm_inst_s *inst) {
    // check parameters
    if (!inst)
        return 0;

    // HLT does not have operand 2 in any mod
    if (inst->opcode == INST_HLT)
        return 0;

    // if mod 0
    if (inst->mod == 0) {
        if (inst->opcode == INST_JMP
                || inst->opcode == INST_JMPE)
            return 0;
        return 1;
    }

    // if mod 1
    return 1;
}

// decode an instruction
struct vm_inst_s* vm_inst_decode (struct vm_inst_s **inst, uint8_t *bytes, int len) {
    // check parameters
    if (!inst || !bytes || len <= 0)
        return NULL;

    // alloc instruction
    if (!*inst) {
        *inst = calloc(1, sizeof(**inst));
        if (!*inst)
            return NULL;
    }

    //
    (*inst)->opcode = *bytes >> 5;
    (*inst)->sz = 1;
    if ((*inst)->opcode != INST_HLT) {
        (*inst)->mod = (*bytes & 0x10) >> 4;
        (*inst)->operand1 = *bytes & 0x7;
    }
    else {
        (*inst)->mod = 0;
        (*inst)->operand1 = 0;
    }

    // decode second operand if present
    if (vm_inst_has_operand2(*inst)) {
        (*inst)->sz = 2;
        (*inst)->operand2 = *(bytes+1);
        // if mod0
        if ((*inst)->mod == 0)
            (*inst)->operand2 &= 0x7;
        // else if mod1 (immediate)
        else if ((*inst)->mod == 1) {
            // movm: operand2 is a register
            if ((*inst)->opcode == INST_MOVM)
                (*inst)->operand2 &= 0x7;
        }
    }

    return *inst;
}

// get an instruction repr
int vm_inst_repr (struct vm_inst_s *inst) {
    char buffer[256];
    uint8_t reg1, reg2;

    // check parameter
    if (!inst)
        return -1;

    // alloc repr
    if (!inst->repr) {
        inst->repr = calloc(1024, sizeof(*(inst->repr)));
        if (!inst->repr)
            return -1;
        inst->szRepr = 1024;
    }

    // set to zero first
    memset(inst->repr, 0, inst->szRepr);

    // reg
    reg1 = inst->operand1 & 0x7;
    reg2 = inst->operand2 & 0x7;

    // if we try to have more than 6 registers
    //      or we try to jmp to cs or ds
    // then instruction is invalid
    if (reg1 >= 6
            || (inst->opcode == INST_JMP && reg1 >= 4)
            || (inst->opcode == INST_JMPE && reg1 >= 4)
       ) {
        strcpy(inst->repr, "invalid");
        inst->lenRepr = strlen(inst->repr);
        return inst->lenRepr;
    }

    //
    strcpy(inst->repr, op_repr[inst->opcode]);
    // if HLT
    // then finished
    if (inst->opcode == INST_HLT) {
        inst->lenRepr = strlen(inst->repr);
        return inst->lenRepr;
    }
    // else we continue disassembling
    strncat(inst->repr, " ", inst->szRepr - strlen(inst->repr));
    // mod 0
    if (inst->mod == 0) {
        strncat(inst->repr, reg_repr[reg1], inst->szRepr - strlen(inst->repr));
        if (vm_inst_has_operand2(inst)) {
            strncat(inst->repr, ", ", inst->szRepr - strlen(inst->repr));
            if (inst->opcode != INST_MOVM)
                strncat(inst->repr, reg_repr[reg2], inst->szRepr - strlen(inst->repr));
            else {
                strncat(inst->repr, "[ds:", inst->szRepr - strlen(inst->repr));
                strncat(inst->repr, reg_repr[reg2], inst->szRepr - strlen(inst->repr));
                strncat(inst->repr, "]", inst->szRepr - strlen(inst->repr));
            }
        }
    }
    // mod 1
    else {
        // jmp and jmpe
        if (inst->opcode == INST_JMP || inst->opcode == INST_JMPE) {
            // if we try to have more than 4 registers for jmp or jmpe
            // then instruction is invalid
            if (reg2 >= 4) {
                strcpy(inst->repr, "invalid");
                inst->lenRepr = strlen(inst->repr);
                return inst->lenRepr;
            }

            snprintf(inst->repr, inst->szRepr - strlen(inst->repr), "%s %d:", op_repr[inst->opcode], inst->operand2);
            strncat(inst->repr, reg_repr[reg1], inst->szRepr - strlen(inst->repr));
        }
        // movm
        else if (inst->opcode == INST_MOVM) {
            // if we try to have more than 6 registers
            // then instruction is invalid
            if (reg2 >= 6) {
                strcpy(inst->repr, "invalid");
                inst->lenRepr = strlen(inst->repr);
                return inst->lenRepr;
            }

            strncat(inst->repr, "[ds:", inst->szRepr - strlen(inst->repr));
            strncat(inst->repr, reg_repr[reg1], inst->szRepr - strlen(inst->repr));
            strncat(inst->repr, "]", inst->szRepr - strlen(inst->repr));
            strncat(inst->repr, ", ", inst->szRepr - strlen(inst->repr));
            strncat(inst->repr, reg_repr[reg2], inst->szRepr - strlen(inst->repr));
        }
        // all the other instructions
        else {
            strncat(inst->repr, reg_repr[reg1], inst->szRepr - strlen(inst->repr));
            snprintf(buffer, 256,", %d", inst->operand2);
            strncat(inst->repr, buffer, inst->szRepr - strlen(inst->repr));
        }
    }
    inst->repr[inst->szRepr - 1] = '\0';
    inst->lenRepr = strlen(inst->repr);

    return inst->lenRepr;
}

/*! @desc   print disassembly
 *  @param  bytes   Byte code
 *  @param  len     Length of byte code
 *  @param  nInstruction    Number of instruction to disassemble
 *  @ret    NULL
 */
void vm_inst_disasm_show (uint8_t *bytes, int len, int nInstruction) {
    int idxLen, nInst;
    struct vm_inst_s *inst = NULL;
    // for address line
    static uint8_t *origin = NULL;

    // check parameter
    if (!bytes || len <= 0 || nInstruction <= 0)
        return;

    // set origin
    if (origin == NULL)
        origin = bytes;

    idxLen = nInst = 0;
    while (idxLen < len && nInst < nInstruction) {
        inst = vm_inst_decode(&inst, bytes + idxLen, len - idxLen);

        vm_inst_repr(inst);

        printf("0x%04x: %s\n", bytes - origin + idxLen, inst->repr);

        idxLen += inst->sz;
        nInst++;
    }
    free(inst->repr);
    free(inst);
}

// exec instruction in mod0
int vm_exec_mod0(struct vm_inst_s *inst) {
    // check parameter
    if (!inst) {
        printf("failed executing in mod0\n");
        return -1;
    }

    if (((inst->operand1 & 0x7) >= 6 || (inst->operand2 & 0x7) >= 6) && inst->opcode != INST_HLT)
        printf("trying to execute invalid instruction\n");

    // execute instruction
    switch (inst->opcode) {
        case INST_JMP:
            vm_cpu.pc = vm_addr_linear(vm_cpu.cs, vm_cpu.r[inst->operand1 & 0x7]);
            break;
        case INST_MOVR:
            vm_cpu.r[inst->operand1 & 0x7] = vm_cpu.r[inst->operand2 & 0x7];
            vm_cpu.pc += 2;
            break;
        case INST_MOVM:
            vm_cpu.r[inst->operand1 & 0x7] = memory_get(vm_cpu.ds, vm_cpu.r[inst->operand2 & 0x7]);
            vm_cpu.pc += 2;
            break;
        case INST_ADD:
            vm_cpu.r[inst->operand1 & 0x7] += vm_cpu.r[inst->operand2 & 0x7];
            vm_cpu.pc += 2;
            break;
        case INST_XOR:
            vm_cpu.r[inst->operand1 & 0x7] ^= vm_cpu.r[inst->operand2 & 0x7];
            vm_cpu.pc += 2;
            break;
        case INST_CMP:
            if (vm_cpu.r[inst->operand1 & 0x7] == vm_cpu.r[inst->operand2 & 0x7])
                vm_cpu.fl = 0;
            else if (vm_cpu.r[inst->operand1 & 0x7] < vm_cpu.r[inst->operand2 & 0x7])
                vm_cpu.fl = 0xff;
            else
                vm_cpu.fl = 1;
            vm_cpu.pc += 2;
            break;
            // jump if equal
        case INST_JMPE:
            if (vm_cpu.fl == 0)
                vm_cpu.pc = vm_addr_linear(vm_cpu.cs, vm_cpu.r[inst->operand1 & 0x7]);
            else
                vm_cpu.pc++;
            break;
        case INST_HLT:
            vm_cpu.pc++;
            printf("CPU HLT\n");
            vm_cpu_show();
            return INST_HLT;
            break;
    }

    return 0;
}

// exec instruction in mod1
int vm_exec_mod1(struct vm_inst_s *inst) {
    // check parameter
    if (!inst) {
        printf("failed executing in mod1\n");
        return -1;
    }

    if ((inst->operand1 & 0x7) >= 6 && inst->opcode != INST_HLT)
        printf("trying to execute invalid instruction\n");

    // execute instruction
    switch (inst->opcode) {
        case INST_JMP:
            vm_cpu.pc = vm_addr_linear(inst->operand2, vm_cpu.r[inst->operand1 & 0x7]);
            vm_cpu.cs = inst->operand2;
            break;
        case INST_MOVR:
            vm_cpu.r[inst->operand1 & 0x7] = inst->operand2;
            vm_cpu.pc += 2;
            break;
        case INST_MOVM:
            memory_set(vm_cpu.ds, vm_cpu.r[inst->operand1 & 0x7], vm_cpu.r[inst->operand2 & 0x7]);
            vm_cpu.pc += 2;
            break;
        case INST_ADD:
            vm_cpu.r[inst->operand1 & 0x7] += inst->operand2;
            vm_cpu.pc += 2;
            break;
        case INST_XOR:
            vm_cpu.r[inst->operand1 & 0x7] ^= inst->operand2;
            vm_cpu.pc += 2;
            break;
        case INST_CMP:
            if (vm_cpu.r[inst->operand1 & 0x7] == inst->operand2)
                vm_cpu.fl = 0;
            else if (vm_cpu.r[inst->operand1 & 0x7] < inst->operand2)
                vm_cpu.fl = 0xff;
            else
                vm_cpu.fl = 1;
            vm_cpu.pc += 2;
            break;
        case INST_JMPE:
            if (vm_cpu.fl == 0) {
                vm_cpu.pc = vm_addr_linear(inst->operand2, vm_cpu.r[inst->operand1 & 0x7]);
                vm_cpu.cs = inst->operand2;
            }
            else
                vm_cpu.pc += 2;
            break;
        case INST_HLT:
            vm_cpu.pc++;
            printf("CPU HLT\n");
            vm_cpu_show();
            return INST_HLT;
            break;
    }

    return 0;
}

// exec vm code
int vm_exec(uint8_t *bytes, int len) {
    struct vm_inst_s *inst = NULL;

    // check parameter
    if (!bytes || len <= 0)
        return -1;

    // real program counter
    inst = vm_inst_decode(&inst, bytes, len);
    while (inst->opcode != INST_HLT && bytes + vm_cpu.pc < bytes + len) {
        // 
        if (inst->mod == 0) {
            vm_exec_mod0(inst);
        }
        else {
            vm_exec_mod1(inst);
        }

#ifdef GCHQ_VM_DEBUG
        printf("== DEBUG\n");
        if (inst->mod)
            printf("executing in mod 1\n");
        else
            printf("executing in mod 0\n");
        vm_inst_repr(inst);
        printf("instruction: %s\n", inst->repr);
        vm_inst_dump(inst);
        vm_cpu_show();
        printf("\n");
#endif

        // decode next instruction
        inst = vm_inst_decode(&inst, bytes + vm_cpu.pc, 2);
    }
    free(inst->repr);
    free(inst);

    return 0;
}

// == DEBUG related

// show CPU state
void vm_cpu_show (void) {
    printf("== CPU STATE\n");
    printf("pc: 0x%02x - %d\n", vm_cpu.pc, vm_cpu.pc);
    printf("r0: 0x%02x - %d\n", vm_cpu.r0, vm_cpu.r0);
    printf("r1: 0x%02x - %d\n", vm_cpu.r1, vm_cpu.r1);
    printf("r2: 0x%02x - %d\n", vm_cpu.r2, vm_cpu.r2);
    printf("r3: 0x%02x - %d\n", vm_cpu.r3, vm_cpu.r3);
    printf("cs: 0x%02x - %d\n", vm_cpu.cs, vm_cpu.cs);
    printf("ds: 0x%02x - %d\n", vm_cpu.ds, vm_cpu.ds);
    printf("fl: 0x%02x\n", vm_cpu.fl);
}

// dump an instruction
void vm_inst_dump (struct vm_inst_s *inst) {
    // check parameter
    if (!inst)
        return;

    printf("byte1: %02x\n", inst->byte1);
    printf("dump(byte1): ");
    dump_byte(inst->byte1);
    printf("opcode: %d - %s\n", inst->opcode, op_repr[inst->opcode]);
    printf("mod: %d\n", inst->mod);
    printf("operand1: %d - %s\n", inst->operand1, reg_repr[inst->operand1]);
    if (vm_inst_has_operand2(inst)) {
        if (inst->mod)
            printf("operand2: %d\n", inst->operand2);
        else
            printf("operand2: %d - %s\n", inst->operand2, reg_repr[inst->operand2]);
        printf("dump(operand2): ");
        dump_byte(inst->operand2);
    }
}


// dump a byte (showing its bits)
void dump_byte(uint8_t byte) {
    int idxByte;

    for (idxByte = 7; idxByte >= 0; idxByte--) {
        printf("%d ", (byte >> idxByte) & 0x1);
    }
    printf("\n");
}

// dump
int dump (const unsigned char *bytes, const int nbytes, const size_t align) {
    size_t idxBytes, j, last;
    int nDisp;
    int lineNum;

    if (!bytes || nbytes <= 0)
        return -1;

    // first part of line is hex
    for (idxBytes = 0, last = 0, lineNum = 0; idxBytes < nbytes; idxBytes++) {
        // show line number
        if ( idxBytes % align == 0) {
            printf("%3d : 0x%03x : ", lineNum, idxBytes);
            lineNum++;
        }
        // show byte
        printf ("%02x ", bytes[idxBytes]);
        // if we got to the alignment value or end of bytes
        // we print the second part of the line
        if ( (idxBytes + 1) % align == 0 || idxBytes == nbytes - 1 ) {
            // we print spaces if we arrived at end of bytes
            if (idxBytes == nbytes - 1) {
                // compute the number of spaces to show
                nDisp = align - (nbytes % align);
                nDisp = (nbytes % align) ? nDisp : 0;
                for (j = 0; j < nDisp; j++)
                    printf("   ");
            }
            // separation
            printf ("| ");
            // second part of line is corresponding character
            for (j = last; j < last + align && j < nbytes;  j++) {
                if (isprint(bytes[j]))
                    printf ("%c", bytes[j]);
                else
                    putchar ('.');
            }
            putchar ('\n');
            last = idxBytes + 1;
        }
    }

    return 0;
}

int main (int argc, char *argv[]) {
#ifdef GCHQ_DISAS
    // before bytecode execution
    printf("== DISASM (before)\n");
    vm_inst_disasm_show(memory, sizeof(memory), 16);
    printf("[...]\n");
    vm_inst_disasm_show(memory + 250, sizeof(memory), 32);
    printf("\n");
#endif

#ifdef GCHQ_MEMDUMP
    printf("== MEMORY DUMP (before)\n");
    dump(memory, sizeof(memory), 16);
    printf("\n");
#endif

    // initialize the CPU
    printf("[+] Initializing VM CPU\n");
    vm_cpu.ds = 0x10;
    // execute the bytecode
    printf("[+] Executing bytecode\n");
    vm_exec(memory, sizeof(memory));
    printf("[+] Finished executing bytecode\n");
    printf("[+] Answer: '%s'\n", memory + 448);
    printf("\n");

#ifdef GCHQ_DISAS
    // after bytecode execution
    printf("== DISASM (after)\n");
    vm_inst_disasm_show(memory, sizeof(memory), 16);
    printf("[...]\n");
    vm_inst_disasm_show(memory + 250, sizeof(memory), 24);
    printf("[...]\n");
    vm_inst_disasm_show(memory + 304, sizeof(memory), 24);
    printf("\n");
#endif

#ifdef GCHQ_MEMDUMP
    printf("== MEMORY DUMP (after)\n");
    dump(memory, sizeof(memory), 16);
    printf("\n");
#endif

    /*
    // what is in the 512 + 256 bytes?
#ifdef GCHQ_DISAS
printf("== DISASM\n");
vm_inst_disasm_show(memory + 512, 256, 256);
printf("\n");
#endif
    //*/

    return 0;
}

