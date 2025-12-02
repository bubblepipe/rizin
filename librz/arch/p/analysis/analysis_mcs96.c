#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include "p/asm/asm_mcs96.c"

// Manual:
// https://datasheets.chipdb.org/Intel/MCS96/MANUALS/27231703.PDF

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
    switch (query) {
        case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
            return 1;
        case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
            return 6;
        case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
            return 1; 
        case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
            return 2; // WORDs must be aligned at even byte boundaries in the address space. 
        case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
            return true;
        default:
            return -1;
    }
}

/**
 * Extract 11-bit signed displacement from sjmp/scall instruction.
 * Format: (instr|xxx)(disp-low) 
 *
 * \param opcode First byte of the instruction, containing upper 3 bits of the displacement
 * \param disp_low Second byte of the instruction, containing lower 8 bits of the displacement
 * \return Sign-extended 16-bit displacement (-1024 to +1023)
 */
static st16 extract_disp11(ut8 opcode, ut8 disp_low) {
    st16 upper3bits = (st16)(opcode & 0b00000111);
    st16 disp = (upper3bits << 8) | disp_low;
    
    // Sign-extend from 11 bits to 16 bits
    if (disp & 0x400) {  // Check if bit 10 (sign bit) is set
        disp |= 0xF800;  // Set bits 15-11 to extend the sign
    }

    return disp;
}

static char *get_reg_profile(RzAnalysis *analysis) {
    const char *p =
        "=PC pc\n"
        "=SP sp\n"
        "=SR psw\n"
        "gpr pc  .16  0   0\n"   // Program counter
        "gpr sp  .16  2   0\n"   // Stack pointer
        "gpr psw .16  4   0\n";  // Processor status word
    return rz_str_dup(p);
}

typedef enum {
	MCS96_ADDRESSING_REG_DIRECT = 0, // 2 reg 
	MCS96_ADDRESSING_IMMEDIATE = 1,  // 1 reg + 1 imm
	MCS96_ADDRESSING_INDIRECT = 2,   // 
	MCS96_ADDRESSING_INDEXED = 3,
} MCS96_ADDRESSING_MODE;

/**
 * Extract addressing mode from MCS-96 instruction opcode.
 * The lower 2 bits (aa) encode the addressing mode for many instructions.
 * Format: (xxxxxxaa)
 *
 * \param opcode The instruction opcode byte
 * \return Addressing mode (0-3)
 */
static MCS96_ADDRESSING_MODE extract_addressing_mode(ut8 opcode) {
	return (MCS96_ADDRESSING_MODE)(opcode & 0x03);
}


/**
 * Extract shift count from the second byte of shift instructions, and update 
 * the analysis op accordingly.
 * The count may be specified either as an immediate value in the range of 0 to 
 * 15 (0FH), inclusive, or as the content of any register (10H – 0FFH) with a 
 * value in the range of 0 to 31 (1FH), inclusive.
 */
static void analyze_shift_count(RzAnalysisOp *op, ut8 byte) {
    if (byte <= 0x0F) { // immediate value
        op->val = byte; 
    } else { // register value
        op->ptr = byte; 
    }
}

static int analyze_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
    RzStrBuf str = {0};
    int size = mcs96_len(buf, len, &str); 

    // for valid instructions, a positive integer returned from mcs96_len guarantees:
    // 1. size > 0 
    // 2. size >= len
    // there should be no need to check for size > len after this point.
    if (size <= 0) {  
        return -1;
    }

    ut8 opcode = buf[0];
    op->size = size;
    op->addr = addr;
    op->nopcode = 1;
    op->id = opcode; // TODO: more specific id?
    op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
    
    MCS96_ADDRESSING_MODE addr_mode = extract_addressing_mode(opcode);

    switch (opcode) {
    case 0x00:  // skip
        op->type = RZ_ANALYSIS_OP_TYPE_NOP;
        break;
    case 0x01: case 0x02: case 0x03: case 0x04:  // illegal
    case 0x05: case 0x06: case 0x07:
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0x08: // shr
        op->type = RZ_ANALYSIS_OP_TYPE_SHR;
        op->sign = false;
        analyze_shift_count(op, buf[1]);
        break;
    case 0x09: // shl
        op->type = RZ_ANALYSIS_OP_TYPE_SHL;
        op->sign = false;
        analyze_shift_count(op, buf[1]);
        break;
    case 0x0a: // shra
        op->type = RZ_ANALYSIS_OP_TYPE_SAR;
        op->sign = true;
        analyze_shift_count(op, buf[1]);
        break;
    case 0x0b: 
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0x0c: // shrl
        op->type = RZ_ANALYSIS_OP_TYPE_SHR;
        op->sign = false;
        analyze_shift_count(op, buf[1]);
        break; 
    case 0x0d: // shll
        op->type = RZ_ANALYSIS_OP_TYPE_SHL;
        op->sign = false;
        analyze_shift_count(op, buf[1]);
        break;
    case 0x0e: // shral
        op->type = RZ_ANALYSIS_OP_TYPE_SAR;
        op->sign = true;
        analyze_shift_count(op, buf[1]);
        break;  
    case 0x0f: // norml
        op->type = RZ_ANALYSIS_OP_TYPE_UNK;
        break;
    case 0x10: case 0x11: case 0x12: case 0x13: 
    case 0x14: case 0x15: case 0x16: case 0x17: // invalid
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0x18: // shrb
        op->type = RZ_ANALYSIS_OP_TYPE_SHR;
        op->sign = false;
        analyze_shift_count(op, buf[1]);
        break;
    case 0x19: // shlb
        op->type = RZ_ANALYSIS_OP_TYPE_SHL;
        op->sign = false;
        analyze_shift_count(op, buf[1]);
        break;
    case 0x1a: // shrab
        op->type = RZ_ANALYSIS_OP_TYPE_SAR;
        op->sign = true;
        analyze_shift_count(op, buf[1]);
        break;
    case 0x1b: case 0x1c: case 0x1d: case 0x1e: 
    case 0x1f: // invalid
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0x20: case 0x21: case 0x22: case 0x23:  
    case 0x24: case 0x25: case 0x26: case 0x27: // sjmp
        op->type = RZ_ANALYSIS_OP_TYPE_JMP;
        op->id = opcode & 0b11111000; // chop off lower 3 bits 
        st16 imm = extract_disp11(opcode, buf[1]);
        op->val = imm;
        op->jump = addr + op->size + imm;
        op->eob = true;
        break;
    case 0x28: case 0x29: case 0x2a: case 0x2b:  
    case 0x2c: case 0x2d: case 0x2e: case 0x2f: // scall
        op->type = RZ_ANALYSIS_OP_TYPE_CALL;
        op->id = opcode & 0b11111000; // chop off lower 3 bits 
        imm = extract_disp11(opcode, buf[1]);
        op->val = imm;
        op->jump = addr + op->size + imm;
        op->eob = true;
        op->stackptr = -2; 
        op->stackop = RZ_ANALYSIS_STACK_INC;
        break;
    case 0x30: case 0x31: case 0x32: case 0x33: 
    case 0x34: case 0x35: case 0x36: case 0x37: // jbc
    case 0x38: case 0x39: case 0x3a: case 0x3b: 
    case 0x3c: case 0x3d: case 0x3e: case 0x3f: // jbs
        op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
        imm = (st8)buf[2]; // 8-bit displacement
        op->val = imm;
        op->jump = addr + op->size + imm;
        op->fail = addr + op->size;   
        op->eob = true;
        break;
    case 0x40: case 0x41: case 0x42: case 0x43: // and 
        op->type = RZ_ANALYSIS_OP_TYPE_AND;
        break;
    case 0x44: case 0x45: case 0x46: case 0x47: // add 
        op->type = RZ_ANALYSIS_OP_TYPE_ADD;
        break;
    case 0x48: case 0x49: case 0x4a: case 0x4b: // sub 
        op->type = RZ_ANALYSIS_OP_TYPE_SUB;
        break;
    case 0x4c: case 0x4d: case 0x4e: case 0x4f: // mulu
        op->type = RZ_ANALYSIS_OP_TYPE_MUL;
        break;
    case 0x50: case 0x51: case 0x52: case 0x53: // andb
        op->type = RZ_ANALYSIS_OP_TYPE_AND;
        break;
    case 0x54: case 0x55: case 0x56: case 0x57: // addb
        op->type = RZ_ANALYSIS_OP_TYPE_ADD;
        break;
    case 0x58: case 0x59: case 0x5a: case 0x5b: // subb
        op->type = RZ_ANALYSIS_OP_TYPE_SUB;
        break;
    case 0x5c: case 0x5d: case 0x5e: case 0x5f: // mulub
        op->type = RZ_ANALYSIS_OP_TYPE_MUL;
        break;
    case 0x60: case 0x61: case 0x62: case 0x63: // and
        op->type = RZ_ANALYSIS_OP_TYPE_AND;
        break;
    case 0x64: case 0x65: case 0x66: case 0x67: // add
        op->type = RZ_ANALYSIS_OP_TYPE_ADD;
        break;
    case 0x68: case 0x69: case 0x6a: case 0x6b: // sub
        op->type = RZ_ANALYSIS_OP_TYPE_SUB;
        break;
    case 0x6c: case 0x6d: case 0x6e: case 0x6f: // mulu
        op->type = RZ_ANALYSIS_OP_TYPE_MUL;
        break;
    case 0x70: case 0x71: case 0x72: case 0x73: // andb
        op->type = RZ_ANALYSIS_OP_TYPE_AND;
        break;
    case 0x74: case 0x75: case 0x76: case 0x77: // addb
        op->type = RZ_ANALYSIS_OP_TYPE_ADD;
        break;
    case 0x78: case 0x79: case 0x7a: case 0x7b: // subb
        op->type = RZ_ANALYSIS_OP_TYPE_SUB;
        break;
    case 0x7c: case 0x7d: case 0x7e: case 0x7f: // mulub
        op->type = RZ_ANALYSIS_OP_TYPE_MUL;
        break;
    case 0x80: case 0x81: case 0x82: case 0x83: // or
        op->type = RZ_ANALYSIS_OP_TYPE_OR;
        break;
    case 0x84: case 0x85: case 0x86: case 0x87: // xor
        op->type = RZ_ANALYSIS_OP_TYPE_XOR;
        break;
    case 0x88: case 0x89: case 0x8a: case 0x8b: // cmp
        op->type = RZ_ANALYSIS_OP_TYPE_CMP;
        break;
    case 0x8c: case 0x8d: case 0x8e: case 0x8f: // divu
        op->type = RZ_ANALYSIS_OP_TYPE_DIV;
        break;
    case 0x90: case 0x91: case 0x92: case 0x93: // orb
        op->type = RZ_ANALYSIS_OP_TYPE_OR;
        break;
    case 0x94: case 0x95: case 0x96: case 0x97: // xorb
        op->type = RZ_ANALYSIS_OP_TYPE_XOR;
        break;
    case 0x98: case 0x99: case 0x9a: case 0x9b: // cmpb
        op->type = RZ_ANALYSIS_OP_TYPE_CMP;
        break;
    case 0x9c: case 0x9d: case 0x9e: case 0x9f: // divub
        op->type = RZ_ANALYSIS_OP_TYPE_DIV;
        break;
    case 0xa0: case 0xa1: case 0xa2: case 0xa3: // ld
        op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
        break;
    case 0xa4: case 0xa5: case 0xa6: case 0xa7: // addc
        op->type = RZ_ANALYSIS_OP_TYPE_ADD;
        break;
    case 0xa8: case 0xa9: case 0xaa: case 0xab: // subc
        op->type = RZ_ANALYSIS_OP_TYPE_SUB;
        break;
    case 0xac: case 0xad: case 0xae: case 0xaf: // ldbze
        op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
        break;
    case 0xb0: case 0xb1: case 0xb2: case 0xb3: // ldb
        op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
        break;
    case 0xb4: case 0xb5: case 0xb6: case 0xb7: // addcb
        op->type = RZ_ANALYSIS_OP_TYPE_ADD;
        break;
    case 0xb8: case 0xb9: case 0xba: case 0xbb: // subcb
        op->type = RZ_ANALYSIS_OP_TYPE_SUB;
        break;
    case 0xbc: case 0xbd: case 0xbe: case 0xbf: // ldbse
        op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
        break;
    case 0xc0: // st - direct 
        op->type = RZ_ANALYSIS_OP_TYPE_STORE;
        op->ptr = buf[1];
        break;
    case 0xc1: // invalid
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xc2: case 0xc3: case 0xc4:
        op->type = RZ_ANALYSIS_OP_TYPE_STORE;
        break;
    case 0xc5:
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xc6: case 0xc7: // stb
        op->type = RZ_ANALYSIS_OP_TYPE_STORE;
        break;
    case 0xc8: case 0xc9: case 0xca: case 0xcb: // push
        op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
        op->stackptr = -2;
        op->stackop = RZ_ANALYSIS_STACK_INC;
        break;
    case 0xcc: // pop
        op->type = RZ_ANALYSIS_OP_TYPE_POP;
        op->stackptr = 2;
        op->stackop = RZ_ANALYSIS_STACK_DEC;
        break;
    case 0xcd: // invalid
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xce: case 0xcf: // pop
        op->type = RZ_ANALYSIS_OP_TYPE_POP;
        op->stackptr = 2;
        op->stackop = RZ_ANALYSIS_STACK_DEC;
        break;
    case 0xd0: case 0xd1: case 0xd2: case 0xd3:
    case 0xd4: case 0xd5: case 0xd6: case 0xd7: 
    case 0xd8: case 0xd9: case 0xda: case 0xdb:
    case 0xdc: case 0xdd: case 0xde: case 0xdf: // jump instructions
        imm = (st8)buf[1];
        op->jump = addr + op->size + imm;
        op->fail = addr + op->size;   
        op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
        op->eob = true;
        break;
    case 0xe0: // djnzw
        imm = (st8)buf[2];
        op->jump = addr + op->size + imm;
        op->fail = addr + op->size;   
        op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
        op->eob = true;
        break;
    case 0xe1: case 0xe2: 
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xe3: // br
        op->type = RZ_ANALYSIS_OP_TYPE_JMP;
        op->eob = true;
        break;
    case 0xe4: case 0xe5: case 0xe6:
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xe7: // ljmp
        op->type = RZ_ANALYSIS_OP_TYPE_JMP;
        imm = (st16)rz_read_le16(buf + 1);
        op->val = imm;
        op->jump = addr + op->size + imm;
        op->eob = true;
        break;
    case 0xe8: case 0xe9: case 0xea: case 0xeb:
    case 0xec: case 0xed: case 0xee:
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xef: // lcall
        op->type = RZ_ANALYSIS_OP_TYPE_CALL;
        imm = (st16)rz_read_le16(buf + 1);
        op->val = imm;
        op->jump = addr + op->size + imm;
        op->stackptr = -2;
        op->stackop = RZ_ANALYSIS_STACK_INC;
        op->eob = true;
        break;
    case 0xf0: // ret
        op->type = RZ_ANALYSIS_OP_TYPE_RET;
        op->eob = true;
        op->stackptr = 2;
        op->stackop = RZ_ANALYSIS_STACK_DEC;
        break;
    case 0xf1: // invalid
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xf2: // pushf
        op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
        op->stackptr = -2;
        op->stackop = RZ_ANALYSIS_STACK_INC;
        break;
    case 0xf3: // popf
        op->type = RZ_ANALYSIS_OP_TYPE_POP;
        op->stackop = RZ_ANALYSIS_STACK_DEC;
        op->stackptr = 2;
        break;
    case 0xf4: case 0xf5: case 0xf6: 
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xf7: // trap
        op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
        break;
    case 0xf8: case 0xf9: case 0xfa: case 0xfb: // clrc, setc, di, ei
    case 0xfc: // clrvt
        op->type = RZ_ANALYSIS_OP_TYPE_UNK;
        break;
    case 0xfd: // nop
        op->type = RZ_ANALYSIS_OP_TYPE_NOP;
        break;
    case 0xfe: // invalid
        op->type = RZ_ANALYSIS_OP_TYPE_ILL;
        break;
    case 0xff: // rst
        op->type = RZ_ANALYSIS_OP_TYPE_UNK;
        break;
    default:
        return -1;
    }


    switch (opcode) {
        case 0x40: case 0x41: case 0x42: case 0x43: // and  
        case 0x44: case 0x45: case 0x46: case 0x47: // add  
        case 0x48: case 0x49: case 0x4a: case 0x4b: // sub  
        case 0x4c: case 0x4d: case 0x4e: case 0x4f: // mulu 
        case 0x60: case 0x61: case 0x62: case 0x63: // and
        case 0x64: case 0x65: case 0x66: case 0x67: // add
        case 0x68: case 0x69: case 0x6a: case 0x6b: // sub
        case 0x6c: case 0x6d: case 0x6e: case 0x6f: // mulu
        case 0x80: case 0x81: case 0x82: case 0x83: // or
        case 0x84: case 0x85: case 0x86: case 0x87: // xor
        case 0x88: case 0x89: case 0x8a: case 0x8b: // cmp
        case 0x8c: case 0x8d: case 0x8e: case 0x8f: // divu
        case 0xa0: case 0xa1: case 0xa2: case 0xa3: // ld
        case 0xa4: case 0xa5: case 0xa6: case 0xa7: // addc
        case 0xa8: case 0xa9: case 0xaa: case 0xab: // subc
        case 0xc8: case 0xc9: case 0xca: case 0xcb: // push
            switch (addr_mode) {
                case MCS96_ADDRESSING_REG_DIRECT:
                    op->ptr = rz_read_le16(buf + 1);
                break;
                case MCS96_ADDRESSING_IMMEDIATE:
                    op->val = rz_read_le16(buf + 1);
                break;
                default:
                    break;
            }
            break;
        case 0x50: case 0x51: case 0x52: case 0x53: // andb    
        case 0x54: case 0x55: case 0x56: case 0x57: // addb    
        case 0x58: case 0x59: case 0x5a: case 0x5b: // subb    
        case 0x5c: case 0x5d: case 0x5e: case 0x5f: // mulub    
        case 0x70: case 0x71: case 0x72: case 0x73: // andb    
        case 0x74: case 0x75: case 0x76: case 0x77: // addb    
        case 0x78: case 0x79: case 0x7a: case 0x7b: // subb    
        case 0x7c: case 0x7d: case 0x7e: case 0x7f: // mulub    
        case 0x90: case 0x91: case 0x92: case 0x93: // orb    
        case 0x94: case 0x95: case 0x96: case 0x97: // xorb    
        case 0x98: case 0x99: case 0x9a: case 0x9b: // cmpb    
        case 0x9c: case 0x9d: case 0x9e: case 0x9f: // divub    
        case 0xac: case 0xad: case 0xae: case 0xaf: // ldbze
        case 0xb0: case 0xb1: case 0xb2: case 0xb3: // ldb    
        case 0xb4: case 0xb5: case 0xb6: case 0xb7: // addcb    
        case 0xb8: case 0xb9: case 0xba: case 0xbb: // subcb    
        case 0xbc: case 0xbd: case 0xbe: case 0xbf: // ldbse    
            switch (addr_mode) {
                case MCS96_ADDRESSING_REG_DIRECT:
                    op->ptr = buf[1];
                break;
                case MCS96_ADDRESSING_IMMEDIATE:
                    op->val = buf[1];
                break;
                default:
            break;
            }
        default:
            break;
    }

    return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_mcs96 = {
    .name = "mcs96",
    .desc = "Intel MCS-96 analyzer",
    .license = "LGPL3",
    .arch = "mcs96",
    .bits = 16,
    .archinfo = archinfo,
    .get_reg_profile = get_reg_profile,
    .op = analyze_op,
};