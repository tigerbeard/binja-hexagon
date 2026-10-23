/*
 * The version that introduced each overlay instruction, in the form of QEMU's
 * tag_rev_info.c.inc, for tests/isa_versions.py: ds_master's revisions, and
 * for memcpy the first CPU llvm-mc accepts it for.
 */
    [V6_vabs_f8] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vfneg_f8] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vfmax_f8] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vfmin_f8] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vadd_hf_f8] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vsub_hf_f8] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vmpy_hf_f8] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vmpy_hf_f8_acc] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vcvt_f8_hf] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vcvt_hf_f8] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vcvt2_b_hf] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vcvt2_ub_hf] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vcvt2_hf_b] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vcvt2_hf_ub] = { .introduced = HEX_VER_V79, .removed = HEX_VER_NONE },
    [V6_vconv_f8_qf16] = { .introduced = HEX_VER_V81, .removed = HEX_VER_NONE },
    [V6_vconv_qf16_f8] = { .introduced = HEX_VER_V81, .removed = HEX_VER_NONE },
    [L6_memcpy] = { .introduced = HEX_VER_V66, .removed = HEX_VER_NONE },
