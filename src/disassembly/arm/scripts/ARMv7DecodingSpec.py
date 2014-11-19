instructions = [
{
    "name" : "ADC Immediate",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADC{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "11110 i#1 01010 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ThumbExpandImm(i:imm3:imm8);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ADC Immediate",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADC{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0010101 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "ADC Register",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADCS <Rdn>, <Rm>:ADC<c> <Rdn>, <Rm>",
    "pattern" : "0100000101 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock();
    (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "ADC Register",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADC{S}<c>.W <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "11101011010 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ADC Register",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0000101 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "ADC (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADC{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0000101 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs);
    setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "ADD (immediate, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADDS <Rd>, <Rn>, #<imm3>:ADD<c> <Rd>, <Rn>, #<imm3>",
    "pattern" : "0001110 imm3#3 Rn#3 Rd#3",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); setflags = !InITBlock(); imm32 = ZeroExtend(imm3, 32);"""
} , {
    "name" : "ADD (immediate, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADDS <Rdn>, #<imm8>:ADD<c> <Rdn>, #<imm8>",
    "pattern" : "00110 Rdn#3 imm8#8",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); setflags = !InITBlock(); imm32 = ZeroExtend(imm8, 32);"""
} , {
    "name" : "ADD (immediate, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADD{S}<c>.W <Rd>, <Rn>, #<const>",
    "pattern" : "11110 i#1 01000 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rd == '1111' && S == '1' then SEE CMN (immediate);
    if Rn == '1101' then SEE ADD (SP plus immediate);
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ThumbExpandImm(i:imm3:imm8);
    if d == 13 || (d == 15 && S == '0') || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "ADD (immediate, Thumb)",
    "encoding" : "T4",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADDW<c> <Rd>, <Rn>, #<imm12>",
    "pattern" : "11110 i#1 100000 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rn == '1111' then SEE ADR;
    if Rn == '1101' then SEE ADD (SP plus immediate);
    d = UInt(Rd); n = UInt(Rn); setflags = FALSE; imm32 = ZeroExtend(i:imm3:imm8, 32);
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ADD (immediate, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0010100 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rn == '1111' && S == '0' then SEE ADR;
    if Rn == '1101' then SEE ADD (SP plus immediate);
    if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "ADD (register, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADDS <Rd>, <Rn>, <Rm>:ADD<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "0001100 Rm#3 Rn#3 Rd#3",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = !InITBlock(); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "ADD (register, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD<c> <Rdn>, <Rm>",
    "pattern" : "01000100 DN#1 Rm#4 Rdn#3",
    "decoder" : """if (DN:Rdn) == '1101' || Rm == '1101' then SEE ADD (SP plus register, Thumb);
    d = UInt(DN:Rdn); n = d; m = UInt(Rm); setflags = FALSE; (shift_t, shift_n) = (SRType_LSL, 0);
    if n == 15 && m == 15 then UNPREDICTABLE;
    if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "ADD (register, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADD{S}<c>.W <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "11101011000 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE CMN (register);
    if Rn == '1101' then SEE ADD (SP plus register, Thumb);
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d == 13 || (d == 15 && S == '0') || n == 15 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ADD (register, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0000100 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    if Rn == '1101' then SEE ADD (SP plus register, ARM);
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "ADD (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0000100 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs);
    setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "ADD (SP plus immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD<c> <Rd>, SP, #<imm32>",
    "pattern" : "10101 Rd#3 imm8#8",
    "decoder" : """d = UInt(Rd); setflags = FALSE; imm32 = ZeroExtend(imm8:'00', 32);"""
} , {
    "name" : "ADD (SP plus immediate)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD<c> SP, SP, #<imm32>",
    "pattern" : "101100000 imm7#7",
    "decoder" : """d = 13; setflags = FALSE; imm32 = ZeroExtend(imm7:'00', 32);"""
} , {
    "name" : "ADD (SP plus immediate)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADD{S}<c>.W <Rd>, SP, #<const>",
    "pattern" : "11110 i#1 01000 S#1 11010 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rd == '1111' && S == '1' then SEE CMN (immediate);
    d = UInt(Rd); setflags = (S == '1'); imm32 = ThumbExpandImm(i:imm3:imm8);
    if d == 15 && S == '0' then UNPREDICTABLE;"""
} , {
    "name" : "ADD (SP plus immediate)",
    "encoding" : "T4",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADDW<c> <Rd>, SP, #<imm12>",
    "pattern" : "11110 i#1 10000011010 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); setflags = FALSE; imm32 = ZeroExtend(i:imm3:imm8, 32);
    if d == 15 then UNPREDICTABLE;"""
} , {
    "name" : "ADD (SP plus immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD{S}<c> <Rd>, SP, #<const>",
    "pattern" : "cond#4 0010100 S#1 1101 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); setflags = (S == '1'); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "ADD (SP plus register, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD<c> <Rdm>, SP, <Rdm>",
    "pattern" : "01000100 DM#1 1101 Rdm#3",
    "decoder" : """d = UInt(DM:Rdm); m = UInt(DM:Rdm); setflags = FALSE;
    if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE;
    (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "ADD (SP plus register, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD<c> SP, <Rm>",
    "pattern" : "01000100 1 Rm#4 101",
    "decoder" : """if Rm == '1101' then SEE encoding T1;
    d = 13; m = UInt(Rm); setflags = FALSE; (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "ADD (SP plus register, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADD{S}<c>.W <Rd>, SP, <Rm>{, <shift>}",
    "pattern" : "11101011000 S#1 11010 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE CMN (register);
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d == 13 && (shift_t != SRType_LSL || shift_n > 3) then UNPREDICTABLE;
    if (d == 15 && S == '0') || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ADD (SP plus register, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADD{S}<c> <Rd>, SP, <Rm>{, <shift>}",
    "pattern" : "cond#4 0000100 S#1 1101 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
(shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "ADR",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADR<c> <Rd>, <label>",
    "pattern" : "10100 Rd#3 imm8#8",
    "decoder" : """d = UInt(Rd); imm32 = ZeroExtend(imm8:'00', 32); add = TRUE;"""
} , {
    "name" : "ADR",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADR<c>.W <Rd>, <label>",
    "pattern" : "11110 i#1 10101011110 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); imm32 = ZeroExtend(i:imm3:imm8, 32); add = FALSE;
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ADR",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ADR<c>.W <Rd>, <label>",
    "pattern" : "11110 i#1 10000011110 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); imm32 = ZeroExtend(i:imm3:imm8, 32); add = TRUE;
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ADR",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADR<c> <Rd>, <label>",
    "pattern" : "cond#4 001010001111 Rd#4 imm12#12",
    "decoder" : """d = UInt(Rd); imm32 = ARMExpandImm(imm12); add = TRUE;"""
} , {
    "name" : "ADR",
    "encoding" : "A2",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ADR<c> <Rd>, <label>",
    "pattern" : "cond#4 001001001111 Rd#4 imm12#12",
    "decoder" : """d = UInt(Rd); imm32 = ARMExpandImm(imm12); add = FALSE;"""
} , {
    "name" : "AND (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "AND{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "11110 i#1 00000 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rd == '1111' && S == '1' then SEE TST (immediate);
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1');
    (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if d == 13 || (d == 15 && S == '0') || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "AND (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "AND{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0010000 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1');
    (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);"""
} , {
    "name" : "AND (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ANDS <Rdn>, <Rm>:AND<c> <Rdn>, <Rm>",
    "pattern" : "0100000000 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock(); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "AND (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "AND{S}<c>.W <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "11101010000 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE TST (register);
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d == 13 || (d == 15 && S == '0') || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "AND (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "AND{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0000000 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "AND (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "AND{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0000000 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs); setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "ASR (immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ASRS <Rd>, <Rm>, #<shift_n>:ASR<c> <Rd>, <Rm>, #<shift_n>",
    "pattern" : "00010 imm5#5 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = !InITBlock(); (-, shift_n) = DecodeImmShift('10', imm5);"""
} , {
    "name" : "ASR (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ASR{S}<c>.W <Rd>, <Rm>, #<shift_n>",
    "pattern" : "11101010010 S#1 11110 imm3#3 Rd#4 imm2#2 10 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = (S == '1'); (-, shift_n) = DecodeImmShift('10', imm3:imm2);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ASR (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ASR{S}<c> <Rd>, <Rm>, #<shift_n>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 imm5#5 100 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    (-, shift_n) = DecodeImmShift('10', imm5);"""
} , {
    "name" : "ASR (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ASRS <Rdn>, <Rm>:ASR<c> <Rdn>, <Rm>",
    "pattern" : "0100000100 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock();"""
} , {
    "name" : "ASR (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ASR{S}<c>.W <Rd>, <Rn>, <Rm>",
    "pattern" : "11111010010 S#1 Rn#4 1111 Rd#4 0000 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ASR (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ASR{S}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 Rm#4 0101 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "B",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "B<c> <label>",
    "pattern" : "1101 cond#4 imm8#8",
    "decoder" : """if cond == '1110' then UNDEFINED;
    if cond == '1111' then SEE SVC;
    imm32 = SignExtend(imm8:'0', 32);
    if InITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "B",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "B<c> <label>",
    "pattern" : "11100 imm11#11",
    "decoder" : """imm32 = SignExtend(imm11:'0', 32);
    if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "B",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "B<c>.W <label>",
    "pattern" : "11110 S#1 cond#4 imm6#6 10 J1#1 0 J2#1 imm11#11",
    "decoder" : """if cond<3:1> == '111' then SEE "Related encodings";
    imm32 = SignExtend(S:J2:J1:imm6:imm11:'0', 32);
    if InITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "B",
    "encoding" : "T4",
    "version" : "ARMv6T2, ARMv7",
    "format" : "B<c>.W <label>",
    "pattern" : "11110 S#1 imm10#10 10 J1#1 1 J2#1 imm11#11",
    "decoder" : """I1 = NOT(J1 EOR S); I2 = NOT(J2 EOR S); imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
    if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "B",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "B<c> <label>",
    "pattern" : "cond#4 1010 imm24#24",
    "decoder" : """imm32 = SignExtend(imm24:'00', 32);"""
} , {
    "name" : "BFC",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "BFC<c> <Rd>, #<lsb>, #<width>",
    "pattern" : "11110011011011110 imm3#3 Rd#4 imm2#2 0 msb#5",
    "decoder" : """d = UInt(Rd); msbit = UInt(msb); lsbit = UInt(imm3:imm2);
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "BFC",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "BFC<c> <Rd>, #<lsb>, #<width>",
    "pattern" : "cond#4 0111110 msb#5 Rd#4 lsb#5 0011111",
    "decoder" : """d = UInt(Rd); msbit = UInt(msb); lsbit = UInt(lsb);
    if d == 15 then UNPREDICTABLE;"""
} , {
    "name" : "BFI",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "BFI<c> <Rd>, <Rn>, #<lsb>, #<width>",
    "pattern" : "111100110110 Rn#4 0 imm3#3 Rd#4 imm2#2 0 msb#5",
    "decoder" : """if Rn == '1111' then SEE BFC;
    d = UInt(Rd); n = UInt(Rn); msbit = UInt(msb); lsbit = UInt(imm3:imm2);
    if d IN {13,15} || n == 13 then UNPREDICTABLE;"""
} , {
    "name" : "BFI",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "BFI<c> <Rd>, <Rn>, #<lsb>, #<width>",
    "pattern" : "cond#4 0111110 msb#5 Rd#4 lsb#5 001 Rn#4",
    "decoder" : """if Rn == '1111' then SEE BFC;
    d = UInt(Rd); n = UInt(Rn); msbit = UInt(msb); lsbit = UInt(lsb);
    if d == 15 then UNPREDICTABLE;"""
} , {
    "name" : "BIC (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "BIC{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "11110 i#1 00001 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "BIC (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BIC{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0011110 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1');
    (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);"""
} , {
    "name" : "BIC (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BICS <Rdn>, <Rm>:BIC<c> <Rdn>, <Rm>",
    "pattern" : "0100001110 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock(); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "BIC (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "BIC{S}<c>.W <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "11101010001 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "BIC (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BIC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0001110 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "BIC (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BIC{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0001110 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs); setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "BKPT",
    "encoding" : "T1",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BKPT #<imm8>",
    "pattern" : "10111110 imm8#8",
    "decoder" : """imm32 = ZeroExtend(imm8, 32);"""
} , {
    "name" : "BKPT",
    "encoding" : "A1",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BKPT #<imm32>",
    "pattern" : "cond#4 00010010 imm12#12 0111 imm4#4",
    "decoder" : """imm32 = ZeroExtend(imm12:imm4, 32);
    if cond != '1110' then UNPREDICTABLE;
    """
} , {
    "name" : "BL, BLX (immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BL<c> <label>",
    "pattern" : "11110 S#1 imm10#10 11 J1#1 1 J2#1 imm11#11",
    "decoder" : """I1 = NOT(J1 EOR S); I2 = NOT(J2 EOR S); imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
    if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "BL, BLX (immediate)",
    "encoding" : "T2",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BLX<c> <label>",
    "pattern" : "11110 S#1 imm10H#10 11 J1#1 0 J2#1 imm10L#10 H#1",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE || H == '1' then UNDEFINED;
    I1 = NOT(J1 EOR S); I2 = NOT(J2 EOR S); imm32 = SignExtend(S:I1:I2:imm10H:imm10L:'00', 32); targetInstrSet = InstrSet_ARM;
    if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "BL, BLX (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BL<c> <label>",
    "pattern" : "cond#4 1011 imm24#24",
    "decoder" : """imm32 = SignExtend(imm24:'00', 32); targetInstrSet = InstrSet_ARM;"""
} , {
    "name" : "BL, BLX (immediate)",
    "encoding" : "A2",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BLX <label>",
    "pattern" : "1111101 H#1 imm24#24",
    "decoder" : """imm32 = SignExtend(imm24:H:'0', 32); targetInstrSet = InstrSet_Thumb;"""
} , {
    "name" : "BLX (register)",
    "encoding" : "T1",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BLX<c> <Rm>",
    "pattern" : "010001111 Rm#4 000",
    "decoder" : """m = UInt(Rm);
    if m == 15 then UNPREDICTABLE;
    if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "BLX (register)",
    "encoding" : "A1",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BLX<c> <Rm>",
    "pattern" : "cond#4 000100101111111111110011 Rm#4",
    "decoder" : """m = UInt(Rm);
    if m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "BX",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BX<c> <Rm>",
    "pattern" : "010001110 Rm#4 000",
    "decoder" : """m = UInt(Rm);
    if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "BX",
    "encoding" : "A1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "BX<c> <Rm>",
    "pattern" : "cond#4 000100101111111111110001 Rm#4",
    "decoder" : """m = UInt(Rm);"""
} , {
    "name" : "BXJ",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "BXJ<c> <Rm>",
    "pattern" : "111100111100 Rm#4 1000111100000000",
    "decoder" : """m = UInt(Rm);
    if m IN {13,15} then UNPREDICTABLE;
    if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "BXJ",
    "encoding" : "A1",
    "version" : "ARMv5TEJ, ARMv6All, ARMv7",
    "format" : "BXJ<c> <Rm>",
    "pattern" : "cond#4 000100101111111111110010 Rm#4",
    "decoder" : """m = UInt(Rm);
    if m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "CBNZ, CBZ",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CB{N}Z <Rn>, <label>",
    "pattern" : "1011 op#1 0 i#1 1 imm5#5 Rn#3",
    "decoder" : """n = UInt(Rn); imm32 = ZeroExtend(i:imm5:'0', 32); nonzero = (op == '1');
    if InITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "CDP, CDP2",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CDP<c> <coproc>, #<opc1>, <CRd>, <CRn>, <CRm>, #<opc2>",
    "pattern" : "11101110 opc1#4 CRn#4 CRd#4 coproc#4 opc2#3 0 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "Floating-point instructions";
    cp = UInt(coproc);"""
} , {
    "name" : "CDP, CDP2",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CDP<c> <coproc>, #<opc1>, <CRd>, <CRn>, <CRm>, #<opc2>",
    "pattern" : "cond#4 1110 opc1#4 CRn#4 CRd#4 coproc#4 opc2#3 0 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "Floating-point instructions";
    cp = UInt(coproc);"""
} , {
    "name" : "CDP, CDP2",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CDP2<c> <coproc>, #<opc1>, <CRd>, <CRn>, <CRm>, #<opc2>",
    "pattern" : "11111110 opc1#4 CRn#4 CRd#4 coproc#4 opc2#3 0 CRm#4",
    "decoder" : """cp = UInt(coproc);"""
} , {
    "name" : "CDP, CDP2",
    "encoding" : "A2",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CDP2<c> <coproc>, #<opc1>, <CRd>, <CRn>, <CRm>, #<opc2>",
    "pattern" : "11111110 opc1#4 CRn#4 CRd#4 coproc#4 opc2#3 0 CRm#4",
    "decoder" : """cp = UInt(coproc);"""
} , {
    "name" : "CLREX",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "CLREX<c>",
    "pattern" : "11110011101111111000111100101111",
    "decoder" : """NOP();"""
} , {
    "name" : "CLREX",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "CLREX",
    "pattern" : "11110101011111111111000000011111",
    "decoder" : """NOP();"""
} , {
    "name" : "CLZ",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CLZ<c> <Rd>, <Rm>",
    "pattern" : "111110101011 Rm_#4 1111 Rd#4 1000 Rm#4",
    "decoder" : """if !Consistent(Rm) then UNPREDICTABLE;
    d = UInt(Rd); m = UInt(Rm);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "CLZ",
    "encoding" : "A1",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CLZ<c> <Rd>, <Rm>",
    "pattern" : "cond#4 000101101111 Rd#4 11110001 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm);
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "CMN (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CMN<c> <Rn>, #<const>",
    "pattern" : "11110 i#1 010001 Rn#4 0 imm3#3 1111 imm8#8",
    "decoder" : """n = UInt(Rn); imm32 = ThumbExpandImm(i:imm3:imm8);
    if n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "CMN (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMN<c> <Rn>, #<const>",
    "pattern" : "cond#4 00110111 Rn#4 0000 imm12#12",
    "decoder" : """n = UInt(Rn); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "CMN (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMN<c> <Rn>, <Rm>",
    "pattern" : "0100001011 Rm#3 Rn#3",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "CMN (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CMN<c>.W <Rn>, <Rm>{, <shift>}",
    "pattern" : "111010110001 Rn#4 0 imm3#3 1111 imm2#2 type#2 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if n == 15 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "CMN (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMN<c> <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 00010111 Rn#4 0000 imm5#5 type#2 0 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "CMN (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMN<c> <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 00010111 Rn#4 0000 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); s = UInt(Rs);
    shift_t = DecodeRegShift(type);
    if n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "CMP (immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMP<c> <Rn>, #<imm8>",
    "pattern" : "00101 Rn#3 imm8#8",
    "decoder" : """n = UInt(Rn); imm32 = ZeroExtend(imm8, 32);"""
} , {
    "name" : "CMP (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CMP<c>.W <Rn>, #<const>",
    "pattern" : "11110 i#1 011011 Rn#4 0 imm3#3 1111 imm8#8",
    "decoder" : """n = UInt(Rn); imm32 = ThumbExpandImm(i:imm3:imm8);
    if n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "CMP (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMP<c> <Rn>, #<const>",
    "pattern" : "cond#4 00110101 Rn#4 0000 imm12#12",
    "decoder" : """n = UInt(Rn); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "CMP (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMP<c> <Rn>, <Rm>",
    "pattern" : "0100001010 Rm#3 Rn#3",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "CMP (register)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMP<c> <Rn>, <Rm>",
    "pattern" : "01000101 N#1 Rm#4 Rn#3",
    "decoder" : """n = UInt(N:Rn); m = UInt(Rm);
    (shift_t, shift_n) = (SRType_LSL, 0);
    if n < 8 && m < 8 then UNPREDICTABLE;
    if n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "CMP (register)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CMP<c>.W <Rn>, <Rm> {, <shift>}",
    "pattern" : "111010111011 Rn#4 0 imm3#3 1111 imm2#2 type#2 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if n == 15 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "CMP (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMP<c> <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 00010101 Rn#4 0000 imm5#5 type#2 0 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "CMP (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CMP<c> <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 00010101 Rn#4 0000 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); s = UInt(Rs);
    shift_t = DecodeRegShift(type);
    if n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "DBG",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "DBG<c> #<option>",
    "pattern" : "1111001110101111100000001111 option#4",
    "decoder" : """NOP();"""
} , {
    "name" : "DBG",
    "encoding" : "A1",
    "version" : "ARMv7",
    "format" : "DBG<c> #<option>",
    "pattern" : "cond#4 001100100000111100001111 option#4",
    "decoder" : """NOP();"""
} , {
    "name" : "DMB",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "DMB<c> <option>",
    "pattern" : "1111001110111111100011110101 option#4",
    "decoder" : """NOP();"""
} , {
    "name" : "DMB",
    "encoding" : "A1",
    "version" : "ARMv7",
    "format" : "DMB <option>",
    "pattern" : "1111010101111111111100000101 option#4",
    "decoder" : """NOP();"""
} , {
    "name" : "DSB",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "DSB<c> <option>",
    "pattern" : "1111001110111111100011110100 option#4",
    "decoder" : """NOP();"""
} , {
    "name" : "DSB",
    "encoding" : "A1",
    "version" : "ARMv7",
    "format" : "DSB <option>",
    "pattern" : "1111010101111111111100000100 option#4",
    "decoder" : """NOP();"""
} , {
    "name" : "EOR (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "EOR{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "11110 i#1 00100 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rd == '1111' && S == '1' then SEE TEQ (immediate);
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1');
    (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if d == 13 || (d == 15 && S == '0') || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "EOR (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "EOR{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0010001 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1');
    (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);"""
} , {
    "name" : "EOR (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "EORS <Rdn>, <Rm>:EOR<c> <Rdn>, <Rm>",
    "pattern" : "0100000001 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock(); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "EOR (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "EOR{S}<c>.W <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "11101010100 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE TEQ (register);
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d == 13 || (d == 15 && S == '0') || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "EOR (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "EOR{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0000001 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "EOR (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "EOR{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0000001 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs); setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "ISB",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "ISB<c> <option>",
    "pattern" : "1111001110111111100011110110 option#4",
    "decoder" : """NOP();"""
} , {
    "name" : "ISB",
    "encoding" : "A1",
    "version" : "ARMv7",
    "format" : "ISB <option>",
    "pattern" : "1111010101111111111100000110 option#4",
    "decoder" : """NOP();"""
} , {
    "name" : "IT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "10111111 firstcond#4 mask#4",
    "decoder" : """if mask == '0000' then SEE "Related encodings";
    if firstcond == '1111' || (firstcond == '1110' && BitCount(mask) != 1) then UNPREDICTABLE;
    if InITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "LDC, LDC2 (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1110110 P#1 U#1 D#1 W#1 1 Rn#4 CRd#4 coproc#4 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDC, LDC2 (literal);
    if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MRRC, MRRC2;
    if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    n = UInt(Rn); cp = UInt(coproc);
    imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');"""
} , {
    "name" : "LDC, LDC2 (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 110 P#1 U#1 D#1 W#1 1 Rn#4 CRd#4 coproc#4 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDC, LDC2 (literal);
    if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MRRC, MRRC2;
    if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    n = UInt(Rn); cp = UInt(coproc);
    imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');"""
} , {
    "name" : "LDC, LDC2 (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1111110 P#1 U#1 D#1 W#1 1 Rn#4 CRd#4 coproc#4 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDC, LDC2 (literal);
    if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MRRC, MRRC2;
    if coproc IN "101x" then UNDEFINED;
    n = UInt(Rn); cp = UInt(coproc);
    imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');"""
} , {
    "name" : "LDC, LDC2 (immediate)",
    "encoding" : "A2",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1111110 P#1 U#1 D#1 W#1 1 Rn#4 CRd#4 coproc#4 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDC, LDC2 (literal);
    if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MRRC, MRRC2;
    if coproc IN "101x" then UNDEFINED;
    n = UInt(Rn); cp = UInt(coproc);
    imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');"""
} , {
    "name" : "LDC, LDC2 (literal)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1110110 P#1 U#1 D#1 W#1 11111 CRd#4 coproc#4 imm8#8",
    "decoder" : """if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MRRC, MRRC2;
    if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    index = (P == '1'); add = (U == '1'); cp = UInt(coproc); imm32 = ZeroExtend(imm8:'00', 32);
    if W == '1' || (P == '0' && CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "LDC, LDC2 (literal)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 110 P#1 U#1 D#1 W#1 11111 CRd#4 coproc#4 imm8#8",
    "decoder" : """if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MRRC, MRRC2;
    if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    index = (P == '1'); add = (U == '1'); cp = UInt(coproc); imm32 = ZeroExtend(imm8:'00', 32);
    if W == '1' || (P == '0' && CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "LDC, LDC2 (literal)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1111110 P#1 U#1 D#1 W#1 11111 CRd#4 coproc#4 imm8#8",
    "decoder" : """if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MRRC, MRRC2;
    if coproc IN "101x" then UNDEFINED;
    index = (P == '1'); add = (U == '1'); cp = UInt(coproc); imm32 = ZeroExtend(imm8:'00', 32);
    if W == '1' || (P == '0' && CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "LDC, LDC2 (literal)",
    "encoding" : "A2",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1111110 P#1 U#1 D#1 W#1 11111 CRd#4 coproc#4 imm8#8",
    "decoder" : """if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MRRC, MRRC2;
    if coproc IN "101x" then UNDEFINED;
    index = (P == '1'); add = (U == '1'); cp = UInt(coproc); imm32 = ZeroExtend(imm8:'00', 32);
    if W == '1' || (P == '0' && CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "LDM/LDMIA/LDMFD (Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "11001 Rn#3 register_list#8",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then SEE "ThumbEE instructions";
    n = UInt(Rn); registers = '00000000':register_list; wback = (registers<n> == '0');
    if BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "LDM/LDMIA/LDMFD (Thumb)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDM<c>.W <Rn>{!}, <registers>",
    "pattern" : "1110100010 W#1 1 Rn#4 P#1 M#1 0 register_list#13",
    "decoder" : """if W == '1' && Rn == '1101' then SEE POP (Thumb);
    n = UInt(Rn); registers = P:M:'0':register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 2 || (P == '1' && M == '1') then UNPREDICTABLE;
    if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE;
    if wback && registers<n> == '1' then UNPREDICTABLE;"""
} , {
    "name" : "LDM/LDMIA/LDMFD (ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDM<c> <Rn>{!}, <registers>",
    "pattern" : "cond#4 100010 W#1 1 Rn#4 register_list#16",
    "decoder" : """if W == '1' && Rn == '1101' && BitCount(register_list) > 1 then SEE POP (ARM);
    n = UInt(Rn); registers = register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;
    if wback && registers<n> == '1' && ArchVersion() >= 7 then UNPREDICTABLE;"""
} , {
    "name" : "LDMDA/LDMFA",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDMDA<c> <Rn>{!}, <registers>",
    "pattern" : "cond#4 100000 W#1 1 Rn#4 register_list#16",
    "decoder" : """n = UInt(Rn); registers = register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;
    if wback && registers<n> == '1' && ArchVersion() >= 7 then UNPREDICTABLE;"""
} , {
    "name" : "LDMDB/LDMEA",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDMDB<c> <Rn>{!}, <registers>",
    "pattern" : "1110100100 W#1 1 Rn#4 P#1 M#1 0 register_list#13",
    "decoder" : """n = UInt(Rn); registers = P:M:'0':register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 2 || (P == '1' && M == '1') then UNPREDICTABLE;
    if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE;
    if wback && registers<n> == '1' then UNPREDICTABLE;"""
} , {
    "name" : "LDMDB/LDMEA",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDMDB<c> <Rn>{!}, <registers>",
    "pattern" : "cond#4 100100 W#1 1 Rn#4 register_list#16",
    "decoder" : """n = UInt(Rn); registers = register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;
    if wback && registers<n> == '1' && ArchVersion() >= 7 then UNPREDICTABLE;"""
} , {
    "name" : "LDMIB/LDMED",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDMIB<c> <Rn>{!}, <registers>",
    "pattern" : "cond#4 100110 W#1 1 Rn#4 register_list#16",
    "decoder" : """n = UInt(Rn); registers = register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;
    if wback && registers<n> == '1' && ArchVersion() >= 7 then UNPREDICTABLE;"""
} , {
    "name" : "LDR (immediate, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDR<c> <Rt>, [<Rn>{, #<imm32>}]",
    "pattern" : "01101 imm5#5 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm5:'00', 32); index = TRUE; add = TRUE; wback = FALSE;"""
} , {
    "name" : "LDR (immediate, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDR<c> <Rt>, [SP{, #<imm32>}]",
    "pattern" : "10011 Rt#3 imm8#8",
    "decoder" : """t = UInt(Rt); n = 13; imm32 = ZeroExtend(imm8:'00', 32); index = TRUE; add = TRUE; wback = FALSE;"""
} , {
    "name" : "LDR (immediate, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDR<c>.W <Rt>, [<Rn>{, #<imm12>}]",
    "pattern" : "111110001101 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rn == '1111' then SEE LDR (literal);
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); index = TRUE; add = TRUE; wback = FALSE;
    if t == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "LDR (immediate, Thumb)",
    "encoding" : "T4",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "111110000101 Rn#4 Rt#4 1 P#1 U#1 W#1 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDR (literal);
    if P == '1' && U == '1' && W == '0' then SEE LDRT;
    if Rn == '1101' && P == '0' && U == '1' && W == '1' && imm8 == '00000100' then SEE POP;
    if P == '0' && W == '0' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn);
    imm32 = ZeroExtend(imm8, 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if (wback && n == t) || (t == 15 && InITBlock() && !LastInITBlock()) then UNPREDICTABLE;"""
} , {
    "name" : "LDR (immediate, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 010 P#1 U#1 0 W#1 1 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rn == '1111' then SEE LDR (literal);
    if P == '0' && W == '1' then SEE LDRT;
    if Rn == '1101' && P == '0' && U == '1' && W == '0' && imm12 == '000000000100' then SEE POP;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if wback && n == t then UNPREDICTABLE;"""
} , {
    "name" : "LDR (literal)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDR<c> <Rt>, <label>",
    "pattern" : "01001 Rt#3 imm8#8",
    "decoder" : """t = UInt(Rt); imm32 = ZeroExtend(imm8:'00', 32); add = TRUE;"""
} , {
    "name" : "LDR (literal)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDR<c>.W <Rt>, <label>",
    "pattern" : "11111000 U#1 1011111 Rt#4 imm12#12",
    "decoder" : """t = UInt(Rt); imm32 = ZeroExtend(imm12, 32); add = (U == '1');
    if t == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "LDR (literal)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDR<c> <Rt>, <label>",
    "pattern" : "cond#4 0101 U#1 0011111 Rt#4 imm12#12",
    "decoder" : """t = UInt(Rt); imm32 = ZeroExtend(imm12, 32); add = (U == '1');"""
} , {
    "name" : "LDR (register, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDR<c> <Rt>, [<Rn>, <Rm>]",
    "pattern" : "0101100 Rm#3 Rn#3 Rt#3",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then SEE "Modified operation in ThumbEE";
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "LDR (register, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDR<c>.W <Rt>, [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "111110000101 Rn#4 Rt#4 000000 imm2#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE LDR (literal);
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if m IN {13,15} then UNPREDICTABLE;
    if t == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "LDR (register, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 011 P#1 U#1 0 W#1 1 Rn#4 Rt#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if P == '0' && W == '1' then SEE LDRT;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "LDRB (immediate, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRB<c> <Rt>, [<Rn>{, #<imm5>}]",
    "pattern" : "01111 imm5#5 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm5, 32); index = TRUE; add = TRUE; wback = FALSE;"""
} , {
    "name" : "LDRB (immediate, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRB<c>.W <Rt>, [<Rn>{, #<imm12>}]",
    "pattern" : "111110001001 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rt == '1111' then SEE PLD;
    if Rn == '1111' then SEE LDRB (literal);
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); index = TRUE; add = TRUE; wback = FALSE;
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "LDRB (immediate, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "111110000001 Rn#4 Rt#4 1 P#1 U#1 W#1 imm8#8",
    "decoder" : """if Rt == '1111' && P == '1' && U == '0' && W == '0' then SEE PLD, PLDW (immediate);
    if Rn == '1111' then SEE LDRB (literal);
    if P == '1' && U == '1' && W == '0' then SEE LDRBT;
    if P == '0' && W == '0' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8, 32);
    index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if t == 13 || (t == 15 && W == '1') || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "LDRB (immediate, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 010 P#1 U#1 1 W#1 1 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rn == '1111' then SEE LDRB (literal);
    if P == '0' && W == '1' then SEE LDRBT;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if t == 15 || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "LDRB (literal)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRB<c> <Rt>, <label>",
    "pattern" : "11111000 U#1 0011111 Rt#4 imm12#12",
    "decoder" : """if Rt == '1111' then SEE PLD;
    t = UInt(Rt); imm32 = ZeroExtend(imm12, 32); add = (U == '1');
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "LDRB (literal)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRB<c> <Rt>, <label>",
    "pattern" : "cond#4 0101 U#1 1011111 Rt#4 imm12#12",
    "decoder" : """t = UInt(Rt); imm32 = ZeroExtend(imm12, 32); add = (U == '1');
    if t == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRB (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRB<c> <Rt>, [<Rn>, <Rm>]",
    "pattern" : "0101110 Rm#3 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); index = TRUE; add = TRUE; wback = FALSE; (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "LDRB (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRB<c>.W <Rt>, [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "111110000001 Rn#4 Rt#4 000000 imm2#2 Rm#4",
    "decoder" : """if Rt == '1111' then SEE PLD;
    if Rn == '1111' then SEE LDRB (literal);
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); index = TRUE; add = TRUE; wback = FALSE; (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if t == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRB (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 011 P#1 U#1 1 W#1 1 Rn#4 Rt#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if P == '0' && W == '1' then SEE LDRBT;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if t == 15 || m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "LDRBT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRBT<c> <Rt>, [<Rn>, #<imm8>]",
    "pattern" : "111110000001 Rn#4 Rt#4 1110 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDRB (literal);
    t = UInt(Rt); n = UInt(Rn); postindex = FALSE; add = TRUE; register_form = FALSE; imm32 = ZeroExtend(imm8, 32);
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRBT",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRBT<c> <Rt>, [<Rn>], #+/-<imm12>",
    "pattern" : "cond#4 0100 U#1 111 Rn#4 Rt#4 imm12#12",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); postindex = TRUE; add = (U == '1'); register_form = FALSE; imm32 = ZeroExtend(imm12, 32);
    if t == 15 || n == 15 || n == t then UNPREDICTABLE;"""
} , {
    "name" : "LDRBT",
    "encoding" : "A2",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRBT<c> <Rt>, [<Rn>],+/-<Rm>{, <shift>}",
    "pattern" : "cond#4 0110 U#1 111 Rn#4 Rt#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); postindex = TRUE; add = (U == '1'); register_form = TRUE; (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;
    if ArchVersion() < 6 && m == n then UNPREDICTABLE;"""
} , {
    "name" : "LDRD (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1110100 P#1 U#1 1 W#1 1 Rn#4 Rt#4 Rt2#4 imm8#8",
    "decoder" : """if P == '0' && W == '0' then SEE "Related encodings";
    if Rn == '1111' then SEE LDRD (literal);
    t = UInt(Rt); t2 = UInt(Rt2); n = UInt(Rn); imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if wback && (n == t || n == t2) then UNPREDICTABLE;
    if t IN {13,15} || t2 IN {13,15} || t == t2 then UNPREDICTABLE;"""
} , {
    "name" : "LDRD (immediate)",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 P#1 U#1 1 W#1 0 Rn#4 Rt#4 imm4H#4 1101 imm4L#4",
    "decoder" : """if Rn == '1111' then SEE LDRD (literal);
    if Rt<0> == '1' then UNPREDICTABLE;
    t = UInt(Rt); t2 = t+1; n = UInt(Rn); imm32 = ZeroExtend(imm4H:imm4L, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if P == '0' && W == '1' then UNPREDICTABLE;
    if wback && (n == t || n == t2) then UNPREDICTABLE;
    if t2 == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRD (literal)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRD<c> <Rt>, <Rt2>, <label>",
    "pattern" : "1110100 P#1 U#1 1 W#1 11111 Rt#4 Rt2#4 imm8#8",
    "decoder" : """if P == '0' && W == '0' then SEE "Related encodings";
    t = UInt(Rt); t2 = UInt(Rt2);
    imm32 = ZeroExtend(imm8:'00', 32); add = (U == '1');
    if t IN {13,15} || t2 IN {13,15} || t == t2 then UNPREDICTABLE;
    if W == '1' then UNPREDICTABLE;"""
} , {
    "name" : "LDRD (literal)",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "LDRD<c> <Rt>, <Rt2>, <label>",
    "pattern" : "cond#4 0001 U#1 1001111 Rt#4 imm4H#4 1101 imm4L#4",
    "decoder" : """if Rt<0> == '1' then UNPREDICTABLE;
    t = UInt(Rt); t2 = t+1; imm32 = ZeroExtend(imm4H:imm4L, 32); add = (U == '1');
    if t2 == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRD (register)",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 P#1 U#1 0 W#1 0 Rn#4 Rt#4 00001101 Rm#4",
    "decoder" : """if Rt<0> == '1' then UNPREDICTABLE;
    t = UInt(Rt); t2 = t+1; n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if P == '0' && W == '1' then UNPREDICTABLE;
    if t2 == 15 || m == 15 || m == t || m == t2 then UNPREDICTABLE;
    if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "LDREX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDREX<c> <Rt>, [<Rn>{, #<imm32>}]",
    "pattern" : "111010000101 Rn#4 Rt#4 1111 imm8#8",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8:'00', 32);
    if t IN {13,15} || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDREX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "LDREX<c> <Rt>, [<Rn>]",
    "pattern" : "cond#4 00011001 Rn#4 Rt#4 111110011111",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); imm32 = Zeros(32);
    if t == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDREXB",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "LDREXB<c> <Rt>, [<Rn>]",
    "pattern" : "111010001101 Rn#4 Rt#4 111101001111",
    "decoder" : """t = UInt(Rt); n = UInt(Rn);
    if t IN {13,15} || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDREXB",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "LDREXB<c> <Rt>, [<Rn>]",
    "pattern" : "cond#4 00011101 Rn#4 Rt#4 111110011111",
    "decoder" : """t = UInt(Rt); n = UInt(Rn);
    if t == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDREXD",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "LDREXD<c> <Rt>, <Rt2>, [<Rn>]",
    "pattern" : "111010001101 Rn#4 Rt#4 Rt2#4 01111111",
    "decoder" : """t = UInt(Rt); t2 = UInt(Rt2); n = UInt(Rn);
    if t IN {13,15} || t2 IN {13,15} || t == t2 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDREXD",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "LDREXD<c> <Rt>, <Rt2>, [<Rn>]",
    "pattern" : "cond#4 00011011 Rn#4 Rt#4 111110011111",
    "decoder" : """t = UInt(Rt); t2 = t+1; n = UInt(Rn);
    if Rt<0> == '1' || Rt == '1110' || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDREXH",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "LDREXH<c> <Rt>, [<Rn>]",
    "pattern" : "111010001101 Rn#4 Rt#4 111101011111",
    "decoder" : """t = UInt(Rt); n = UInt(Rn);
    if t IN {13,15} || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDREXH",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "LDREXH<c> <Rt>, [<Rn>]",
    "pattern" : "cond#4 00011111 Rn#4 Rt#4 111110011111",
    "decoder" : """t = UInt(Rt); n = UInt(Rn);
    if t == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRH (immediate, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRH<c> <Rt>, [<Rn>{, #<imm32>}]",
    "pattern" : "10001 imm5#5 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm5:'0', 32); index = TRUE; add = TRUE; wback = FALSE;"""
} , {
    "name" : "LDRH (immediate, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRH<c>.W <Rt>, [<Rn>{, #<imm12>}]",
    "pattern" : "111110001011 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rt == '1111' then SEE "Related instructions";
    if Rn == '1111' then SEE LDRH (literal);
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); index = TRUE; add = TRUE; wback = FALSE;
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "LDRH (immediate, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "111110000011 Rn#4 Rt#4 1 P#1 U#1 W#1 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDRH (literal);
    if Rt == '1111' && P == '1' && U == '0' && W == '0' then SEE "Related instructions";
    if P == '1' && U == '1' && W == '0' then SEE LDRHT;
    if P == '0' && W == '0' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8, 32);
    index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if t ==13 || (t ==15 && W == '1') || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "LDRH (immediate, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 P#1 U#1 1 W#1 1 Rn#4 Rt#4 imm4H#4 1011 imm4L#4",
    "decoder" : """if Rn == '1111' then SEE LDRH (literal);
    if P == '0' && W == '1' then SEE LDRHT;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm4H:imm4L, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if t == 15 || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "LDRH (literal)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRH<c> <Rt>, <label>",
    "pattern" : "11111000 U#1 0111111 Rt#4 imm12#12",
    "decoder" : """if Rt == '1111' then SEE "Related instructions";
    t = UInt(Rt); imm32 = ZeroExtend(imm12, 32); add = (U == '1');
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "LDRH (literal)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRH<c> <Rt>, <label>",
    "pattern" : "cond#4 0001 U#1 1011111 Rt#4 imm4H#4 1011 imm4L#4",
    "decoder" : """t = UInt(Rt); imm32 = ZeroExtend(imm4H:imm4L, 32); add = (U == '1');
    if t == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRH (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRH<c> <Rt>, [<Rn>, <Rm>]",
    "pattern" : "0101101 Rm#3 Rn#3 Rt#3",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then SEE "Modified operation in ThumbEE";
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = TRUE; add = TRUE; wback = FALSE;
    (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "LDRH (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRH<c>.W <Rt>, [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "111110000011 Rn#4 Rt#4 000000 imm2#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE LDRH (literal);
    if Rt == '1111' then SEE "Related instructions";
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); index = TRUE; add = TRUE;
    wback = FALSE; (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if t == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRH (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 P#1 U#1 0 W#1 1 Rn#4 Rt#4 00001011 Rm#4",
    "decoder" : """if P == '0' && W == '1' then SEE LDRHT;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1'); (shift_t, shift_n) = (SRType_LSL, 0);
    if t == 15 || m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "LDRHT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRHT<c> <Rt>, [<Rn>, #<imm8>]",
    "pattern" : "111110000011 Rn#4 Rt#4 1110 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDRH (literal);
    t = UInt(Rt); n = UInt(Rn); postindex = FALSE; add = TRUE; register_form = FALSE; imm32 = ZeroExtend(imm8, 32);
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRHT",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRHT<c> <Rt>, [<Rn>] {, #+/-<imm8>}",
    "pattern" : "cond#4 0000 U#1 111 Rn#4 Rt#4 imm4H#4 1011 imm4L#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); postindex = TRUE; add = (U == '1'); register_form = FALSE; imm32 = ZeroExtend(imm4H:imm4L, 32);
    if t == 15 || n == 15 || n == t then UNPREDICTABLE;"""
} , {
    "name" : "LDRHT",
    "encoding" : "A2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRHT<c> <Rt>, [<Rn>], +/-<Rm>",
    "pattern" : "cond#4 0000 U#1 011 Rn#4 Rt#4 00001011 Rm#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); postindex = TRUE; add = (U == '1'); register_form = TRUE;
    if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRSB (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSB<c> <Rt>, [<Rn>, #<imm12>]",
    "pattern" : "111110011001 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rt == '1111' then SEE PLI;
    if Rn == '1111' then SEE LDRSB (literal);
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); index = TRUE; add = TRUE; wback = FALSE;
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "LDRSB (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "111110010001 Rn#4 Rt#4 1 P#1 U#1 W#1 imm8#8",
    "decoder" : """if Rt == '1111' && P == '1' && U == '0' && W == '0' then SEE PLI;
    if Rn == '1111' then SEE LDRSB (literal);
    if P == '1' && U == '1' && W == '0' then SEE LDRSBT;
    if P == '0' && W == '0' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8, 32);
    index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if t == 13 || (t == 15 && W == '1') || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "LDRSB (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 P#1 U#1 1 W#1 1 Rn#4 Rt#4 imm4H#4 1101 imm4L#4",
    "decoder" : """if Rn == '1111' then SEE LDRSB (literal);
    if P == '0' && W == '1' then SEE LDRSBT;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm4H:imm4L, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if t == 15 || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "LDRSB (literal)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSB<c> <Rt>, <label>",
    "pattern" : "11111001 U#1 0011111 Rt#4 imm12#12",
    "decoder" : """if Rt == '1111' then SEE PLI;
    t = UInt(Rt); imm32 = ZeroExtend(imm12, 32); add = (U == '1');
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "LDRSB (literal)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRSB<c> <Rt>, <label>",
    "pattern" : "cond#4 0001 U#1 1011111 Rt#4 imm4H#4 1101 imm4L#4",
    "decoder" : """t = UInt(Rt); imm32 = ZeroExtend(imm4H:imm4L, 32); add = (U == '1');
    if t == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRSB (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRSB<c> <Rt>, [<Rn>, <Rm>]",
    "pattern" : "0101011 Rm#3 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); add = TRUE; wback = FALSE; index = TRUE;
    (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "LDRSB (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSB<c>.W <Rt>, [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "111110010001 Rn#4 Rt#4 000000 imm2#2 Rm#4",
    "decoder" : """if Rt == '1111' then SEE PLI;
    if Rn == '1111' then SEE LDRSB (literal);
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); index = TRUE; add = TRUE; wback = FALSE; (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if t == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRSB (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 P#1 U#1 0 W#1 1 Rn#4 Rt#4 00001101 Rm#4",
    "decoder" : """if P == '0' && W == '1' then SEE LDRSBT;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1'); (shift_t, shift_n) = (SRType_LSL, 0);
    if t == 15 || m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "LDRSBT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSBT<c> <Rt>, [<Rn>, #<imm8>]",
    "pattern" : "111110010001 Rn#4 Rt#4 1110 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDRSB (literal);
    t = UInt(Rt); n = UInt(Rn); postindex = FALSE; add = TRUE; register_form = FALSE; imm32 = ZeroExtend(imm8, 32);
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRSBT",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSBT<c> <Rt>, [<Rn>] {, #+/-<imm8>}",
    "pattern" : "cond#4 0000 U#1 111 Rn#4 Rt#4 imm4H#4 1101 imm4L#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); postindex = TRUE; add = (U == '1'); register_form = FALSE; imm32 = ZeroExtend(imm4H:imm4L, 32);
    if t == 15 || n == 15 || n == t then UNPREDICTABLE;"""
} , {
    "name" : "LDRSBT",
    "encoding" : "A2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSBT<c> <Rt>, [<Rn>], +/-<Rm>",
    "pattern" : "cond#4 0000 U#1 011 Rn#4 Rt#4 00001101 Rm#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); postindex = TRUE; add = (U == '1'); register_form = TRUE;
    if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRSH (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSH<c> <Rt>, [<Rn>, #<imm12>]",
    "pattern" : "111110011011 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rn == '1111' then SEE LDRSH (literal);
    if Rt == '1111' then SEE "Related instructions";
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); index = TRUE; add = TRUE; wback = FALSE;
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "LDRSH (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "111110010011 Rn#4 Rt#4 1 P#1 U#1 W#1 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDRSH (literal);
    if Rt == '1111' && P == '1' && U == '0' && W == '0' then SEE "Related instructions";
    if P == '1' && U == '1' && W == '0' then SEE LDRSHT;
    if P == '0' && W == '0' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8, 32);
    index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if t == 13 || (t == 15 && W == '1') || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "LDRSH (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 P#1 U#1 1 W#1 1 Rn#4 Rt#4 imm4H#4 1111 imm4L#4",
    "decoder" : """if Rn == '1111' then SEE LDRSH (literal);
    if P == '0' && W == '1' then SEE LDRSHT;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm4H:imm4L, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if t == 15 || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "LDRSH (literal)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSH<c> <Rt>, <label>",
    "pattern" : "11111001 U#1 0111111 Rt#4 imm12#12",
    "decoder" : """if Rt == '1111' then SEE "Related instructions";
    t = UInt(Rt); imm32 = ZeroExtend(imm12, 32); add = (U == '1');
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "LDRSH (literal)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRSH<c> <Rt>, <label>",
    "pattern" : "cond#4 0001 U#1 1011111 Rt#4 imm4H#4 1111 imm4L#4",
    "decoder" : """t = UInt(Rt); imm32 = ZeroExtend(imm4H:imm4L, 32); add = (U == '1');
    if t == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRSH (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRSH<c> <Rt>, [<Rn>, <Rm>]",
    "pattern" : "0101111 Rm#3 Rn#3 Rt#3",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then SEE "Modified operation in ThumbEE";
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = TRUE; add = TRUE; wback = FALSE;
    (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "LDRSH (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSH<c>.W <Rt>, [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "111110010011 Rn#4 Rt#4 000000 imm2#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE LDRSH (literal);
    if Rt == '1111' then SEE "Related instructions";
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); index = TRUE; add = TRUE; wback = FALSE; (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if t == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRSH (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 P#1 U#1 0 W#1 1 Rn#4 Rt#4 00001111 Rm#4",
    "decoder" : """if P == '0' && W == '1' then SEE LDRSHT;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1'); (shift_t, shift_n) = (SRType_LSL, 0);
    if t == 15 || m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "LDRSHT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSHT<c> <Rt>, [<Rn>, #<imm8>]",
    "pattern" : "111110010011 Rn#4 Rt#4 1110 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDRSH (literal);
    t = UInt(Rt); n = UInt(Rn); postindex = FALSE; add = TRUE; register_form = FALSE; imm32 = ZeroExtend(imm8, 32);
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRSHT",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSHT<c> <Rt>, [<Rn>] {, #+/-<imm8>}",
    "pattern" : "cond#4 0000 U#1 111 Rn#4 Rt#4 imm4H#4 1111 imm4L#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); postindex = TRUE; add = (U == '1'); register_form = FALSE; imm32 = ZeroExtend(imm4H:imm4L, 32);
    if t == 15 || n == 15 || n == t then UNPREDICTABLE;"""
} , {
    "name" : "LDRSHT",
    "encoding" : "A2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRSHT<c> <Rt>, [<Rn>], +/-<Rm>",
    "pattern" : "cond#4 0000 U#1 011 Rn#4 Rt#4 00001111 Rm#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); postindex = TRUE; add = (U == '1'); register_form = TRUE;
    if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LDRT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LDRT<c> <Rt>, [<Rn>, #<imm8>]",
    "pattern" : "111110000101 Rn#4 Rt#4 1110 imm8#8",
    "decoder" : """if Rn == '1111' then SEE LDR (literal);
    t = UInt(Rt); n = UInt(Rn); postindex = FALSE; add = TRUE; register_form = FALSE; imm32 = ZeroExtend(imm8, 32);
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LDRT",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRT<c> <Rt>, [<Rn>] {, #+/-<imm12>}",
    "pattern" : "cond#4 0100 U#1 011 Rn#4 Rt#4 imm12#12",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); postindex = TRUE; add = (U == '1'); register_form = FALSE; imm32 = ZeroExtend(imm12, 32);
    if t == 15 || n == 15 || n == t then UNPREDICTABLE;"""
} , {
    "name" : "LDRT",
    "encoding" : "A2",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDRT<c> <Rt>, [<Rn>],+/-<Rm>{, <shift>}",
    "pattern" : "cond#4 0110 U#1 011 Rn#4 Rt#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); postindex = TRUE; add = (U == '1'); register_form = TRUE; (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;
    if ArchVersion() < 6 && m == n then UNPREDICTABLE;"""
} , {
    "name" : "LSL (immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LSLS <Rd>, <Rm>, #<shift_n>:LSL<c> <Rd>, <Rm>, #<shift_n>",
    "pattern" : "00000 imm5#5 Rm#3 Rd#3",
    "decoder" : """if imm5 == '00000' then SEE MOV (register, Thumb);
    d = UInt(Rd); m = UInt(Rm); setflags = !InITBlock(); (-, shift_n) = DecodeImmShift('00', imm5);"""
} , {
    "name" : "LSL (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LSL{S}<c>.W <Rd>, <Rm>, #<shift_n>",
    "pattern" : "11101010010 S#1 11110 imm3#3 Rd#4 imm2#2 00 Rm#4",
    "decoder" : """if (imm3:imm2) == '00000' then SEE MOV (register, Thumb);
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1'); (-, shift_n) = DecodeImmShift('00', imm3:imm2);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LSL (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LSL{S}<c> <Rd>, <Rm>, #<imm5>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 imm5#5 000 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    if imm5 == '00000' then SEE MOV (register, ARM);
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    (-, shift_n) = DecodeImmShift('00', imm5); imm5 = shift_n;"""
} , {
    "name" : "LSL (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LSLS <Rdn>, <Rm>:LSL<c> <Rdn>, <Rm>",
    "pattern" : "0100000010 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock();"""
} , {
    "name" : "LSL (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LSL{S}<c>.W <Rd>, <Rn>, <Rm>",
    "pattern" : "11111010000 S#1 Rn#4 1111 Rd#4 0000 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LSL (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LSL{S}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 Rm#4 0001 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "LSR (immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LSRS <Rd>, <Rm>, #<shift_n>:LSR<c> <Rd>, <Rm>, #<shift_n>",
    "pattern" : "00001 imm5#5 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = !InITBlock(); (-, shift_n) = DecodeImmShift('01', imm5);"""
} , {
    "name" : "LSR (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LSR{S}<c>.W <Rd>, <Rm>, #<shift_n>",
    "pattern" : "11101010010 S#1 11110 imm3#3 Rd#4 imm2#2 01 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = (S == '1'); (-, shift_n) = DecodeImmShift('01', imm3:imm2);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LSR (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LSR{S}<c> <Rd>, <Rm>, #<shift_n>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 imm5#5 010 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    (-, shift_n) = DecodeImmShift('01', imm5);"""
} , {
    "name" : "LSR (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LSRS <Rdn>, <Rm>:LSR<c> <Rdn>, <Rm>",
    "pattern" : "0100000011 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock();"""
} , {
    "name" : "LSR (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "LSR{S}<c>.W <Rd>, <Rn>, <Rm>",
    "pattern" : "11111010001 S#1 Rn#4 1111 Rd#4 0000 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "LSR (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LSR{S}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 Rm#4 0011 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "MCR, MCR2",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MCR<c> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}",
    "pattern" : "11101110 opc1#3 0 CRn#4 Rt#4 coproc#4 opc2#3 1 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    t = UInt(Rt); cp = UInt(coproc);
    if t == 15 || (t == 13 && (CurrentInstrSet() != InstrSet_ARM)) then UNPREDICTABLE;"""
} , {
    "name" : "MCR, MCR2",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MCR<c> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}",
    "pattern" : "cond#4 1110 opc1#3 0 CRn#4 Rt#4 coproc#4 opc2#3 1 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    t = UInt(Rt); cp = UInt(coproc);
    if t == 15 || (t == 13 && (CurrentInstrSet() != InstrSet_ARM)) then UNPREDICTABLE;"""
} , {
    "name" : "MCR, MCR2",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MCR2<c> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}",
    "pattern" : "11111110 opc1#3 0 CRn#4 Rt#4 coproc#4 opc2#3 1 CRm#4",
    "decoder" : """if coproc IN "101x" then UNDEFINED;
    t = UInt(Rt); cp = UInt(coproc);
    if t == 15 || (t == 13 && (CurrentInstrSet() != InstrSet_ARM)) then UNPREDICTABLE;"""
} , {
    "name" : "MCR, MCR2",
    "encoding" : "A2",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MCR2<c> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}",
    "pattern" : "11111110 opc1#3 0 CRn#4 Rt#4 coproc#4 opc2#3 1 CRm#4",
    "decoder" : """if coproc IN "101x" then UNDEFINED;
    t = UInt(Rt); cp = UInt(coproc);
    if t == 15 || (t == 13 && (CurrentInstrSet() != InstrSet_ARM)) then UNPREDICTABLE;"""
} , {
    "name" : "MCRR, MCRR2",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MCRR<c> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>",
    "pattern" : "111011000100 Rt2#4 Rt#4 coproc#4 opc1#4 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    t = UInt(Rt); t2 = UInt(Rt2); cp = UInt(coproc);
    if t == 15 || t2 == 15 then UNPREDICTABLE;
    if (t == 13 || t2 == 13) && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MCRR, MCRR2",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "MCRR<c> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>",
    "pattern" : "cond#4 11000100 Rt2#4 Rt#4 coproc#4 opc1#4 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    t = UInt(Rt); t2 = UInt(Rt2); cp = UInt(coproc);
    if t == 15 || t2 == 15 then UNPREDICTABLE;
    if (t == 13 || t2 == 13) && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MCRR, MCRR2",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MCRR2<c> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>",
    "pattern" : "111011000100 Rt2#4 Rt#4 coproc#4 opc1#4 CRm#4",
    "decoder" : """if coproc IN "101x" then UNDEFINED;
    t = UInt(Rt); t2 = UInt(Rt2); cp = UInt(coproc);
    if t == 15 || t2 == 15 then UNPREDICTABLE;
    if (t == 13 || t2 == 13) && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MCRR, MCRR2",
    "encoding" : "A2",
    "version" : "ARMv6All, ARMv7",
    "format" : "MCRR2<c> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>",
    "pattern" : "111111000100 Rt2#4 Rt#4 coproc#4 opc1#4 CRm#4",
    "decoder" : """if coproc IN "101x" then UNDEFINED;
    t = UInt(Rt); t2 = UInt(Rt2); cp = UInt(coproc);
    if t == 15 || t2 == 15 then UNPREDICTABLE;
    if (t == 13 || t2 == 13) && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MLA",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MLA<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "111110110000 Rn#4 Ra#4 Rd#4 0000 Rm#4",
    "decoder" : """if Ra == '1111' then SEE MUL;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); setflags = FALSE;
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a == 13 then UNPREDICTABLE;"""
} , {
    "name" : "MLA",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MLA{S}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 0000001 S#1 Rd#4 Ra#4 Rm#4 1001 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); setflags = (S == '1');
    if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;
    if ArchVersion() < 6 && d == n then UNPREDICTABLE;"""
} , {
    "name" : "MLS",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MLS<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "111110110000 Rn#4 Ra#4 Rd#4 0001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MLS",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MLS<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 00000110 Rd#4 Ra#4 Rm#4 1001 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra);
    if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;"""
} , {
    "name" : "MOV (immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MOVS <Rd>, #<imm8>:MOV<c> <Rd>, #<imm8>",
    "pattern" : "00100 Rd#3 imm8#8",
    "decoder" : """d = UInt(Rd); setflags = !InITBlock(); imm32 = ZeroExtend(imm8, 32); carry = APSR.C;"""
} , {
    "name" : "MOV (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MOV{S}<c>.W <Rd>, #<const>",
    "pattern" : "11110 i#1 00010 S#1 11110 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); setflags = (S == '1'); (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MOV (immediate)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MOVW<c> <Rd>, #<imm32>",
    "pattern" : "11110 i#1 100100 imm4#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); setflags = FALSE; imm32 = ZeroExtend(imm4:i:imm3:imm8, 32);
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MOV (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MOV{S}<c> <Rd>, #<const>",
    "pattern" : "cond#4 0011101 S#1 0000 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); setflags = (S == '1'); (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);"""
} , {
    "name" : "MOV (immediate)",
    "encoding" : "A2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MOVW<c> <Rd>, #<imm32>",
    "pattern" : "cond#4 00110000 imm4#4 Rd#4 imm12#12",
    "decoder" : """d = UInt(Rd); setflags = FALSE; imm32 = ZeroExtend(imm4:imm12, 32);
    if d == 15 then UNPREDICTABLE;"""
} , {
    "name" : "MOV (register, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MOV<c> <Rd>, <Rm>",
    "pattern" : "01000110 D#1 Rm#4 Rd#3",
    "decoder" : """d = UInt(D:Rd); m = UInt(Rm); setflags = FALSE;
    if d == 15 && InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "MOV (register, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MOVS <Rd>, <Rm>",
    "pattern" : "0000000000 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = TRUE;
    if InITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "MOV (register, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MOV{S}<c>.W <Rd>, <Rm>",
    "pattern" : "11101010010 S#1 11110000 Rd#4 0000 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    if setflags && (d IN {13,15} || m IN {13,15}) then UNPREDICTABLE;
    if !setflags && (d == 15 || m == 15 || (d == 13 && m == 13)) then UNPREDICTABLE;"""
} , {
    "name" : "MOV (register, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MOV{S}<c> <Rd>, <Rm>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 00000000 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');"""
} , {
    "name" : "MOVT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MOVT<c> <Rd>, #<imm32>",
    "pattern" : "11110 i#1 101100 imm4#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); imm32 = imm4:i:imm3:imm8;
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MOVT",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MOVT<c> <Rd>, #<imm32>",
    "pattern" : "cond#4 00110100 imm4#4 Rd#4 imm12#12",
    "decoder" : """d = UInt(Rd); imm32 = imm4:imm12;
    if d == 15 then UNPREDICTABLE;"""
} , {
    "name" : "MRC, MRC2",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MRC<c> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}",
    "pattern" : "11101110 opc1#3 1 CRn#4 Rt#4 coproc#4 opc2#3 1 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    t = UInt(Rt); cp = UInt(coproc);
    if t == 13 && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MRC, MRC2",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MRC<c> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}",
    "pattern" : "cond#4 1110 opc1#3 1 CRn#4 Rt#4 coproc#4 opc2#3 1 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    t = UInt(Rt); cp = UInt(coproc);
    if t == 13 && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MRC, MRC2",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MRC2<c> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}",
    "pattern" : "11111110 opc1#3 1 CRn#4 Rt#4 coproc#4 opc2#3 1 CRm#4",
    "decoder" : """if coproc IN "101x" then UNDEFINED;
    t = UInt(Rt); cp = UInt(coproc);
    if t == 13 && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MRC, MRC2",
    "encoding" : "A2",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MRC2<c> <coproc>, #<opc1>, <Rt>, <CRn>, <CRm>{, #<opc2>}",
    "pattern" : "11111110 opc1#3 1 CRn#4 Rt#4 coproc#4 opc2#3 1 CRm#4",
    "decoder" : """if coproc IN "101x" then UNDEFINED;
    t = UInt(Rt); cp = UInt(coproc);
    if t == 13 && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MRRC, MRRC2",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MRRC<c> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>",
    "pattern" : "111011000101 Rt2#4 Rt#4 coproc#4 opc1#4 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    t = UInt(Rt); t2 = UInt(Rt2); cp = UInt(coproc);
    if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE;
    if (t == 13 || t2 == 13) && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MRRC, MRRC2",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "MRRC<c> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>",
    "pattern" : "cond#4 11000101 Rt2#4 Rt#4 coproc#4 opc1#4 CRm#4",
    "decoder" : """if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    t = UInt(Rt); t2 = UInt(Rt2); cp = UInt(coproc);
    if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE;
    if (t == 13 || t2 == 13) && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MRRC, MRRC2",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MRRC2<c> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>",
    "pattern" : "111111000101 Rt2#4 Rt#4 coproc#4 opc1#4 CRm#4",
    "decoder" : """if coproc IN "101x" then UNDEFINED;
    t = UInt(Rt); t2 = UInt(Rt2); cp = UInt(coproc);
    if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE;
    if (t == 13 || t2 == 13) && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MRRC, MRRC2",
    "encoding" : "A2",
    "version" : "ARMv6All, ARMv7",
    "format" : "MRRC2<c> <coproc>, #<opc1>, <Rt>, <Rt2>, <CRm>",
    "pattern" : "111111000101 Rt2#4 Rt#4 coproc#4 opc1#4 CRm#4",
    "decoder" : """if coproc IN "101x" then UNDEFINED;
    t = UInt(Rt); t2 = UInt(Rt2); cp = UInt(coproc);
    if t == 15 || t2 == 15 || t == t2 then UNPREDICTABLE;
    if (t == 13 || t2 == 13) && (CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "MRS",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MRS<c> <Rd>, <spec_reg>",
    "pattern" : "11110011111 R#1 11111000 Rd#4 00000000",
    "decoder" : """d = UInt(Rd); read_spsr = (R == '1');
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MRS",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MRS<c> <Rd>, <spec_reg>",
    "pattern" : "cond#4 00010 R#1 001111 Rd#4 000000000000",
    "decoder" : """d = UInt(Rd); read_spsr = (R == '1');
    if d == 15 then UNPREDICTABLE;"""
} , {
    "name" : "MSR (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MSR<c> <spec_reg>, #<const>",
    "pattern" : "cond#4 00110 R#1 10 mask#4 1111 imm12#12",
    "decoder" : """if mask == '0000' && R == '0' then SEE "Related encodings";
    imm32 = ARMExpandImm(imm12); write_spsr = (R == '1');
if mask == '0000' then UNPREDICTABLE;"""
} , {
    "name" : "MSR (register)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MSR<c> <spec_reg>, <Rn>",
    "pattern" : "11110011100 R#1 Rn#4 1000 mask#4 00000000",
    "decoder" : """n = UInt(Rn); write_spsr = (R == '1');
    if mask == '0000' then UNPREDICTABLE;
    if n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MSR (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MSR<c> <spec_reg>, <Rn>",
    "pattern" : "cond#4 00010 R#1 10 mask#4 111100000000 Rn#4",
    "decoder" : """n = UInt(Rn); write_spsr = (R == '1');
    if mask == '0000' then UNPREDICTABLE;
    if n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "MUL",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MULS <Rdm>, <Rn>, <Rdm>:MUL<c> <Rdm>, <Rn>, <Rdm>",
    "pattern" : "0100001101 Rn#3 Rdm#3",
    "decoder" : """d = UInt(Rdm); n = UInt(Rn); m = UInt(Rdm); setflags = !InITBlock();
    if ArchVersion() < 6 && d == n then UNPREDICTABLE;"""
} , {
    "name" : "MUL",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MUL<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "111110110000 Rn#4 1111 Rd#4 0000 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = FALSE;
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MUL",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MUL{S}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0000000 S#1 Rd#4 0000 Rm#4 1001 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if ArchVersion() < 6 && d == n then UNPREDICTABLE;"""
} , {
    "name" : "MVN (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MVN{S}<c> <Rd>, #<const>",
    "pattern" : "11110 i#1 00011 S#1 11110 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); setflags = (S == '1');
    (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MVN (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MVN{S}<c> <Rd>, #<const>",
    "pattern" : "cond#4 0011111 S#1 0000 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); setflags = (S == '1');
    (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);"""
} , {
    "name" : "MVN (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MVNS <Rd>, <Rm>:MVN<c> <Rd>, <Rm>",
    "pattern" : "0100001111 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = !InITBlock(); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "MVN (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "MVN{S}<c>.W <Rd>, <Rm>{, <shift>}",
    "pattern" : "11101010011 S#1 11110 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "MVN (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MVN{S}<c> <Rd>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0001111 S#1 0000 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "MVN (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "MVN{S}<c> <Rd>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0001111 S#1 0000 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); s = UInt(Rs);
    setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "NOP",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "NOP<c>",
    "pattern" : "1011111100000000",
    "decoder" : """NOP();"""
} , {
    "name" : "NOP",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "NOP<c>.W",
    "pattern" : "11110011101011111000000000000000",
    "decoder" : """NOP();"""
} , {
    "name" : "NOP",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv6T2, ARMv7",
    "format" : "NOP<c>",
    "pattern" : "cond#4 0011001000001111000000000000",
    "decoder" : """NOP();"""
} , {
    "name" : "ORN (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ORN{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "11110 i#1 00011 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rn == '1111' then SEE MVN (immediate);
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if d IN {13,15} || n == 13 then UNPREDICTABLE;"""
} , {
    "name" : "ORN (register)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ORN{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "11101010011 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE MVN (register);
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d IN {13,15} || n == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ORR (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ORR{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "11110 i#1 00010 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rn == '1111' then SEE MOV (immediate);
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if d IN {13,15} || n == 13 then UNPREDICTABLE;"""
} , {
    "name" : "ORR (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ORR{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0011100 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1');
    (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);"""
} , {
    "name" : "ORR (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ORRS <Rdn>, <Rm>:ORR<c> <Rdn>, <Rm>",
    "pattern" : "0100001100 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock(); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "ORR (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ORR{S}<c>.W <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "11101010010 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE "Related encodings";
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d IN {13,15} || n == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ORR (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ORR{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0001100 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "ORR (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ORR{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0001100 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs); setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "PKH",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "11101010110 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 tb#1 T#1 Rm#4",
    "decoder" : """if S == '1' || T == '1' then UNDEFINED;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); tbform = (tb == '1');
    (shift_t, shift_n) = DecodeImmShift(tb:'0', imm3:imm2);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "PKH",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 01101000 Rn#4 Rd#4 imm5#5 tb#1 01 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); tbform = (tb == '1');
    (shift_t, shift_n) = DecodeImmShift(tb:'0', imm5);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "PLD, PLDW (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "PLD{W}<c> [<Rn>, #<imm12>]",
    "pattern" : "1111100010 W#1 1 Rn#4 1111 imm12#12",
    "decoder" : """if Rn == '1111' then SEE PLD (literal);
    n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); add = TRUE; is_pldw = (W == '1');"""
} , {
    "name" : "PLD, PLDW (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "PLD{W}<c> [<Rn>, #-<imm8>]",
    "pattern" : "1111100000 W#1 1 Rn#4 11111100 imm8#8",
    "decoder" : """if Rn == '1111' then SEE PLD (literal);
    n = UInt(Rn); imm32 = ZeroExtend(imm8, 32); add = FALSE; is_pldw = (W == '1');"""
} , {
    "name" : "PLD, PLDW (immediate)",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "PLD{W} [<Rn>, #+/-<imm12>]",
    "pattern" : "11110101 U#1 R#1 01 Rn#4 1111 imm12#12",
    "decoder" : """if Rn == '1111' then SEE PLD (literal);
    n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); add = (U == '1'); is_pldw = (R == '0');"""
} , {
    "name" : "PLD (literal)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "PLD<c> <label>",
    "pattern" : "11111000 U#1 00111111111 imm12#12",
    "decoder" : """imm32 = ZeroExtend(imm12, 32); add = (U == '1');"""
} , {
    "name" : "PLD (literal)",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "PLD <label>",
    "pattern" : "11110101 U#1 10111111111 imm12#12",
    "decoder" : """imm32 = ZeroExtend(imm12, 32); add = (U == '1');"""
} , {
    "name" : "PLD, PLDW (register)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "PLD{W}<c> [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "1111100000 W#1 1 Rn#4 1111000000 imm2#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE PLD (literal);
    n = UInt(Rn); m = UInt(Rm); add = TRUE; is_pldw = (W == '1'); (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "PLD, PLDW (register)",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "PLD{W} [<Rn>,+/-<Rm>{, <shift>}]",
    "pattern" : "11110111 U#1 R#1 01 Rn#4 1111 imm5#5 type#2 0 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); add = (U == '1'); is_pldw = (R == '0'); (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if m == 15 || (n == 15 && is_pldw) then UNPREDICTABLE;"""
} , {
    "name" : "PLI (immediate, literal)",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "PLI<c> [<Rn>, #<imm12>]",
    "pattern" : "111110011001 Rn#4 1111 imm12#12",
    "decoder" : """if Rn == '1111' then SEE encoding T3;
    n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); add = TRUE;"""
} , {
    "name" : "PLI (immediate, literal)",
    "encoding" : "T2",
    "version" : "ARMv7",
    "format" : "PLI<c> [<Rn>, #-<imm8>]",
    "pattern" : "111110010001 Rn#4 11111100 imm8#8",
    "decoder" : """if Rn == '1111' then SEE encoding T3;
    n = UInt(Rn); imm32 = ZeroExtend(imm8, 32); add = FALSE;"""
} , {
    "name" : "PLI (immediate, literal)",
    "encoding" : "T3",
    "version" : "ARMv7",
    "format" : "PLI<c> <label>",
    "pattern" : "11111001 U#1 00111111111 imm12#12",
    "decoder" : """n = 15; imm32 = ZeroExtend(imm12, 32); add = (U == '1');"""
} , {
    "name" : "PLI (immediate, literal)",
    "encoding" : "A1",
    "version" : "ARMv7",
    "format" : "PLI [<Rn>, #+/-<imm32>]",
    "pattern" : "11110100 U#1 101 Rn#4 1111 imm12#12",
    "decoder" : """n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); add = (U == '1');"""
} , {
    "name" : "PLI (register)",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "PLI<c> [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "111110010001 Rn#4 1111000000 imm2#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE PLI (immediate, literal);
    n = UInt(Rn); m = UInt(Rm); add = TRUE; (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "PLI (register)",
    "encoding" : "A1",
    "version" : "ARMv7",
    "format" : "PLI [<Rn>,+/-<Rm>{, <shift>}]",
    "pattern" : "11110110 U#1 101 Rn#4 1111 imm5#5 type#2 0 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); add = (U == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "POP (Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "POP<c> <registers>",
    "pattern" : "1011110 P#1 register_list#8",
    "decoder" : """registers = P:'0000000':register_list; UnalignedAllowed = FALSE;
    if BitCount(registers) < 1 then UNPREDICTABLE;
    if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "POP (Thumb)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "POP<c>.W <registers>",
    "pattern" : "1110100010111101 P#1 M#1 0 register_list#13",
    "decoder" : """registers = P:M:'0':register_list; UnalignedAllowed = FALSE;
    if BitCount(registers) < 2 || (P == '1' && M == '1') then UNPREDICTABLE;
    if registers<15> == '1' && InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "POP (Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "POP<c>.W <registers>",
    "pattern" : "1111100001011101 Rt#4 101100000100",
    "decoder" : """t = UInt(Rt); registers = Zeros(16); registers = 1 << t; UnalignedAllowed = TRUE;
    if t == 13 || (t == 15 && InITBlock() && !LastInITBlock()) then UNPREDICTABLE;"""
} , {
    "name" : "POP (ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "POP<c> <registers>",
    "pattern" : "cond#4 100010111101 register_list#16",
    "decoder" : """if BitCount(register_list) < 2 then SEE LDM/LDMIA/LDMFD (ARM);
    registers = register_list; UnalignedAllowed = FALSE;
    if registers<13> == '1' && ArchVersion() >= 7 then UNPREDICTABLE;"""
} , {
    "name" : "POP (ARM)",
    "encoding" : "A2",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "POP<c> <registers>",
    "pattern" : "cond#4 010010011101 Rt#4 000000000100",
    "decoder" : """t = UInt(Rt); registers = Zeros(16); registers = 1 << t; UnalignedAllowed = TRUE;
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "PUSH",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "PUSH<c> <registers>",
    "pattern" : "1011010 M#1 register_list#8",
    "decoder" : """registers = '0':M:'000000':register_list; UnalignedAllowed = FALSE;
    if BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "PUSH",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "PUSH<c>.W <registers>",
    "pattern" : "11101001001011010 M#1 0 register_list#13",
    "decoder" : """registers = '0':M:'0':register_list; UnalignedAllowed = FALSE;
    if BitCount(registers) < 2 then UNPREDICTABLE;"""
} , {
    "name" : "PUSH",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "PUSH<c>.W <registers>",
    "pattern" : "1111100001001101 Rt#4 110100000100",
    "decoder" : """t = UInt(Rt); registers = Zeros(16); registers = 1 << t; UnalignedAllowed = TRUE;
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "PUSH",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "PUSH<c> <registers>",
    "pattern" : "cond#4 100100101101 register_list#16",
    "decoder" : """if BitCount(register_list) < 2 then SEE STMDB (STMFD);
    registers = register_list; UnalignedAllowed = FALSE;"""
} , {
    "name" : "PUSH",
    "encoding" : "A2",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "PUSH<c> <registers>",
    "pattern" : "cond#4 010100101101 Rt#4 000000000100",
    "decoder" : """t = UInt(Rt); registers = Zeros(16); registers = 1 << t; UnalignedAllowed = TRUE;
    if t == 13 then UNPREDICTABLE;"""
} , {
    "name" : "QADD",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QADD<c> <Rd>, <Rm>, <Rn>",
    "pattern" : "111110101000 Rn#4 1111 Rd#4 1000 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QADD",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "QADD<c> <Rd>, <Rm>, <Rn>",
    "pattern" : "cond#4 00010000 Rn#4 Rd#4 00000101 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QADD16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "111110101001 Rn#4 1111 Rd#4 0001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QADD16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "QADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 01100010 Rn#4 Rd#4 11110001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QADD8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "111110101000 Rn#4 1111 Rd#4 0001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QADD8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "QADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 01100010 Rn#4 Rd#4 11111001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QASX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "111110101010 Rn#4 1111 Rd#4 0001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QASX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "QASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 01100010 Rn#4 Rd#4 11110011 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QDADD",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QDADD<c> <Rd>, <Rm>, <Rn>",
    "pattern" : "111110101000 Rn#4 1111 Rd#4 1001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QDADD",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "QDADD<c> <Rd>, <Rm>, <Rn>",
    "pattern" : "cond#4 00010100 Rn#4 Rd#4 00000101 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QDSUB",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QDSUB<c> <Rd>, <Rm>, <Rn>",
    "pattern" : "111110101000 Rn#4 1111 Rd#4 1011 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QDSUB",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "QDSUB<c> <Rd>, <Rm>, <Rn>",
    "pattern" : "cond#4 00010110 Rn#4 Rd#4 00000101 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QSAX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "111110101110 Rn#4 1111 Rd#4 0001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QSAX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "QSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 01100010 Rn#4 Rd#4 11110101 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QSUB",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QSUB<c> <Rd>, <Rm>, <Rn>",
    "pattern" : "111110101000 Rn#4 1111 Rd#4 1010 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QSUB",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "QSUB<c> <Rd>, <Rm>, <Rn>",
    "pattern" : "cond#4 00010010 Rn#4 Rd#4 00000101 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QSUB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "111110101101 Rn#4 1111 Rd#4 0001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QSUB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "QSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 01100010 Rn#4 Rd#4 11110111 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "QSUB8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "QSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "111110101100 Rn#4 1111 Rd#4 0001 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "QSUB8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "QSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 01100010 Rn#4 Rd#4 11111111 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "RBIT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "RBIT<c> <Rd>, <Rm>",
    "pattern" : "111110101001 Rm_#4 1111 Rd#4 1010 Rm#4",
    "decoder" : """if !Consistent(Rm) then UNPREDICTABLE;
    d = UInt(Rd); m = UInt(Rm);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "RBIT",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "RBIT<c> <Rd>, <Rm>",
    "pattern" : "cond#4 011011111111 Rd#4 11110011 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm);
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "REV",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "REV<c> <Rd>, <Rm>",
    "pattern" : "1011101000 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm);"""
} , {
    "name" : "REV",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "REV<c>.W <Rd>, <Rm>",
    "pattern" : "111110101001 Rm_#4 1111 Rd#4 1000 Rm#4",
    "decoder" : """if !Consistent(Rm) then UNPREDICTABLE;
    d = UInt(Rd); m = UInt(Rm);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "REV",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "REV<c> <Rd>, <Rm>",
    "pattern" : "cond#4 011010111111 Rd#4 11110011 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm);
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "REV16",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "REV16<c> <Rd>, <Rm>",
    "pattern" : "1011101001 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm);"""
} , {
    "name" : "REV16",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "REV16<c>.W <Rd>, <Rm>",
    "pattern" : "111110101001 Rm_#4 1111 Rd#4 1001 Rm#4",
    "decoder" : """if !Consistent(Rm) then UNPREDICTABLE;
    d = UInt(Rd); m = UInt(Rm);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "REV16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "REV16<c> <Rd>, <Rm>",
    "pattern" : "cond#4 011010111111 Rd#4 11111011 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm);
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "REVSH",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "REVSH<c> <Rd>, <Rm>",
    "pattern" : "1011101011 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm);"""
} , {
    "name" : "REVSH",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "REVSH<c>.W <Rd>, <Rm>",
    "pattern" : "111110101001 Rm_#4 1111 Rd#4 1011 Rm#4",
    "decoder" : """if !Consistent(Rm) then UNPREDICTABLE;
    d = UInt(Rd); m = UInt(Rm);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "REVSH",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "REVSH<c> <Rd>, <Rm>",
    "pattern" : "cond#4 011011111111 Rd#4 11111011 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm);
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "ROR (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ROR{S}<c> <Rd>, <Rm>, #<shift_n>",
    "pattern" : "11101010010 S#1 11110 imm3#3 Rd#4 imm2#2 11 Rm#4",
    "decoder" : """if (imm3:imm2) == '00000' then SEE RRX;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1'); (-, shift_n) = DecodeImmShift('11', imm3:imm2);
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ROR (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ROR{S}<c> <Rd>, <Rm>, #<shift_n>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 imm5#5 110 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    if imm5 == '00000' then SEE RRX;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    (-, shift_n) = DecodeImmShift('11', imm5);"""
} , {
    "name" : "ROR (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RORS <Rdn>, <Rm>:ROR<c> <Rdn>, <Rm>",
    "pattern" : "0100000111 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock();"""
} , {
    "name" : "ROR (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "ROR{S}<c>.W <Rd>, <Rn>, <Rm>",
    "pattern" : "11111010011 S#1 Rn#4 1111 Rd#4 0000 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "ROR (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "ROR{S}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 Rm#4 0111 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "RRX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "RRX{S}<c> <Rd>, <Rm>",
    "pattern" : "11101010010 S#1 11110000 Rd#4 0011 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "RRX",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RRX{S}<c> <Rd>, <Rm>",
    "pattern" : "cond#4 0001101 S#1 0000 Rd#4 00000110 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');"""
} , {
    "name" : "RSB (immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RSBS <Rd>, <Rn>, #0:RSB<c> <Rd>, <Rn>, #0",
    "pattern" : "0 1 0 0 0 0 1 0 0 1 Rn#3 Rd#3",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); setflags = !InITBlock(); imm32 = Zeros(32);"""
} , {
    "name" : "RSB (immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "RSB{S}<c>.W <Rd>, <Rn>, #<const>",
    "pattern" : "1 1 1 1 0 i#1 0 1 1 1 0 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ThumbExpandImm(i:imm3:imm8);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "RSB (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RSB{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0 0 1 0 0 1 1 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "RSB (register)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "RSB{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "1 1 1 0 1 0 1 1 1 1 0 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "RSB (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RSB{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0 0 0 0 0 1 1 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "RSB (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RSB{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0 0 0 0 0 1 1 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs); setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "RSC (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RSC{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0 0 1 0 1 1 1 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "RSC (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RSC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0 0 0 0 1 1 1 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "RSC (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "RSC{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0 0 0 0 1 1 1 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs); setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SADD16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 1 Rn#4 1 1 1 1 Rd#4 0 0 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SADD16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 0 1 Rn#4 Rd#4 1 1 1 1 0 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SADD8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 0 Rn#4 1 1 1 1 Rd#4 0 0 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SADD8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 0 1 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SASX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 1 0 Rn#4 1 1 1 1 Rd#4 0 0 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SASX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 0 1 Rn#4 Rd#4 1 1 1 1 0 0 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SBC (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SBC{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "1 1 1 1 0 i#1 0 1 0 1 1 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ThumbExpandImm(i:imm3:imm8);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SBC (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SBC{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0 0 1 0 1 1 0 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "SBC (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SBCS <Rdn>, <Rm>:SBC<c> <Rdn>, <Rm>",
    "pattern" : "0 1 0 0 0 0 0 1 1 0 Rm#3 Rdn#3",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); m = UInt(Rm); setflags = !InITBlock(); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "SBC (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SBC{S}<c>.W <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "1 1 1 0 1 0 1 1 0 1 1 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SBC (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SBC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0 0 0 0 1 1 0 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "SBC (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SBC{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0 0 0 0 1 1 0 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs); setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SBFX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SBFX<c> <Rd>, <Rn>, #<lsb>, #<widthminus1>",
    "pattern" : "1 1 1 1 0 0 1 1 0 1 0 0 Rn#4 0 imm3#3 Rd#4 imm2#2 0 widthm1#5",
    "decoder" : """d = UInt(Rd); n = UInt(Rn);
    lsbit = UInt(imm3:imm2); widthminus1 = UInt(widthm1);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SBFX",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SBFX<c> <Rd>, <Rn>, #<lsb>, #<widthminus1>",
    "pattern" : "cond#4 0 1 1 1 1 0 1 widthm1#5 Rd#4 lsb#5 1 0 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn);
    lsbit = UInt(lsb); widthminus1 = UInt(widthm1);
    if d == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SDIV",
    "encoding" : "T1",
    "version" : "ARMv7R, ARMv7VE",
    "format" : "SDIV<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 0 0 1 Rn#4 1 1 1 1 Rd#4 1 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SDIV",
    "encoding" : "A1",
    "version" : "ARMv7VE",
    "format" : "SDIV<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 1 0 0 0 1 Rd#4 1 1 1 1 Rm#4 0 0 0 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SEL",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SEL<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 1 0 Rn#4 1 1 1 1 Rd#4 1 0 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SEL",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SEL<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 1 0 0 0 Rn#4 Rd#4 1 1 1 1 1 0 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SETEND",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SETEND <endian_specifier>",
    "pattern" : "1 0 1 1 0 1 1 0 0 1 0 1 E#1 0 0 0",
    "decoder" : """set_bigend = (E == '1');
    if InITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "SETEND",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SETEND <endian_specifier>",
    "pattern" : "1 1 1 1 0 0 0 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 E#1 0 0 0 0 0 0 0 0 0",
    "decoder" : """set_bigend = (E == '1');"""
} , {
    "name" : "SEV",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "SEV<c>",
    "pattern" : "1 0 1 1 1 1 1 1 0 1 0 0 0 0 0 0",
    "decoder" : """NOP();"""
} , {
    "name" : "SEV",
    "encoding" : "T2",
    "version" : "ARMv7",
    "format" : "SEV<c>.W",
    "pattern" : "1 1 1 1 0 0 1 1 1 0 1 0 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0",
    "decoder" : """NOP();"""
} , {
    "name" : "SEV",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "SEV<c>",
    "pattern" : "cond#4 0 0 1 1 0 0 1 0 0 0 0 0 1 1 1 1 0 0 0 0 0 0 0 0 0 1 0 0",
    "decoder" : """NOP();"""
} , {
    "name" : "SHADD16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SHADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 1 Rn#4 1 1 1 1 Rd#4 0 0 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SHADD16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SHADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 1 1 Rn#4 Rd#4 1 1 1 1 0 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SHADD8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SHADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 0 Rn#4 1 1 1 1 Rd#4 0 0 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SHADD8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SHADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 1 1 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SHASX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SHASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 1 0 Rn#4 1 1 1 1 Rd#4 0 0 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SHASX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SHASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 1 1 Rn#4 Rd#4 1 1 1 1 0 0 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SHSAX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SHSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 1 0 Rn#4 1 1 1 1 Rd#4 0 0 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SHSAX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SHSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 1 1 Rn#4 Rd#4 1 1 1 1 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SHSUB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SHSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 1 Rn#4 1 1 1 1 Rd#4 0 0 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SHSUB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SHSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 1 1 Rn#4 Rd#4 1 1 1 1 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SHSUB8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SHSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 0 Rn#4 1 1 1 1 Rd#4 0 0 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SHSUB8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SHSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 1 1 Rn#4 Rd#4 1 1 1 1 1 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMLABB, SMLABT, SMLATB, SMLATT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMLA<x><y><c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "1 1 1 1 1 0 1 1 0 0 0 1 Rn#4 Ra#4 Rd#4 0 0 N#1 M#1 Rm#4",
    "decoder" : """if Ra == '1111' then SEE SMULBB, SMULBT, SMULTB, SMULTT;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra);
    n_high = (N == '1'); m_high = (M == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a == 13 then UNPREDICTABLE;"""
} , {
    "name" : "SMLABB, SMLABT, SMLATB, SMLATT",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "SMLA<x><y><c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 0 0 0 1 0 0 0 0 Rd#4 Ra#4 Rm#4 1 M#1 N#1 0 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); n_high = (N == '1'); m_high = (M == '1');
    if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMLAD",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMLAD{X}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "1 1 1 1 1 0 1 1 0 0 1 0 Rn#4 Ra#4 Rd#4 0 0 0 M#1 Rm#4",
    "decoder" : """if Ra == '1111' then SEE SMUAD;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra);
    m_swap = (M == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a == 13 then UNPREDICTABLE;"""
} , {
    "name" : "SMLAD",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMLAD{X}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 0 1 1 1 0 0 0 0 Rd#4 Ra#4 Rm#4 0 0 M#1 1 Rn#4",
    "decoder" : """if Ra == '1111' then SEE SMUAD;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); m_swap = (M == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMLAL",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMLAL<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 1 0 0 Rn#4 RdLo#4 RdHi#4 0 0 0 0 Rm#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); setflags = FALSE;
    if dLo IN {13,15} || dHi IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "SMLAL",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SMLAL{S}<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 0 0 0 1 1 1 S#1 RdHi#4 RdLo#4 Rm#4 1 0 0 1 Rn#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;
    if ArchVersion() < 6 && (dHi == n || dLo == n) then UNPREDICTABLE;"""
} , {
    "name" : "SMLALBB, SMLALBT, SMLALTB, SMLALTT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMLAL<x><y><c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 1 0 0 Rn#4 RdLo#4 RdHi#4 1 0 N#1 M#1 Rm#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm);
    n_high = (N == '1'); m_high = (M == '1');
    if dLo IN {13,15} || dHi IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "SMLALBB, SMLALBT, SMLALTB, SMLALTT",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "SMLAL<x><y><c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 0 0 1 0 1 0 0 RdHi#4 RdLo#4 Rm#4 1 M#1 N#1 0 Rn#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); n_high = (N == '1'); m_high = (M == '1');
    if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "SMLALD",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMLALD{X}<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 1 0 0 Rn#4 RdLo#4 RdHi#4 1 1 0 M#1 Rm#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); m_swap = (M == '1');
    if dLo IN {13,15} || dHi IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "SMLALD",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMLALD{X}<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 1 0 1 0 0 RdHi#4 RdLo#4 Rm#4 0 0 M#1 1 Rn#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); m_swap = (M == '1');
    if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "SMLAWB, SMLAWT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMLAW<y><c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "1 1 1 1 1 0 1 1 0 0 1 1 Rn#4 Ra#4 Rd#4 0 0 0 M#1 Rm#4",
    "decoder" : """if Ra == '1111' then SEE SMULWB, SMULWT;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); m_high = (M == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a == 13 then UNPREDICTABLE;"""
} , {
    "name" : "SMLAWB, SMLAWT",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "SMLAW<y><c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 0 0 0 1 0 0 1 0 Rd#4 Ra#4 Rm#4 1 M#1 0 0 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); m_high = (M == '1');
    if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMLSD",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMLSD{X}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "1 1 1 1 1 0 1 1 0 1 0 0 Rn#4 Ra#4 Rd#4 0 0 0 M#1 Rm#4",
    "decoder" : """if Ra == '1111' then SEE SMUSD;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); m_swap = (M == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a == 13 then UNPREDICTABLE;"""
} , {
    "name" : "SMLSD",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMLSD{X}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 0 1 1 1 0 0 0 0 Rd#4 Ra#4 Rm#4 0 1 M#1 1 Rn#4",
    "decoder" : """if Ra == '1111' then SEE SMUSD;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); m_swap = (M == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMLSLD",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMLSLD{X}<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 1 0 1 Rn#4 RdLo#4 RdHi#4 1 1 0 M#1 Rm#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); m_swap = (M == '1');
    if dLo IN {13,15} || dHi IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "SMLSLD",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMLSLD{X}<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 1 0 1 0 0 RdHi#4 RdLo#4 Rm#4 0 1 M#1 1 Rn#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); m_swap = (M == '1');
    if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "SMMLA",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMMLA{R}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "1 1 1 1 1 0 1 1 0 1 0 1 Rn#4 Ra#4 Rd#4 0 0 0 R#1 Rm#4",
    "decoder" : """if Ra == '1111' then SEE SMMUL;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); round = (R == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a == 13 then UNPREDICTABLE;"""
} , {
    "name" : "SMMLA",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMMLA{R}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 0 1 1 1 0 1 0 1 Rd#4 Ra#4 Rm#4 0 0 R#1 1 Rn#4",
    "decoder" : """if Ra == '1111' then SEE SMMUL;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); round = (R == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMMLS",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMMLS{R}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "1 1 1 1 1 0 1 1 0 1 1 0 Rn#4 Ra#4 Rd#4 0 0 0 R#1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); round = (R == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SMMLS",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMMLS{R}<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 0 1 1 1 0 1 0 1 Rd#4 Ra#4 Rm#4 1 1 R#1 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra); round = (R == '1');
    if d == 15 || n == 15 || m == 15 || a == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMMUL",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMMUL{R}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 0 1 0 1 Rn#4 1 1 1 1 Rd#4 0 0 0 R#1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); round = (R == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SMMUL",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMMUL{R}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 1 0 1 0 1 Rd#4 1 1 1 1 Rm#4 0 0 R#1 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); round = (R == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMUAD",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMUAD{X}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 0 0 1 0 Rn#4 1 1 1 1 Rd#4 0 0 0 M#1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); m_swap = (M == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SMUAD",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMUAD{X}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 1 0 0 0 0 Rd#4 1 1 1 1 Rm#4 0 0 M#1 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); m_swap = (M == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMULBB, SMULBT, SMULTB, SMULTT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMUL<x><y><c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 0 0 0 1 Rn#4 1 1 1 1 Rd#4 0 0 N#1 M#1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    n_high = (N == '1'); m_high = (M == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SMULBB, SMULBT, SMULTB, SMULTT",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "SMUL<x><y><c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 0 0 1 0 1 1 0 Rd#4 0 0 0 0 Rm#4 1 M#1 N#1 0 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    n_high = (N == '1'); m_high = (M == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMULL",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMULL<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 0 0 0 Rn#4 RdLo#4 RdHi#4 0 0 0 0 Rm#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); setflags = FALSE;
    if dLo IN {13,15} || dHi IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "SMULL",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SMULL{S}<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 0 0 0 1 1 0 S#1 RdHi#4 RdLo#4 Rm#4 1 0 0 1 Rn#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;
    if ArchVersion() < 6 && (dHi == n || dLo == n) then UNPREDICTABLE;"""
} , {
    "name" : "SMULWB, SMULWT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMULW<y><c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 0 0 1 1 Rn#4 1 1 1 1 Rd#4 0 0 0 M#1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); m_high = (M == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SMULWB, SMULWT",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "SMULW<y><c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 0 0 1 0 0 1 0 Rd#4 0 0 0 0 Rm#4 1 M#1 1 0 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); m_high = (M == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMUSD",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SMUSD{X}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 0 1 0 0 Rn#4 1 1 1 1 Rd#4 0 0 0 M#1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); m_swap = (M == '1');
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SMUSD",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SMUSD{X}<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 1 0 0 0 0 Rd#4 1 1 1 1 Rm#4 0 1 M#1 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); m_swap = (M == '1');
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SSAT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SSAT<c> <Rd>, #<saturate_to>, <Rn>{, <shift>}",
    "pattern" : "1 1 1 1 0 0 1 1 0 0 sh#1 0 Rn#4 0 imm3#3 Rd#4 imm2#2 0 sat_imm#5",
    "decoder" : """if sh == '1' && (imm3:imm2) == '00000' then SEE SSAT16;
    d = UInt(Rd); n = UInt(Rn); saturate_to = UInt(sat_imm)+1; (shift_t, shift_n) = DecodeImmShift(sh:'0', imm3:imm2);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SSAT",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SSAT<c> <Rd>, #<saturate_to>, <Rn>{, <shift>}",
    "pattern" : "cond#4 0 1 1 0 1 0 1 sat_imm#5 Rd#4 imm5#5 sh#1 0 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); saturate_to = UInt(sat_imm)+1; (shift_t, shift_n) = DecodeImmShift(sh:'0', imm5);
    if d == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SSAT16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SSAT16<c> <Rd>, #<saturate_to>, <Rn>",
    "pattern" : "1 1 1 1 0 0 1 1 0 0 1 0 Rn#4 0 0 0 0 Rd#4 0 0 0 0 sat_imm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); saturate_to = UInt(sat_imm)+1;
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SSAT16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SSAT16<c> <Rd>, #<saturate_to>, <Rn>",
    "pattern" : "cond#4 0 1 1 0 1 0 1 0 sat_imm#4 Rd#4 1 1 1 1 0 0 1 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); saturate_to = UInt(sat_imm)+1;
    if d == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SSAX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 1 0 Rn#4 1 1 1 1 Rd#4 0 0 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SSAX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 0 1 Rn#4 Rd#4 1 1 1 1 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SSUB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 1 Rn#4 1 1 1 1 Rd#4 0 0 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SSUB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 0 1 Rn#4 Rd#4 1 1 1 1 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SSUB8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 0 Rn#4 1 1 1 1 Rd#4 0 0 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SSUB8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 0 0 1 Rn#4 Rd#4 1 1 1 1 1 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "STC, STC2",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 0 P#1 U#1 D#1 W#1 0 Rn#4 CRd#4 coproc#4 imm8#8",
    "decoder" : """if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MCRR, MCRR2;
    if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    n = UInt(Rn); cp = UInt(coproc);
    imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "STC, STC2",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 0 P#1 U#1 D#1 W#1 0 Rn#4 CRd#4 coproc#4 imm8#8",
    "decoder" : """if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MCRR, MCRR2;
    if coproc IN "101x" then SEE "AdvancedSIMD and Floating-point";
    n = UInt(Rn); cp = UInt(coproc);
    imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "STC, STC2",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 0 P#1 U#1 D#1 W#1 0 Rn#4 CRd#4 coproc#4 imm8#8",
    "decoder" : """if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MCRR, MCRR2;
    if coproc IN "101x" then UNDEFINED;
    n = UInt(Rn); cp = UInt(coproc);
    imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "STC, STC2",
    "encoding" : "A2",
    "version" : "ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 0 P#1 U#1 D#1 W#1 0 Rn#4 CRd#4 coproc#4 imm8#8",
    "decoder" : """if P == '0' && U == '0' && D == '0' && W == '0' then UNDEFINED;
    if P == '0' && U == '0' && D == '1' && W == '0' then SEE MCRR, MCRR2;
    if coproc IN "101x" then UNDEFINED;
    n = UInt(Rn); cp = UInt(coproc);
    imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "STM (STMIA, STMEA)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STM<c> <Rn>!, <registers>",
    "pattern" : "1 1 0 0 0 Rn#3 register_list#8",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then SEE "ThumbEE instructions";
    n = UInt(Rn); registers = '00000000':register_list; wback = TRUE;
    if BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "STM (STMIA, STMEA)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STM<c>.W <Rn>{!}, <registers>",
    "pattern" : "1 1 1 0 1 0 0 0 1 0 W#1 0 Rn#4 0 M#1 0 register_list#13",
    "decoder" : """n = UInt(Rn); registers = '0':M:'0':register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 2 then UNPREDICTABLE;
    if wback && registers<n> == '1' then UNPREDICTABLE;"""
} , {
    "name" : "STM (STMIA, STMEA)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STM<c> <Rn>{!}, <registers>",
    "pattern" : "cond#4 1 0 0 0 1 0 W#1 0 Rn#4 register_list#16",
    "decoder" : """n = UInt(Rn); registers = register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "STMDA (STMED)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STMDA<c> <Rn>{!}, <registers>",
    "pattern" : "cond#4 1 0 0 0 0 0 W#1 0 Rn#4 register_list#16",
    "decoder" : """n = UInt(Rn); registers = register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "STMDB (STMFD)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STMDB<c> <Rn>{!}, <registers>",
    "pattern" : "1 1 1 0 1 0 0 1 0 0 W#1 0 Rn#4 0 M#1 0 register_list#13",
    "decoder" : """if W == '1' && Rn == '1101' then SEE PUSH;
    n = UInt(Rn); registers = '0':M:'0':register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 2 then UNPREDICTABLE;
    if wback && registers<n> == '1' then UNPREDICTABLE;"""
} , {
    "name" : "STMDB (STMFD)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STMDB<c> <Rn>{!}, <registers>",
    "pattern" : "cond#4 1 0 0 1 0 0 W#1 0 Rn#4 register_list#16",
    "decoder" : """if W == '1' && Rn == '1101' && BitCount(register_list) >= 2 then SEE PUSH;
    n = UInt(Rn); registers = register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "STMIB (STMFA)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STMIB<c> <Rn>{!}, <registers>",
    "pattern" : "cond#4 1 0 0 1 1 0 W#1 0 Rn#4 register_list#16",
    "decoder" : """n = UInt(Rn); registers = register_list; wback = (W == '1');
    if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "STR (immediate, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STR<c> <Rt>, [<Rn>{, #<imm32>}]",
    "pattern" : "0 1 1 0 0 imm5#5 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm5:'00', 32); index = TRUE; add = TRUE; wback = FALSE;"""
} , {
    "name" : "STR (immediate, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STR<c> <Rt>, [SP, #<imm32>]",
    "pattern" : "1 0 0 1 0 Rt#3 imm8#8",
    "decoder" : """t = UInt(Rt); n = 13; imm32 = ZeroExtend(imm8:'00', 32);
    index = TRUE; add = TRUE; wback = FALSE;"""
} , {
    "name" : "STR (immediate, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STR<c>.W <Rt>, [<Rn>, #<imm12>]",
    "pattern" : "1 1 1 1 1 0 0 0 1 1 0 0 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); index = TRUE; add = TRUE; wback = FALSE;
    if t == 15 then UNPREDICTABLE;"""
} , {
    "name" : "STR (immediate, Thumb)",
    "encoding" : "T4",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 0 0 1 0 0 Rn#4 Rt#4 1 P#1 U#1 W#1 imm8#8",
    "decoder" : """if P == '1' && U == '1' && W == '0' then SEE STRT;
    if Rn == '1101' && P == '1' && U == '0' && W == '1' && imm8 == '00000100' then SEE PUSH;
    if Rn == '1111' || (P == '0' && W == '0') then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8, 32);
    index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if t == 15 || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "STR (immediate, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 0 1 0 P#1 U#1 0 W#1 0 Rn#4 Rt#4 imm12#12",
    "decoder" : """if P == '0' && W == '1' then SEE STRT;
    if Rn == '1101' && P == '1' && U == '0' && W == '1' && imm12 == '000000000100' then SEE PUSH;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if wback && (n == 15 || n == t) then UNPREDICTABLE;"""
} , {
    "name" : "STR (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STR<c> <Rt>, [<Rn>, <Rm>]",
    "pattern" : "0 1 0 1 0 0 0 Rm#3 Rn#3 Rt#3",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then SEE "Modified operation in ThumbEE";
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = TRUE; add = TRUE; wback = FALSE;
    (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "STR (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STR<c>.W <Rt>, [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "1 1 1 1 1 0 0 0 0 1 0 0 Rn#4 Rt#4 0 0 0 0 0 0 imm2#2 Rm#4",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); index = TRUE; add = TRUE; wback = FALSE; (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if t == 15 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STR (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 0 1 1 P#1 U#1 0 W#1 0 Rn#4 Rt#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if P == '0' && W == '1' then SEE STRT;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "STRB (immediate, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STRB<c> <Rt>, [<Rn>, #<imm5>]",
    "pattern" : "0 1 1 1 0 imm5#5 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm5, 32); index = TRUE; add = TRUE; wback = FALSE;"""
} , {
    "name" : "STRB (immediate, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRB<c>.W <Rt>, [<Rn>, #<imm12>]",
    "pattern" : "1 1 1 1 1 0 0 0 1 0 0 0 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); index = TRUE; add = TRUE; wback = FALSE;
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STRB (immediate, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 0 0 0 0 0 Rn#4 Rt#4 1 P#1 U#1 W#1 imm8#8",
    "decoder" : """if P == '1' && U == '1' && W == '0' then SEE STRBT;
    if Rn == '1111' || (P == '0' && W == '0') then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8, 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if t IN {13,15} || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "STRB (immediate, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 0 1 0 P#1 U#1 1 W#1 0 Rn#4 Rt#4 imm12#12",
    "decoder" : """if P == '0' && W == '1' then SEE STRBT;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if t == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;"""
} , {
    "name" : "STRB (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STRB<c> <Rt>, [<Rn>, <Rm>]",
    "pattern" : "0 1 0 1 0 1 0 Rm#3 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); index = TRUE; add = TRUE; wback = FALSE; (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "STRB (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRB<c>.W <Rt>, [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "1 1 1 1 1 0 0 0 0 0 0 0 Rn#4 Rt#4 0 0 0 0 0 0 imm2#2 Rm#4",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = TRUE; add = TRUE; wback = FALSE; (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if t IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STRB (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 0 1 1 P#1 U#1 1 W#1 0 Rn#4 Rt#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if P == '0' && W == '1' then SEE STRBT;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if t == 15 || m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "STRBT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRBT<c> <Rt>, [<Rn>, #<imm8>]",
    "pattern" : "1 1 1 1 1 0 0 0 0 0 0 0 Rn#4 Rt#4 1 1 1 0 imm8#8",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); postindex = FALSE; add = TRUE; register_form = FALSE; imm32 = ZeroExtend(imm8, 32);
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STRBT",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STRBT<c> <Rt>, [<Rn>], #+/-<imm12>",
    "pattern" : "cond#4 0 1 0 0 U#1 1 1 0 Rn#4 Rt#4 imm12#12",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); postindex = TRUE; add = (U == '1'); register_form = FALSE; imm32 = ZeroExtend(imm12, 32);
    if t == 15 || n == 15 || n == t then UNPREDICTABLE;"""
} , {
    "name" : "STRBT",
    "encoding" : "A2",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STRBT<c> <Rt>, [<Rn>],+/-<Rm>{, <shift>}",
    "pattern" : "cond#4 0 1 1 0 U#1 1 1 0 Rn#4 Rt#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); postindex = TRUE; add = (U == '1'); register_form = TRUE; (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;
    if ArchVersion() < 6 && m == n then UNPREDICTABLE;"""
} , {
    "name" : "STRD (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 0 0 P#1 U#1 1 W#1 0 Rn#4 Rt#4 Rt2#4 imm8#8",
    "decoder" : """if P == '0' && W == '0' then SEE "Related encodings";
    t = UInt(Rt); t2 = UInt(Rt2); n = UInt(Rn); imm32 = ZeroExtend(imm8:'00', 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if wback && (n == t || n == t2) then UNPREDICTABLE;
    if n == 15 || t IN {13,15} || t2 IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STRD (immediate)",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 0 0 0 P#1 U#1 1 W#1 0 Rn#4 Rt#4 imm4H#4 1 1 1 1 imm4L#4",
    "decoder" : """if Rt<0> == '1' then UNPREDICTABLE;
    t = UInt(Rt); t2 = t+1; n = UInt(Rn); imm32 = ZeroExtend(imm4H:imm4L, 32); index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if P == '0' && W == '1' then UNPREDICTABLE;
    if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE;
    if t2 == 15 then UNPREDICTABLE;"""
} , {
    "name" : "STRD (register)",
    "encoding" : "A1",
    "version" : "ARMv5TEAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 0 0 0 P#1 U#1 0 W#1 0 Rn#4 Rt#4 0 0 0 0 1 1 1 1 Rm#4",
    "decoder" : """if Rt<0> == '1' then UNPREDICTABLE;
    t = UInt(Rt); t2 = t+1; n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if P == '0' && W == '1' then UNPREDICTABLE;
    if t2 == 15 || m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t || n == t2) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "STREX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STREX<c> <Rd>, <Rt>, [<Rn>{, #<imm32>}]",
    "pattern" : "1 1 1 0 1 0 0 0 0 1 0 0 Rn#4 Rt#4 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8:'00', 32);
    if d IN {13,15} || t IN {13,15} || n == 15 then UNPREDICTABLE;
    if d == n || d == t then UNPREDICTABLE;"""
} , {
    "name" : "STREX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "STREX<c> <Rd>, <Rt>, [<Rn>]",
    "pattern" : "cond#4 0 0 0 1 1 0 0 0 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rt#4",
    "decoder" : """d = UInt(Rd); t = UInt(Rt); n = UInt(Rn); imm32 = Zeros(32);
    if d == 15 || t == 15 || n == 15 then UNPREDICTABLE;
    if d == n || d == t then UNPREDICTABLE;"""
} , {
    "name" : "STREXB",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "STREXB<c> <Rd>, <Rt>, [<Rn>]",
    "pattern" : "1 1 1 0 1 0 0 0 1 1 0 0 Rn#4 Rt#4 1 1 1 1 0 1 0 0 Rd#4",
    "decoder" : """d = UInt(Rd); t = UInt(Rt); n = UInt(Rn);
    if d IN {13,15} || t IN {13,15} || n == 15 then UNPREDICTABLE;
    if d == n || d == t then UNPREDICTABLE;"""
} , {
    "name" : "STREXB",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "STREXB<c> <Rd>, <Rt>, [<Rn>]",
    "pattern" : "cond#4 0 0 0 1 1 1 0 0 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rt#4",
    "decoder" : """d = UInt(Rd); t = UInt(Rt); n = UInt(Rn);
    if d == 15 || t == 15 || n == 15 then UNPREDICTABLE;
    if d == n || d == t then UNPREDICTABLE;"""
} , {
    "name" : "STREXD",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "STREXD<c> <Rd>, <Rt>, <Rt2>, [<Rn>]",
    "pattern" : "1 1 1 0 1 0 0 0 1 1 0 0 Rn#4 Rt#4 Rt2#4 0 1 1 1 Rd#4",
    "decoder" : """d = UInt(Rd); t = UInt(Rt); t2 = UInt(Rt2); n = UInt(Rn);
    if d IN {13,15} || t IN {13,15} || t2 IN {13,15} || n == 15 then UNPREDICTABLE;
    if d == n || d == t || d == t2 then UNPREDICTABLE;"""
} , {
    "name" : "STREXD",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "STREXD<c> <Rd>, <Rt>, <Rt2>, [<Rn>]",
    "pattern" : "cond#4 0 0 0 1 1 0 1 0 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rt#4",
    "decoder" : """d = UInt(Rd); t = UInt(Rt); t2 = t+1; n = UInt(Rn);
    if d == 15 || Rt<0> == '1' || Rt == '1110' || n == 15 then UNPREDICTABLE;
    if d == n || d == t || d == t2 then UNPREDICTABLE;"""
} , {
    "name" : "STREXH",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "STREXH<c> <Rd>, <Rt>, [<Rn>]",
    "pattern" : "1 1 1 0 1 0 0 0 1 1 0 0 Rn#4 Rt#4 1 1 1 1 0 1 0 1 Rd#4",
    "decoder" : """d = UInt(Rd); t = UInt(Rt); n = UInt(Rn);
    if d IN {13,15} || t IN {13,15} || n == 15 then UNPREDICTABLE;
    if d == n || d == t then UNPREDICTABLE;"""
} , {
    "name" : "STREXH",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "STREXH<c> <Rd>, <Rt>, [<Rn>]",
    "pattern" : "cond#4 0 0 0 1 1 1 1 0 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rt#4",
    "decoder" : """d = UInt(Rd); t = UInt(Rt); n = UInt(Rn);
    if d == 15 || t == 15 || n == 15 then UNPREDICTABLE;
    if d == n || d == t then UNPREDICTABLE;"""
} , {
    "name" : "STRH (immediate, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STRH<c> <Rt>, [<Rn>{, #<imm32>}]",
    "pattern" : "1 0 0 0 0 imm5#5 Rn#3 Rt#3",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm5:'0', 32); index = TRUE; add = TRUE; wback = FALSE;"""
} , {
    "name" : "STRH (immediate, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRH<c>.W <Rt>, [<Rn>{, #<imm12>}]",
    "pattern" : "1 1 1 1 1 0 0 0 1 0 1 0 Rn#4 Rt#4 imm12#12",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm12, 32); index = TRUE; add = TRUE; wback = FALSE;
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STRH (immediate, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 0 0 0 1 0 Rn#4 Rt#4 1 P#1 U#1 W#1 imm8#8",
    "decoder" : """if P == '1' && U == '1' && W == '0' then SEE STRHT;
    if Rn == '1111' || (P == '0' && W == '0') then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm8, 32); index = (P == '1'); add = (U == '1'); wback = (W == '1');
    if t IN {13,15} || (wback && n == t) then UNPREDICTABLE;"""
} , {
    "name" : "STRH (immediate, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 0 0 0 P#1 U#1 1 W#1 0 Rn#4 Rt#4 imm4H#4 1 0 1 1 imm4L#4",
    "decoder" : """if P == '0' && W == '1' then SEE STRHT;
    t = UInt(Rt); n = UInt(Rn); imm32 = ZeroExtend(imm4H:imm4L, 32);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1');
    if t == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;"""
} , {
    "name" : "STRH (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STRH<c> <Rt>, [<Rn>, <Rm>]",
    "pattern" : "0 1 0 1 0 0 1 Rm#3 Rn#3 Rt#3",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then SEE "Modified operation in ThumbEE";
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = TRUE; add = TRUE; wback = FALSE;
    (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "STRH (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRH<c>.W <Rt>, [<Rn>, <Rm>{, LSL #<imm2>}]",
    "pattern" : "1 1 1 1 1 0 0 0 0 0 1 0 Rn#4 Rt#4 0 0 0 0 0 0 imm2#2 Rm#4",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = TRUE; add = TRUE; wback = FALSE; (shift_t, shift_n) = (SRType_LSL, UInt(imm2));
    if t IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STRH (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 0 0 0 P#1 U#1 0 W#1 0 Rn#4 Rt#4 0 0 0 0 1 0 1 1 Rm#4",
    "decoder" : """if P == '0' && W == '1' then SEE STRHT;
    t = UInt(Rt); n = UInt(Rn); m = UInt(Rm);
    index = (P == '1'); add = (U == '1'); wback = (P == '0') || (W == '1'); (shift_t, shift_n) = (SRType_LSL, 0);
    if t == 15 || m == 15 then UNPREDICTABLE;
    if wback && (n == 15 || n == t) then UNPREDICTABLE;
    if ArchVersion() < 6 && wback && m == n then UNPREDICTABLE;"""
} , {
    "name" : "STRHT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRHT<c> <Rt>, [<Rn>, #<imm8>]",
    "pattern" : "1 1 1 1 1 0 0 0 0 0 1 0 Rn#4 Rt#4 1 1 1 0 imm8#8",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); postindex = FALSE; add = TRUE; register_form = FALSE; imm32 = ZeroExtend(imm8, 32);
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STRHT",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRHT<c> <Rt>, [<Rn>] {, #+/-<imm8>}",
    "pattern" : "cond#4 0 0 0 0 U#1 1 1 0 Rn#4 Rt#4 imm4H#4 1 0 1 1 imm4L#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); postindex = TRUE; add = (U == '1'); register_form = FALSE; imm32 = ZeroExtend(imm4H:imm4L, 32);
    if t == 15 || n == 15 || n == t then UNPREDICTABLE;"""
} , {
    "name" : "STRHT",
    "encoding" : "A2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRHT<c> <Rt>, [<Rn>], +/-<Rm>",
    "pattern" : "cond#4 0 0 0 0 U#1 0 1 0 Rn#4 Rt#4 0 0 0 0 1 0 1 1 Rm#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); postindex = TRUE; add = (U == '1'); register_form = TRUE;
    if t == 15 || n == 15 || n == t || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "STRT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "STRT<c> <Rt>, [<Rn>, #<imm8>]",
    "pattern" : "1 1 1 1 1 0 0 0 0 1 0 0 Rn#4 Rt#4 1 1 1 0 imm8#8",
    "decoder" : """if Rn == '1111' then UNDEFINED;
    t = UInt(Rt); n = UInt(Rn); postindex = FALSE; add = TRUE; register_form = FALSE; imm32 = ZeroExtend(imm8, 32);
    if t IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "STRT",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STRT<c> <Rt>, [<Rn>] {, +/-<imm12>}",
    "pattern" : "cond#4 0 1 0 0 U#1 0 1 0 Rn#4 Rt#4 imm12#12",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); postindex = TRUE; add = (U == '1'); register_form = FALSE; imm32 = ZeroExtend(imm12, 32);
    if n == 15 || n == t then UNPREDICTABLE;"""
} , {
    "name" : "STRT",
    "encoding" : "A2",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STRT<c> <Rt>, [<Rn>],+/-<Rm>{, <shift>}",
    "pattern" : "cond#4 0 1 1 0 U#1 0 1 0 Rn#4 Rt#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """t = UInt(Rt); n = UInt(Rn); m = UInt(Rm); postindex = TRUE; add = (U == '1'); register_form = TRUE; (shift_t, shift_n) = DecodeImmShift(type, imm5);
    if n == 15 || n == t || m == 15 then UNPREDICTABLE;
    if ArchVersion() < 6 && m == n then UNPREDICTABLE;"""
} , {
    "name" : "SUB (immediate, Thumb)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUBS <Rd>, <Rn>, #<imm3>:SUB<c> <Rd>, <Rn>, #<imm3>",
    "pattern" : "0 0 0 1 1 1 1 imm3#3 Rn#3 Rd#3",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); setflags = !InITBlock(); imm32 = ZeroExtend(imm3, 32);"""
} , {
    "name" : "SUB (immediate, Thumb)",
    "encoding" : "T2",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUBS <Rdn>, #<imm8>:SUB<c> <Rdn>, #<imm8>",
    "pattern" : "0 0 1 1 1 Rdn#3 imm8#8",
    "decoder" : """d = UInt(Rdn); n = UInt(Rdn); setflags = !InITBlock(); imm32 = ZeroExtend(imm8, 32);"""
} , {
    "name" : "SUB (immediate, Thumb)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SUB{S}<c>.W <Rd>, <Rn>, #<const>",
    "pattern" : "1 1 1 1 0 i#1 0 1 1 0 1 S#1 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rd == '1111' && S == '1' then SEE CMP (immediate);
    if Rn == '1101' then SEE SUB (SP minus immediate);
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ThumbExpandImm(i:imm3:imm8);
    if d == 13 || (d == 15 && S == '0') || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SUB (immediate, Thumb)",
    "encoding" : "T4",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SUBW<c> <Rd>, <Rn>, #<imm12>",
    "pattern" : "1 1 1 1 0 i#1 1 0 1 0 1 0 Rn#4 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rn == '1111' then SEE ADR;
    if Rn == '1101' then SEE SUB (SP minus immediate);
    d = UInt(Rd); n = UInt(Rn); setflags = FALSE; imm32 = ZeroExtend(i:imm3:imm8, 32);
    if d IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SUB (immediate, ARM)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUB{S}<c> <Rd>, <Rn>, #<const>",
    "pattern" : "cond#4 0 0 1 0 0 1 0 S#1 Rn#4 Rd#4 imm12#12",
    "decoder" : """if Rn == '1111' && S == '0' then SEE ADR;
    if Rn == '1101' then SEE SUB (SP minus immediate);
    if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); n = UInt(Rn); setflags = (S == '1'); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "SUB (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUBS <Rd>, <Rn>, <Rm>:SUB<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "0 0 0 1 1 0 1 Rm#3 Rn#3 Rd#3",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = !InITBlock(); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "SUB (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SUB{S}<c>.W <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "1 1 1 0 1 0 1 1 1 0 1 S#1 Rn#4 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE CMP (register);
    if Rn == '1101' then SEE SUB (SP minus register);
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d == 13 || (d == 15 && S == '0') || n == 15 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SUB (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUB{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0 0 0 0 0 1 0 S#1 Rn#4 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    if Rn == '1101' then SEE SUB (SP minus register);
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1'); (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "SUB (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUB{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0 0 0 0 0 1 0 S#1 Rn#4 Rd#4 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); s = UInt(Rs); setflags = (S == '1'); shift_t = DecodeRegShift(type);
    if d == 15 || n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SUB (SP minus immediate)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUB<c> SP, SP, #<imm32>",
    "pattern" : "1 0 1 1 0 0 0 0 1 imm7#7",
    "decoder" : """d = 13; setflags = FALSE; imm32 = ZeroExtend(imm7:'00', 32);"""
} , {
    "name" : "SUB (SP minus immediate)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SUB{S}<c>.W <Rd>, SP, #<const>",
    "pattern" : "1 1 1 1 0 i#1 0 1 1 0 1 S#1 1 1 0 1 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """if Rd == '1111' && S == '1' then SEE CMP (immediate);
    d = UInt(Rd); setflags = (S == '1'); imm32 = ThumbExpandImm(i:imm3:imm8);
    if d == 15 && S == '0' then UNPREDICTABLE;"""
} , {
    "name" : "SUB (SP minus immediate)",
    "encoding" : "T3",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SUBW<c> <Rd>, SP, #<imm12>",
    "pattern" : "1 1 1 1 0 i#1 1 0 1 0 1 0 1 1 0 1 0 imm3#3 Rd#4 imm8#8",
    "decoder" : """d = UInt(Rd); setflags = FALSE; imm32 = ZeroExtend(i:imm3:imm8, 32);
    if d == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SUB (SP minus immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUB{S}<c> <Rd>, SP, #<const>",
    "pattern" : "cond#4 0 0 1 0 0 1 0 S#1 1 1 0 1 Rd#4 imm12#12",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); setflags = (S == '1'); imm32 = ARMExpandImm(imm12);"""
} , {
    "name" : "SUB (SP minus register)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SUB{S}<c> <Rd>, SP, <Rm>{, <shift>}",
    "pattern" : "1 1 1 0 1 0 1 1 1 0 1 S#1 1 1 0 1 0 imm3#3 Rd#4 imm2#2 type#2 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE CMP (register);
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if d == 13 && (shift_t != SRType_LSL || shift_n > 3) then UNPREDICTABLE;
    if (d == 15 && S == '0') || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SUB (SP minus register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SUB{S}<c> <Rd>, SP, <Rm>{, <shift>}",
    "pattern" : "cond#4 0 0 0 0 0 1 0 S#1 1 1 0 1 Rd#4 imm5#5 type#2 0 Rm#4",
    "decoder" : """if Rd == '1111' && S == '1' then SEE SUBS PC, LR and related instructions;
    d = UInt(Rd); m = UInt(Rm); setflags = (S == '1');
    (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "SVC",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SVC<c> #<imm8>",
    "pattern" : "1 1 0 1 1 1 1 1 imm8#8",
    "decoder" : """imm32 = ZeroExtend(imm8, 32);"""
} , {
    "name" : "SVC",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "SVC<c> #<imm24>",
    "pattern" : "cond#4 1 1 1 1 imm24#24",
    "decoder" : """imm32 = ZeroExtend(imm24, 32);"""
} , {
    "name" : "SWP, SWPB",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv7, ARMv7VE",
    "format" : "SWP{B}<c> <Rt>, <Rt2>, [<Rn>]",
    "pattern" : "cond#4 0 0 0 1 0 B#1 0 0 Rn#4 Rt#4 0 0 0 0 1 0 0 1 Rt2#4",
    "decoder" : """t = UInt(Rt); t2 = UInt(Rt2); n = UInt(Rn); size = if B == '1' then 1 else 4;
    if t == 15 || t2 == 15 || n == 15 || n == t || n == t2 then UNPREDICTABLE;"""
} , {
    "name" : "SXTAB",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SXTAB<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 1 0 0 Rn#4 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE SXTB;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || n == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SXTAB",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SXTAB<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 0 1 0 Rn#4 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """if Rn == '1111' then SEE SXTB;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SXTAB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SXTAB16<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 0 1 0 Rn#4 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE SXTB16;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || n == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SXTAB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SXTAB16<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 0 0 0 Rn#4 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """if Rn == '1111' then SEE SXTB16;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SXTAH",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SXTAH<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 0 0 0 Rn#4 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE SXTH;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || n == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SXTAH",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SXTAH<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 0 1 1 Rn#4 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """if Rn == '1111' then SEE SXTH;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SXTB",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SXTB<c> <Rd>, <Rm>",
    "pattern" : "1 0 1 1 0 0 1 0 0 1 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = 0;"""
} , {
    "name" : "SXTB",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SXTB<c>.W <Rd>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 1 0 0 1 1 1 1 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SXTB",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SXTB<c> <Rd>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 0 1 0 1 1 1 1 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SXTB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SXTB16<c> <Rd>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 0 1 0 1 1 1 1 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SXTB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SXTB16<c> <Rd>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 0 0 0 1 1 1 1 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SXTH",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SXTH<c> <Rd>, <Rm>",
    "pattern" : "1 0 1 1 0 0 1 0 0 0 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = 0;"""
} , {
    "name" : "SXTH",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SXTH<c>.W <Rd>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 0 0 0 1 1 1 1 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "SXTH",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SXTH<c> <Rd>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 0 1 1 1 1 1 1 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "TBB, TBH",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "TBB<c> [<Rn>, <Rm>]:TBH<c> [<Rn>, <Rm>, LSL #1]",
    "pattern" : "1 1 1 0 1 0 0 0 1 1 0 1 Rn#4 1 1 1 1 0 0 0 0 0 0 0 H#1 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); is_tbh = (H == '1');
    if n == 13 || m IN {13,15} then UNPREDICTABLE;
    if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "TEQ (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "TEQ<c> <Rn>, #<const>",
    "pattern" : "1 1 1 1 0 i#1 0 0 1 0 0 1 Rn#4 0 imm3#3 1 1 1 1 imm8#8",
    "decoder" : """n = UInt(Rn);
    (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "TEQ (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "TEQ<c> <Rn>, #<const>",
    "pattern" : "cond#4 0 0 1 1 0 0 1 1 Rn#4 0 0 0 0 imm12#12",
    "decoder" : """n = UInt(Rn);
    (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);"""
} , {
    "name" : "TEQ (register)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "TEQ<c> <Rn>, <Rm>{, <shift>}",
    "pattern" : "1 1 1 0 1 0 1 0 1 0 0 1 Rn#4 0 imm3#3 1 1 1 1 imm2#2 type#2 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "TEQ (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "TEQ<c> <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0 0 0 1 0 0 1 1 Rn#4 0 0 0 0 imm5#5 type#2 0 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "TEQ (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "TEQ<c> <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0 0 0 1 0 0 1 1 Rn#4 0 0 0 0 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); s = UInt(Rs);
    shift_t = DecodeRegShift(type);
    if n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "TST (immediate)",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "TST<c> <Rn>, #<const>",
    "pattern" : "1 1 1 1 0 i#1 0 0 0 0 0 1 Rn#4 0 imm3#3 1 1 1 1 imm8#8",
    "decoder" : """n = UInt(Rn);
    (imm32, carry) = ThumbExpandImm_C(i:imm3:imm8, APSR.C);
    if n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "TST (immediate)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "TST<c> <Rn>, #<const>",
    "pattern" : "cond#4 0 0 1 1 0 0 0 1 Rn#4 0 0 0 0 imm12#12",
    "decoder" : """n = UInt(Rn);
    (imm32, carry) = ARMExpandImm_C(imm12, APSR.C);"""
} , {
    "name" : "TST (register)",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "TST<c> <Rn>, <Rm>",
    "pattern" : "0 1 0 0 0 0 1 0 0 0 Rm#3 Rn#3",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); (shift_t, shift_n) = (SRType_LSL, 0);"""
} , {
    "name" : "TST (register)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "TST<c>.W <Rn>, <Rm>{, <shift>}",
    "pattern" : "1 1 1 0 1 0 1 0 0 0 0 1 Rn#4 0 imm3#3 1 1 1 1 imm2#2 type#2 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = DecodeImmShift(type, imm3:imm2);
    if n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "TST (register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "TST<c> <Rn>, <Rm>{, <shift>}",
    "pattern" : "cond#4 0 0 0 1 0 0 0 1 Rn#4 0 0 0 0 imm5#5 type#2 0 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm);
    (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , {
    "name" : "TST (register-shifted register)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "TST<c> <Rn>, <Rm>, <type> <Rs>",
    "pattern" : "cond#4 0 0 0 1 0 0 0 1 Rn#4 0 0 0 0 Rs#4 0 type#2 1 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); s = UInt(Rs);
    shift_t = DecodeRegShift(type);
    if n == 15 || m == 15 || s == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UADD16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 1 Rn#4 1 1 1 1 Rd#4 0 1 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UADD16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 0 1 Rn#4 Rd#4 1 1 1 1 0 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UADD8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 0 Rn#4 1 1 1 1 Rd#4 0 1 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UADD8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 0 1 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UASX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 1 0 Rn#4 1 1 1 1 Rd#4 0 1 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UASX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 0 1 Rn#4 Rd#4 1 1 1 1 0 0 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UBFX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UBFX<c> <Rd>, <Rn>, #<lsb>, #<widthminus1>",
    "pattern" : "1 1 1 1 0 0 1 1 1 1 0 0 Rn#4 0 imm3#3 Rd#4 imm2#2 0 widthm1#5",
    "decoder" : """d = UInt(Rd); n = UInt(Rn);
    lsbit = UInt(imm3:imm2); widthminus1 = UInt(widthm1);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UBFX",
    "encoding" : "A1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UBFX<c> <Rd>, <Rn>, #<lsb>, #<widthminus1>",
    "pattern" : "cond#4 0 1 1 1 1 1 1 widthm1#5 Rd#4 lsb#5 1 0 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn);
    lsbit = UInt(lsb); widthminus1 = UInt(widthm1);
    if d == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UDF",
    "encoding" : "T1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6, ARMv7",
    "format" : "UDF<c> #<imm8>",
    "pattern" : "1 1 0 1 1 1 1 0 imm8#8",
    "decoder" : """imm32 = ZeroExtend(imm8, 32);"""
} , {
    "name" : "UDF",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UDF<c>.W #<imm32>",
    "pattern" : "1 1 1 1 0 1 1 1 1 1 1 1 imm4#4 1 0 1 0 imm12#12",
    "decoder" : """imm32 = ZeroExtend(imm4:imm12, 32);"""
} , {
    "name" : "UDF",
    "encoding" : "A1",
    "version" : "ARMv4T, ARMv5TAll, ARMv6, ARMv7",
    "format" : "UDF<c> #<imm32>",
    "pattern" : "1 1 1 0 0 1 1 1 1 1 1 1 imm12#12 1 1 1 1 imm4#4",
    "decoder" : """imm32 = ZeroExtend(imm12:imm4, 32);"""
} , {
    "name" : "UDIV",
    "encoding" : "T1",
    "version" : "ARMv7R, ARMv7VE",
    "format" : "UDIV<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 0 1 1 Rn#4 1 1 1 1 Rd#4 1 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UDIV",
    "encoding" : "A1",
    "version" : "ARMv7VE",
    "format" : "UDIV<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 1 0 0 1 1 Rd#4 1 1 1 1 Rm#4 0 0 0 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UHADD16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UHADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 1 Rn#4 1 1 1 1 Rd#4 0 1 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UHADD16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UHADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 1 Rn#4 Rd#4 1 1 1 1 0 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UHADD8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UHADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 0 Rn#4 1 1 1 1 Rd#4 0 1 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UHADD8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UHADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 1 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UHASX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UHASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 1 0 Rn#4 1 1 1 1 Rd#4 0 1 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UHASX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UHASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 1 Rn#4 Rd#4 1 1 1 1 0 0 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UHSAX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UHSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 1 0 Rn#4 1 1 1 1 Rd#4 0 1 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UHSAX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UHSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 1 Rn#4 Rd#4 1 1 1 1 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UHSUB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UHSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 1 Rn#4 1 1 1 1 Rd#4 0 1 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UHSUB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UHSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 1 Rn#4 Rd#4 1 1 1 1 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UHSUB8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UHSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 0 Rn#4 1 1 1 1 Rd#4 0 1 1 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UHSUB8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UHSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 1 Rn#4 Rd#4 1 1 1 1 1 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UMAAL",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UMAAL<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 1 1 0 Rn#4 RdLo#4 RdHi#4 0 1 1 0 Rm#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm);
    if dLo IN {13,15} || dHi IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "UMAAL",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UMAAL<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 0 0 0 0 1 0 0 RdHi#4 RdLo#4 Rm#4 1 0 0 1 Rn#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm);
    if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "UMLAL",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UMLAL<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 1 1 0 Rn#4 RdLo#4 RdHi#4 0 0 0 0 Rm#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); setflags = FALSE;
    if dLo IN {13,15} || dHi IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "UMLAL",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "UMLAL{S}<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 0 0 0 1 0 1 S#1 RdHi#4 RdLo#4 Rm#4 1 0 0 1 Rn#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;
    if ArchVersion() < 6 && (dHi == n || dLo == n) then UNPREDICTABLE;"""
} , {
    "name" : "UMULL",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UMULL<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 1 0 1 0 Rn#4 RdLo#4 RdHi#4 0 0 0 0 Rm#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); setflags = FALSE;
    if dLo IN {13,15} || dHi IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;"""
} , {
    "name" : "UMULL",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "UMULL{S}<c> <RdLo>, <RdHi>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 0 0 0 1 0 0 S#1 RdHi#4 RdLo#4 Rm#4 1 0 0 1 Rn#4",
    "decoder" : """dLo = UInt(RdLo); dHi = UInt(RdHi); n = UInt(Rn); m = UInt(Rm); setflags = (S == '1');
    if dLo == 15 || dHi == 15 || n == 15 || m == 15 then UNPREDICTABLE;
    if dHi == dLo then UNPREDICTABLE;
    if ArchVersion() < 6 && (dHi == n || dLo == n) then UNPREDICTABLE;"""
} , {
    "name" : "UQADD16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UQADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 1 Rn#4 1 1 1 1 Rd#4 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UQADD16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UQADD16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 0 Rn#4 Rd#4 1 1 1 1 0 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UQADD8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UQADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 0 0 Rn#4 1 1 1 1 Rd#4 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UQADD8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UQADD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 0 Rn#4 Rd#4 1 1 1 1 1 0 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UQASX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UQASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 0 1 0 Rn#4 1 1 1 1 Rd#4 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UQASX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UQASX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 0 Rn#4 Rd#4 1 1 1 1 0 0 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UQSAX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UQSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 1 0 Rn#4 1 1 1 1 Rd#4 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UQSAX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UQSAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 0 Rn#4 Rd#4 1 1 1 1 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UQSUB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UQSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 1 Rn#4 1 1 1 1 Rd#4 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UQSUB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UQSUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 0 Rn#4 Rd#4 1 1 1 1 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UQSUB8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UQSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 0 Rn#4 1 1 1 1 Rd#4 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UQSUB8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UQSUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 1 0 Rn#4 Rd#4 1 1 1 1 1 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "USAD8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "USAD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 1 0 1 1 1 Rn#4 1 1 1 1 Rd#4 0 0 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "USAD8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "USAD8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 1 1 0 0 0 Rd#4 1 1 1 1 Rm#4 0 0 0 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "USADA8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "USADA8<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "1 1 1 1 1 0 1 1 0 1 1 1 Rn#4 Ra#4 Rd#4 0 0 0 0 Rm#4",
    "decoder" : """if Ra == '1111' then SEE USAD8;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} || a == 13 then UNPREDICTABLE;"""
} , {
    "name" : "USADA8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "USADA8<c> <Rd>, <Rn>, <Rm>, <Ra>",
    "pattern" : "cond#4 0 1 1 1 1 0 0 0 Rd#4 Ra#4 Rm#4 0 0 0 1 Rn#4",
    "decoder" : """if Ra == '1111' then SEE USAD8;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); a = UInt(Ra);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "USAT",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "USAT<c> <Rd>, #<saturate_to>, <Rn>{, <shift>}",
    "pattern" : "1 1 1 1 0 0 1 1 1 0 sh#1 0 Rn#4 0 imm3#3 Rd#4 imm2#2 0 sat_imm#5",
    "decoder" : """if sh == '1' && (imm3:imm2) == '00000' then SEE USAT16;
    d = UInt(Rd); n = UInt(Rn); saturate_to = UInt(sat_imm); (shift_t, shift_n) = DecodeImmShift(sh:'0', imm3:imm2);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "USAT",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "USAT<c> <Rd>, #<saturate_to>, <Rn>{, <shift>}",
    "pattern" : "cond#4 0 1 1 0 1 1 1 sat_imm#5 Rd#4 imm5#5 sh#1 0 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); saturate_to = UInt(sat_imm); (shift_t, shift_n) = DecodeImmShift(sh:'0', imm5);
    if d == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "USAT16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "USAT16<c> <Rd>, #<saturate_to>, <Rn>",
    "pattern" : "1 1 1 1 0 0 1 1 1 0 1 0 Rn#4 0 0 0 0 Rd#4 0 0 0 0 sat_imm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); saturate_to = UInt(sat_imm);
    if d IN {13,15} || n IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "USAT16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "USAT16<c> <Rd>, #<saturate_to>, <Rn>",
    "pattern" : "cond#4 0 1 1 0 1 1 1 0 sat_imm#4 Rd#4 1 1 1 1 0 0 1 1 Rn#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); saturate_to = UInt(sat_imm);
    if d == 15 || n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "USAX",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "USAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 1 0 Rn#4 1 1 1 1 Rd#4 0 1 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "USAX",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "USAX<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 0 1 Rn#4 Rd#4 1 1 1 1 0 1 0 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "USUB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "USUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 1 Rn#4 1 1 1 1 Rd#4 0 1 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "USUB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "USUB16<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 0 1 Rn#4 Rd#4 1 1 1 1 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "USUB8",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "USUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "1 1 1 1 1 0 1 0 1 1 0 0 Rn#4 1 1 1 1 Rd#4 0 1 0 0 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d IN {13,15} || n IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "USUB8",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "USUB8<c> <Rd>, <Rn>, <Rm>",
    "pattern" : "cond#4 0 1 1 0 0 1 0 1 Rn#4 Rd#4 1 1 1 1 1 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); n = UInt(Rn); m = UInt(Rm);
    if d == 15 || n == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UXTAB",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UXTAB<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 1 0 1 Rn#4 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE UXTB;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || n == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UXTAB",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UXTAB<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 1 1 0 Rn#4 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """if Rn == '1111' then SEE UXTB;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UXTAB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UXTAB16<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 0 1 1 Rn#4 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE UXTB16;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || n == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UXTAB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UXTAB16<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 1 0 0 Rn#4 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """if Rn == '1111' then SEE UXTB16;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UXTAH",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UXTAH<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 0 0 1 Rn#4 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """if Rn == '1111' then SEE UXTH;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || n == 13 || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UXTAH",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UXTAH<c> <Rd>, <Rn>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 1 1 1 Rn#4 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """if Rn == '1111' then SEE UXTH;
    d = UInt(Rd); n = UInt(Rn); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UXTB",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UXTB<c> <Rd>, <Rm>",
    "pattern" : "1 0 1 1 0 0 1 0 1 1 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = 0;"""
} , {
    "name" : "UXTB",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UXTB<c>.W <Rd>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 1 0 1 1 1 1 1 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UXTB",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UXTB<c> <Rd>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 1 1 0 1 1 1 1 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UXTB16",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UXTB16<c> <Rd>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 0 1 1 1 1 1 1 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UXTB16",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UXTB16<c> <Rd>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 1 0 0 1 1 1 1 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "UXTH",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UXTH<c> <Rd>, <Rm>",
    "pattern" : "1 0 1 1 0 0 1 0 1 0 Rm#3 Rd#3",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = 0;"""
} , {
    "name" : "UXTH",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "UXTH<c>.W <Rd>, <Rm>{, <rotation>}",
    "pattern" : "1 1 1 1 1 0 1 0 0 0 0 1 1 1 1 1 1 1 1 1 Rd#4 1 0 rotate#2 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d IN {13,15} || m IN {13,15} then UNPREDICTABLE;"""
} , {
    "name" : "UXTH",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "UXTH<c> <Rd>, <Rm>{, <rotation>}",
    "pattern" : "cond#4 0 1 1 0 1 1 1 1 1 1 1 1 Rd#4 rotate#2 0 0 0 1 1 1 Rm#4",
    "decoder" : """d = UInt(Rd); m = UInt(Rm); rotation = UInt(rotate:'000');
    if d == 15 || m == 15 then UNPREDICTABLE;"""
} , {
    "name" : "VABA, VABAL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 1 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = FALSE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VABA, VABAL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 1 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = FALSE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VABA, VABAL",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "VABAL<c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 1 0 1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = TRUE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = 1;"""
} , {
    "name" : "VABA, VABAL",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "VABAL<c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 size#2 Vn#4 Vd#4 0 1 0 1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = TRUE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = 1;"""
} , {
    "name" : "VABD, VABDL (integer)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 1 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = FALSE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VABD, VABDL (integer)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 1 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = FALSE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VABD, VABDL (integer)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "VABDL<c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 1 1 1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = TRUE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = 1;"""
} , {
    "name" : "VABD, VABDL (integer)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "VABDL<c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 size#2 Vn#4 Vd#4 0 1 1 1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = TRUE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = 1;"""
} , {
    "name" : "VABD (floating-point)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 1 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VABD (floating-point)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 1 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VABS",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 1 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    advsimd = TRUE; floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VABS",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 1 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    advsimd = TRUE; floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VABS",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 0 0 0 0 Vd#4 1 0 1 sz#1 1 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VABS",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 0 0 0 0 Vd#4 1 0 1 sz#1 1 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VACGE, VACGT, VACLE, VACLT",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 1 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    or_equal = (op == '0'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VACGE, VACGT, VACLE, VACLT",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 1 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    or_equal = (op == '0'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VADD",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VADD",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 size#2 Vn#4 Vd#4 1 0 0 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VADD (floating-point)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VADD (floating-point)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VADD (floating-point)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 0 D#1 1 1 Vn#4 Vd#4 1 0 1 sz#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VADD (floating-point)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 0 D#1 1 1 Vn#4 Vd#4 1 0 1 sz#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VADDHN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VADDHN<c>.<dt> <Dd>, <Qn>, <Qm>",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 1 0 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize; d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VADDHN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VADDHN<c>.<dt> <Dd>, <Qn>, <Qm>",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 size#2 Vn#4 Vd#4 0 1 0 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize; d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VADDL, VADDW",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 0 0 op#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' || (op == '1' && Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize; is_vaddw = (op == '1'); d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VADDL, VADDW",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 size#2 Vn#4 Vd#4 0 0 0 op#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' || (op == '1' && Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize; is_vaddw = (op == '1'); d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VAND (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 0 0 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VAND (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 0 0 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VBIC (immediate)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 i#1 1 1 1 1 1 D#1 0 0 0 imm3#3 Vd#4 cmode#4 0 Q#1 1 1 imm4#4",
    "decoder" : """if cmode<0> == '0' || cmode<3:2> == '11' then SEE "Related encodings";
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    imm64 = AdvSIMDExpandImm('1', cmode, i:imm3:imm4);
    d = UInt(D:Vd); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VBIC (immediate)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 i#1 1 D#1 0 0 0 imm3#3 Vd#4 cmode#4 0 Q#1 1 1 imm4#4",
    "decoder" : """if cmode<0> == '0' || cmode<3:2> == '11' then SEE "Related encodings";
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    imm64 = AdvSIMDExpandImm('1', cmode, i:imm3:imm4);
    d = UInt(D:Vd); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VBIC (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 0 1 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VBIC (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 0 1 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VBIF, VBIT, VBSL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 op#2 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if op == '00' then SEE VEOR;
    if op == '01' then operation = VBitOps_VBSL;
    if op == '10' then operation = VBitOps_VBIT;
    if op == '11' then operation = VBitOps_VBIF;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VBIF, VBIT, VBSL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 op#2 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if op == '00' then SEE VEOR;
    if op == '01' then operation = VBitOps_VBSL;
    if op == '10' then operation = VBitOps_VBIT;
    if op == '11' then operation = VBitOps_VBIF;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCEQ (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    int_operation = TRUE; esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCEQ (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    int_operation = TRUE; esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCEQ (register)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 1 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    int_operation = FALSE; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCEQ (register)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 1 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    int_operation = FALSE; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCEQ (immediate #0)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 0 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCEQ (immediate #0)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 0 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGE (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 0 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    type = if U == '1' then VCGEtype_unsigned else VCGEtype_signed;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGE (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 0 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    type = if U == '1' then VCGEtype_unsigned else VCGEtype_signed;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGE (register)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 1 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    type = VCGEtype_fp; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGE (register)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 1 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    type = VCGEtype_fp; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGE (immediate #0)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 0 0 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGE (immediate #0)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 0 0 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGT (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 0 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    type = if U == '1' then VCGTtype_unsigned else VCGTtype_signed;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGT (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 0 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    type = if U == '1' then VCGTtype_unsigned else VCGTtype_signed;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGT (register)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 1 sz#1 Vn#4 Vd#4 1 1 1 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    type = VCGTtype_fp; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGT (register)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 1 sz#1 Vn#4 Vd#4 1 1 1 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    type = VCGTtype_fp; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGT (immediate #0)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 0 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCGT (immediate #0)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 0 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCLE (immediate #0)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 0 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCLE (immediate #0)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 0 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCLS",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 0 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCLS",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 0 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCLT (immediate #0)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 1 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCLT (immediate #0)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 1 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCLZ",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 0 0 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCLZ",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 0 0 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCMP, VCMPE",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 0 1 0 0 Vd#4 1 0 1 sz#1 E#1 1 M#1 0 Vm#4",
    "decoder" : """dp_operation = (sz == '1'); quiet_nan_exc = (E == '1'); with_zero = FALSE; d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VCMP, VCMPE",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 0 1 0 0 Vd#4 1 0 1 sz#1 E#1 1 M#1 0 Vm#4",
    "decoder" : """dp_operation = (sz == '1'); quiet_nan_exc = (E == '1'); with_zero = FALSE; d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VCMP, VCMPE",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 0 1 0 1 Vd#4 1 0 1 sz#1 E#1 1 0 0 0 0 0 0",
    "decoder" : """dp_operation = (sz == '1'); quiet_nan_exc = (E == '1'); with_zero = TRUE; d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);"""
} , {
    "name" : "VCMP, VCMPE",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 0 1 0 1 Vd#4 1 0 1 sz#1 E#1 1 0 0 0 0 0 0",
    "decoder" : """dp_operation = (sz == '1'); quiet_nan_exc = (E == '1'); with_zero = TRUE; d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);"""
} , {
    "name" : "VCNT",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 0 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size != '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8; elements = 8;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCNT",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 0 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size != '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8; elements = 8;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCVT (between floating-point and integer, AdvancedSIMD)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "111111111 D#1 11 size#2 11 Vd#4 011 op#2 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size != '10' then UNDEFINED;
    to_integer = (op<1> == '1'); unsigned_ = (op<0> == '1'); esize = 32; elements = 2;
    if to_integer then
        round_zero = TRUE;
    else
        round_nearest = TRUE;
    endif
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCVT (between floating-point and integer, AdvancedSIMD)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "111100111 D#1 11 size#2 11 Vd#4 011 op#2 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size != '10' then UNDEFINED;
    to_integer = (op<1> == '1'); unsigned_ = (op<0> == '1'); esize = 32; elements = 2;
    if to_integer then
        round_zero = TRUE;
    else
        round_nearest = TRUE;
    endif
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCVT, VCVTR (between floating-point and integer, Floating-point)",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 1 opc2#3 Vd#4 1 0 1 sz#1 op#1 1 M#1 0 Vm#4",
    "decoder" : """if opc2 != '000' && !(opc2 IN "10x") then SEE "Related encodings";
    to_integer = (opc2<2> == '1'); dp_operation = (sz == 1);
    if to_integer then
        unsigned_ = (opc2<0> == '0');
        round_zero = (op == '1');
        d = UInt(Vd:D);
        m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);
    else
        unsigned_ = (op == '0');
        round_nearest = FALSE;
        m = UInt(Vm:M);
        d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    endif"""
} , {
    "name" : "VCVT, VCVTR (between floating-point and integer, Floating-point)",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 1 opc2#3 Vd#4 1 0 1 sz#1 op#1 1 M#1 0 Vm#4",
    "decoder" : """if opc2 != '000' && !(opc2 IN "10x") then SEE "Related encodings";
    to_integer = (opc2<2> == '1'); dp_operation = (sz == 1);
    if to_integer then
        unsigned_ = (opc2<0> == '0');
        round_zero = (op == '1');
        d = UInt(Vd:D);
        m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);
    else
        unsigned_ = (op == '0');
        round_nearest = FALSE;
        m = UInt(Vm:M);
        d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    endif"""
} , {
    "name" : "VCVT (between floating-point and fixed-point, AdvancedSIMD)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 1 1 1 op#1 0 Q#1 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if imm6 IN "0xxxxx" then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    to_fixed = (op == '1'); unsigned_ = (U == '1');
    if to_fixed then
        round_zero = TRUE;
    else
        round_nearest = TRUE;
    endif
    esize = 32; frac_bits = 64 - UInt(imm6); elements = 2;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCVT (between floating-point and fixed-point, AdvancedSIMD)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 1 1 1 op#1 0 Q#1 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if imm6 IN "0xxxxx" then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    to_fixed = (op == '1'); unsigned_ = (U == '1');
    if to_fixed then
        round_zero = TRUE;
    else
        round_nearest = TRUE;
    endif
    esize = 32; frac_bits = 64 - UInt(imm6); elements = 2;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VCVT (between floating-point and fixed-point, Floating-point)",
    "encoding" : "T1",
    "version" : "VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 1 op#1 1 U#1 Vd#4 1 0 1 sf#1 sx#1 1 i#1 0 imm4#4",
    "decoder" : """to_fixed = (op == '1');
    dp_operation = (sf == '1');
    unsigned_ = (U == '1');
    size = if sx == '0' then 16 else 32;
    frac_bits = size - UInt(imm4:i);
    if to_fixed then
        round_zero = TRUE;
    else
        round_nearest = TRUE;
    endif
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    if frac_bits < 0 then UNPREDICTABLE;"""
} , {
    "name" : "VCVT (between floating-point and fixed-point, Floating-point)",
    "encoding" : "A1",
    "version" : "VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 1 op#1 1 U#1 Vd#4 1 0 1 sf#1 sx#1 1 i#1 0 imm4#4",
    "decoder" : """to_fixed = (op == '1');
    dp_operation = (sf == '1');
    unsigned_ = (U == '1');
    size = if sx == '0' then 16 else 32;
    frac_bits = size - UInt(imm4:i);
    if to_fixed then
        round_zero = TRUE;
    else
        round_nearest = TRUE;
    endif
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    if frac_bits < 0 then UNPREDICTABLE;"""
} , {
    "name" : "VCVT (between double-precision and single-precision)",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 0 1 1 1 Vd#4 1 0 1 sz#1 1 1 M#1 0 Vm#4",
    "decoder" : """double_to_single = (sz == '1');
    d = if double_to_single then UInt(Vd:D) else UInt(D:Vd);
    m = if double_to_single then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VCVT (between double-precision and single-precision)",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 0 1 1 1 Vd#4 1 0 1 sz#1 1 1 M#1 0 Vm#4",
    "decoder" : """double_to_single = (sz == '1');
    d = if double_to_single then UInt(Vd:D) else UInt(D:Vd);
    m = if double_to_single then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VCVT (between half-precision and single-precision, AdvancedSIMD)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 1 1 op#1 0 0 M#1 0 Vm#4",
    "decoder" : """half_to_single = (op == '1');
    if size != '01' then UNDEFINED;
    if half_to_single && Vd<0> == '1' then UNDEFINED;
    if !half_to_single && Vm<0> == '1' then UNDEFINED;
    esize = 16; elements = 4;
    m = UInt(M:Vm); d = UInt(D:Vd);"""
} , {
    "name" : "VCVT (between half-precision and single-precision, AdvancedSIMD)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 1 1 op#1 0 0 M#1 0 Vm#4",
    "decoder" : """half_to_single = (op == '1');
    if size != '01' then UNDEFINED;
    if half_to_single && Vd<0> == '1' then UNDEFINED;
    if !half_to_single && Vm<0> == '1' then UNDEFINED;
    esize = 16; elements = 4;
    m = UInt(M:Vm); d = UInt(D:Vd);"""
} , {
    "name" : "VCVTB, VCVTT",
    "encoding" : "T1",
    "version" : "VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 0 0 1 op#1 Vd#4 1 0 1 0 T#1 1 M#1 0 Vm#4",
    "decoder" : """half_to_single = (op == '0');
    lowbit = if T == '1' then 16 else 0; m = UInt(Vm:M); d = UInt(Vd:D);"""
} , {
    "name" : "VCVTB, VCVTT",
    "encoding" : "A1",
    "version" : "VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 0 0 1 op#1 Vd#4 1 0 1 0 T#1 1 M#1 0 Vm#4",
    "decoder" : """half_to_single = (op == '0');
    lowbit = if T == '1' then 16 else 0; m = UInt(Vm:M); d = UInt(Vd:D);"""
} , {
    "name" : "VDIV",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 0 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VDIV",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 0 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VDUP (scalar)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 imm4#4 Vd#4 1 1 0 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if imm4 IN "x000" then UNDEFINED;
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    case imm4 of
        when "xxx1" esize = 8; elements = 8; index = UInt(imm4<3:1>);
        when "xx10" esize = 16; elements = 4; index = UInt(imm4<3:2>);
        when "x100" esize = 32; elements = 2; index = UInt(imm4<3>);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VDUP (scalar)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 imm4#4 Vd#4 1 1 0 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if imm4 IN "x000" then UNDEFINED;
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    case imm4 of
        when "xxx1" esize = 8; elements = 8; index = UInt(imm4<3:1>);
        when "xx10" esize = 16; elements = 4; index = UInt(imm4<3:2>);
        when "x100" esize = 32; elements = 2; index = UInt(imm4<3>);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VDUP (ARM core register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 b#1 Q#1 0 Vd#4 Rt#4 1 0 1 1 D#1 0 e#1 1 0 0 0 0",
    "decoder" : """if Q == '1' && Vd<0> == '1' then UNDEFINED;
    d = UInt(D:Vd); t = UInt(Rt);
    regs = if Q == '0' then 1 else 2;
    case b:e of
        when '00' esize = 32; elements = 2;
        when '01' esize = 16; elements = 4;
        when '10' esize = 8; elements = 8;
        when '11' UNDEFINED;
    endcase
    if t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) then UNPREDICTABLE;"""
} , {
    "name" : "VDUP (ARM core register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 b#1 Q#1 0 Vd#4 Rt#4 1 0 1 1 D#1 0 e#1 1 0 0 0 0",
    "decoder" : """if Q == '1' && Vd<0> == '1' then UNDEFINED;
    d = UInt(D:Vd); t = UInt(Rt);
    regs = if Q == '0' then 1 else 2;
    case b:e of
        when '00' esize = 32; elements = 2;
        when '01' esize = 16; elements = 4;
        when '10' esize = 8; elements = 8;
        when '11' UNDEFINED;
    endcase
    if t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) then UNPREDICTABLE;"""
} , {
    "name" : "VEOR",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 0 0 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VEOR",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 0 0 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VEXT",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 1 1 Vn#4 Vd#4 imm4#4 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if Q == '0' && imm4<3> == '1' then UNDEFINED;
    quadword_operation = (Q == '1'); position = 8 * UInt(imm4);
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VEXT",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 1 1 Vn#4 Vd#4 imm4#4 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if Q == '0' && imm4<3> == '1' then UNDEFINED;
    quadword_operation = (Q == '1'); position = 8 * UInt(imm4);
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VFMA, VFMS",
    "encoding" : "T1",
    "version" : "AdvancedSIMDv2",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; op1_neg = (op == '1'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VFMA, VFMS",
    "encoding" : "A1",
    "version" : "AdvancedSIMDv2",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; op1_neg = (op == '1'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VFMA, VFMS",
    "encoding" : "T2",
    "version" : "VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then UNPREDICTABLE;
    advsimd = FALSE; dp_operation = (sz == '1'); op1_neg = (op == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VFMA, VFMS",
    "encoding" : "A2",
    "version" : "VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then UNPREDICTABLE;
    advsimd = FALSE; dp_operation = (sz == '1'); op1_neg = (op == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VFNMA, VFNMS",
    "encoding" : "T1",
    "version" : "VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 0 1 Vn#4 Vd#4 1 0 1 sz#1 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then UNPREDICTABLE;
    op1_neg = (op == '1');
    dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N); m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VFNMA, VFNMS",
    "encoding" : "A1",
    "version" : "VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 0 1 Vn#4 Vd#4 1 0 1 sz#1 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then UNPREDICTABLE;
    op1_neg = (op == '1');
    dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VHADD, VHSUB",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 0 op#1 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    add = (op == '0'); unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VHADD, VHSUB",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 0 op#1 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    add = (op == '0'); unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VLD1 (multiple single elements)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 0 D#1 1 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """case type of
    when '0111'
        regs = 1;
        if align<1> == '1' then UNDEFINED;
    when '1010'
        regs = 2;
        if align == '11' then UNDEFINED;
    when '0110'
        regs = 3;
        if align<1> == '1' then UNDEFINED;
    when '0010'
        regs = 4;
    otherwise
        SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLD1 (multiple single elements)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 0 D#1 1 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """case type of
    when '0111'
        regs = 1;
        if align<1> == '1' then UNDEFINED;
    when '1010'
        regs = 2;
        if align == '11' then UNDEFINED;
    when '0110'
        regs = 3;
        if align<1> == '1' then UNDEFINED;
    when '0010'
        regs = 4;
    otherwise
        SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLD1 (single element to one lane)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 1 0 Rn#4 Vd#4 size#2 0 0 index_align#4 Rm#4",
    "decoder" : """if size == '11' then SEE VLD1 (single element to all lanes);
    case size of
        when '00'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); alignment = 1;
        when '01'
            if index_align<1> != '0' then UNDEFINED;
            ebytes = 2; esize = 16;
            index = UInt(index_align<3:2>);
            alignment = if index_align<0> == '0' then 1 else 2;
        when '10'
            if index_align<2> != '0' then UNDEFINED;
            if index_align<1:0> != '00' && index_align<1:0> != '11' then UNDEFINED;
            ebytes = 4;
            esize = 32;
            index = UInt(index_align<3>);
            alignment = if index_align<1:0> == '00' then 1 else 4;
    endcase
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "VLD1 (single element to one lane)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 1 0 Rn#4 Vd#4 size#2 0 0 index_align#4 Rm#4",
    "decoder" : """if size == '11' then SEE VLD1 (single element to all lanes);
    case size of
        when '00'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); alignment = 1;
        when '01'
            if index_align<1> != '0' then UNDEFINED;
            ebytes = 2; esize = 16;
            index = UInt(index_align<3:2>);
            alignment = if index_align<0> == '0' then 1 else 2;
        when '10'
            if index_align<2> != '0' then UNDEFINED;
            if index_align<1:0> != '00' && index_align<1:0> != '11' then UNDEFINED;
            ebytes = 4;
            esize = 32;
            index = UInt(index_align<3>);
            alignment = if index_align<1:0> == '00' then 1 else 4;
    endcase
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "VLD1 (single element to all lanes)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 1 0 Rn#4 Vd#4 1 1 0 0 size#2 T#1 a#1 Rm#4",
    "decoder" : """if size == '11' || (size == '00' && a == '1') then UNDEFINED;
    ebytes = 1 << UInt(size);
    elements = 8 DIV ebytes;
    regs = if T == '0' then 1 else 2;
    alignment = if a == '0' then 1 else ebytes;
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLD1 (single element to all lanes)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 1 0 Rn#4 Vd#4 1 1 0 0 size#2 T#1 a#1 Rm#4",
    "decoder" : """if size == '11' || (size == '00' && a == '1') then UNDEFINED;
    ebytes = 1 << UInt(size);
    elements = 8 DIV ebytes;
    regs = if T == '0' then 1 else 2;
    alignment = if a == '0' then 1 else ebytes;
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLD2 (multiple 2-element structures)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 0 D#1 1 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case type of
        when '1000'
            regs = 1; inc = 1;
            if align == '11' then UNDEFINED;
        when '1001'
            regs = 1; inc = 2;
            if align == '11' then UNDEFINED;
        when '0011'
            regs = 2; inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLD2 (multiple 2-element structures)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 0 D#1 1 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case type of
        when '1000'
            regs = 1; inc = 1;
            if align == '11' then UNDEFINED;
        when '1001'
            regs = 1; inc = 2;
            if align == '11' then UNDEFINED;
        when '0011'
            regs = 2; inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLD2 (single 2-element structure to one lane)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 1 0 Rn#4 Vd#4 size#2 0 1 index_align#4 Rm#4",
    "decoder" : """if size == '11' then SEE VLD2 (single 2-element structure to all lanes);
    case size of
        when '00'
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
            alignment = if index_align<0> == '0' then 1 else 2;
        when '01'
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 4;
        when '10'
            if index_align<1> != '0' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 8;
    endcase
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD2 (single 2-element structure to one lane)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 1 0 Rn#4 Vd#4 size#2 0 1 index_align#4 Rm#4",
    "decoder" : """if size == '11' then SEE VLD2 (single 2-element structure to all lanes);
    case size of
        when '00'
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
            alignment = if index_align<0> == '0' then 1 else 2;
        when '01'
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 4;
        when '10'
            if index_align<1> != '0' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 8;
    endcase
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD2 (single 2-element structure to all lanes)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 1 0 Rn#4 Vd#4 1 1 0 1 size#2 T#1 a#1 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    ebytes = 1 << UInt(size);
    elements = 8 DIV ebytes;
    alignment = if a == '0' then 1 else 2*ebytes;
    inc = if T == '0' then 1 else 2;
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD2 (single 2-element structure to all lanes)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 1 0 Rn#4 Vd#4 1 1 0 1 size#2 T#1 a#1 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    ebytes = 1 << UInt(size);
    elements = 8 DIV ebytes;
    alignment = if a == '0' then 1 else 2*ebytes;
    inc = if T == '0' then 1 else 2;
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD3 (multiple 3-element structures)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 0 D#1 1 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' || align<1> == '1' then UNDEFINED;
    case type of
        when '0100'
            inc = 1;
        when '0101'
            inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align<0> == '0' then 1 else 8;
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD3 (multiple 3-element structures)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 0 D#1 1 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' || align<1> == '1' then UNDEFINED;
    case type of
        when '0100'
            inc = 1;
        when '0101'
            inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align<0> == '0' then 1 else 8;
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD3 (single 3-element structure to one lane)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 1 0 Rn#4 Vd#4 size#2 1 0 index_align#4 Rm#4",
    "decoder" : """if size == '11' then SEE VLD3 (single 3-element structure to all lanes);
    case size of
        when '00'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
        when '01'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>); inc = if index_align<1> == '0' then 1 else 2;
        when '10'
            if index_align<1:0> != '00' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>); inc = if index_align<2> == '0' then 1 else 2;
    endcase
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD3 (single 3-element structure to one lane)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 1 0 Rn#4 Vd#4 size#2 1 0 index_align#4 Rm#4",
    "decoder" : """if size == '11' then SEE VLD3 (single 3-element structure to all lanes);
    case size of
        when '00'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
        when '01'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>); inc = if index_align<1> == '0' then 1 else 2;
        when '10'
            if index_align<1:0> != '00' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>); inc = if index_align<2> == '0' then 1 else 2;
    endcase
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD3 (single 3-element structure to all lanes)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 1 0 Rn#4 Vd#4 1 1 1 0 size#2 T#1 a#1 Rm#4",
    "decoder" : """if size == '11' || a == '1' then UNDEFINED;
    ebytes = 1 << UInt(size); elements = 8 DIV ebytes;
    inc = if T == '0' then 1 else 2;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD3 (single 3-element structure to all lanes)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 1 0 Rn#4 Vd#4 1 1 1 0 size#2 T#1 a#1 Rm#4",
    "decoder" : """if size == '11' || a == '1' then UNDEFINED;
    ebytes = 1 << UInt(size); elements = 8 DIV ebytes;
    inc = if T == '0' then 1 else 2;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD4 (multiple 4-element structures)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 0 D#1 1 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case type of
        when '0000'
            inc = 1;
        when '0001'
            inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD4 (multiple 4-element structures)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 0 D#1 1 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case type of
        when '0000'
            inc = 1;
        when '0001'
            inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD4 (single 4-element structure to one lane)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 1 0 Rn#4 Vd#4 size#2 1 1 index_align#4 Rm#4",
    "decoder" : """if size == '11' then SEE VLD4 (single 4-element structure to all lanes);
    case size of
        when '00'
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
            alignment = if index_align<0> == '0' then 1 else 4;
        when '01'
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 8;
        when '10'
            if index_align<1:0> == '11' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
            alignment = if index_align<1:0> == '00' then 1 else 4 << UInt(index_align<1:0>);
    endcase
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD4 (single 4-element structure to one lane)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 1 0 Rn#4 Vd#4 size#2 1 1 index_align#4 Rm#4",
    "decoder" : """if size == '11' then SEE VLD4 (single 4-element structure to all lanes);
    case size of
        when '00'
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
            alignment = if index_align<0> == '0' then 1 else 4;
        when '01'
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 8;
        when '10'
            if index_align<1:0> == '11' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
            alignment = if index_align<1:0> == '00' then 1 else 4 << UInt(index_align<1:0>);
    endcase
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD4 (single 4-element structure to all lanes)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 1 0 Rn#4 Vd#4 1 1 1 1 size#2 T#1 a#1 Rm#4",
    "decoder" : """if size == '11' && a == '0' then UNDEFINED;
    if size == '11' then
        ebytes = 4; elements = 2; alignment = 16;
    else
        ebytes = 1 << UInt(size); elements = 8 DIV ebytes;
        if size == '10' then
            alignment = if a == '0' then 1 else 8;
        else
            alignment = if a == '0' then 1 else 4*ebytes;
        endif
    endif
    inc = if T == '0' then 1 else 2;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLD4 (single 4-element structure to all lanes)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 1 0 Rn#4 Vd#4 1 1 1 1 size#2 T#1 a#1 Rm#4",
    "decoder" : """if size == '11' && a == '0' then UNDEFINED;
    if size == '11' then
        ebytes = 4; elements = 2; alignment = 16;
    else
        ebytes = 1 << UInt(size); elements = 8 DIV ebytes;
        if size == '10' then
            alignment = if a == '0' then 1 else 8;
        else
            alignment = if a == '0' then 1 else 4*ebytes;
        endif
    endif
    inc = if T == '0' then 1 else 2;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VLDM",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VLDM{mode}<c> <Rn>{!}, <list>",
    "pattern" : "1 1 1 0 1 1 0 P#1 U#1 D#1 W#1 1 Rn#4 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """if P == '0' && U == '0' && W == '0' then SEE "Related encodings";
    if P == '0' && U == '1' && W == '1' && Rn == '1101' then SEE VPOP;
    if P == '1' && W == '0' then SEE VLDR;
    if P == U && W == '1' then UNDEFINED;
    single_regs = FALSE; add = (U == '1'); wback = (W == '1');
    d = UInt(D:Vd); n = UInt(Rn); imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8) DIV 2;
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;
    if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLDM",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VLDM{mode}<c> <Rn>{!}, <list>",
    "pattern" : "cond#4 1 1 0 P#1 U#1 D#1 W#1 1 Rn#4 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """if P == '0' && U == '0' && W == '0' then SEE "Related encodings";
    if P == '0' && U == '1' && W == '1' && Rn == '1101' then SEE VPOP;
    if P == '1' && W == '0' then SEE VLDR;
    if P == U && W == '1' then UNDEFINED;
    single_regs = FALSE; add = (U == '1'); wback = (W == '1');
    d = UInt(D:Vd); n = UInt(Rn); imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8) DIV 2;
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;
    if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLDM",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VLDM{mode}<c> <Rn>{!}, <list>",
    "pattern" : "1 1 1 0 1 1 0 P#1 U#1 D#1 W#1 1 Rn#4 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """if P == '0' && U == '0' && W == '0' then SEE "Related encodings";
    if P == '0' && U == '1' && W == '1' && Rn == '1101' then SEE VPOP;
    if P == '1' && W == '0' then SEE VLDR;
    if P == U && W == '1' then UNDEFINED;
    single_regs = TRUE; add = (U == '1'); wback = (W == '1'); d = UInt(Vd:D); n = UInt(Rn);
    imm32 = ZeroExtend(imm8:'00', 32); regs = UInt(imm8);
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;
    if regs == 0 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLDM",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VLDM{mode}<c> <Rn>{!}, <list>",
    "pattern" : "cond#4 1 1 0 P#1 U#1 D#1 W#1 1 Rn#4 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """if P == '0' && U == '0' && W == '0' then SEE "Related encodings";
    if P == '0' && U == '1' && W == '1' && Rn == '1101' then SEE VPOP;
    if P == '1' && W == '0' then SEE VLDR;
    if P == U && W == '1' then UNDEFINED;
    single_regs = TRUE; add = (U == '1'); wback = (W == '1'); d = UInt(Vd:D); n = UInt(Rn);
    imm32 = ZeroExtend(imm8:'00', 32); regs = UInt(imm8);
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;
    if regs == 0 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VLDR",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 0 1 U#1 D#1 0 1 Rn#4 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """single_reg = FALSE; add = (U == '1'); imm32 = ZeroExtend(imm8:'00', 32); d = UInt(D:Vd); n = UInt(Rn);"""
} , {
    "name" : "VLDR",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 0 1 U#1 D#1 0 1 Rn#4 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """single_reg = FALSE; add = (U == '1'); imm32 = ZeroExtend(imm8:'00', 32); d = UInt(D:Vd); n = UInt(Rn);"""
} , {
    "name" : "VLDR",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 0 1 U#1 D#1 0 1 Rn#4 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """single_reg = TRUE; add = (U == '1'); imm32 = ZeroExtend(imm8:'00', 32); d = UInt(Vd:D); n = UInt(Rn);"""
} , {
    "name" : "VLDR",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 0 1 U#1 D#1 0 1 Rn#4 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """single_reg = TRUE; add = (U == '1'); imm32 = ZeroExtend(imm8:'00', 32); d = UInt(Vd:D); n = UInt(Rn);"""
} , {
    "name" : "VMAX, VMIN (integer)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 1 1 0 N#1 Q#1 M#1 op#1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    maximum = (op == '0'); unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMAX, VMIN (integer)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 1 1 0 N#1 Q#1 M#1 op#1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    maximum = (op == '0'); unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMAX, VMIN (floating-point)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    maximum = (op == '0'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMAX, VMIN (floating-point)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    maximum = (op == '0'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMLA, VMLAL, VMLS, VMLSL (integer)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 op#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    add = (op == '0'); long_destination = FALSE;
    unsigned_ = FALSE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMLA, VMLAL, VMLS, VMLSL (integer)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 op#1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    add = (op == '0'); long_destination = FALSE;
    unsigned_ = FALSE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMLA, VMLAL, VMLS, VMLSL (integer)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 0 op#1 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' then UNDEFINED;
    add = (op == '0'); long_destination = TRUE; unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = 1;"""
} , {
    "name" : "VMLA, VMLAL, VMLS, VMLSL (integer)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 size#2 Vn#4 Vd#4 1 0 op#1 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' then UNDEFINED;
    add = (op == '0'); long_destination = TRUE; unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = 1;"""
} , {
    "name" : "VMLA, VMLS (floating-point)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; add = (op == '0'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMLA, VMLS (floating-point)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; add = (op == '0'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMLA, VMLS (floating-point)",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 0 D#1 0 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1'); add = (op == '0');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VMLA, VMLS (floating-point)",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 0 D#1 0 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1'); add = (op == '0');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VMLA, VMLAL, VMLS, VMLSL (by scalar)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 Q#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 op#1 0 F#1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || (F == '1' && size == '01') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = FALSE;
    add = (op == '0'); floating_point = (F == '1'); long_destination = FALSE;
    d = UInt(D:Vd); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VMLA, VMLAL, VMLS, VMLSL (by scalar)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 Q#1 1 D#1 size#2 Vn#4 Vd#4 0 op#1 0 F#1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || (F == '1' && size == '01') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = FALSE;
    add = (op == '0'); floating_point = (F == '1'); long_destination = FALSE;
    d = UInt(D:Vd); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VMLA, VMLAL, VMLS, VMLSL (by scalar)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 op#1 1 0 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    unsigned_ = (U == '1'); add = (op == '0'); floating_point = FALSE; long_destination = TRUE;
    d = UInt(D:Vd); n = UInt(N:Vn); regs = 1;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VMLA, VMLAL, VMLS, VMLSL (by scalar)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 size#2 Vn#4 Vd#4 0 op#1 1 0 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    unsigned_ = (U == '1'); add = (op == '0'); floating_point = FALSE; long_destination = TRUE;
    d = UInt(D:Vd); n = UInt(N:Vn); regs = 1;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VMOV (immediate)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 i#1 1 1 1 1 1 D#1 0 0 0 imm3#3 Vd#4 cmode#4 0 Q#1 op#1 1 imm4#4",
    "decoder" : """if op == '0' && cmode<0> == '1' && cmode<3:2> != '11' then SEE VORR (immediate);
    if op == '1' && cmode != '1110' then SEE "Related encodings";
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    single_register = FALSE; advsimd = TRUE; imm64 = AdvSIMDExpandImm(op, cmode, i:imm3:imm4);
    d = UInt(D:Vd); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMOV (immediate)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 i#1 1 D#1 0 0 0 imm3#3 Vd#4 cmode#4 0 Q#1 op#1 1 imm4#4",
    "decoder" : """if op == '0' && cmode<0> == '1' && cmode<3:2> != '11' then SEE VORR (immediate);
    if op == '1' && cmode != '1110' then SEE "Related encodings";
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    single_register = FALSE; advsimd = TRUE; imm64 = AdvSIMDExpandImm(op, cmode, i:imm3:imm4);
    d = UInt(D:Vd); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMOV (immediate)",
    "encoding" : "T2",
    "version" : "VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 imm4H#4 Vd#4 1 0 1 sz#1 0 0 0 0 imm4L#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    single_register = (sz == '0'); advsimd = FALSE;
    if single_register then
        d = UInt(Vd:D);
        imm32 = VFPExpandImm(imm4H:imm4L, 32);
    else
        d = UInt(D:Vd);
        imm64 = VFPExpandImm(imm4H:imm4L, 64);
        regs = 1;
    endif"""
} , {
    "name" : "VMOV (immediate)",
    "encoding" : "A2",
    "version" : "VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 imm4H#4 Vd#4 1 0 1 sz#1 0 0 0 0 imm4L#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    single_register = (sz == '0'); advsimd = FALSE;
    if single_register then
        d = UInt(Vd:D); imm32 = VFPExpandImm(imm4H:imm4L, 32);
    else
        d = UInt(D:Vd); imm64 = VFPExpandImm(imm4H:imm4L, 64); regs = 1;
    endif"""
} , {
    "name" : "VMOV (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 1 0 Vm_#4 Vd#4 0 0 0 1 M_#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if !Consistent(M) || !Consistent(Vm) then SEE VORR (register);
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    single_register = FALSE; advsimd = TRUE;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMOV (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 1 0 Vm_#4 Vd#4 0 0 0 1 M_#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if !Consistent(M) || !Consistent(Vm) then SEE VORR (register);
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    single_register = FALSE; advsimd = TRUE;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMOV (register)",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 0 0 0 0 Vd#4 1 0 1 sz#1 0 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    single_register = (sz == '0'); advsimd = FALSE;
    if single_register then
        d = UInt(Vd:D); m = UInt(Vm:M);
    else
        d = UInt(D:Vd); m = UInt(M:Vm); regs = 1;
    endif"""
} , {
    "name" : "VMOV (register)",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 0 0 0 0 Vd#4 1 0 1 sz#1 0 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    single_register = (sz == '0'); advsimd = FALSE;
    if single_register then
        d = UInt(Vd:D); m = UInt(Vm:M);
    else
        d = UInt(D:Vd); m = UInt(M:Vm); regs = 1;
    endif"""
} , {
    "name" : "VMOV (ARM core register to scalar)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VMOV<c>.<size> <Dd[x]>, <Rt>",
    "pattern" : "1 1 1 0 1 1 1 0 0 opc1#2 0 Vd#4 Rt#4 1 0 1 1 D#1 opc2#2 1 0 0 0 0",
    "decoder" : """case opc1:opc2 of
        when "1xxx" advsimd = TRUE; esize = 8; index = UInt(opc1<0>:opc2);
        when "0xx1" advsimd = TRUE; esize = 16; index = UInt(opc1<0>:opc2<1>);
        when "0x00" advsimd = FALSE; esize = 32; index = UInt(opc1<0>);
        when "0x10" UNDEFINED;
    endcase
    d = UInt(D:Vd); t = UInt(Rt);
    if t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (ARM core register to scalar)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VMOV<c>.<size> <Dd[x]>, <Rt>",
    "pattern" : "cond#4 1 1 1 0 0 opc1#2 0 Vd#4 Rt#4 1 0 1 1 D#1 opc2#2 1 0 0 0 0",
    "decoder" : """case opc1:opc2 of
        when "1xxx" advsimd = TRUE; esize = 8; index = UInt(opc1<0>:opc2);
        when "0xx1" advsimd = TRUE; esize = 16; index = UInt(opc1<0>:opc2<1>);
        when "0x00" advsimd = FALSE; esize = 32; index = UInt(opc1<0>);
        when "0x10" UNDEFINED;
    endcase
    d = UInt(D:Vd); t = UInt(Rt);
    if t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (scalar to ARM core register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VMOV<c>.<dt> <Rt>, <Dn[x]>",
    "pattern" : "1 1 1 0 1 1 1 0 U#1 opc1#2 1 Vn#4 Rt#4 1 0 1 1 N#1 opc2#2 1 0 0 0 0",
    "decoder" : """case U:opc1:opc2 of
        when "x1xxx" advsimd = TRUE; esize = 8; index = UInt(opc1<0>:opc2);
        when "x0xx1" advsimd = TRUE; esize = 16; index = UInt(opc1<0>:opc2<1>);
        when "00x00" advsimd = FALSE; esize = 32; index = UInt(opc1<0>);
        when "10x00" UNDEFINED;
        when "x0x10" UNDEFINED;
    endcase
    t = UInt(Rt); n = UInt(N:Vn); unsigned_ = (U == '1');
    if t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (scalar to ARM core register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VMOV<c>.<dt> <Rt>, <Dn[x]>",
    "pattern" : "cond#4 1 1 1 0 U#1 opc1#2 1 Vn#4 Rt#4 1 0 1 1 N#1 opc2#2 1 0 0 0 0",
    "decoder" : """case U:opc1:opc2 of
        when "x1xxx" advsimd = TRUE; esize = 8; index = UInt(opc1<0>:opc2);
        when "x0xx1" advsimd = TRUE; esize = 16; index = UInt(opc1<0>:opc2<1>);
        when "00x00" advsimd = FALSE; esize = 32; index = UInt(opc1<0>);
        when "10x00" UNDEFINED;
        when "x0x10" UNDEFINED;
    endcase
    t = UInt(Rt); n = UInt(N:Vn); unsigned_ = (U == '1');
    if t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (between ARM core register and single-precision register)",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 0 0 0 op#1 Vn#4 Rt#4 1 0 1 0 N#1 0 0 1 0 0 0 0",
    "decoder" : """to_arm_register = (op == '1'); t = UInt(Rt); n = UInt(Vn:N);
    if t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (between ARM core register and single-precision register)",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 0 0 0 op#1 Vn#4 Rt#4 1 0 1 0 N#1 0 0 1 0 0 0 0",
    "decoder" : """to_arm_register = (op == '1'); t = UInt(Rt); n = UInt(Vn:N);
    if t == 15 || (CurrentInstrSet() != InstrSet_ARM && t == 13) then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (between two ARM core registers and two single-precision registers)",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 0 0 0 1 0 op#1 Rt2#4 Rt#4 1 0 1 0 0 0 M#1 1 Vm#4",
    "decoder" : """to_arm_registers = (op == '1'); t = UInt(Rt); t2 = UInt(Rt2); m = UInt(Vm:M);
    if t == 15 || t2 == 15 || m == 31 then UNPREDICTABLE;
    if CurrentInstrSet() != InstrSet_ARM && (t == 13 || t2 == 13) then UNPREDICTABLE;
    if to_arm_registers && t == t2 then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (between two ARM core registers and two single-precision registers)",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 0 0 0 1 0 op#1 Rt2#4 Rt#4 1 0 1 0 0 0 M#1 1 Vm#4",
    "decoder" : """to_arm_registers = (op == '1'); t = UInt(Rt); t2 = UInt(Rt2); m = UInt(Vm:M);
    if t == 15 || t2 == 15 || m == 31 then UNPREDICTABLE;
    if CurrentInstrSet() != InstrSet_ARM && (t == 13 || t2 == 13) then UNPREDICTABLE;
    if to_arm_registers && t == t2 then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (between two ARM core registers and a doubleword extension register)",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 0 0 0 1 0 op#1 Rt2#4 Rt#4 1 0 1 1 0 0 M#1 1 Vm#4",
    "decoder" : """to_arm_registers = (op == '1'); t = UInt(Rt); t2 = UInt(Rt2); m = UInt(M:Vm);
    if t == 15 || t2 == 15 then UNPREDICTABLE;
    if CurrentInstrSet() != InstrSet_ARM && (t == 13 || t2 == 13) then UNPREDICTABLE;
    if to_arm_registers && t == t2 then UNPREDICTABLE;"""
} , {
    "name" : "VMOV (between two ARM core registers and a doubleword extension register)",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 0 0 0 1 0 op#1 Rt2#4 Rt#4 1 0 1 1 0 0 M#1 1 Vm#4",
    "decoder" : """to_arm_registers = (op == '1'); t = UInt(Rt); t2 = UInt(Rt2); m = UInt(M:Vm);
    if t == 15 || t2 == 15 then UNPREDICTABLE;
    if CurrentInstrSet() != InstrSet_ARM && (t == 13 || t2 == 13) then UNPREDICTABLE;
    if to_arm_registers && t == t2 then UNPREDICTABLE;"""
} , {
    "name" : "VMOVL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VMOVL<c>.<dt> <Qd>, <Dm>",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm3#3 0 0 0 Vd#4 1 0 1 0 0 0 M#1 1 Vm#4",
    "decoder" : """if imm3 == '000' then SEE "Related encodings";
    if imm3 != '001' && imm3 != '010' && imm3 != '100' then SEE VSHLL;
    if Vd<0> == '1' then UNDEFINED;
    esize = 8 * UInt(imm3);
    unsigned_ = (U == '1'); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VMOVL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VMOVL<c>.<dt> <Qd>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm3#3 0 0 0 Vd#4 1 0 1 0 0 0 M#1 1 Vm#4",
    "decoder" : """if imm3 == '000' then SEE "Related encodings";
    if imm3 != '001' && imm3 != '010' && imm3 != '100' then SEE VSHLL;
    if Vd<0> == '1' then UNDEFINED;
    esize = 8 * UInt(imm3);
    unsigned_ = (U == '1'); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VMOVN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VMOVN<c>.<dt> <Dd>, <Qm>",
    "pattern" : "111111111 D#1 11 size#2 10 Vd#4 001000 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VMOVN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VMOVN<c>.<dt> <Dd>, <Qm>",
    "pattern" : "111100111 D#1 11 size#2 10 Vd#4 001000 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VMRS",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VMRS<c> <Rt>, <spec_reg>",
    "pattern" : "111011101111 reg#4 Rt#4 101000010000",
    "decoder" : """t = UInt(Rt); if t == 13 && CurrentInstrSet() != InstrSet_ARM then UNPREDICTABLE;
if t == 15 && reg != '0001' then UNPREDICTABLE;"""
} , {
    "name" : "VMRS",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VMRS<c> <Rt>, <spec_reg>",
    "pattern" : "cond#4 11101111 reg#4 Rt#4 101000010000",
    "decoder" : """t = UInt(Rt); if t == 13 && CurrentInstrSet() != InstrSet_ARM then UNPREDICTABLE;
if t == 15 && reg != '0001' then UNPREDICTABLE;"""
} , {
    "name" : "VMSR",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VMSR<c> <spec_reg>, <Rt>",
    "pattern" : "111011101110 reg#4 Rt#4 101000010000",
    "decoder" : """t = UInt(Rt); if t == 15 || (t == 13 && CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "VMSR",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VMSR<c> <spec_reg>, <Rt>",
    "pattern" : "cond#4 11101110 reg#4 Rt#4 101000010000",
    "decoder" : """t = UInt(Rt); if t == 15 || (t == 13 && CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;"""
} , {
    "name" : "VMUL, VMULL (integer and polynomial)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 op#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if size == '11' || (op == '1' && size != '00') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    polynomial = (op == '1'); long_destination = FALSE;
    unsigned_ = FALSE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMUL, VMULL (integer and polynomial)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 op#1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if size == '11' || (op == '1' && size != '00') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    polynomial = (op == '1'); long_destination = FALSE;
    unsigned_ = FALSE;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMUL, VMULL (integer and polynomial)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "VMULL<c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 1 op#1 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if op == '1' && (U != '0' || size != '00') then UNDEFINED;
    if Vd<0> == '1' then UNDEFINED;
    polynomial = (op == '1'); long_destination = TRUE; unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = 1;"""
} , {
    "name" : "VMUL, VMULL (integer and polynomial)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "VMULL<c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 size#2 Vn#4 Vd#4 1 1 op#1 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if op == '1' && (U != '0' || size != '00') then UNDEFINED;
    if Vd<0> == '1' then UNDEFINED;
    polynomial = (op == '1'); long_destination = TRUE; unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = 1;"""
} , {
    "name" : "VMUL (floating-point)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMUL (floating-point)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMUL (floating-point)",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 0 D#1 1 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VMUL (floating-point)",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 0 D#1 1 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VMUL, VMULL (by scalar)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 Q#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 0 0 F#1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || (F == '1' && size == '01') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = FALSE;
    floating_point = (F == '1'); long_destination = FALSE;
    d = UInt(D:Vd); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VMUL, VMULL (by scalar)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 Q#1 1 D#1 size#2 Vn#4 Vd#4 1 0 0 F#1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || (F == '1' && size == '01') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = FALSE;
    floating_point = (F == '1'); long_destination = FALSE;
    d = UInt(D:Vd); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VMUL, VMULL (by scalar)",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "VMULL<c>.<dt> <Qd>, <Dn>, <Dm[x]>",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 0 1 0 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = TRUE; floating_point = FALSE;
    d = UInt(D:Vd); n = UInt(N:Vn); regs = 1;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VMUL, VMULL (by scalar)",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "VMULL<c>.<dt> <Qd>, <Dn>, <Dm[x]>",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 size#2 Vn#4 Vd#4 1 0 1 0 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    unsigned_ = (U == '1'); long_destination = TRUE; floating_point = FALSE;
    d = UInt(D:Vd); n = UInt(N:Vn); regs = 1;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VMVN (immediate)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 i#1 1 1 1 1 1 D#1 0 0 0 imm3#3 Vd#4 cmode#4 0 Q#1 1 1 imm4#4",
    "decoder" : """if (cmode<0> == '1' && cmode<3:2> != '11') || cmode<3:1> == '111' then SEE "Related encodings";
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    imm64 = AdvSIMDExpandImm('1', cmode, i:imm3:imm4);
    d = UInt(D:Vd); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMVN (immediate)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 i#1 1 D#1 0 0 0 imm3#3 Vd#4 cmode#4 0 Q#1 1 1 imm4#4",
    "decoder" : """if (cmode<0> == '1' && cmode<3:2> != '11') || cmode<3:1> == '111' then SEE "Related encodings";
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    imm64 = AdvSIMDExpandImm('1', cmode, i:imm3:imm4);
    d = UInt(D:Vd); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMVN (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 0 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size != '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VMVN (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 0 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size != '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VNEG",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 1 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    advsimd = TRUE; floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VNEG",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 1 Vd#4 0 F#1 1 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (F == '1' && size != '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    advsimd = TRUE; floating_point = (F == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VNEG",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 0 0 0 1 Vd#4 1 0 1 sz#1 0 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VNEG",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 0 0 0 1 Vd#4 1 0 1 sz#1 0 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VNMLA, VNMLS, VNMUL",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 0 D#1 0 1 Vn#4 Vd#4 1 0 1 sz#1 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    type = if op == '1' then VFPNegMul_VNMLA else VFPNegMul_VNMLS; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VNMLA, VNMLS, VNMUL",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 0 D#1 0 1 Vn#4 Vd#4 1 0 1 sz#1 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    type = if op == '1' then VFPNegMul_VNMLA else VFPNegMul_VNMLS; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VNMLA, VNMLS, VNMUL",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 0 D#1 1 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    type = VFPNegMul_VNMUL;
    dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VNMLA, VNMLS, VNMUL",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 0 D#1 1 0 Vn#4 Vd#4 1 0 1 sz#1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    type = VFPNegMul_VNMUL;
    dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VORN (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 1 1 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VORN (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 1 1 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VORR (immediate)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 i#1 1 1 1 1 1 D#1 0 0 0 imm3#3 Vd#4 cmode#4 0 Q#1 0 1 imm4#4",
    "decoder" : """if cmode<0> == '0' || cmode<3:2> == '11' then SEE VMOV (immediate);
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    imm64 = AdvSIMDExpandImm('0', cmode, i:imm3:imm4);
    d = UInt(D:Vd); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VORR (immediate)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 i#1 1 D#1 0 0 0 imm3#3 Vd#4 cmode#4 0 Q#1 0 1 imm4#4",
    "decoder" : """if cmode<0> == '0' || cmode<3:2> == '11' then SEE VMOV (immediate);
    if Q == '1' && Vd<0> == '1' then UNDEFINED;
    imm64 = AdvSIMDExpandImm('0', cmode, i:imm3:imm4);
    d = UInt(D:Vd); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VORR (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 1 0 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if N == M && Vn == Vm then SEE VMOV (register);
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VORR (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 1 0 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if N == M && Vn == Vm then SEE VMOV (register);
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VPADAL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 1 0 op#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (op == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VPADAL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 1 0 op#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (op == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VPADD (integer)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VPADD<c>.<dt> <Dd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if size == '11' || Q == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VPADD (integer)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VPADD<c>.<dt> <Dd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 size#2 Vn#4 Vd#4 1 0 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if size == '11' || Q == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VPADD (floating-point)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VPADD<c>.F32 <Dd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if sz == '1' || Q == '1' then UNDEFINED;
    esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VPADD (floating-point)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VPADD<c>.F32 <Dd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if sz == '1' || Q == '1' then UNDEFINED;
    esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VPADDL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 0 1 0 op#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (op == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VPADDL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 0 1 0 op#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (op == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VPMAX, VPMIN (integer)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VP<op><c>.<dt> <Dd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 1 0 N#1 Q#1 M#1 op#1 Vm#4",
    "decoder" : """if size == '11' || Q == '1' then UNDEFINED;
    maximum = (op == '0'); unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VPMAX, VPMIN (integer)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VP<op><c>.<dt> <Dd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 1 0 1 0 N#1 Q#1 M#1 op#1 Vm#4",
    "decoder" : """if size == '11' || Q == '1' then UNDEFINED;
    maximum = (op == '0'); unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VPMAX, VPMIN (floating-point)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VP<op><c>.F32 <Dd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if sz == '1' || Q == '1' then UNDEFINED;
    maximum = (op == '0'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VPMAX, VPMIN (floating-point)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VP<op><c>.F32 <Dd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 op#1 sz#1 Vn#4 Vd#4 1 1 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if sz == '1' || Q == '1' then UNDEFINED;
    maximum = (op == '0'); esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VPOP",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VPOP <list>",
    "pattern" : "1 1 1 0 1 1 0 0 1 D#1 1 1 1 1 0 1 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """single_regs = FALSE; d = UInt(D:Vd); imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8) DIV 2;
    if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VPOP",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VPOP <list>",
    "pattern" : "cond#4 1 1 0 0 1 D#1 1 1 1 1 0 1 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """single_regs = FALSE; d = UInt(D:Vd); imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8) DIV 2;
    if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VPOP",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VPOP <list>",
    "pattern" : "1 1 1 0 1 1 0 0 1 D#1 1 1 1 1 0 1 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """single_regs = TRUE; d = UInt(Vd:D);
    imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8);
    if regs == 0 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VPOP",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VPOP <list>",
    "pattern" : "cond#4 1 1 0 0 1 D#1 1 1 1 1 0 1 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """single_regs = TRUE; d = UInt(Vd:D);
    imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8);
    if regs == 0 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VPUSH",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VPUSH<c> <list>",
    "pattern" : "1 1 1 0 1 1 0 1 0 D#1 1 0 1 1 0 1 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """single_regs = FALSE; d = UInt(D:Vd); imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8) DIV 2;
    if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VPUSH",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VPUSH<c> <list>",
    "pattern" : "cond#4 1 1 0 1 0 D#1 1 0 1 1 0 1 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """single_regs = FALSE; d = UInt(D:Vd); imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8) DIV 2;
    if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VPUSH",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VPUSH<c> <list>",
    "pattern" : "1 1 1 0 1 1 0 1 0 D#1 1 0 1 1 0 1 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """single_regs = TRUE; d = UInt(Vd:D);
    imm32 = ZeroExtend(imm8:'00', 32); regs = UInt(imm8);
    if regs == 0 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VPUSH",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VPUSH<c> <list>",
    "pattern" : "cond#4 1 1 0 1 0 D#1 1 0 1 1 0 1 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """single_regs = TRUE; d = UInt(Vd:D);
    imm32 = ZeroExtend(imm8:'00', 32); regs = UInt(imm8);
    if regs == 0 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VQABS",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 1 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQABS",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 1 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQADD",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 0 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQADD",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 0 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQDMLAL, VQDMLSL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VQD<op><c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 0 op#1 1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    add = (op == '0');
    scalar_form = FALSE; d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    esize = 8 << UInt(size); elements = 64 DIV esize;"""
} , {
    "name" : "VQDMLAL, VQDMLSL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VQD<op><c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 size#2 Vn#4 Vd#4 1 0 op#1 1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    add = (op == '0');
    scalar_form = FALSE; d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    esize = 8 << UInt(size); elements = 64 DIV esize;"""
} , {
    "name" : "VQDMLAL, VQDMLSL",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "VQD<op><c>.<dt> <Qd>, <Dn>, <Dm[x]>",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 op#1 1 1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    add = (op == '0');
    scalar_form = TRUE; d = UInt(D:Vd); n = UInt(N:Vn);
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VQDMLAL, VQDMLSL",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "VQD<op><c>.<dt> <Qd>, <Dn>, <Dm[x]>",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 size#2 Vn#4 Vd#4 0 op#1 1 1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    add = (op == '0');
    scalar_form = TRUE; d = UInt(D:Vd); n = UInt(N:Vn);
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VQDMULH",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '00' || size == '11' then UNDEFINED;
    scalar_form = FALSE; esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQDMULH",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 size#2 Vn#4 Vd#4 1 0 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '00' || size == '11' then UNDEFINED;
    scalar_form = FALSE; esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQDMULH",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 Q#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 1 0 0 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED;
    scalar_form = TRUE; d = UInt(D:Vd); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VQDMULH",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 Q#1 1 D#1 size#2 Vn#4 Vd#4 1 1 0 0 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED;
    scalar_form = TRUE; d = UInt(D:Vd); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VQDMULL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VQDMULL<c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 1 0 1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    scalar_form = FALSE; d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    esize = 8 << UInt(size); elements = 64 DIV esize;"""
} , {
    "name" : "VQDMULL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VQDMULL<c>.<dt> <Qd>, <Dn>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 size#2 Vn#4 Vd#4 1 1 0 1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    scalar_form = FALSE; d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    esize = 8 << UInt(size); elements = 64 DIV esize;"""
} , {
    "name" : "VQDMULL",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "VQDMULL<c>.<dt> <Qd>, <Dn>, <Dm[x]>",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 0 1 1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    scalar_form = TRUE; d = UInt(D:Vd); n = UInt(N:Vn);
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VQDMULL",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "VQDMULL<c>.<dt> <Qd>, <Dn>, <Dm[x]>",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 size#2 Vn#4 Vd#4 1 0 1 1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' || Vd<0> == '1' then UNDEFINED;
    scalar_form = TRUE; d = UInt(D:Vd); n = UInt(N:Vn);
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VQMOVN, VQMOVUN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VQMOV{U}N<c>.<type><size> <Dd>, <Qm>",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 1 0 op#2 M#1 0 Vm#4",
    "decoder" : """if op == '00' then SEE VMOVN;
    if size == '11' || Vm<0> == '1' then UNDEFINED;
    src_unsigned = (op == '11'); dest_unsigned = (op<0> == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VQMOVN, VQMOVUN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VQMOV{U}N<c>.<type><size> <Dd>, <Qm>",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 1 0 op#2 M#1 0 Vm#4",
    "decoder" : """if op == '00' then SEE VMOVN;
    if size == '11' || Vm<0> == '1' then UNDEFINED;
    src_unsigned = (op == '11'); dest_unsigned = (op<0> == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VQNEG",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 1 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQNEG",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 1 1 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQRDMULH",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '00' || size == '11' then UNDEFINED;
    scalar_form = FALSE; esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQRDMULH",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 1 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '00' || size == '11' then UNDEFINED;
    scalar_form = FALSE; esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQRDMULH",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 Q#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 1 1 0 1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED;
    scalar_form = TRUE; d = UInt(D:Vd); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VQRDMULH",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 Q#1 1 D#1 size#2 Vn#4 Vd#4 1 1 0 1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if size == '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vn<0> == '1') then UNDEFINED;
    scalar_form = TRUE; d = UInt(D:Vd); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;
    if size == '01' then esize = 16; elements = 4; m = UInt(Vm<2:0>); index = UInt(M:Vm<3>);
    if size == '10' then esize = 32; elements = 2; m = UInt(Vm); index = UInt(M);"""
} , {
    "name" : "VQRSHL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 1 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQRSHL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 1 0 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQRSHRN, VQRSHRUN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VQRSHR{U}N<c>.<type><size> <Dd>, <Qm>, #<imm>",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 1 0 0 op#1 0 1 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if U == '0' && op == '0' then SEE VRSHRN;
    if Vm<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "01xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "1xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
    endcase
    src_unsigned = (U == '1' && op == '1'); dest_unsigned = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VQRSHRN, VQRSHRUN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VQRSHR{U}N<c>.<type><size> <Dd>, <Qm>, #<imm>",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 1 0 0 op#1 0 1 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if U == '0' && op == '0' then SEE VRSHRN;
    if Vm<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "01xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "1xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
    endcase
    src_unsigned = (U == '1' && op == '1'); dest_unsigned = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VQSHL (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 1 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQSHL (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 1 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQSHL, VQSHLU (immediate)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 0 1 1 op#1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if U == '0' && op == '0' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = UInt(imm6) - 8;
        when "001xxxx" esize = 16; elements = 4; shift_amount = UInt(imm6) - 16;
        when "01xxxxx" esize = 32; elements = 2; shift_amount = UInt(imm6) - 32;
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = UInt(imm6);
    endcase
    src_unsigned = (U == '1' && op == '1'); dest_unsigned = (U == '1');
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQSHL, VQSHLU (immediate)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 0 1 1 op#1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if U == '0' && op == '0' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = UInt(imm6) - 8;
        when "001xxxx" esize = 16; elements = 4; shift_amount = UInt(imm6) - 16;
        when "01xxxxx" esize = 32; elements = 2; shift_amount = UInt(imm6) - 32;
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = UInt(imm6);
    endcase
    src_unsigned = (U == '1' && op == '1'); dest_unsigned = (U == '1');
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQSHRN, VQSHRUN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VQSHR{U}N<c>.<type><size> <Dd>, <Qm>, #<imm>",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 1 0 0 op#1 0 0 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if U == '0' && op == '0' then SEE VSHRN;
    if Vm<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "01xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "1xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
    endcase
    src_unsigned = (U == '1' && op == '1'); dest_unsigned = (U == '1');
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VQSHRN, VQSHRUN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VQSHR{U}N<c>.<type><size> <Dd>, <Qm>, #<imm>",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 1 0 0 op#1 0 0 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if U == '0' && op == '0' then SEE VSHRN;
    if Vm<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "01xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "1xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
    endcase
    src_unsigned = (U == '1' && op == '1'); dest_unsigned = (U == '1');
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VQSUB",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 0 1 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VQSUB",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 0 1 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRADDHN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VRADDHN<c>.<dt> <Dd>, <Qn>, <Qm>",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 1 0 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VRADDHN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VRADDHN<c>.<dt> <Dd>, <Qn>, <Qm>",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 size#2 Vn#4 Vd#4 0 1 0 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VRECPE",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 1 Vd#4 0 1 0 F#1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size != '10' then UNDEFINED;
    floating_point = (F == '1'); esize = 32; elements = 2;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRECPE",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 1 Vd#4 0 1 0 F#1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size != '10' then UNDEFINED;
    floating_point = (F == '1'); esize = 32; elements = 2;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRECPS",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRECPS",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 0 sz#1 Vn#4 Vd#4 1 1 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VREV16, VREV32, VREV64",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 0 0 op#2 Q#1 M#1 0 Vm#4",
    "decoder" : """if UInt(op)+UInt(size) >= 3 then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    groupsize = (1 << (3-UInt(op)-UInt(size)));
    groupsize_minus_one = groupsize-1;
    esize_minus_one = esize-1;
    reverse_mask = groupsize_minus_one<esize_minus_one:0>;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VREV16, VREV32, VREV64",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 0 0 Vd#4 0 0 0 op#2 Q#1 M#1 0 Vm#4",
    "decoder" : """if UInt(op)+UInt(size) >= 3 then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    groupsize = (1 << (3-UInt(op)-UInt(size)));
    groupsize_minus_one = groupsize-1;
    esize_minus_one = esize-1;
    reverse_mask = groupsize_minus_one<esize_minus_one:0>;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRHADD",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRHADD",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 0 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSHL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSHL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSHR",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 0 0 1 0 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSHR",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 0 0 1 0 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSHRN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VRSHRN<c>.I<size> <Dd>, <Qm>, #<imm>",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 imm6#6 Vd#4 1 0 0 0 0 1 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if Vm<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "01xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "1xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VRSHRN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VRSHRN<c>.I<size> <Dd>, <Qm>, #<imm>",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 imm6#6 Vd#4 1 0 0 0 0 1 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if Vm<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "01xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "1xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VRSQRTE",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 1 Vd#4 0 1 0 F#1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size != '10' then UNDEFINED;
    floating_point = (F == '1'); esize = 32; elements = 2;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSQRTE",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 1 Vd#4 0 1 0 F#1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size != '10' then UNDEFINED;
    floating_point = (F == '1'); esize = 32; elements = 2;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSQRTS",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 1 sz#1 Vn#4 Vd#4 1 1 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSQRTS",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 1 sz#1 Vn#4 Vd#4 1 1 1 1 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSRA",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 0 0 1 1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSRA",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 0 0 1 1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VRSUBHN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VRSUBHN<c>.<dt> <Dd>, <Qn>, <Qm>",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 1 1 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VRSUBHN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VRSUBHN<c>.<dt> <Dd>, <Qn>, <Qm>",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 size#2 Vn#4 Vd#4 0 1 1 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VSHL (immediate)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 imm6#6 Vd#4 0 1 0 1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if L:imm6 IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = UInt(imm6) - 8;
        when "001xxxx" esize = 16; elements = 4; shift_amount = UInt(imm6) - 16;
        when "01xxxxx" esize = 32; elements = 2; shift_amount = UInt(imm6) - 32;
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSHL (immediate)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 imm6#6 Vd#4 0 1 0 1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if L:imm6 IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = UInt(imm6) - 8;
        when "001xxxx" esize = 16; elements = 4; shift_amount = UInt(imm6) - 16;
        when "01xxxxx" esize = 32; elements = 2; shift_amount = UInt(imm6) - 32;
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSHL (register)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 0 1 0 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSHL (register)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 0 D#1 size#2 Vn#4 Vd#4 0 1 0 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vm<0> == '1' || Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); n = UInt(N:Vn); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSHLL",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VSHLL<c>.<type><size> <Qd>, <Dm>, #<imm>",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 1 0 1 0 0 0 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if Vd<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = UInt(imm6) - 8;
        when "01xxxx" esize = 16; elements = 4; shift_amount = UInt(imm6) - 16;
        when "1xxxxx" esize = 32; elements = 2; shift_amount = UInt(imm6) - 32;
    endcase
    if shift_amount == 0 then SEE VMOVL;
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VSHLL",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VSHLL<c>.<type><size> <Qd>, <Dm>, #<imm>",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 1 0 1 0 0 0 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if Vd<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = UInt(imm6) - 8;
        when "01xxxx" esize = 16; elements = 4; shift_amount = UInt(imm6) - 16;
        when "1xxxxx" esize = 32; elements = 2; shift_amount = UInt(imm6) - 32;
    endcase
    if shift_amount == 0 then SEE VMOVL;
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VSHLL",
    "encoding" : "T2",
    "version" : "AdvancedSIMD",
    "format" : "VSHLL<c>.<type><size> <Qd>, <Dm>, #<imm>",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 1 1 0 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' || Vd<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); shift_amount = esize;
    unsigned_ = FALSE;
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VSHLL",
    "encoding" : "A2",
    "version" : "AdvancedSIMD",
    "format" : "VSHLL<c>.<type><size> <Qd>, <Dm>, #<imm>",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 1 1 0 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' || Vd<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); shift_amount = esize;
    unsigned_ = FALSE;
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VSHR",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 0 0 0 0 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSHR",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 0 0 0 0 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSHRN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VSHRN<c>.I<size> <Dd>, <Qm>, #<imm>",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 imm6#6 Vd#4 1 0 0 0 0 0 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if Vm<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "01xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "1xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VSHRN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VSHRN<c>.I<size> <Dd>, <Qm>, #<imm>",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 imm6#6 Vd#4 1 0 0 0 0 0 M#1 1 Vm#4",
    "decoder" : """if imm6 IN "000xxx" then SEE "Related encodings";
    if Vm<0> == '1' then UNDEFINED;
    case imm6 of
        when "001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "01xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "1xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VSLI",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 imm6#6 Vd#4 0 1 0 1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = UInt(imm6) - 8;
        when "001xxxx" esize = 16; elements = 4; shift_amount = UInt(imm6) - 16;
        when "01xxxxx" esize = 32; elements = 2; shift_amount = UInt(imm6) - 32;
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSLI",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 imm6#6 Vd#4 0 1 0 1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = UInt(imm6) - 8;
        when "001xxxx" esize = 16; elements = 4; shift_amount = UInt(imm6) - 16;
        when "01xxxxx" esize = 32; elements = 2; shift_amount = UInt(imm6) - 32;
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSQRT",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 1 D#1 1 1 0 0 0 1 Vd#4 1 0 1 sz#1 1 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VSQRT",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 1 D#1 1 1 0 0 0 1 Vd#4 1 0 1 sz#1 1 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VSRA",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 imm6#6 Vd#4 0 0 0 1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSRA",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 imm6#6 Vd#4 0 0 0 1 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    unsigned_ = (U == '1'); d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSRI",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 imm6#6 Vd#4 0 1 0 0 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSRI",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 imm6#6 Vd#4 0 1 0 0 L#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if (L:imm6) IN "0000xxx" then SEE "Related encodings";
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    case L:imm6 of
        when "0001xxx" esize = 8; elements = 8; shift_amount = 16 - UInt(imm6);
        when "001xxxx" esize = 16; elements = 4; shift_amount = 32 - UInt(imm6);
        when "01xxxxx" esize = 32; elements = 2; shift_amount = 64 - UInt(imm6);
        when "1xxxxxx" esize = 64; elements = 1; shift_amount = 64 - UInt(imm6);
    endcase
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VST1 (multiple single elements)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 0 D#1 0 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """case type of
        when '0111'
            regs = 1;
            if align<1> == '1' then UNDEFINED;
        when '1010'
            regs = 2;
            if align == '11' then UNDEFINED;
        when '0110'
            regs = 3;
            if align<1> == '1' then UNDEFINED;
        when '0010'
            regs = 4;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VST1 (multiple single elements)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 0 D#1 0 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """case type of
        when '0111'
            regs = 1;
            if align<1> == '1' then UNDEFINED;
        when '1010'
            regs = 2;
            if align == '11' then UNDEFINED;
        when '0110'
            regs = 3;
            if align<1> == '1' then UNDEFINED;
        when '0010'
            regs = 4;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VST1 (single element from one lane)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 0 0 Rn#4 Vd#4 size#2 0 0 index_align#4 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case size of
        when '00'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); alignment = 1;
        when '01'
            if index_align<1> != '0' then UNDEFINED;
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            alignment = if index_align<0> == '0' then 1 else 2;
        when '10'
            if index_align<2> != '0' then UNDEFINED;
            if index_align<1:0> != '00' && index_align<1:0> != '11' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            alignment = if index_align<1:0> == '00' then 1 else 4;
    endcase
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "VST1 (single element from one lane)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 0 0 Rn#4 Vd#4 size#2 0 0 index_align#4 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case size of
        when '00'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); alignment = 1;
        when '01'
            if index_align<1> != '0' then UNDEFINED;
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            alignment = if index_align<0> == '0' then 1 else 2;
        when '10'
            if index_align<2> != '0' then UNDEFINED;
            if index_align<1:0> != '00' && index_align<1:0> != '11' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            alignment = if index_align<1:0> == '00' then 1 else 4;
    endcase
    d = UInt(D:Vd); n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "VST2 (multiple 2-element structures)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 0 D#1 0 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case type of
        when '1000'
            regs = 1; inc = 1;
            if align == '11' then UNDEFINED;
        when '1001'
            regs = 1; inc = 2;
            if align == '11' then UNDEFINED;
        when '0011'
            regs = 2; inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VST2 (multiple 2-element structures)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 0 D#1 0 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case type of
        when '1000'
            regs = 1; inc = 1;
            if align == '11' then UNDEFINED;
        when '1001'
            regs = 1; inc = 2;
            if align == '11' then UNDEFINED;
        when '0011'
            regs = 2; inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2+regs > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VST2 (single 2-element structure from one lane)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 0 0 Rn#4 Vd#4 size#2 0 1 index_align#4 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case size of
        when '00'
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
            alignment = if index_align<0> == '0' then 1 else 2;
        when '01'
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 4;
        when '10'
            if index_align<1> != '0' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 8;
    endcase
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST2 (single 2-element structure from one lane)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 0 0 Rn#4 Vd#4 size#2 0 1 index_align#4 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case size of
        when '00'
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
            alignment = if index_align<0> == '0' then 1 else 2;
        when '01'
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 4;
        when '10'
            if index_align<1> != '0' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 8;
    endcase
    d = UInt(D:Vd); d2 = d + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d2 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST3 (multiple 3-element structures)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 0 D#1 0 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' || align<1> == '1' then UNDEFINED;
    case type of
        when '0100'
            inc = 1;
        when '0101'
            inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align<0> == '0' then 1 else 8;
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST3 (multiple 3-element structures)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 0 D#1 0 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' || align<1> == '1' then UNDEFINED;
    case type of
        when '0100'
            inc = 1;
        when '0101'
            inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align<0> == '0' then 1 else 8;
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST3 (single 3-element structure from one lane)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 0 0 Rn#4 Vd#4 size#2 1 0 index_align#4 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case size of
        when '00'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
        when '01'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
        when '10'
            if index_align<1:0> != '00' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
    endcase
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST3 (single 3-element structure from one lane)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 0 0 Rn#4 Vd#4 size#2 1 0 index_align#4 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case size of
        when '00'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
        when '01'
            if index_align<0> != '0' then UNDEFINED;
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
        when '10'
            if index_align<1:0> != '00' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
    endcase
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d3 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST4 (multiple 4-element structures)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 0 D#1 0 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case type of
        when '0000'
            inc = 1;
        when '0001'
            inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST4 (multiple 4-element structures)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 0 D#1 0 0 Rn#4 Vd#4 type#4 size#2 align#2 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case type of
        when '0000'
            inc = 1;
        when '0001'
            inc = 2;
        otherwise
            SEE "Related encodings";
    endcase
    alignment = if align == '00' then 1 else 4 << UInt(align);
    ebytes = 1 << UInt(size); esize = 8 * ebytes; elements = 8 DIV ebytes;
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST4 (single 4-element structure from one lane)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 0 0 1 1 D#1 0 0 Rn#4 Vd#4 size#2 1 1 index_align#4 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case size of
        when '00'
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
            alignment = if index_align<0> == '0' then 1 else 4;
        when '01'
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 8;
        when '10'
            if index_align<1:0> == '11' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
            alignment = if index_align<1:0> == '00' then 1 else 4 << UInt(index_align<1:0>);
    endcase
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VST4 (single 4-element structure from one lane)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 1 0 0 1 D#1 0 0 Rn#4 Vd#4 size#2 1 1 index_align#4 Rm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    case size of
        when '00'
            ebytes = 1; esize = 8; index = UInt(index_align<3:1>); inc = 1;
            alignment = if index_align<0> == '0' then 1 else 4;
        when '01'
            ebytes = 2; esize = 16; index = UInt(index_align<3:2>);
            inc = if index_align<1> == '0' then 1 else 2;
            alignment = if index_align<0> == '0' then 1 else 8;
        when '10'
            if index_align<1:0> == '11' then UNDEFINED;
            ebytes = 4; esize = 32; index = UInt(index_align<3>);
            inc = if index_align<2> == '0' then 1 else 2;
            alignment = if index_align<1:0> == '00' then 1 else 4 << UInt(index_align<1:0>);
    endcase
    d = UInt(D:Vd); d2 = d + inc; d3 = d2 + inc; d4 = d3 + inc; n = UInt(Rn); m = UInt(Rm);
    wback = (m != 15); register_index = (m != 15 && m != 13);
    if n == 15 || d4 > 31 then UNPREDICTABLE;"""
} , {
    "name" : "VSTM",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VSTM{mode}<c> <Rn>{!}, <list>",
    "pattern" : "1 1 1 0 1 1 0 P#1 U#1 D#1 W#1 0 Rn#4 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """if P == '0' && U == '0' && W == '0' then SEE "Related encodings";
    if P == '1' && U == '0' && W == '1' && Rn == '1101' then SEE VPUSH;
    if P == '1' && W == '0' then SEE VSTR;
    if P == U && W == '1' then UNDEFINED;
    single_regs = FALSE; add = (U == '1'); wback = (W == '1');
    d = UInt(D:Vd); n = UInt(Rn); imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8) DIV 2;
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;
    if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VSTM",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VSTM{mode}<c> <Rn>{!}, <list>",
    "pattern" : "cond#4 1 1 0 P#1 U#1 D#1 W#1 0 Rn#4 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """if P == '0' && U == '0' && W == '0' then SEE "Related encodings";
    if P == '1' && U == '0' && W == '1' && Rn == '1101' then SEE VPUSH;
    if P == '1' && W == '0' then SEE VSTR;
    if P == U && W == '1' then UNDEFINED;
    single_regs = FALSE; add = (U == '1'); wback = (W == '1');
    d = UInt(D:Vd); n = UInt(Rn); imm32 = ZeroExtend(imm8:'00', 32);
    regs = UInt(imm8) DIV 2;
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;
    if regs == 0 || regs > 16 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VSTM",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VSTM{mode}<c> <Rn>{!}, <list>",
    "pattern" : "1 1 1 0 1 1 0 P#1 U#1 D#1 W#1 0 Rn#4 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """if P == '0' && U == '0' && W == '0' then SEE "Related encodings";
    if P == '1' && U == '0' && W == '1' && Rn == '1101' then SEE VPUSH;
    if P == '1' && W == '0' then SEE VSTR;
    if P == U && W == '1' then UNDEFINED;
    single_regs = TRUE; add = (U == '1'); wback = (W == '1'); d = UInt(Vd:D); n = UInt(Rn);
    imm32 = ZeroExtend(imm8:'00', 32); regs = UInt(imm8);
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;
    if regs == 0 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VSTM",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VSTM{mode}<c> <Rn>{!}, <list>",
    "pattern" : "cond#4 1 1 0 P#1 U#1 D#1 W#1 0 Rn#4 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """if P == '0' && U == '0' && W == '0' then SEE "Related encodings";
    if P == '1' && U == '0' && W == '1' && Rn == '1101' then SEE VPUSH;
    if P == '1' && W == '0' then SEE VSTR;
    if P == U && W == '1' then UNDEFINED;
    single_regs = TRUE; add = (U == '1'); wback = (W == '1'); d = UInt(Vd:D); n = UInt(Rn);
    imm32 = ZeroExtend(imm8:'00', 32); regs = UInt(imm8);
    if n == 15 && (wback || CurrentInstrSet() != InstrSet_ARM) then UNPREDICTABLE;
    if regs == 0 || (d+regs) > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VSTR",
    "encoding" : "T1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VSTR<c> <Dd>, [<Rn>{, #+/-<imm32>}]",
    "pattern" : "1 1 1 0 1 1 0 1 U#1 D#1 0 0 Rn#4 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """single_reg = FALSE; add = (U == '1'); imm32 = ZeroExtend(imm8:'00', 32);
    d = UInt(D:Vd); n = UInt(Rn);
    if n == 15 && CurrentInstrSet() != InstrSet_ARM then UNPREDICTABLE;"""
} , {
    "name" : "VSTR",
    "encoding" : "A1",
    "version" : "VFPv2, VFPv3, VFPv4, AdvancedSIMD",
    "format" : "VSTR<c> <Dd>, [<Rn>{, #+/-<imm32>}]",
    "pattern" : "cond#4 1 1 0 1 U#1 D#1 0 0 Rn#4 Vd#4 1 0 1 1 imm8#8",
    "decoder" : """single_reg = FALSE; add = (U == '1'); imm32 = ZeroExtend(imm8:'00', 32);
    d = UInt(D:Vd); n = UInt(Rn);
    if n == 15 && CurrentInstrSet() != InstrSet_ARM then UNPREDICTABLE;"""
} , {
    "name" : "VSTR",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VSTR<c> <Sd>, [<Rn>{, #+/-<imm32>}]",
    "pattern" : "1 1 1 0 1 1 0 1 U#1 D#1 0 0 Rn#4 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """single_reg = TRUE; add = (U == '1'); imm32 = ZeroExtend(imm8:'00', 32);
    d = UInt(Vd:D); n = UInt(Rn);
    if n == 15 && CurrentInstrSet() != InstrSet_ARM then UNPREDICTABLE;"""
} , {
    "name" : "VSTR",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "VSTR<c> <Sd>, [<Rn>{, #+/-<imm32>}]",
    "pattern" : "cond#4 1 1 0 1 U#1 D#1 0 0 Rn#4 Vd#4 1 0 1 0 imm8#8",
    "decoder" : """single_reg = TRUE; add = (U == '1'); imm32 = ZeroExtend(imm8:'00', 32);
    d = UInt(Vd:D); n = UInt(Rn);
    if n == 15 && CurrentInstrSet() != InstrSet_ARM then UNPREDICTABLE;"""
} , {
    "name" : "VSUB (integer)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSUB (integer)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 0 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSUB (floating-point)",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 1 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSUB (floating-point)",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 0 0 D#1 1 sz#1 Vn#4 Vd#4 1 1 0 1 N#1 Q#1 M#1 0 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if sz == '1' then UNDEFINED;
    advsimd = TRUE; esize = 32; elements = 2;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSUB (floating-point)",
    "encoding" : "T2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 0 0 D#1 1 1 Vn#4 Vd#4 1 0 1 sz#1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VSUB (floating-point)",
    "encoding" : "A2",
    "version" : "VFPv2, VFPv3, VFPv4",
    "format" : "CUSTOM",
    "pattern" : "cond#4 1 1 1 0 0 D#1 1 1 Vn#4 Vd#4 1 0 1 sz#1 N#1 1 M#1 0 Vm#4",
    "decoder" : """if FPSCR.LEN != '000' || FPSCR.STRIDE != '00' then SEE "VFP vectors";
    advsimd = FALSE; dp_operation = (sz == '1');
    d = if dp_operation then UInt(D:Vd) else UInt(Vd:D);
    n = if dp_operation then UInt(N:Vn) else UInt(Vn:N);
    m = if dp_operation then UInt(M:Vm) else UInt(Vm:M);"""
} , {
    "name" : "VSUBHN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "VSUBHN<c>.<dt> <Dd>, <Qn>, <Qm>",
    "pattern" : "1 1 1 0 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 1 1 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VSUBHN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "VSUBHN<c>.<dt> <Dd>, <Qn>, <Qm>",
    "pattern" : "1 1 1 1 0 0 1 0 1 D#1 size#2 Vn#4 Vd#4 0 1 1 0 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vn<0> == '1' || Vm<0> == '1' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VSUBL, VSUBW",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 U#1 1 1 1 1 1 D#1 size#2 Vn#4 Vd#4 0 0 1 op#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' || (op == '1' && Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize; is_vsubw = (op == '1');
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VSUBL, VSUBW",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 U#1 1 D#1 size#2 Vn#4 Vd#4 0 0 1 op#1 N#1 0 M#1 0 Vm#4",
    "decoder" : """if size == '11' then SEE "Related encodings";
    if Vd<0> == '1' || (op == '1' && Vn<0> == '1') then UNDEFINED;
    unsigned_ = (U == '1');
    esize = 8 << UInt(size); elements = 64 DIV esize; is_vsubw = (op == '1');
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);"""
} , {
    "name" : "VSWP",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 0 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size != '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VSWP",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 0 0 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size != '00' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VTBL, VTBX",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "V<op><c>.8 <Dd>, <list>, <Dm>",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 Vn#4 Vd#4 1 0 len#2 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """is_vtbl = (op == '0'); length = UInt(len)+1;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    if n+length > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VTBL, VTBX",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "V<op><c>.8 <Dd>, <list>, <Dm>",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 Vn#4 Vd#4 1 0 len#2 N#1 op#1 M#1 0 Vm#4",
    "decoder" : """is_vtbl = (op == '0'); length = UInt(len)+1;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm);
    if n+length > 32 then UNPREDICTABLE;"""
} , {
    "name" : "VTRN",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 0 0 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VTRN",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 0 0 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VTST",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 1 1 1 1 0 D#1 size#2 Vn#4 Vd#4 1 0 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VTST",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 0 0 0 1 0 0 D#1 size#2 Vn#4 Vd#4 1 0 0 0 N#1 Q#1 M#1 1 Vm#4",
    "decoder" : """if Q == '1' && (Vd<0> == '1' || Vn<0> == '1' || Vm<0> == '1') then UNDEFINED;
    if size == '11' then UNDEFINED;
    esize = 8 << UInt(size); elements = 64 DIV esize;
    d = UInt(D:Vd); n = UInt(N:Vn); m = UInt(M:Vm); regs = if Q == '0' then 1 else 2;"""
} , {
    "name" : "VUZP",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 0 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (Q == '0' && size == '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    quadword_operation = (Q == '1'); esize = 8 << UInt(size);
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VUZP",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 0 1 0 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (Q == '0' && size == '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    quadword_operation = (Q == '1'); esize = 8 << UInt(size);
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VZIP",
    "encoding" : "T1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 1 1 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 0 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (Q == '0' && size == '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    quadword_operation = (Q == '1'); esize = 8 << UInt(size);
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "VZIP",
    "encoding" : "A1",
    "version" : "AdvancedSIMD",
    "format" : "CUSTOM",
    "pattern" : "1 1 1 1 0 0 1 1 1 D#1 1 1 size#2 1 0 Vd#4 0 0 0 1 1 Q#1 M#1 0 Vm#4",
    "decoder" : """if size == '11' || (Q == '0' && size == '10') then UNDEFINED;
    if Q == '1' && (Vd<0> == '1' || Vm<0> == '1') then UNDEFINED;
    quadword_operation = (Q == '1'); esize = 8 << UInt(size);
    d = UInt(D:Vd); m = UInt(M:Vm);"""
} , {
    "name" : "WFE",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "WFE<c>",
    "pattern" : "1 0 1 1 1 1 1 1 0 0 1 0 0 0 0 0",
    "decoder" : """NOP();"""
} , {
    "name" : "WFE",
    "encoding" : "T2",
    "version" : "ARMv7",
    "format" : "WFE<c>.W",
    "pattern" : "1 1 1 1 0 0 1 1 1 0 1 0 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0",
    "decoder" : """NOP();"""
} , {
    "name" : "WFE",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "WFE<c>",
    "pattern" : "cond#4 0 0 1 1 0 0 1 0 0 0 0 0 1 1 1 1 0 0 0 0 0 0 0 0 0 0 1 0",
    "decoder" : """NOP();"""
} , {
    "name" : "WFI",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "WFI<c>",
    "pattern" : "1 0 1 1 1 1 1 1 0 0 1 1 0 0 0 0",
    "decoder" : """NOP();"""
} , {
    "name" : "WFI",
    "encoding" : "T2",
    "version" : "ARMv7",
    "format" : "WFI<c>.W",
    "pattern" : "1 1 1 1 0 0 1 1 1 0 1 0 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1",
    "decoder" : """NOP();"""
} , {
    "name" : "WFI",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "WFI<c>",
    "pattern" : "cond#4 0 0 1 1 0 0 1 0 0 0 0 0 1 1 1 1 0 0 0 0 0 0 0 0 0 0 1 1",
    "decoder" : """NOP();"""
} , {
    "name" : "YIELD",
    "encoding" : "T1",
    "version" : "ARMv7",
    "format" : "YIELD<c>",
    "pattern" : "1 0 1 1 1 1 1 1 0 0 0 1 0 0 0 0",
    "decoder" : """NOP();"""
} , {
    "name" : "YIELD",
    "encoding" : "T2",
    "version" : "ARMv7",
    "format" : "YIELD<c>.W",
    "pattern" : "1 1 1 1 0 0 1 1 1 0 1 0 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1",
    "decoder" : """NOP();"""
} , {
    "name" : "YIELD",
    "encoding" : "A1",
    "version" : "ARMv6K, ARMv7",
    "format" : "YIELD<c>",
    "pattern" : "cond#4 0011001000001111000000000001",
    "decoder" : """NOP();"""
} , {
    "name" : "CPS (Thumb)",
    "encoding" : "T1",
    "version" : "ARMv6All, ARMv7",
    "format" : "CPS<effect> <iflags>",
    "pattern" : "10110110011 im#1 0 A#1 I#1 F#1",
    "decoder" : """if A:I:F == '000' then UNPREDICTABLE;
enable = (im == '0');
disable = (im == '1');
changemode = FALSE;
affectA = (A == '1');
affectI = (I == '1');
affectF = (F == '1');
if InITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "CPS (Thumb)",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "CPS<effect>.W <iflags>{, #<mode>}",
    "pattern" : "111100111010111110000 imod#2 M#1 A#1 I#1 F#1 mode#5",
    "decoder" : """if imod == '00' && M == '0' then SEE "Hint instructions";
if mode != '00000' && M == '0' then UNPREDICTABLE;
if (imod<1> == '1' && A:I:F == '000') || (imod<1> == '0' && A:I:F != '000') then UNPREDICTABLE;
enable = (imod == '10');
disable = (imod == '11');
changemode = (M == '1');
affectA = (A == '1');
affectI = (I == '1');
affectF = (F == '1');
if imod == '01' || InITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "CPS (ARM)",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "CPS<effect> <iflags>{, #<mode>}",
    "pattern" : "111100010000 imod#2 M#1 00000000 A#1 I#1 F#1 0 mode#5",
    "decoder" : """if mode != '00000' && M == '0' then UNPREDICTABLE;
if (imod<1> == '1' && A:I:F == '000') || (imod<1> == '0' && A:I:F != '000') then UNPREDICTABLE;
enable = (imod == '10');
disable = (imod == '11');
changemode = (M == '1');
affectA = (A == '1');
affectI = (I == '1');
affectF = (F == '1');
if (imod == '00' && M == '0') || imod == '01' then UNPREDICTABLE;"""
} , {
    "name" : "ERET",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7VE",
    "format" : "ERET",
    "pattern" : "111100111101111010001111 imm8#8",
    "decoder" : """if imm8 != '00000000' then SEE SUBS PC, LR and related instructions;"""
} , {
    "name" : "ERET",
    "encoding" : "A1",
    "version" : "ARMv7VE",
    "format" : "ERET",
    "pattern" : "cond#4 0001011000000000000001101110",
    "decoder" : """NOP();"""
} , {
    "name" : "HVC",
    "encoding" : "T1",
    "version" : "ARMv7VE",
    "format" : "HVC #<imm16>",
    "pattern" : "111101111110 imm4#4 1000 imm12#12",
    "decoder" : """if InITBlock() then UNPREDICTABLE;
imm16 = imm4:imm12;"""
} , {
    "name" : "HVC",
    "encoding" : "A1",
    "version" : "ARMv7VE",
    "format" : "HVC #<imm16>",
    "pattern" : "cond#4 00010100 imm12#12 0111 imm4#4",
    "decoder" : """if cond != 1110 then UNPREDICTABLE;
imm16 = imm12:imm4;"""
} , {
    "name" : "LDM (exception return)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDM<amode><c> <Rn>{!}, <registers_with_pc>^",
    "pattern" : "cond#4 100 P#1 U#1 1 W#1 1 Rn#4 1 register_list#15",
    "decoder" : """n = UInt(Rn);
registers = register_list;
wback = (W == '1');
increment = (U == '1');
wordhigher = (P == U);
if n == 15 then UNPREDICTABLE;
if wback && registers<n> == '1' && ArchVersion() >= 7 then UNPREDICTABLE;"""
} , {
    "name" : "LDM (User registers)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "LDM<amode><c> <Rn>, <registers_without_pc>^",
    "pattern" : "cond#4 100 P#1 U#1 101 Rn#4 0 register_list#15",
    "decoder" : """n = UInt(Rn);
registers = register_list;
increment = (U == '1');
wordhigher = (P == U);
if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "MRS (Banked register)",
    "encoding" : "T1",
    "version" : "ARMv7VE",
    "format" : "MRS<c> <Rd>, <banked_reg>",
    "pattern" : "11110011111 R#1 m1#4 1000 Rd#4 001 m#1 0000",
    "decoder" : """d = UInt(Rd); read_spsr = (R == '1'); if d IN {13,15} then UNPREDICTABLE; SYSm = m:m1;"""
} , {
    "name" : "MRS (Banked register)",
    "encoding" : "A1",
    "version" : "ARMv7VE",
    "format" : "MRS<c> <Rd>, <banked_reg>",
    "pattern" : "cond#4 00010 R#1 10 m1#4 1111001 m#1 0000 Rd#4",
    "decoder" : """d = UInt(Rd); read_spsr = (R == '1'); if d == 15 then UNPREDICTABLE; SYSm = m:m1;"""
} , {
    "name" : "RFE",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "RFEDB<c> <Rn>{!}",
    "pattern" : "1110100000 W#1 1 Rn#4 1100000000000000",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then UNPREDICTABLE;
n = UInt(Rn); wback = (W == '1'); increment = FALSE; wordhigher = FALSE; if n == 15 then UNPREDICTABLE;
if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "RFE",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "RFE{IA}<c> <Rn>{!}",
    "pattern" : "1110100110 W#1 1 Rn#4 1100000000000000",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then UNPREDICTABLE;
n = UInt(Rn); wback = (W == '1'); increment = TRUE; wordhigher = FALSE; if n == 15 then UNPREDICTABLE;
if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "RFE",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "RFE<amode> <Rn>{!}",
    "pattern" : "1111100 P#1 U#1 0 W#1 1 Rn#4 0000101000000000",
    "decoder" : """n = UInt(Rn); wback = (W == '1'); inc = (U == '1'); wordhigher = (P == U); if n == 15 then UNPREDICTABLE;"""
} , {
    "name" : "SMC (previously SMI)",
    "encoding" : "T1",
    "version" : "ARMSecurityExtension",
    "format" : "SMC<c> #<imm32>",
    "pattern" : "111101111111 imm4#4 1000000000000000",
    "decoder" : """imm32 = ZeroExtend(imm4, 32); if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "SMC (previously SMI)",
    "encoding" : "T2",
    "version" : "ARMSecurityExtension",
    "format" : "SMC<c> #<imm32>",
    "pattern" : "cond#4 000101100000000000000111 imm4#4",
    "decoder" : """imm32 = ZeroExtend(imm4, 32);"""
} , {
    "name" : "SRS, Thumb",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SRSDB<c> SP{!}, #<mode>",
    "pattern" : "1110100000 W#1 0110111000000000 mode#5",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then UNPREDICTABLE; wback = (W == '1'); increment = FALSE; wordhigher = FALSE;"""
} , {
    "name" : "SRS, Thumb",
    "encoding" : "T2",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SRSDB<c> SP{!}, #<mode>",
    "pattern" : "1110100110 W#1 0110111000000000 mode#5",
    "decoder" : """if CurrentInstrSet() == InstrSet_ThumbEE then UNPREDICTABLE; wback = (W == '1'); increment = TRUE; wordhigher = FALSE;"""
} , {
    "name" : "SRS, ARM",
    "encoding" : "A1",
    "version" : "ARMv6All, ARMv7",
    "format" : "SRS<amode> SP{!}, #<mode>",
    "pattern" : "1111100 P#1 U#1 1 W#1 0110100000101000 mode#5",
    "decoder" : """wback = (W == '1'); inc = (U == '1'); wordhigher = (P == U);"""
} , {
    "name" : "STM (User registers)",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "STM<amode><c> <Rn>, <registers>^",
    "pattern" : "cond#4 100 P#1 U#1 100 Rn#4 register_list#16",
    "decoder" : """n = UInt(Rn); registers = register_list; increment = (U == '1'); wordhigher = (P == U); if n == 15 || BitCount(registers) < 1 then UNPREDICTABLE;"""
} , {
    "name" : "SUBS PC, LR and related instructions, Thumb",
    "encoding" : "T1",
    "version" : "ARMv6T2, ARMv7",
    "format" : "SUBS<c> PC, LR, #<imm32>",
    "pattern" : "111100111101111010001111 imm8#8",
    "decoder" : """if IsZero(imm8) then SEE ERET;
if CurrentInstrSet() == InstrSet_ThumbEE then UNPREDICTABLE;
if CurrentModeIsHyp() then UNDEFINED; n = 14; imm32 = ZeroExtend(imm8, 32);
if InITBlock() && !LastInITBlock() then UNPREDICTABLE;"""
} , {
    "name" : "SUBS PC, LR and related instructions, ARM",
    "encoding" : "A1",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 001 opcode_#4 1 Rn#4 1111 imm12#12",
    "decoder" : """n = UInt(Rn); imm32 = ARMExpandImm(imm12); register_form = FALSE;"""
} , {
    "name" : "SUBS PC, LR and related instructions, ARM",
    "encoding" : "A2",
    "version" : "ARMv4All, ARMv5TAll, ARMv6All, ARMv7",
    "format" : "CUSTOM",
    "pattern" : "cond#4 000 opcode_#4 1 Rn#4 1111 imm5#5 type#2 0 Rm#4",
    "decoder" : """n = UInt(Rn); m = UInt(Rm); register_form = TRUE; (shift_t, shift_n) = DecodeImmShift(type, imm5);"""
} , ]
