instructions = [{
    "name" : "ADC immediate",
    "operation" : """if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], imm32, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
    endif

    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif"""
}, { 
    "name" : "ADC (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], shifted, APSR.C);

    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "ADC (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], shifted, APSR.C);
    R[d] = result;
    
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif
"""
}, { 
    "name" : "ADD (immediate, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], imm32, '0');
    R[d] = result;
    
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif
"""
}, { 
    "name" : "ADD (immediate, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], imm32, '0');
    
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "ADD (register, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], shifted, '0');
    
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "ADD (register, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], shifted, '0');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "ADD (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], shifted, '0');
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif
"""
}, { 
    "name" : "ADD (SP plus immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[13], imm32, '0');
    if d == 15 then 
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "ADD (SP plus register, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[13], shifted, '0');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "ADD (SP plus register, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[13], shifted, '0');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "ADR",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = if add then (Align(R[15],4) + imm32) else (Align(R[15],4) - imm32);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
    endif
endif
"""
}, { 
    "name" : "AND (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[n] AND imm32;
    if d == 15 then 
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "AND (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] AND shifted;
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "AND (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] AND shifted;
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "ASR (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry) = Shift_C(R[m], SRType_ASR, shift_n, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "ASR (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[m]<7:0>);
    (result, carry) = Shift_C(R[n], SRType_ASR, shift_n, APSR.C);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "B",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    BranchWritePC(R[15] + imm32);
endif
"""
}, { 
    "name" : "BFC",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if msbit >= lsbit then
        tmp_val = R[d];
        set_bits(tmp_val, msbit, lsbit, Replicate('0', msbit-lsbit+1));
        R[d] = tmp_val;
    else
        UNPREDICTABLE;
    endif
endif
"""
}, { 
    "name" : "BFI",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if msbit >= lsbit then
        tmp = msbit-lsbit;
        tmp_val = R[d];
        set_bits(tmp_val, msbit, lsbit, R[n]<tmp:0>);
        R[d] = tmp_val;
    else
        UNPREDICTABLE;
    endif
endif
"""
}, { 
    "name" : "BIC (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[n] AND NOT(imm32);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "BIC (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] AND NOT(shifted);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "BIC (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] AND NOT(shifted);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "BKPT",
    "operation" : """
EncodingSpecificOperations();
BKPTInstrDebugEvent();
"""
}, { 
    "name" : "BL, BLX (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if CurrentInstrSet() == InstrSet_ARM then
        R[14] = R[15] - 4;
    else
        R[14] = R[15]<31:1> : '1';
    endif

    if targetInstrSet == InstrSet_ARM then
        targetAddress = Align(R[15],4) + imm32;
    else
        targetAddress = R[15] + imm32;
    endif

    SelectInstrSet(targetInstrSet);
    BranchWritePC(targetAddress);
endif
"""
}, { 
    "name" : "BLX (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    target = R[m];
    if CurrentInstrSet() == InstrSet_ARM then
        next_instr_addr = R[15] - 4;
        R[14] = next_instr_addr;
    else
        next_instr_addr = R[15] - 2;
        R[14] = next_instr_addr<31:1> : '1';
    endif

    BXWritePC(target);
endif
"""
}, { 
    "name" : "BX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    BXWritePC(R[m]);
endif
"""
}, { 
    "name" : "BXJ",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if HaveVirtExt() && !IsSecure() && !CurrentModeIsHyp() && HSTR.TJDBX == '1' then
        HSRString = Zeros(25);
        tmp_val = HSRString;
        set_bits(tmp_val, 3, 0, m);
        HSRString = tmp_val;
        WriteHSR('001010', HSRString);
        TakeHypTrapException();
    endif

    if JMCR.JE == '0' || CurrentInstrSet() == InstrSet_ThumbEE then
        BXWritePC(R[m]);
    else
        if JazelleAcceptsExecution() then
            SwitchToJazelleExecution();
        else
            SUBARCHITECTURE_DEFINED handler call;
        endif
    endif
endif
"""
}, { 
    "name" : "CBNZ, CBZ",
    "operation" : """
EncodingSpecificOperations();
if nonzero ^ IsZero(R[n]) then
    BranchWritePC(R[15] + imm32);
endif
"""
}, { 
    "name" : "CDP, CDP2",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if !Coproc_Accepted(cp, ThisInstr()) then
        GenerateCoprocessorException();
    else
        Coproc_InternalOperation(cp, ThisInstr());
    endif
endif
"""
}, { 
    "name" : "CLREX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    ClearExclusiveLocal(ProcessorID());
endif
"""
}, { 
    "name" : "CLZ",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = CountLeadingZeroBits(R[m]);
    R[d] = result<31:0>;
endif
"""
}, { 
    "name" : "CMN (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], imm32, '0');
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
    APSR.V = overflow;
endif
"""
}, { 
    "name" : "CMN (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], shifted, '0');
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
    APSR.V = overflow;
endif
"""
}, { 
    "name" : "CMN (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], shifted, '0');
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
    APSR.V = overflow;
endif
"""
}, { 
    "name" : "CMP (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), '1');
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
    APSR.V = overflow;
endif
"""
}, { 
    "name" : "CMP (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), '1');
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
    APSR.V = overflow;
endif
"""
}, { 
    "name" : "CMP (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), '1');
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
    APSR.V = overflow;
endif
"""
}, { 
    "name" : "CPS (Thumb)",
    "operation" : """
EncodingSpecificOperations();
if CurrentModeIsNotUser() then
    cpsr_val = CPSR;
    if enable then
        if affectA then set_bit(cpsr_val, 8, 0); endif
        if affectI then set_bit(cpsr_val, 7, 0); endif
        if affectF then set_bit(cpsr_val, 6, 0); endif
    endif

    if disable then
        if affectA then set_bit(cpsr_val, 8, 1); endif
        if affectI then set_bit(cpsr_val, 7, 1); endif
        if affectF then set_bit(cpsr_val, 6, 1); endif
    endif

    if changemode then
        set_bits(cpsr_val, 4, 0, mode);
    endif

    CPSRWriteByInstr(cpsr_val, '1111', FALSE);
    if CPSR<4:0> == '11010' && CPSR.J == '1' && CPSR.T == '1' then
        UNPREDICTABLE;
    endif
endif
"""
}, { 
    "name" : "CPS (ARM)",
    "operation" : """
EncodingSpecificOperations();
if CurrentModeIsNotUser() then
    cpsr_val = CPSR;
    if enable then
        if affectA then set_bit(cpsr_val, 8, 0); endif
        if affectI then set_bit(cpsr_val, 7, 0); endif
        if affectF then set_bit(cpsr_val, 6, 0); endif
    endif

    if disable then
        if affectA then set_bit(cpsr_val, 8, 1); endif
        if affectI then set_bit(cpsr_val, 7, 1); endif
        if affectF then set_bit(cpsr_val, 6, 1); endif
    endif

    if changemode then
        set_bits(cpsr_val, 4, 0, mode);
    endif
    
    CPSRWriteByInstr(cpsr_val, '1111', FALSE);
endif
"""
}, { 
    "name" : "DBG",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    Hint_Debug(option);
endif
"""
}, { 
    "name" : "DMB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    case option of
        when '0010' domain = MBReqDomain_OuterShareable; types = MBReqTypes_Writes;
        when '0011' domain = MBReqDomain_OuterShareable; types = MBReqTypes_All;
        when '0110' domain = MBReqDomain_Nonshareable; types = MBReqTypes_Writes;
        when '0111' domain = MBReqDomain_Nonshareable; types = MBReqTypes_All;
        when '1010' domain = MBReqDomain_InnerShareable; types = MBReqTypes_Writes;
        when '1011' domain = MBReqDomain_InnerShareable; types = MBReqTypes_All;
        when '1110' domain = MBReqDomain_FullSystem; types = MBReqTypes_Writes;
        otherwise   domain = MBReqDomain_FullSystem; types = MBReqTypes_All;
    endcase

    if HaveVirtExt() && !IsSecure() && !CurrentModeIsHyp() then
        if HCR.BSU == '11' then
            domain = MBReqDomain_FullSystem;
        endif
    
        if HCR.BSU == '10' && domain != MBReqDomain_FullSystem then
            domain = MBReqDomain_OuterShareable;
        endif

        if HCR.BSU == '01' && domain == MBReqDomain_Nonshareable then
            domain = MBReqDomain_InnerShareable;
        endif
    endif

    DataMemoryBarrier(domain, types);
endif
"""
}, { 
    "name" : "DSB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    case option of
        when '0010' domain = MBReqDomain_OuterShareable; types = MBReqTypes_Writes;
        when '0011' domain = MBReqDomain_OuterShareable; types = MBReqTypes_All;
        when '0110' domain = MBReqDomain_Nonshareable; types = MBReqTypes_Writes;
        when '0111' domain = MBReqDomain_Nonshareable; types = MBReqTypes_All;
        when '1010' domain = MBReqDomain_InnerShareable; types = MBReqTypes_Writes;
        when '1011' domain = MBReqDomain_InnerShareable; types = MBReqTypes_All;
        when '1110' domain = MBReqDomain_FullSystem; types = MBReqTypes_Writes;
        otherwise   domain = MBReqDomain_FullSystem; types = MBReqTypes_All;
    endcase

    if HaveVirtExt() && !IsSecure() && !CurrentModeIsHyp() then
        if HCR.BSU == '11' then
            domain = MBReqDomain_FullSystem;
        endif

        if HCR.BSU == '10' && domain != MBReqDomain_FullSystem then
            domain = MBReqDomain_OuterShareable;
        endif

        if HCR.BSU == '01' && domain == MBReqDomain_Nonshareable then
            domain = MBReqDomain_InnerShareable;
        endif
    endif
    
    DataSynchronizationBarrier(domain, types);
endif
"""
}, { 
    "name" : "EOR (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[n] EOR imm32;
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "EOR (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] EOR shifted;
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "EOR (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] EOR shifted;
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "ERET",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if (CurrentModeIsUserOrSystem() || CurrentInstrSet() == InstrSet_ThumbEE) then
        UNPREDICTABLE;
    else
        new_pc_value = if CurrentModeIsHyp() then ELR_hyp else R[14];

        CPSRWriteByInstr(SPSR, '1111', TRUE);
        if CPSR<4:0> == '11010' && CPSR.J == '1' && CPSR.T == '1' then
            UNPREDICTABLE;
        else
            BranchWritePC(new_pc_value);
        endif
    endif
endif
"""
}, { 
    "name" : "HVC",
    "operation" : """
EncodingSpecificOperations();
if !HasVirtExt() || IsSecure() || !CurrentModeIsNotUser() then
    UNDEFINED;
else
    if SCR.HCE == '0' then
        if CurrentModeIsHyp() then
            UNPREDICTABLE;
        else
            UNDEFINED;
        endif
    else
        CallHypervisor(imm32);
    endif
endif
"""
}, { 
    "name" : "ISB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    InstructionSynchronizationBarrier();
endif
"""
}, { 
    "name" : "IT",
    "operation" : """
EncodingSpecificOperations();
tmp_val = ITSTATE.IT;
set_bits(tmp_val, 7, 0, firstcond:mask);
ITSTATE.IT = tmp_val;
"""
}, { 
    "name" : "LDC, LDC2 (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();

    if !Coproc_Accepted(cp, ThisInstr()) then
        GenerateCoprocessorException();
    else
        NullCheckIfThumbEE(n);
        offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
        address = if index then offset_addr else R[n];
        
        repeat
            Coproc_SendLoadedWord(MemA[address,4], cp, ThisInstr());
            address = address + 4;
        until Coproc_DoneLoading(cp, ThisInstr())
        
        if wback then
            R[n] = offset_addr;
        endif
    endif
endif
"""
}, { 
    "name" : "LDC, LDC2 (literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();

    if !Coproc_Accepted(cp, ThisInstr()) then
        GenerateCoprocessorException();
    else
        NullCheckIfThumbEE(15);
        offset_addr = if add then (Align(R[15],4) + imm32) else (Align(R[15],4) - imm32);
        address = if index then offset_addr else Align(R[15],4);

        repeat
            Coproc_SendLoadedWord(MemA[address,4], cp, ThisInstr());
            address = address + 4;
        until Coproc_DoneLoading(cp, ThisInstr())
    endif
endif
"""
}, { 
    "name" : "LDM/LDMIA/LDMFD (Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    for i = 0 to 14
        if registers<i> == '1' then
            R[i] = MemA[address,4];
            address = address + 4;
        endif
    endfor
    
    if registers<15> == '1' then
        LoadWritePC(MemA[address,4]);
    endif

    if wback && registers<n> == '0' then
        R[n] = R[n] + 4*BitCount(registers);
    endif

    if wback && registers<n> == '1' then
        R[n] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDM/LDMIA/LDMFD (ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    for i = 0 to 14
        if registers<i> == '1' then
            R[i] = MemA[address,4];
            address = address + 4;
        endif
    endfor

    if registers<15> == '1' then
        LoadWritePC(MemA[address,4]);
    endif

    if wback && registers<n> == '0' then
        R[n] = R[n] + 4*BitCount(registers);
    endif

    if wback && registers<n> == '1' then
        R[n] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDMDA/LDMFA",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    address = R[n] - 4*BitCount(registers) + 4;
    for i = 0 to 14
        if registers<i> == '1' then
            R[i] = MemA[address,4];
            address = address + 4;
        endif
    endfor
    
    if registers<15> == '1' then
        LoadWritePC(MemA[address,4]);
    endif

    if wback && registers<n> == '0' then
        R[n] = R[n] - 4*BitCount(registers);
    endif

    if wback && registers<n> == '1' then
        R[n] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDMDB/LDMEA",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n] - 4*BitCount(registers);
    for i = 0 to 14
        if registers<i> == '1' then
            R[i] = MemA[address,4];
            address = address + 4;
        endif
    endfor
    
    if registers<15> == '1' then
        LoadWritePC(MemA[address,4]);
    endif

    if wback && registers<n> == '0' then
        R[n] = R[n] - 4*BitCount(registers);
    endif

    if wback && registers<n> == '1' then
        R[n] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDMIB/LDMED",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    address = R[n] + 4;
    for i = 0 to 14
        if registers<i> == '1' then
            R[i] = MemA[address,4];
            address = address + 4;
        endif
    endfor

    if registers<15> == '1' then
        LoadWritePC(MemA[address,4]);
    endif

    if wback && registers<n> == '0' then
        R[n] = R[n] + 4*BitCount(registers);
    endif

    if wback && registers<n> == '1' then
        R[n] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDR (immediate, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    data = MemU[address,4];
    if wback then
        R[n] = offset_addr;
    endif

    if t == 15 then
        if address<1:0> == '00' then
            LoadWritePC(data);
        else
            UNPREDICTABLE;
        endif
    endif

    if UnalignedSupport() || address<1:0> == '00' then
        R[t] = data;
    else 
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDR (immediate, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    data = MemU[address,4];
    if wback then
        R[n] = offset_addr;
    endif

    if t == 15 then
        if address<1:0> == '00' then
            LoadWritePC(data);
        else
            UNPREDICTABLE;
        endif
    endif
    
    if UnalignedSupport() || address<1:0> == '00' then
        R[t] = data;
    else
        R[t] = ROR(data, 8*UInt(address<1:0>));
    endif
endif
"""
}, { 
    "name" : "LDR (literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(15);
    base = Align(R[15],4);
    address = if add then (base + imm32) else (base - imm32);
    data = MemU[address,4];

    if t == 15 then
        if address<1:0> == '00' then
            LoadWritePC(data);
        else
            UNPREDICTABLE;
        endif
    endif

    if UnalignedSupport() || address<1:0> == '00' then
        R[t] = data;
    else
        if CurrentInstrSet() == InstrSet_ARM then
            R[t] = ROR(data, 8 * UInt(address<1:0>));
        else
            R[t] = UNKNOWN_VALUE;
        endif
    endif
endif
"""
}, { 
    "name" : "LDR (register, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = (R[n] + offset);
    address = offset_addr;
    data = MemU[address,4];
    
    if t == 15 then
        if address<1:0> == '00' then
            LoadWritePC(data);
        else
            UNPREDICTABLE;
        endif
    endif

    if UnalignedSupport() || address<1:0> == '00' then
        R[t] = data;
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDR (register, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if index then offset_addr else R[n];
    data = MemU[address,4];

    if wback then R[n] = offset_addr;
        if t == 15 then
            if address<1:0> == '00' then
                LoadWritePC(data);
            else
                UNPREDICTABLE;
            endif
        endif
    endif

    if UnalignedSupport() || address<1:0> == '00' then
        R[t] = data;
    else
        R[t] = ROR(data, 8*UInt(address<1:0>));
    endif
endif
"""
}, { 
    "name" : "LDRB (immediate, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    R[t] = ZeroExtend(MemU[address,1], 32);
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDRB (immediate, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    R[t] = ZeroExtend(MemU[address,1], 32);
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDRB (literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(15);
    base = Align(R[15],4);
    address = if add then (base + imm32) else (base - imm32);
    R[t] = ZeroExtend(MemU[address,1], 32);
endif
"""
}, { 
    "name" : "LDRB (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if index then offset_addr else R[n];
    R[t] = ZeroExtend(MemU[address,1],32);
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDRBT",
    "operation" : """
if ConditionPassed() then
    if CurrentModeIsHyp() then
        UNPREDICTABLE;
    endif

    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = if register_form then Shift(R[m], shift_t, shift_n, APSR.C) else imm32;
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if postindex then R[n] else offset_addr;
    R[t] = ZeroExtend(MemU_unpriv[address,1],32);
    if postindex then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDRD (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    
    if HaveLPAE() && address<2:0> == '000' then
        data = MemA[address,8];
        if BigEndian() then
            R[t] = data<63:32>;
            R[t2] = data<31:0>;
        else
            R[t] = data<31:0>;
            R[t2] = data<63:32>;
        endif
    else
        tmp1 = address + 4;
        R[t] = MemA[address,4];
        R[t2] = MemA[tmp1,4];
    endif
    
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDRD (literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(15);
    address = if add then (Align(R[15],4) + imm32) else (Align(R[15],4) - imm32);
    if HaveLPAE() && address<2:0> == '000' then
        data = MemA[address,8];
        if BigEndian() then
            R[t] = data<63:32>;
            R[t2] = data<31:0>;
        else
            R[t] = data<31:0>;
            R[t2] = data<63:32>;
        endif
    else
        tmp1 = address + 4;
        R[t] = MemA[address,4];
        R[t2] = MemA[tmp1,4];
    endif
endif
"""
}, { 
    "name" : "LDRD (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset_addr = if add then (R[n] + R[m]) else (R[n] - R[m]);
    address = if index then offset_addr else R[n];
    if HaveLPAE() && address<2:0> == '000' then
        data = MemA[address,8];
        if BigEndian() then
            R[t] = data<63:32>;
            R[t2] = data<31:0>;
        else
            R[t] = data<31:0>;
            R[t2] = data<63:32>;
        endif
    else
        tmp1 = address + 4;
        R[t] = MemA[address,4];
        R[t2] = MemA[tmp1,4];
    endif

    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDREX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n] + imm32;
    SetExclusiveMonitors(address,4);
    R[t] = MemA[address,4];
endif
"""
}, { 
    "name" : "LDREXB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    SetExclusiveMonitors(address,1);
    R[t] = ZeroExtend(MemA[address,1], 32);
endif
"""
}, { 
    "name" : "LDREXD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    SetExclusiveMonitors(address,8);
    value = MemA[address,8];
    R[t] = if BigEndian() then value<63:32> else value<31:0>;
    R[t2] = if BigEndian() then value<31:0> else value<63:32>;
endif
"""
}, { 
    "name" : "LDREXH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    SetExclusiveMonitors(address,2);
    R[t] = ZeroExtend(MemA[address,2], 32);
endif
"""
}, { 
    "name" : "LDRH (immediate, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    data = MemU[address,2];
    
    if wback then
        R[n] = offset_addr;
    endif
    
    if UnalignedSupport() || address<0> == '0' then
        R[t] = ZeroExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRH (immediate, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    data = MemU[address,2];
    
    if wback then
        R[n] = offset_addr;
    endif

    if UnalignedSupport() || address<0> == '0' then
        R[t] = ZeroExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRH (literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(15);
    base = Align(R[15],4);
    address = if add then (base + imm32) else (base - imm32);
    data = MemU[address,2];
    if UnalignedSupport() || address<0> == '0' then
        R[t] = ZeroExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRH (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if index then offset_addr else R[n];
    data = MemU[address,2];
    
    if wback then
        R[n] = offset_addr;
    endif

    if UnalignedSupport() || address<0> == '0' then
        R[t] = ZeroExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRHT",
    "operation" : """
if ConditionPassed() then
    if CurrentModeIsHyp() then
        UNPREDICTABLE;
    endif

    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = if register_form then R[m] else imm32;
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if postindex then R[n] else offset_addr;
    data = MemU_unpriv[address,2];
    if postindex then
        R[n] = offset_addr;
    endif
    
    if UnalignedSupport() || address<0> == '0' then
        R[t] = ZeroExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRSB (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    R[t] = SignExtend(MemU[address,1], 32);
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDRSB (literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(15);
    base = Align(R[15],4);
    address = if add then (base + imm32) else (base - imm32);
    R[t] = SignExtend(MemU[address,1], 32);
endif
"""
}, { 
    "name" : "LDRSB (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if index then offset_addr else R[n];
    R[t] = SignExtend(MemU[address,1], 32);
    
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDRSBT",
    "operation" : """
if ConditionPassed() then
    if CurrentModeIsHyp() then
        UNPREDICTABLE;
    endif

    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = if register_form then R[m] else imm32;
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if postindex then R[n] else offset_addr;
    R[t] = SignExtend(MemU_unpriv[address,1], 32);
    
    if postindex then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "LDRSH (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    data = MemU[address,2];
    
    if wback then
        R[n] = offset_addr;
    endif

    if UnalignedSupport() || address<0> == '0' then
        R[t] = SignExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRSH (literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(15);
    base = Align(R[15],4);
    address = if add then (base + imm32) else (base - imm32);
    data = MemU[address,2];
    
    if UnalignedSupport() || address<0> == '0' then
        R[t] = SignExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRSH (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if index then offset_addr else R[n];
    data = MemU[address,2];
    if wback then
        R[n] = offset_addr;
    endif

    if UnalignedSupport() || address<0> == '0' then
        R[t] = SignExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRSHT",
    "operation" : """
if ConditionPassed() then
    if CurrentModeIsHyp() then
        UNPREDICTABLE;
    endif

    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = if register_form then R[m] else imm32;
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if postindex then R[n] else offset_addr;
    data = MemU_unpriv[address,2];
    
    if postindex then
        R[n] = offset_addr;
    endif

    if UnalignedSupport() || address<0> == '0' then
        R[t] = SignExtend(data, 32);
    else
        R[t] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "LDRT",
    "operation" : """
if ConditionPassed() then
    if CurrentModeIsHyp() then
        UNPREDICTABLE;
    endif

    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = if register_form then Shift(R[m], shift_t, shift_n, APSR.C) else imm32;
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if postindex then R[n] else offset_addr;
    data = MemU_unpriv[address,4];
    
    if postindex then
        R[n] = offset_addr;
    endif

    if UnalignedSupport() || address<1:0> == '00' then
        R[t] = data;
    else
        if CurrentInstrSet() == InstrSet_ARM then
            R[t] = ROR(data, 8*UInt(address<1:0>));
        else
            R[t] = UNKNOWN_VALUE;
        endif
    endif
endif
"""
}, { 
    "name" : "LSL (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry) = Shift_C(R[m], SRType_LSL, shift_n, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "LSL (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[m]<7:0>);
    (result, carry) = Shift_C(R[n], SRType_LSL, shift_n, APSR.C);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "LSR (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry) = Shift_C(R[m], SRType_LSR, shift_n, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "LSR (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[m]<7:0>);
    (result, carry) = Shift_C(R[n], SRType_LSR, shift_n, APSR.C);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "MCR, MCR2",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if !Coproc_Accepted(cp, ThisInstr()) then
        GenerateCoprocessorException();
    else
        Coproc_SendOneWord(R[t], cp, ThisInstr());
    endif
endif
"""
}, { 
    "name" : "MCRR, MCRR2",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if !Coproc_Accepted(cp, ThisInstr()) then
        GenerateCoprocessorException();
    else
        Coproc_SendTwoWords(R[t2], R[t], cp, ThisInstr());
    endif
endif
"""
}, { 
    "name" : "MLA",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand1 = SInt(R[n]);
    operand2 = SInt(R[m]);
    addend = SInt(R[a]);
    result = operand1 * operand2 + addend;
    R[d] = result<31:0>;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        if ArchVersion() == 4 then
            APSR.C = UNKNOWN_VALUE;
        endif
    endif
endif
"""
}, { 
    "name" : "MLS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand1 = SInt(R[n]);
    operand2 = SInt(R[m]);
    addend = SInt(R[a]);
    result = addend - operand1 * operand2;
    R[d] = result<31:0>;
endif
"""
}, { 
    "name" : "MOV (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = imm32;
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "MOV (register, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[m];
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
        endif
    endif
endif
"""
}, { 
    "name" : "MOV (register, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[m];
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
        endif
    endif
endif
"""
}, { 
    "name" : "MOVT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    tmp_val = R[d];
    set_bits(tmp_val, 31, 16, imm32);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "MRC, MRC2",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if !Coproc_Accepted(cp, ThisInstr()) then
        GenerateCoprocessorException();
    else
        value = Coproc_GetOneWord(cp, ThisInstr());
        if t != 15 then
            R[t] = value;
        else
            APSR.N = value<31>;
            APSR.Z = value<30>;
            APSR.C = value<29>;
            APSR.V = value<28>;
        endif
    endif
endif
"""
}, { 
    "name" : "MRRC, MRRC2",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if !Coproc_Accepted(cp, ThisInstr()) then
        GenerateCoprocessorException();
    else
        (tmp0, tmp1) = Coproc_GetTwoWords(cp, ThisInstr());
        R[t2] = tmp0;
        R[t] = tmp1;
    endif
endif
"""
}, { 
    "name" : "MRS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    R[d] = APSR;
endif
"""
}, { 
    "name" : "MRS (Banked register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if !CurrentModeIsNotUser() then
        UNPREDICTABLE;
    else
        mode = CPSR.M;
        if read_spsr then
            SPSRaccessValid(SYSm, mode);
            case SYSm of
                when '01110' R[d] = SPSR_fiq;
                when '10000' R[d] = SPSR_irq;
                when '10010' R[d] = SPSR_svc;
                when '10100' R[d] = SPSR_abt;
                when '10110' R[d] = SPSR_und;
                when '11100' R[d] = SPSR_mon;
                when '11110' R[d] = SPSR_hyp;
            endcase
        else
            BankedRegisterAccessValid(SYSm, mode);

            if SYSm<4:3> == '00' then
                m = UInt(SYSm<2:0>) + 8;
                R[d] = Rmode[m,16];
            endif

            if SYSm<4:3> == '01' then
                m = UInt(SYSm<2:0>) + 8;
                R[d] = Rmode[m,17];
            endif

            if SYSm<4:3> == '11' then
                if SYSm<1> == '0' then
                    m = UInt(SYSm<0>) + 13;
                    R[d] = Rmode[m,22];
                else
                    if SYSm<0> == '0' then
                        R[d] = Rmode[13,26];
                    else
                        R[d] = ELR_hyp;
                    endif
                endif
            else
                targetmode = 0;
                targetmode = (targetmode << 1) OR 1;
                targetmode = (targetmode << 1) OR (SYSm<2> AND SYSm<1>);
                targetmode = (targetmode << 1) OR (SYSm<2> AND ~SYSm<1>);
                targetmode = (targetmode << 1) OR 1;
                targetmode = (targetmode << 1) OR (SYSm<2> OR SYSm<1>);

                if mode == targetmode then
                    UNPREDICTABLE;
                else
                    m = UInt(SYSm<0>) + 13;
                    R[d] = Rmode[m,targetmode];
                endif
            endif
        endif
    endif
endif
"""
}, { 
    "name" : "MSR (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if write_nzcvq then
        APSR.N = imm32<31>;
        APSR.Z = imm32<30>;
        APSR.C = imm32<29>;
        APSR.V = imm32<28>;
        APSR.Q = imm32<27>;
    endif

    if write_g then
        APSR.GE = imm32<19:16>;
    endif
endif
"""
}, { 
    "name" : "MSR (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if write_nzcvq then
        APSR.N = R[n]<31>;
        APSR.Z = R[n]<30>;
        APSR.C = R[n]<29>;
        APSR.V = R[n]<28>;
        APSR.Q = R[n]<27>;
    endif

    if write_g then
        APSR.GE = R[n]<19:16>;
    endif
endif
"""
}, { 
    "name" : "MSR (Banked register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if !CurrentModeIsNotUser() then
        UNPREDICTABLE;
    else
        mode = CPSR.M;
        if write_spsr then
            SPSRaccessValid(SYSm, mode);
            case SYSm of
                when '01110' SPSR_fiq = R[n];
                when '10000' SPSR_irq = R[n];
                when '10010' SPSR_svc = R[n];
                when '10100' SPSR_abt = R[n];
                when '10110' SPSR_und = R[n];
                when '11100' SPSR_mon = R[n];
                when '11110' SPSR_hyp = R[n];
            endcase
        else
            BankedRegisterAccessValid(SYSm, mode);
            if SYSm<4:3> == '00' then
                m = UInt(SYSm<2:0>) + 8;
                Rmode[m,16] = R[n];
            endif

            if SYSm<4:3> == '01' then
                m = UInt(SYSm<2:0>) + 8;
                Rmode[m,17] = R[n];
            endif

            if SYSm<4:3> == '11' then
                if SYSm<1> == '0' then
                    m = UInt(SYSm<0>) + 13;
                    Rmode[m,22] = R[n];
                else
                    if SYSm<0> == '0' then
                        Rmode[13,26] = R[n];
                    else
                        ELR_hyp = R[n];
                    endif
                endif
            else
                targetmode = 0;
                targetmode = (targetmode << 1) OR 1;
                targetmode = (targetmode << 1) OR (SYSm<2> AND SYSm<1>);
                targetmode = (targetmode << 1) OR (SYSm<2> AND ~SYSm<1>);
                targetmode = (targetmode << 1) OR 1;
                targetmode = (targetmode << 1) OR (SYSm<2> OR SYSm<1>);

                if mode == targetmode then
                    UNPREDICTABLE;
                else
                    m = UInt(SYSm<0>) + 13;
                    Rmode[m,targetmode] = R[n];
                endif
            endif
        endif
    endif
endif
"""
}, { 
    "name" : "MUL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand1 = SInt(R[n]);
    operand2 = SInt(R[m]);
    result = operand1 * operand2;
    R[d] = result<31:0>;
    
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result<31:0>);
        if ArchVersion() == 4 then
            APSR.C = UNKNOWN_VALUE;
        endif
    endif
endif
"""
}, { 
    "name" : "MVN (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = NOT(imm32);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "MVN (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = NOT(shifted);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "MVN (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = NOT(shifted);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "NOP",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
endif
"""
}, { 
    "name" : "ORN (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[n] OR NOT(imm32);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "ORN (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] OR NOT(shifted);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "ORR (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[n] OR imm32;
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "ORR (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] OR shifted;
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "ORR (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] OR shifted;
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "PKH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = Shift(R[m], shift_t, shift_n, APSR.C);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, if tbform then operand2<15:0> else R[n]<15:0>);
    set_bits(tmp_val, 31, 16, if tbform then R[n]<31:16> else operand2<31:16>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "PLD, PLDW (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    address = if add then (R[n] + imm32) else (R[n] - imm32);
    
    if is_pldw then
        Hint_PreloadDataForWrite(address);
    else
        Hint_PreloadData(address);
    endif
endif
"""
}, { 
    "name" : "PLD (literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    address = if add then (Align(R[15],4) + imm32) else (Align(R[15],4) - imm32);
    Hint_PreloadData(address);
endif
"""
}, { 
    "name" : "PLD, PLDW (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    address = if add then (R[n] + offset) else (R[n] - offset);
    if is_pldw then
        Hint_PreloadDataForWrite(address);
    else
        Hint_PreloadData(address);
    endif
endif
"""
}, { 
    "name" : "PLI (immediate, literal)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    base = if n == 15 then Align(R[15],4) else R[n];
    address = if add then (base + imm32) else (base - imm32);
    Hint_PreloadInstr(address);
endif
"""
}, { 
    "name" : "PLI (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    address = if add then (R[n] + offset) else (R[n] - offset);
    Hint_PreloadInstr(address);
endif
"""
}, { 
    "name" : "POP (Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(13);
    address = R[13];
    for i = 0 to 14
        if registers<i> == '1' then
            R[i] = if UnalignedAllowed then MemU[address,4] else MemA[address,4];
            address = address + 4;
        endif
    endfor

    if registers<15> == '1' then
        if UnalignedAllowed then
            if address<1:0> == '00' then
                LoadWritePC(MemU[address,4]);
            else
                UNPREDICTABLE;
            endif
        else
            LoadWritePC(MemA[address,4]);
        endif
    endif

    if registers<13> == '0' then
        R[13] = R[13] + 4*BitCount(registers);
    endif

    if registers<13> == '1' then
        R[13] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "POP (ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(13);
    address = R[13];
    for i = 0 to 14
        if registers<i> == '1' then
            R[i] = if UnalignedAllowed then MemU[address,4] else MemA[address,4];
            address = address + 4;
        endif
    endfor

    if registers<15> == '1' then
        if UnalignedAllowed then
            if address<1:0> == '00' then
                LoadWritePC(MemU[address,4]);
            else
                UNPREDICTABLE;
            endif
        else
            LoadWritePC(MemA[address,4]);
        endif
    endif

    if registers<13> == '0' then
        R[13] = R[13] + 4*BitCount(registers);
    endif

    if registers<13> == '1' then
        R[13] = UNKNOWN_VALUE;
    endif
endif
"""
}, { 
    "name" : "PUSH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(13);
    address = R[13] - 4*BitCount(registers);
    for i = 0 to 14
        if registers<i> == '1' then
            if i == 13 && i != LowestSetBit(registers) then
                MemA[address,4] = UNKNOWN_VALUE;
            else
                if UnalignedAllowed then
                    MemU[address,4] = R[i];
                else
                    MemA[address,4] = R[i];
                endif
            endif

            address = address + 4;
        endif
    endfor
        
    if registers<15> == '1' then
        if UnalignedAllowed then
            MemU[address,4] = PCStoreValue();
        else
            MemA[address,4] = PCStoreValue();
        endif
    endif

    R[13] = R[13] - 4*BitCount(registers);
endif
"""
}, { 
    "name" : "QADD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (R[d], sat) = SignedSatQ(SInt(R[m]) + SInt(R[n]), 32);
    if sat then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "QADD16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = SInt(R[n]<15:0>) + SInt(R[m]<15:0>);
    sum2 = SInt(R[n]<31:16>) + SInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, SignedSat(sum1, 16));
    set_bits(tmp_val, 31, 16, SignedSat(sum2, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "QADD8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = SInt(R[n]<7:0>) + SInt(R[m]<7:0>);
    sum2 = SInt(R[n]<15:8>) + SInt(R[m]<15:8>);
    sum3 = SInt(R[n]<23:16>) + SInt(R[m]<23:16>);
    sum4 = SInt(R[n]<31:24>) + SInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, SignedSat(sum1, 8));
    set_bits(tmp_val, 15, 8, SignedSat(sum2, 8));
    set_bits(tmp_val, 23, 16, SignedSat(sum3, 8));
    set_bits(tmp_val, 31, 24, SignedSat(sum4, 8));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "QASX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff = SInt(R[n]<15:0>) - SInt(R[m]<31:16>);
    sum = SInt(R[n]<31:16>) + SInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, SignedSat(diff, 16));
    set_bits(tmp_val, 31, 16, SignedSat(sum, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "QDADD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (doubled, sat1) = SignedSatQ(2 * SInt(R[n]), 32);
    (R[d], sat2) = SignedSatQ(SInt(R[m]) + SInt(doubled), 32);
    if sat1 || sat2 then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "QDSUB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (doubled, sat1) = SignedSatQ(2 * SInt(R[n]), 32);
    (R[d], sat2) = SignedSatQ(SInt(R[m]) - SInt(doubled), 32);
    if sat1 || sat2 then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "QSAX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum = SInt(R[n]<15:0>) + SInt(R[m]<31:16>);
    diff = SInt(R[n]<31:16>) - SInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, SignedSat(sum, 16));
    set_bits(tmp_val, 31, 16, SignedSat(diff, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "QSUB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (R[d], sat) = SignedSatQ(SInt(R[m]) - SInt(R[n]), 32);
    if sat then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "QSUB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = SInt(R[n]<15:0>) - SInt(R[m]<15:0>);
    diff2 = SInt(R[n]<31:16>) - SInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, SignedSat(diff1, 16));
    set_bits(tmp_val, 31, 16, SignedSat(diff2, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "QSUB8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = SInt(R[n]<7:0>) - SInt(R[m]<7:0>);
    diff2 = SInt(R[n]<15:8>) - SInt(R[m]<15:8>);
    diff3 = SInt(R[n]<23:16>) - SInt(R[m]<23:16>);
    diff4 = SInt(R[n]<31:24>) - SInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, SignedSat(diff1, 8));
    set_bits(tmp_val, 15, 8, SignedSat(diff2, 8));
    set_bits(tmp_val, 23, 16, SignedSat(diff3, 8));
    set_bits(tmp_val, 31, 24, SignedSat(diff4, 8));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "RBIT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = 0;
    for i = 0 to 32
        result = (result << 1) OR R[m]<i>;
    endfor
    R[d] = result;
endif
"""
}, { 
    "name" : "REV",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = 0;
    set_bits(result, 31, 24, R[m]<7:0>);
    set_bits(result, 23, 16, R[m]<15:8>);
    set_bits(result, 15, 8, R[m]<23:16>);
    set_bits(result, 7, 0, R[m]<31:24>);
    R[d] = result;
endif
"""
}, { 
    "name" : "REV16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = 0;
    set_bits(result, 31, 24, R[m]<23:16>);
    set_bits(result, 23, 16, R[m]<31:24>);
    set_bits(result, 15, 8, R[m]<7:0>);
    set_bits(result, 7, 0, R[m]<15:8>);
    R[d] = result;
endif
"""
}, { 
    "name" : "REVSH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = 0;
    set_bits(result, 31, 8, SignExtend(R[m]<7:0>, 24));
    set_bits(result, 7, 0, R[m]<15:8>);
    R[d] = result;
endif
"""
}, { 
    "name" : "RFE",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if CurrentModeIsHyp() then
        UNDEFINED;
    endif

    if (!CurrentModeIsNotUser() || CurrentInstrSet() == InstrSet_ThumbEE) then
        UNPREDICTABLE;
    else
        address = if increment then R[n] else R[n]-8;
        if wordhigher then
            address = address+4;
        endif

        if wback then
            R[n] = if increment then R[n]+8 else R[n]-8;
        endif

        new_pc_value = MemA[address,4];
        tmp = address+4;
        CPSRWriteByInstr(MemA[tmp,4], '1111', TRUE);
        
        if CPSR<4:0> == '11010' && CPSR.J == '1' && CPSR.T == '1' then
            UNPREDICTABLE;
        else
            BranchWritePC(new_pc_value);
        endif
    endif
endif
"""
}, { 
    "name" : "ROR (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry) = Shift_C(R[m], SRType_ROR, shift_n, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "ROR (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[m]<7:0>);
    (result, carry) = Shift_C(R[n], SRType_ROR, shift_n, APSR.C);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
    endif
endif
"""
}, { 
    "name" : "RRX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry) = Shift_C(R[m], SRType_RRX, 1, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
        endif
    endif
endif
"""
}, { 
    "name" : "RSB (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(NOT(R[n]), imm32, '1');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "RSB (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(NOT(R[n]), shifted, '1');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "RSB (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(NOT(R[n]), shifted, '1');
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif
"""
}, { 
    "name" : "RSC (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(NOT(R[n]), imm32, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "RSC (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(NOT(R[n]), shifted, APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "RSC (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(NOT(R[n]), shifted, APSR.C);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif
"""
}, { 
    "name" : "SADD16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = SInt(R[n]<15:0>) + SInt(R[m]<15:0>);
    sum2 = SInt(R[n]<31:16>) + SInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15,0, sum1<15:0>);
    set_bits(tmp_val, 31,16, sum2<15:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bits(tmp_val, 1, 0, if sum1 >= 0 then '11' else '00');
    set_bits(tmp_val, 3, 2, if sum2 >= 0 then '11' else '00');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "SADD8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = SInt(R[n]<7:0>) + SInt(R[m]<7:0>);
    sum2 = SInt(R[n]<15:8>) + SInt(R[m]<15:8>);
    sum3 = SInt(R[n]<23:16>) + SInt(R[m]<23:16>);
    sum4 = SInt(R[n]<31:24>) + SInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, sum1<7:0>);
    set_bits(tmp_val, 15, 8, sum2<7:0>);
    set_bits(tmp_val, 23, 16, sum3<7:0>);
    set_bits(tmp_val, 31, 24, sum4<7:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bit(tmp_val, 0, if sum1 >= 0 then '1' else '0');
    set_bit(tmp_val, 1, if sum2 >= 0 then '1' else '0');
    set_bit(tmp_val, 2, if sum3 >= 0 then '1' else '0');
    set_bit(tmp_val, 3, if sum4 >= 0 then '1' else '0');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "SASX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff = SInt(R[n]<15:0>) - SInt(R[m]<31:16>);
    sum = SInt(R[n]<31:16>) + SInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, diff<15:0>);
    set_bits(tmp_val, 31, 16, sum<15:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bits(tmp_val, 1, 0, if diff >= 0 then '11' else '00');
    set_bits(tmp_val, 3, 2, if sum >= 0 then '11' else '00');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "SBC (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "SBC (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), APSR.C);
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "SBC (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), APSR.C);
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif
"""
}, { 
    "name" : "SBFX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    msbit = lsbit + widthminus1;
    if msbit <= 31 then
        R[d] = SignExtend(R[n]<msbit:lsbit>, 32);
    else
        UNPREDICTABLE;
    endif
endif
"""
}, { 
    "name" : "SDIV",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if SInt(R[m]) == 0 then
        if IntegerZeroDivideTrappingEnabled() then
            GenerateIntegerZeroDivide();
        else
            result = 0;
        endif
    else
        result = RoundTowardsZero(SInt(R[n]) / SInt(R[m]));
    endif

    R[d] = result<31:0>;
endif
"""
}, { 
    "name" : "SEL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, if APSR.GE<0> == '1' then R[n]<7:0> else R[m]<7:0>);
    set_bits(tmp_val, 15, 8, if APSR.GE<1> == '1' then R[n]<15:8> else R[m]<15:8>);
    set_bits(tmp_val, 23, 16, if APSR.GE<2> == '1' then R[n]<23:16> else R[m]<23:16>);
    set_bits(tmp_val, 31, 24, if APSR.GE<3> == '1' then R[n]<31:24> else R[m]<31:24>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SETEND",
    "operation" : """
EncodingSpecificOperations();
ENDIANSTATE = if set_bigend then '1' else '0';
"""
}, { 
    "name" : "SEV",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    SendEvent();
endif
"""
}, { 
    "name" : "SHADD16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = SInt(R[n]<15:0>) + SInt(R[m]<15:0>);
    sum2 = SInt(R[n]<31:16>) + SInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, sum1<16:1>);
    set_bits(tmp_val, 31, 16, sum2<16:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SHADD8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = SInt(R[n]<7:0>) + SInt(R[m]<7:0>);
    sum2 = SInt(R[n]<15:8>) + SInt(R[m]<15:8>);
    sum3 = SInt(R[n]<23:16>) + SInt(R[m]<23:16>);
    sum4 = SInt(R[n]<31:24>) + SInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, sum1<8:1>);
    set_bits(tmp_val, 15, 8, sum2<8:1>);
    set_bits(tmp_val, 23, 16, sum3<8:1>);
    set_bits(tmp_val, 31, 24, sum4<8:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SHASX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff = SInt(R[n]<15:0>) - SInt(R[m]<31:16>);
    sum = SInt(R[n]<31:16>) + SInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, diff<16:1>);
    set_bits(tmp_val, 31, 16, sum<16:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SHSAX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum = SInt(R[n]<15:0>) + SInt(R[m]<31:16>);
    diff = SInt(R[n]<31:16>) - SInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, sum<16:1>);
    set_bits(tmp_val, 31, 16, diff<16:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SHSUB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = SInt(R[n]<15:0>) - SInt(R[m]<15:0>);
    diff2 = SInt(R[n]<31:16>) - SInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, diff1<16:1>);
    set_bits(tmp_val, 31, 16, diff2<16:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SHSUB8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = SInt(R[n]<7:0>) - SInt(R[m]<7:0>);
    diff2 = SInt(R[n]<15:8>) - SInt(R[m]<15:8>);
    diff3 = SInt(R[n]<23:16>) - SInt(R[m]<23:16>);
    diff4 = SInt(R[n]<31:24>) - SInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, diff1<8:1>);
    set_bits(tmp_val, 15, 8, diff2<8:1>);
    set_bits(tmp_val, 23, 16, diff3<8:1>);
    set_bits(tmp_val, 31, 24, diff4<8:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SMC (previously SMI)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if HaveSecurityExt() && CurrentModeIsNotUser() then
        if HaveVirtExt() && !IsSecure() && !CurrentModeIsHyp() && HCR.TSC == '1' then
            HSRString = Zeros(25);
            WriteHSR('010011', HSRString);
            TakeHypTrapException();
        else
            if SCR.SCD == '1' then
                if IsSecure() then
                    UNPREDICTABLE;
                else
                    UNDEFINED;
                endif
            else
                TakeSMCException();
            endif
        endif
    else
        UNDEFINED;
    endif
endif
"""
}, { 
    "name" : "SMLABB, SMLABT, SMLATB, SMLATT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand1 = if n_high then R[n]<31:16> else R[n]<15:0>;
    operand2 = if m_high then R[m]<31:16> else R[m]<15:0>;
    result = SInt(operand1) * SInt(operand2) + SInt(R[a]);
    R[d] = result<31:0>;
    if result != SInt(result<31:0>) then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "SMLAD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = if m_swap then ROR(R[m],16) else R[m];
    product1 = SInt(R[n]<15:0>) * SInt(operand2<15:0>);
    product2 = SInt(R[n]<31:16>) * SInt(operand2<31:16>);
    result = product1 + product2 + SInt(R[a]);
    R[d] = result<31:0>;
    if result != SInt(result<31:0>) then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "SMLAL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = SInt(R[n]) * SInt(R[m]) + SInt(R[dHi]:R[dLo]);
    R[dHi] = result<63:32>;
    R[dLo] = result<31:0>;
    if setflags then
        APSR.N = result<63>;
        APSR.Z = IsZeroBit(result<63:0>);
        if ArchVersion() == 4 then
            APSR.C = UNKNOWN_VALUE;
            APSR.V = UNKNOWN_VALUE;
        endif
    endif
endif
"""
}, { 
    "name" : "SMLALBB, SMLALBT, SMLALTB, SMLALTT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand1 = if n_high then R[n]<31:16> else R[n]<15:0>;
    operand2 = if m_high then R[m]<31:16> else R[m]<15:0>;
    result = SInt(operand1) * SInt(operand2) + SInt(R[dHi]:R[dLo]);
    R[dHi] = result<63:32>;
    R[dLo] = result<31:0>;
endif
"""
}, { 
    "name" : "SMLALD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = if m_swap then ROR(R[m],16) else R[m];
    product1 = SInt(R[n]<15:0>) * SInt(operand2<15:0>);
    product2 = SInt(R[n]<31:16>) * SInt(operand2<31:16>);
    result = product1 + product2 + SInt(R[dHi]:R[dLo]);
    R[dHi] = result<63:32>;
    R[dLo] = result<31:0>;
endif
"""
}, { 
    "name" : "SMLAWB, SMLAWT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = if m_high then R[m]<31:16> else R[m]<15:0>;
    result = SInt(R[n]) * SInt(operand2) + (SInt(R[a]) << 16);
    R[d] = result<47:16>;
    if (result >> 16) != SInt(R[d]) then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "SMLSD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = if m_swap then ROR(R[m],16) else R[m];
    product1 = SInt(R[n]<15:0>) * SInt(operand2<15:0>);
    product2 = SInt(R[n]<31:16>) * SInt(operand2<31:16>);
    result = product1 - product2 + SInt(R[a]);
    R[d] = result<31:0>;
    if result != SInt(result<31:0>) then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "SMLSLD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = if m_swap then ROR(R[m],16) else R[m];
    product1 = SInt(R[n]<15:0>) * SInt(operand2<15:0>);
    product2 = SInt(R[n]<31:16>) * SInt(operand2<31:16>);
    result = product1 - product2 + SInt(R[dHi]:R[dLo]);
    R[dHi] = result<63:32>;
    R[dLo] = result<31:0>;
endif
"""
}, { 
    "name" : "SMMLA",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = (SInt(R[a]) << 32) + SInt(R[n]) * SInt(R[m]);
    if round then
        result = result + 0x80000000;
    endif
    R[d] = result<63:32>;
endif
"""
}, { 
    "name" : "SMMLS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = (SInt(R[a]) << 32) - SInt(R[n]) * SInt(R[m]);
    if round then
        result = result + 0x80000000;
    endif
    R[d] = result<63:32>;
endif
"""
}, { 
    "name" : "SMMUL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = SInt(R[n]) * SInt(R[m]);
    if round then
        result = result + 0x80000000;
    endif
    R[d] = result<63:32>;
endif
"""
}, { 
    "name" : "SMUAD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = if m_swap then ROR(R[m],16) else R[m];
    product1 = SInt(R[n]<15:0>) * SInt(operand2<15:0>);
    product2 = SInt(R[n]<31:16>) * SInt(operand2<31:16>);
    result = product1 + product2;
    R[d] = result<31:0>;
    if result != SInt(result<31:0>) then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "SMULBB, SMULBT, SMULTB, SMULTT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand1 = if n_high then R[n]<31:16> else R[n]<15:0>;
    operand2 = if m_high then R[m]<31:16> else R[m]<15:0>;
    result = SInt(operand1) * SInt(operand2);
    R[d] = result<31:0>;
endif
"""
}, { 
    "name" : "SMULL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = SInt(R[n]) * SInt(R[m]);
    R[dHi] = result<63:32>;
    R[dLo] = result<31:0>;
    if setflags then
        APSR.N = result<63>;
        APSR.Z = IsZeroBit(result<63:0>);
        if ArchVersion() == 4 then
            APSR.C = UNKNOWN_VALUE;
            APSR.V = UNKNOWN_VALUE;
        endif
    endif
endif
"""
}, { 
    "name" : "SMULWB, SMULWT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = if m_high then R[m]<31:16> else R[m]<15:0>;
    product = SInt(R[n]) * SInt(operand2);
    R[d] = product<47:16>;
endif
"""
}, { 
    "name" : "SMUSD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand2 = if m_swap then ROR(R[m],16) else R[m];
    product1 = SInt(R[n]<15:0>) * SInt(operand2<15:0>);
    product2 = SInt(R[n]<31:16>) * SInt(operand2<31:16>);
    result = product1 - product2;
    R[d] = result<31:0>;
endif
"""
}, { 
    "name" : "SRS, Thumb",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if CurrentModeIsHyp() then
        UNDEFINED;
    endif

    if CurrentModeIsUserOrSystem() then
        UNPREDICTABLE;
    endif

    if mode == '11010' then
        UNPREDICTABLE;
    else
        if !IsSecure() then
            if mode == '10110' || (mode == '10001' && NSACR.RFR == '1') then
                UNPREDICTABLE;
            endif
        endif

        base = Rmode[13,mode];
        address = if increment then base else base-8;
        if wordhigher then
            address = address+4;
        endif

        tmp = address + 4;
        MemA[address,4] = R[14];
        MemA[tmp,4] = SPSR;
        if wback then
            Rmode[13,mode] = if increment then base+8 else base-8;
        endif
    endif
endif
"""
}, { 
    "name" : "SRS, ARM",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if CurrentModeIsHyp() then
        UNDEFINED;
    endif

    if CurrentModeIsUserOrSystem() then
        UNPREDICTABLE;
    endif

    if mode == '11010' then
        UNPREDICTABLE;
    else
        if !IsSecure() then
            if mode == '10110' || (mode == '10001' && NSACR.RFR == '1') then
                UNPREDICTABLE;
            endif
        endif

        base = Rmode[13,mode];
        address = if increment then base else base-8;
        if wordhigher then
            address = address+4;
        endif

        tmp = address+4;
        MemA[address,4] = R[14];
        MemA[tmp,4] = SPSR;
        if wback then
            Rmode[13,mode] = if increment then base+8 else base-8;
        endif
    endif
endif
"""
}, { 
    "name" : "SSAT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand = Shift(R[n], shift_t, shift_n, APSR.C);
    (result, sat) = SignedSatQ(SInt(operand), saturate_to);
    R[d] = SignExtend(result, 32);
    if sat then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "SSAT16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result1, sat1) = SignedSatQ(SInt(R[n]<15:0>), saturate_to);
    (result2, sat2) = SignedSatQ(SInt(R[n]<31:16>), saturate_to);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, SignExtend(result1, 16));
    set_bits(tmp_val, 31, 16, SignExtend(result2, 16));
    R[d] = tmp_val;
    if sat1 || sat2 then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "SSAX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum = SInt(R[n]<15:0>) + SInt(R[m]<31:16>);
    diff = SInt(R[n]<31:16>) - SInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, sum<15:0>);
    set_bits(tmp_val, 31, 16, diff<15:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bits(tmp_val, 1, 0, if sum >= 0 then '11' else '00');
    set_bits(tmp_val, 3, 2, if diff >= 0 then '11' else '00');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "SSUB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = SInt(R[n]<15:0>) - SInt(R[m]<15:0>);
    diff2 = SInt(R[n]<31:16>) - SInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, diff1<15:0>);
    set_bits(tmp_val, 31, 16, diff2<15:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bits(tmp_val, 1, 0, if diff1 >= 0 then '11' else '00');
    set_bits(tmp_val, 3, 2, if diff2 >= 0 then '11' else '00');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "SSUB8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = SInt(R[n]<7:0>) - SInt(R[m]<7:0>);
    diff2 = SInt(R[n]<15:8>) - SInt(R[m]<15:8>);
    diff3 = SInt(R[n]<23:16>) - SInt(R[m]<23:16>);
    diff4 = SInt(R[n]<31:24>) - SInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, diff1<7:0>);
    set_bits(tmp_val, 15, 8, diff2<7:0>);
    set_bits(tmp_val, 23, 16, diff3<7:0>);
    set_bits(tmp_val, 31, 24, diff4<7:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bit(tmp_val, 0, if diff1 >= 0 then '1' else '0');
    set_bit(tmp_val, 1, if diff2 >= 0 then '1' else '0');
    set_bit(tmp_val, 2, if diff3 >= 0 then '1' else '0');
    set_bit(tmp_val, 3, if diff4 >= 0 then '1' else '0');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "STC, STC2",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if !Coproc_Accepted(cp, ThisInstr()) then
        GenerateCoprocessorException();
    else
        NullCheckIfThumbEE(n);
        offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
        address = if index then offset_addr else R[n];
        repeat
            MemA[address,4] = Coproc_GetWordToStore(cp, ThisInstr());
            address = address + 4;
        until Coproc_DoneStoring(cp, ThisInstr())

        if wback then
            R[n] = offset_addr;
        endif
    endif
endif
"""
}, { 
    "name" : "STM (STMIA, STMEA)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    for i = 0 to 14
        if registers<i> == '1' then
            if i == n && wback && i != LowestSetBit(registers) then
                MemA[address,4] = UNKNOWN_VALUE;
            else
                MemA[address,4] = R[i];
            endif

            address = address + 4;
        endif
    endfor

    if registers<15> == '1' then
        MemA[address,4] = PCStoreValue();
    endif

    if wback then
        R[n] = R[n] + 4*BitCount(registers);
    endif
endif
"""
}, { 
    "name" : "STMDA (STMED)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    address = R[n] - 4*BitCount(registers) + 4;
    for i = 0 to 14
        if registers<i> == '1' then
            if i == n && wback && i != LowestSetBit(registers) then
                MemA[address,4] = UNKNOWN_VALUE;
            else
                MemA[address,4] = R[i];
            endif
            
            address = address + 4;
        endif
    endfor

    if registers<15> == '1' then
        MemA[address,4] = PCStoreValue();
    endif

    if wback then
        R[n] = R[n] - 4*BitCount(registers);
    endif
endif
"""
}, { 
    "name" : "STMDB (STMFD)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n] - 4*BitCount(registers);
    for i = 0 to 14
        if registers<i> == '1' then
            if i == n && wback && i != LowestSetBit(registers) then
                MemA[address,4] = UNKNOWN_VALUE;
            else
                MemA[address,4] = R[i];
            endif
            
            address = address + 4;
        endif
    endfor

    if registers<15> == '1' then
        MemA[address,4] = PCStoreValue();
    endif

    if wback then
        R[n] = R[n] - 4*BitCount(registers);
    endif
endif
"""
}, { 
    "name" : "STMIB (STMFA)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    address = R[n] + 4;
    for i = 0 to 14
        if registers<i> == '1' then
            if i == n && wback && i != LowestSetBit(registers) then
                MemA[address,4] = UNKNOWN_VALUE;
            else
                MemA[address,4] = R[i];
            endif
            
            address = address + 4;
        endif
    endfor 

    if registers<15> == '1' then
        MemA[address,4] = PCStoreValue();
    endif

    if wback then
        R[n] = R[n] + 4*BitCount(registers);
    endif
endif
"""
}, { 
    "name" : "STR (immediate, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    if UnalignedSupport() || address<1:0> == '00' then
        MemU[address,4] = R[t];
    else
        MemU[address,4] = UNKNOWN_VALUE;
    endif

    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STR (immediate, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    MemU[address,4] = if t == 15 then PCStoreValue() else R[t];
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STR (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if index then offset_addr else R[n];
    if t == 15 then
        data = PCStoreValue();
    else
        data = R[t];
    endif

    if UnalignedSupport() || address<1:0> == '00' || CurrentInstrSet() == InstrSet_ARM then
        MemU[address,4] = data;
    else
        MemU[address,4] = UNKNOWN_VALUE;
    endif

    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRB (immediate, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    MemU[address,1] = R[t]<7:0>;
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRB (immediate, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    MemU[address,1] = R[t]<7:0>;
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRB (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if index then offset_addr else R[n];
    MemU[address,1] = R[t]<7:0>;
    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRBT",
    "operation" : """
if ConditionPassed() then
    if CurrentModeIsHyp() then
        UNPREDICTABLE;
    endif

    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = if register_form then Shift(R[m], shift_t, shift_n, APSR.C) else imm32;
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if postindex then R[n] else offset_addr;
    MemU_unpriv[address,1] = R[t]<7:0>;
    if postindex then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRD (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    
    if HaveLPAE() && address<2:0> == '000' then
        data = 0;
        if BigEndian() then
            set_bits(data,63, 32, R[t]);
            set_bits(data,31, 0, R[t2]);
        else
            set_bits(data,31, 0, R[t]);
            set_bits(data,63, 32, R[t2]);
        endif

        MemA[address,8] = data;
    else
        tmp = address + 4;
        MemA[address,4] = R[t];
        MemA[tmp,4] = R[t2];
    endif

    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRD (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset_addr = if add then (R[n] + R[m]) else (R[n] - R[m]);
    address = if index then offset_addr else R[n];
    if HaveLPAE() && address<2:0> == '000' then
        data = 0;
        if BigEndian() then
            set_bits(data, 63,32, R[t]);
            set_bits(data, 31,0, R[t2]);
        else
            set_bits(data, 31,0, R[t]);
            set_bits(data, 63,32, R[t2]);
        endif
        
        MemA[address,8] = data;
    else
        tmp = address + 4;
        MemA[address,4] = R[t];
        MemA[tmp,4] = R[t2];
    endif

    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STREX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n] + imm32;
    if ExclusiveMonitorsPass(address,4) then
        MemA[address,4] = R[t];
        R[d] = 0;
    else
        R[d] = 1;
    endif
endif
"""
}, { 
    "name" : "STREXB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    if ExclusiveMonitorsPass(address,1) then
        MemA[address,1] = R[t];
        R[d] = 0;
    else
        R[d] = 1;
    endif
endif
"""
}, { 
    "name" : "STREXD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    value = if BigEndian() then R[t]:R[t2] else R[t2]:R[t];
    if ExclusiveMonitorsPass(address,8) then
        MemA[address,8] = value;
        R[d] = 0;
    else
        R[d] = 1;
    endif
endif
"""
}, { 
    "name" : "STREXH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    address = R[n];
    if ExclusiveMonitorsPass(address,2) then
        MemA[address,2] = R[t];
        R[d] = 0;
    else
        R[d] = 1;
    endif
endif
"""
}, { 
    "name" : "STRH (immediate, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    if UnalignedSupport() || address<0> == '0' then
        MemU[address,2] = R[t]<15:0>;
    else
        MemU[address,2] = UNKNOWN_VALUE;
    endif

    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRH (immediate, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    offset_addr = if add then (R[n] + imm32) else (R[n] - imm32);
    address = if index then offset_addr else R[n];
    if UnalignedSupport() || address<0> == '0' then
        MemU[address,2] = R[t]<15:0>;
    else
        MemU[address,2] = UNKNOWN_VALUE;
    endif

    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRH (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = Shift(R[m], shift_t, shift_n, APSR.C);
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if index then offset_addr else R[n];
    if UnalignedSupport() || address<0> == '0' then
        MemU[address,2] = R[t]<15:0>;
    else
        MemU[address,2] = UNKNOWN_VALUE;
    endif

    if wback then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRHT",
    "operation" : """
if ConditionPassed() then
    if CurrentModeIsHyp() then
        UNPREDICTABLE;
    endif

    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = if register_form then R[m] else imm32;
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if postindex then R[n] else offset_addr;
    if UnalignedSupport() || address<0> == '0' then
        MemU_unpriv[address,2] = R[t]<15:0>;
    else
        MemU_unpriv[address,2] = UNKNOWN_VALUE;
    endif

    if postindex then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "STRT",
    "operation" : """
if ConditionPassed() then
    if CurrentModeIsHyp() then
        UNPREDICTABLE;
    endif

    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    offset = if register_form then Shift(R[m], shift_t, shift_n, APSR.C) else imm32;
    offset_addr = if add then (R[n] + offset) else (R[n] - offset);
    address = if postindex then R[n] else offset_addr;
    
    if t == 15 then
        data = PCStoreValue();
    else
        data = R[t];
    endif

    if UnalignedSupport() || address<1:0> == '00' || CurrentInstrSet() == InstrSet_ARM then
        MemU_unpriv[address,4] = data;
    else
        MemU_unpriv[address,4] = UNKNOWN_VALUE;
    endif

    if postindex then
        R[n] = offset_addr;
    endif
endif
"""
}, { 
    "name" : "SUB (immediate, Thumb)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), '1');
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif
"""
}, { 
    "name" : "SUB (immediate, ARM)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[n], NOT(imm32), '1');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "SUB (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), '1');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "SUB (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[n], NOT(shifted), '1');
    R[d] = result;
    if setflags then
        APSR.N = result<31>;
        APSR.Z = IsZeroBit(result);
        APSR.C = carry;
        APSR.V = overflow;
    endif
endif
"""
}, { 
    "name" : "SUB (SP minus immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result, carry, overflow) = AddWithCarry(R[13], NOT(imm32), '1');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "SUB (SP minus register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shifted = Shift(R[m], shift_t, shift_n, APSR.C);
    (result, carry, overflow) = AddWithCarry(R[13], NOT(shifted), '1');
    if d == 15 then
        ALUWritePC(result);
    else
        R[d] = result;
        if setflags then
            APSR.N = result<31>;
            APSR.Z = IsZeroBit(result);
            APSR.C = carry;
            APSR.V = overflow;
        endif
    endif
endif
"""
}, { 
    "name" : "SUBS PC, LR, Thumb",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if (CurrentModeIsUserOrSystem() || CurrentInstrSet() == InstrSet_ThumbEE) then
        UNPREDICTABLE;
    else
        operand2 = imm32;
        (result, -, -) = AddWithCarry(R[n], NOT(operand2), '1');
        CPSRWriteByInstr(SPSR, '1111', TRUE);
        if CPSR<4:0> == '11010' && CPSR.J == '1' && CPSR.T == '1' then
            UNPREDICTABLE;
        else
            BranchWritePC(result);
        endif
    endif
endif
"""
}, { 
    "name" : "SUBS PC, LR and related instructions, ARM",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if CurrentModeIsHyp() then
        UNDEFINED;
    endif

    if CurrentModeIsUserOrSystem() then
        UNPREDICTABLE;
    else
        operand2 = if register_form then Shift(R[m], shift_t, shift_n, APSR.C) else imm32;
        case opcode_ of
            when '0000' result = R[n] AND operand2;
            when '0001' result = R[n] EOR operand2;
            when '0010' (result, -, -) = AddWithCarry(R[n], NOT(operand2), '1');
            when '0011' (result, -, -) = AddWithCarry(NOT(R[n]), operand2, '1');
            when '0100' (result, -, -) = AddWithCarry(R[n], operand2, '0');
            when '0101' (result, -, -) = AddWithCarry(R[n], operand2, APSR.C);
            when '0110' (result, -, -) = AddWithCarry(R[n], NOT(operand2), APSR.C);
            when '0111' (result, -, -) = AddWithCarry(NOT(R[n]), operand2, APSR.C);
            when '1100' result = R[n] OR operand2;
            when '1101' result = operand2;
            when '1110' result = R[n] AND NOT(operand2);
            when '1111' result = NOT(operand2);
        endcase

        CPSRWriteByInstr(SPSR, '1111', TRUE);
        if CPSR<4:0> == '11010' && CPSR.J == '1' && CPSR.T == '1' then
            UNPREDICTABLE;
        else
            BranchWritePC(result);
        endif
    endif
endif
"""
}, { 
    "name" : "SVC (previously SWI)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CallSupervisor(imm32<15:0>);
endif
"""
}, { 
    "name" : "SWP, SWPB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if CurrentModeIsHyp() then
        UNDEFINED;
    endif

    val = R[n];
    data = MemA[val, size];
    tmp = 8*size-1;
    MemA[val, size] = R[t2]<tmp:0>;
    
    if size == 1 then
        R[t] = ZeroExtend(data, 32);
    else
        R[t] = ROR(data, 8*UInt(R[n]<1:0>));
    endif
endif
"""
}, { 
    "name" : "SXTAB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    R[d] = R[n] + SignExtend(rotated<7:0>, 32);
endif
"""
}, { 
    "name" : "SXTAB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, R[n]<15:0> + SignExtend(rotated<7:0>, 16));
    set_bits(tmp_val, 31, 16, R[n]<31:16> + SignExtend(rotated<23:16>, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SXTAH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    R[d] = R[n] + SignExtend(rotated<15:0>, 32);
endif
"""
}, { 
    "name" : "SXTB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    R[d] = SignExtend(rotated<7:0>, 32);
endif
"""
}, { 
    "name" : "SXTB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, SignExtend(rotated<7:0>, 16));
    set_bits(tmp_val, 31, 16, SignExtend(rotated<23:16>, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "SXTH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    R[d] = SignExtend(rotated<15:0>, 32);
endif
"""
}, { 
    "name" : "TBB, TBH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    NullCheckIfThumbEE(n);
    if is_tbh then
        tmp = R[n] + LSL(R[m], 1);
        halfwords = UInt(MemU[tmp, 2]);
    else
        tmp = R[n] + R[m];
        halfwords = UInt(MemU[tmp, 1]);
    endif

    BranchWritePC(R[15] + 2*halfwords);
endif
"""
}, { 
    "name" : "TEQ (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[n] EOR imm32;
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
endif
"""
}, { 
    "name" : "TEQ (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] EOR shifted;
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
endif
"""
}, { 
    "name" : "TEQ (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] EOR shifted;
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
endif
"""
}, { 
    "name" : "TST (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = R[n] AND imm32;
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
endif
"""
}, { 
    "name" : "TST (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] AND shifted;
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
endif
"""
}, { 
    "name" : "TST (register-shifted register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    shift_n = UInt(R[s]<7:0>);
    (shifted, carry) = Shift_C(R[m], shift_t, shift_n, APSR.C);
    result = R[n] AND shifted;
    APSR.N = result<31>;
    APSR.Z = IsZeroBit(result);
    APSR.C = carry;
endif
"""
}, { 
    "name" : "UADD16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = UInt(R[n]<15:0>) + UInt(R[m]<15:0>);
    sum2 = UInt(R[n]<31:16>) + UInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, sum1<15:0>);
    set_bits(tmp_val, 31, 16, sum2<15:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bits(tmp_val, 1, 0, if sum1 >= 0x10000 then '11' else '00');
    set_bits(tmp_val, 3, 2, if sum2 >= 0x10000 then '11' else '00');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "UADD8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = UInt(R[n]<7:0>) + UInt(R[m]<7:0>);
    sum2 = UInt(R[n]<15:8>) + UInt(R[m]<15:8>);
    sum3 = UInt(R[n]<23:16>) + UInt(R[m]<23:16>);
    sum4 = UInt(R[n]<31:24>) + UInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, sum1<7:0>);
    set_bits(tmp_val, 15, 8, sum2<7:0>);
    set_bits(tmp_val, 23, 16, sum3<7:0>);
    set_bits(tmp_val, 31, 24, sum4<7:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bit(tmp_val, 0, if sum1 >= 0x100 then '1' else '0');
    set_bit(tmp_val, 1, if sum2 >= 0x100 then '1' else '0');
    set_bit(tmp_val, 2, if sum3 >= 0x100 then '1' else '0');
    set_bit(tmp_val, 3, if sum4 >= 0x100 then '1' else '0');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "UASX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff = UInt(R[n]<15:0>) - UInt(R[m]<31:16>);
    sum = UInt(R[n]<31:16>) + UInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, diff<15:0>);
    set_bits(tmp_val, 31, 16, sum<15:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bits(tmp_val, 1, 0, if diff >= 0 then '11' else '00');
    set_bits(tmp_val, 3, 2, if sum >= 0x10000 then '11' else '00');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "UBFX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    msbit = lsbit + widthminus1;
    if msbit <= 31 then
        R[d] = ZeroExtend(R[n]<msbit:lsbit>, 32);
    else
        UNPREDICTABLE;
    endif
endif
"""
}, { 
    "name" : "UDF",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    UNDEFINED;
endif
"""
}, { 
    "name" : "UDIV",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    if UInt(R[m]) == 0 then
        if IntegerZeroDivideTrappingEnabled() then
            GenerateIntegerZeroDivide();
        else
            result = 0;
        endif
    else
        result = RoundTowardsZero(UInt(R[n]) / UInt(R[m]));
    endif

    R[d] = result<31:0>;
endif
"""
}, { 
    "name" : "UHADD16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = UInt(R[n]<15:0>) + UInt(R[m]<15:0>);
    sum2 = UInt(R[n]<31:16>) + UInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, sum1<16:1>);
    set_bits(tmp_val, 31, 16, sum2<16:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UHADD8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = UInt(R[n]<7:0>) + UInt(R[m]<7:0>);
    sum2 = UInt(R[n]<15:8>) + UInt(R[m]<15:8>);
    sum3 = UInt(R[n]<23:16>) + UInt(R[m]<23:16>);
    sum4 = UInt(R[n]<31:24>) + UInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, sum1<8:1>);
    set_bits(tmp_val, 15, 8, sum2<8:1>);
    set_bits(tmp_val, 23, 16, sum3<8:1>);
    set_bits(tmp_val, 31, 24, sum4<8:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UHASX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff = UInt(R[n]<15:0>) - UInt(R[m]<31:16>);
    sum = UInt(R[n]<31:16>) + UInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, diff<16:1>);
    set_bits(tmp_val, 31, 16, sum<16:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UHSAX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum = UInt(R[n]<15:0>) + UInt(R[m]<31:16>);
    diff = UInt(R[n]<31:16>) - UInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, sum<16:1>);
    set_bits(tmp_val, 31, 16, diff<16:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UHSUB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = UInt(R[n]<15:0>) - UInt(R[m]<15:0>);
    diff2 = UInt(R[n]<31:16>) - UInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, diff1<16:1>);
    set_bits(tmp_val, 31, 16, diff2<16:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UHSUB8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = UInt(R[n]<7:0>) - UInt(R[m]<7:0>);
    diff2 = UInt(R[n]<15:8>) - UInt(R[m]<15:8>);
    diff3 = UInt(R[n]<23:16>) - UInt(R[m]<23:16>);
    diff4 = UInt(R[n]<31:24>) - UInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, diff1<8:1>);
    set_bits(tmp_val, 15, 8, diff2<8:1>);
    set_bits(tmp_val, 23, 16, diff3<8:1>);
    set_bits(tmp_val, 31, 24, diff4<8:1>);
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UMAAL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = UInt(R[n]) * UInt(R[m]) + UInt(R[dHi]) + UInt(R[dLo]);
    R[dHi] = result<63:32>;
    R[dLo] = result<31:0>;
endif
"""
}, { 
    "name" : "UMLAL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = UInt(R[n]) * UInt(R[m]) + UInt(R[dHi]:R[dLo]);
    R[dHi] = result<63:32>;
    R[dLo] = result<31:0>;
    if setflags then
        APSR.N = result<63>;
        APSR.Z = IsZeroBit(result<63:0>);
        if ArchVersion() == 4 then
            APSR.C = UNKNOWN_VALUE;
            APSR.V = UNKNOWN_VALUE;
        endif
    endif
endif
"""
}, { 
    "name" : "UMULL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    result = UInt(R[n]) * UInt(R[m]);
    R[dHi] = result<63:32>;
    R[dLo] = result<31:0>;
    if setflags then
        APSR.N = result<63>;
        APSR.Z = IsZeroBit(result<63:0>);
        if ArchVersion() == 4 then
            APSR.C = UNKNOWN_VALUE;
            APSR.V = UNKNOWN_VALUE;
        endif
    endif
endif
"""
}, { 
    "name" : "UQADD16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = UInt(R[n]<15:0>) + UInt(R[m]<15:0>);
    sum2 = UInt(R[n]<31:16>) + UInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, UnsignedSat(sum1, 16));
    set_bits(tmp_val, 31, 16, UnsignedSat(sum2, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UQADD8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum1 = UInt(R[n]<7:0>) + UInt(R[m]<7:0>);
    sum2 = UInt(R[n]<15:8>) + UInt(R[m]<15:8>);
    sum3 = UInt(R[n]<23:16>) + UInt(R[m]<23:16>);
    sum4 = UInt(R[n]<31:24>) + UInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, UnsignedSat(sum1, 8));
    set_bits(tmp_val, 15, 8, UnsignedSat(sum2, 8));
    set_bits(tmp_val, 23, 16, UnsignedSat(sum3, 8));
    set_bits(tmp_val, 31, 24, UnsignedSat(sum4, 8));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UQASX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff = UInt(R[n]<15:0>) - UInt(R[m]<31:16>);
    sum = UInt(R[n]<31:16>) + UInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, UnsignedSat(diff, 16));
    set_bits(tmp_val, 31, 16, UnsignedSat(sum, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UQSAX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum = UInt(R[n]<15:0>) + UInt(R[m]<31:16>);
    diff = UInt(R[n]<31:16>) - UInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, UnsignedSat(sum, 16));
    set_bits(tmp_val, 31, 16, UnsignedSat(diff, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UQSUB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = UInt(R[n]<15:0>) - UInt(R[m]<15:0>);
    diff2 = UInt(R[n]<31:16>) - UInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, UnsignedSat(diff1, 16));
    set_bits(tmp_val, 31, 16, UnsignedSat(diff2, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UQSUB8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = UInt(R[n]<7:0>) - UInt(R[m]<7:0>);
    diff2 = UInt(R[n]<15:8>) - UInt(R[m]<15:8>);
    diff3 = UInt(R[n]<23:16>) - UInt(R[m]<23:16>);
    diff4 = UInt(R[n]<31:24>) - UInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, UnsignedSat(diff1, 8));
    set_bits(tmp_val, 15, 8, UnsignedSat(diff2, 8));
    set_bits(tmp_val, 23, 16, UnsignedSat(diff3, 8));
    set_bits(tmp_val, 31, 24, UnsignedSat(diff4, 8));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "USAD8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    absdiff1 = Abs(UInt(R[n]<7:0>) - UInt(R[m]<7:0>));
    absdiff2 = Abs(UInt(R[n]<15:8>) - UInt(R[m]<15:8>));
    absdiff3 = Abs(UInt(R[n]<23:16>) - UInt(R[m]<23:16>));
    absdiff4 = Abs(UInt(R[n]<31:24>) - UInt(R[m]<31:24>));
    result = absdiff1 + absdiff2 + absdiff3 + absdiff4;
    R[d] = result<31:0>;
endif
"""
}, { 
    "name" : "USADA8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    absdiff1 = Abs(UInt(R[n]<7:0>) - UInt(R[m]<7:0>));
    absdiff2 = Abs(UInt(R[n]<15:8>) - UInt(R[m]<15:8>));
    absdiff3 = Abs(UInt(R[n]<23:16>) - UInt(R[m]<23:16>));
    absdiff4 = Abs(UInt(R[n]<31:24>) - UInt(R[m]<31:24>));
    result = UInt(R[a]) + absdiff1 + absdiff2 + absdiff3 + absdiff4;
    R[d] = result<31:0>;
endif
"""
}, { 
    "name" : "USAT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    operand = Shift(R[n], shift_t, shift_n, APSR.C);
    (result, sat) = UnsignedSatQ(SInt(operand), saturate_to);
    R[d] = ZeroExtend(result, 32);
    if sat then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "USAT16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    (result1, sat1) = UnsignedSatQ(SInt(R[n]<15:0>), saturate_to);
    (result2, sat2) = UnsignedSatQ(SInt(R[n]<31:16>), saturate_to);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, ZeroExtend(result1, 16));
    set_bits(tmp_val, 31, 16, ZeroExtend(result2, 16));
    R[d] = tmp_val;
    if sat1 || sat2 then
        APSR.Q = '1';
    endif
endif
"""
}, { 
    "name" : "USAX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    sum = UInt(R[n]<15:0>) + UInt(R[m]<31:16>);
    diff = UInt(R[n]<31:16>) - UInt(R[m]<15:0>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, sum<15:0>);
    set_bits(tmp_val, 31, 16, diff<15:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bits(tmp_val, 1, 0, if sum >= 0x10000 then '11' else '00');
    set_bits(tmp_val, 3, 2, if diff >= 0 then '11' else '00');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "USUB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = UInt(R[n]<15:0>) - UInt(R[m]<15:0>);
    diff2 = UInt(R[n]<31:16>) - UInt(R[m]<31:16>);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, diff1<15:0>);
    set_bits(tmp_val, 31, 16, diff2<15:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;
    set_bits(tmp_val, 1, 0, if diff1 >= 0 then '11' else '00');
    set_bits(tmp_val, 3, 2, if diff2 >= 0 then '11' else '00');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "USUB8",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    diff1 = UInt(R[n]<7:0>) - UInt(R[m]<7:0>);
    diff2 = UInt(R[n]<15:8>) - UInt(R[m]<15:8>);
    diff3 = UInt(R[n]<23:16>) - UInt(R[m]<23:16>);
    diff4 = UInt(R[n]<31:24>) - UInt(R[m]<31:24>);
    tmp_val = R[d];
    set_bits(tmp_val, 7, 0, diff1<7:0>);
    set_bits(tmp_val, 15, 8, diff2<7:0>);
    set_bits(tmp_val, 23, 16, diff3<7:0>);
    set_bits(tmp_val, 31, 24, diff4<7:0>);
    R[d] = tmp_val;
    tmp_val = APSR.GE;    
    set_bit(tmp_val, 0, if diff1 >= 0 then '1' else '0');
    set_bit(tmp_val, 1, if diff2 >= 0 then '1' else '0');
    set_bit(tmp_val, 2, if diff3 >= 0 then '1' else '0');
    set_bit(tmp_val, 3, if diff4 >= 0 then '1' else '0');
    APSR.GE = tmp_val;
endif
"""
}, { 
    "name" : "UXTAB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    R[d] = R[n] + ZeroExtend(rotated<7:0>, 32);
endif
"""
}, { 
    "name" : "UXTAB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, R[n]<15:0> + ZeroExtend(rotated<7:0>, 16));
    set_bits(tmp_val, 31, 16, R[n]<31:16> + ZeroExtend(rotated<23:16>, 16));
    R[d] = tmp_val;
endif
"""
}, { 
    "name" : "UXTAH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    R[d] = R[n] + ZeroExtend(rotated<15:0>, 32);
endif
"""
}, { 
    "name" : "UXTB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    R[d] = ZeroExtend(rotated<7:0>, 32);
endif
"""
}, { 
    "name" : "UXTB16",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    tmp_val = R[d];
    set_bits(tmp_val, 15, 0, ZeroExtend(rotated<7:0>, 16));
    set_bits(tmp_val, 31, 16, ZeroExtend(rotated<23:16>, 16));
    R[d] = tmp_val;    
endif
"""
}, { 
    "name" : "UXTH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    rotated = ROR(R[m], rotation);
    R[d] = ZeroExtend(rotated<15:0>, 32);
endif
"""
}, { 
    "name" : "VABA, VABAL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            npr = n + r;
            mpr = m + r;

            val1 = Din[npr];
            val2 = Din[mpr];
            op1 = Elem[val1, e, esize];
            op2 = Elem[val2, e, esize];
            
            absdiff = Abs(Int(op1,unsigned) - Int(op2,unsigned));
            if long_destination then
                ds = d >> 1;
                esize2 = 2 * esize;
                val1 = Q[ds];
                val2 = Qin[ds];
                Elem[val1, e, esize2] = Elem[val2, e, esize2] + absdiff;
            else
                dr = d + r;
                val1 = D[dr];
                val2 = Din[dr];
                Elem[val1, e, esize] = Elem[val2, e, esize] + absdiff;
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VABD, VABDL (integer)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            npr = n + r;
            mpr = m + r;
            val1 = Din[npr];
            val2 = Din[mpr];
            op1 = Elem[val1,e,esize];
            op2 = Elem[val2,e,esize];
            absdiff = Abs(Int(op1,unsigned) - Int(op2,unsigned));
            if long_destination then
                ds = d >> 1;
                esize2 = 2 * esize;
                esize2_1 = esize2 - 1;
                val1 = Q[ds];
                Elem[val1, e, esize2] = absdiff<esize2_1:0>;
            else
                dr = d + r;
                val1 = D[dr];
                esize2_1 = esize - 1;
                Elem[val1, e, esize] = absdiff<esize2_1:0>;
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VABD (floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            npr = n + r;
            mpr = m + r; 
            val1 = D[npr];
            val2 = D[mpr];
            op1 = Elem[val1,e,esize];
            op2 = Elem[val2,e,esize];

            dpr = d + r;
            val3 = D[dpr];
            Elem[val3,e,esize] = FPAbs(FPSub(op1,op2,FALSE));
        endfor
    endfor
endif
"""
}, { 
    "name" : "VABS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if advsimd then
        for r = 0 to regs-1
            for e = 0 to elements-1
                if floating_point then
                    dpr = d + r;
                    mpr = m + r;
                    Elem[D[dpr],e,esize] = FPAbs(Elem[D[mpr],e,esize]);
                else
                    dpr = d + r;
                    mpr = m + r;
                    esize_1 = esize - 1;
                    result = Abs(SInt(Elem[D[mpr],e,esize]));
                    Elem[D[dpr],e,esize] = result<esize_1:0>;
                endif
            endfor
        endfor
    else
        if dp_operation then
            D[d] = FPAbs(D[m]);
        else
            S[d] = FPAbs(S[m]);
        endif
    endif
endif
"""
}, { 
    "name" : "VACGE, VACGT, VACLE, VACLT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            npr = n + r;
            mpr = m + r;
            op1 = FPAbs(Elem[D[npr],e,esize]);
            op2 = FPAbs(Elem[D[mpr],e,esize]);
            if or_equal then
                test_passed = FPCompareGE(op1, op2, FALSE);
            else
                test_passed = FPCompareGT(op1, op2, FALSE);
            endif

            dpr = d + r;
            Elem[D[dpr],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VADD (integer)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            dpr = d + r;
            npr = n + r;
            mpr = m + r;
            Elem[D[dpr],e,esize] = Elem[D[npr],e,esize] + Elem[D[mpr],e,esize];
        endfor
    endfor
endif
"""
}, { 
    "name" : "VADD (floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if advsimd then
        for r = 0 to regs-1
            for e = 0 to elements-1
                dpr = d + r;
                npr = n + r;
                mpr = m + r;
                Elem[D[dpr],e,esize] = FPAdd(Elem[D[npr],e,esize], Elem[D[mpr],e,esize], FALSE);
            endfor
        endfor
    else
        if dp_operation then
            D[d] = FPAdd(D[n], D[m], TRUE);
        else
            S[d] = FPAdd(S[n], S[m], TRUE);
        endif
    endif
endif
"""
}, { 
    "name" : "VADDHN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for e = 0 to elements-1
        ns1 = n >> 1;
        ms1 = m >> 1;
        result = Elem[Qin[ns1], e, 2 * esize] + Elem[Qin[ms1], e, 2 * esize];
        Elem[D[d],e,esize] = result<2 * esize - 1:esize>;
    endfor
endif
"""
}, { 
    "name" : "VADDL, VADDW",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for e = 0 to elements-1
        if is_vaddw then
            ns1 = n >> 1;
            op1 = Int(Elem[Qin[n>>1],e,2*esize], unsigned);
        else
            op1 = Int(Elem[Din[n],e,esize], unsigned);
        endif

        result = op1 + Int(Elem[Din[m],e,esize],unsigned);
        Elem[Q[d>>1],e,2*esize] = result<2*esize-1:0>;
    endfor
endif
"""
}, { 
    "name" : "VAND (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        D[d+r] = D[n+r] AND D[m+r];
    endfor
endif
"""
}, { 
    "name" : "VBIC (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        D[d+r] = D[d+r] AND NOT(imm64);
    endfor
endif
"""
}, { 
    "name" : "VBIC (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        D[d+r] = D[n+r] AND NOT(D[m+r]);
    endfor
endif
"""
}, { 
    "name" : "VBIF, VBIT, VBSL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        case operation of
            when VBitOps_VBIF D[d+r] = (D[d+r] AND D[m+r]) OR (D[n+r] AND NOT(D[m+r]));
            when VBitOps_VBIT D[d+r] = (D[n+r] AND D[m+r]) OR (D[d+r] AND NOT(D[m+r]));
            when VBitOps_VBSL D[d+r] = (D[n+r] AND D[d+r]) OR (D[m+r] AND NOT(D[d+r]));
        endcase
    endfor
endif
"""
}, { 
    "name" : "VCEQ (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Elem[D[n+r],e,esize];
            op2 = Elem[D[m+r],e,esize];
            if int_operation then
                test_passed = (op1 == op2);
            else
                test_passed = FPCompareEQ(op1, op2, FALSE);
            endif

            Elem[D[d+r],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCEQ (immediate #0)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            if floating_point then
                test_passed = FPCompareEQ(Elem[D[m+r],e,esize], FPZero('0',esize), FALSE);
            else
                test_passed = (Elem[D[m+r],e,esize] == Zeros(esize));
            endif
            Elem[D[d+r],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCGE (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Elem[D[n+r],e,esize];
            op2 = Elem[D[m+r],e,esize];
            case type of
                when VCGEtype_signed test_passed = (SInt(op1) >= SInt(op2));
                when VCGEtype_unsigned test_passed = (UInt(op1) >= UInt(op2));
                when VCGEtype_fp test_passed = FPCompareGE(op1, op2, FALSE);
            endcase

            Elem[D[d+r],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCGE (immediate #0)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            if floating_point then
                test_passed = FPCompareGE(Elem[D[m+r],e,esize], FPZero('0',esize), FALSE);
            else
                test_passed = (SInt(Elem[D[m+r],e,esize]) >= 0);
            endif

            Elem[D[d+r],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCGT (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Elem[D[n+r],e,esize];
            op2 = Elem[D[m+r],e,esize];
            case type of
                when VCGTtype_signed test_passed = (SInt(op1) > SInt(op2));
                when VCGTtype_unsigned test_passed = (UInt(op1) > UInt(op2));
                when VCGTtype_fp test_passed = FPCompareGT(op1, op2, FALSE);
            endcase

            Elem[D[d+r],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCGT (immediate #0)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            if floating_point then
                test_passed = FPCompareGT(Elem[D[m+r],e,esize], FPZero('0',esize), FALSE);
            else
                test_passed = (SInt(Elem[D[m+r],e,esize]) > 0);
            endif
            Elem[D[d+r],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCLE (immediate #0)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            if floating_point then
                test_passed = FPCompareGE(FPZero('0',esize), Elem[D[m+r],e,esize], FALSE);
            else
                test_passed = (SInt(Elem[D[m+r],e,esize]) <= 0);
            endif
            Elem[D[d+r],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCLS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = CountLeadingSignBits(Elem[D[m+r],e,esize]);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCLT (immediate #0)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            if floating_point then
                test_passed = FPCompareGT(FPZero('0',esize), Elem[D[m+r],e,esize], FALSE);
            else
                test_passed = (SInt(Elem[D[m+r],e,esize]) < 0);
            endif

            Elem[D[d+r],e,esize] = if test_passed then Ones(esize) else Zeros(esize);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCLZ",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = CountLeadingZeroBits(Elem[D[m+r],e,esize]);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCMP, VCMPE",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if dp_operation then
        op2 = if with_zero then FPZero('0',64) else D[m];
        (FPSCR.N, FPSCR.Z, FPSCR.C, FPSCR.V) = FPCompare(D[d], op2, quiet_nan_exc, TRUE);
    else
        op2 = if with_zero then FPZero('0',32) else S[m];
        (FPSCR.N, FPSCR.Z, FPSCR.C, FPSCR.V) = FPCompare(S[d], op2, quiet_nan_exc, TRUE);
    endif
endif
"""
}, { 
    "name" : "VCNT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = BitCount(Elem[D[m+r],e,esize]);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCVT (between floating-point and integer, Advanced SIMD)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op = Elem[D[m+r],e,esize];
            if to_integer then
                result = FPToFixed(op, esize, 0, unsigned_, round_zero, FALSE);
            else
                result = FixedToFP(op, esize, 0, unsigned_, round_nearest, FALSE);
            endif
            Elem[D[d+r],e,esize] = result;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCVT, VCVTR (between floating-point and integer, Floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if to_integer then
        if dp_operation then
            S[d] = FPToFixed(D[m], 32, 0, unsigned_, round_zero, TRUE);
        else
            S[d] = FPToFixed(S[m], 32, 0, unsigned_, round_zero, TRUE);
        endif
    else
        if dp_operation then
            D[d] = FixedToFP(S[m], 64, 0, unsigned_, round_nearest, TRUE);
        else
            S[d] = FixedToFP(S[m], 32, 0, unsigned_, round_nearest, TRUE);
        endif
    endif
endif
"""
}, { 
    "name" : "VCVT (between floating-point and fixed-point, Advanced SIMD)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op = Elem[D[m+r],e,esize];
            if to_fixed then
                result = FPToFixed(op, esize, frac_bits, unsigned_, round_zero, FALSE);
            else
                result = FixedToFP(op, esize, frac_bits, unsigned_, round_nearest, FALSE);
            endif
            
            Elem[D[d+r],e,esize] = result;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VCVT (between floating-point and fixed-point, Floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if to_fixed then
        if dp_operation then
            result = FPToFixed(D[d], size, frac_bits, unsigned_, round_zero, TRUE);
            D[d] = if unsigned_ then ZeroExtend(result, 64) else SignExtend(result, 64);
        else
            result = FPToFixed(S[d], size, frac_bits, unsigned_, round_zero, TRUE);
            S[d] = if unsigned_ then ZeroExtend(result, 32) else SignExtend(result, 32);
        endif
    else
        if dp_operation then
            D[d] = FixedToFP(D[d]<size-1:0>, 64, frac_bits, unsigned_, round_nearest, TRUE);
        else
            S[d] = FixedToFP(S[d]<size-1:0>, 32, frac_bits, unsigned_, round_nearest, TRUE);
        endif
    endif
endif
"""
}, { 
    "name" : "VCVT (between double-precision and single-precision)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if double_to_single then
        S[d] = FPDoubleToSingle(D[m], TRUE);
    else
        D[d] = FPSingleToDouble(S[m], TRUE);
    endif
endif
"""
}, { 
    "name" : "VCVT (between half-precision and single-precision, Advanced SIMD)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for e = 0 to elements-1
        if half_to_single then
            Elem[Q[d>>1],e,2*esize] = FPHalfToSingle(Elem[Din[m],e,esize], FALSE);
        else
            Elem[D[d],e,esize] = FPSingleToHalf(Elem[Qin[m>>1],e,2*esize], FALSE);
        endif
    endfor
endif
"""
}, { 
    "name" : "VCVTB, VCVTT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if half_to_single then
        S[d] = FPHalfToSingle(S[m]<lowbit+15:lowbit>, TRUE);
    else
        tmp_val = S[d];
        set_bits(tmp_val, lowbit+15, lowbit, FPSingleToHalf(S[m], TRUE));
        S[d] = tmp_val;
    endif
endif
"""
}, { 
    "name" : "VDIV",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if dp_operation then
        D[d] = FPDiv(D[n], D[m], TRUE);
    else
        S[d] = FPDiv(S[n], S[m], TRUE);
    endif
endif
"""
}, { 
    "name" : "VDUP (scalar)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    scalar = Elem[D[m],index,esize];
    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = scalar;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VDUP (ARM core register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    scalar = R[t]<esize-1:0>;
    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = scalar;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VEOR",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        D[d+r] = D[n+r] EOR D[m+r];
    endfor
endif
"""
}, { 
    "name" : "VEXT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
endif
"""
}, { 
    "name" : "VFMA, VFMS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if advsimd then
        for r = 0 to regs-1
            for e = 0 to elements-1
                op1 = Elem[D[n+r],e,esize];
                if op1_neg then
                    op1 = FPNeg(op1);
                endif

                Elem[D[d+r],e,esize] = FPMulAdd(Elem[D[d+r],e,esize], op1, Elem[D[m+r],e,esize], FALSE);
            endfor
        endfor
    else
        if dp_operation then
            op1 = if op1_neg then FPNeg(D[n]) else D[n];
            D[d] = FPMulAdd(D[d], op1, D[m], TRUE);
        else
            op1 = if op1_neg then FPNeg(S[n]) else S[n];
            S[d] = FPMulAdd(S[d], op1, S[m], TRUE);
        endif
    endif
endif
"""
}, { 
    "name" : "VFNMA, VFNMS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if dp_operation then
        op1 = if op1_neg then FPNeg(D[n]) else D[n];
        D[d] = FPMulAdd(FPNeg(D[d]), op1, D[m], TRUE);
    else
        op1 = if op1_neg then FPNeg(S[n]) else S[n];
        S[d] = FPMulAdd(FPNeg(S[d]), op1, S[m], TRUE);
    endif
endif
"""
}, { 
    "name" : "VHADD, VHSUB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Int(Elem[D[n+r],e,esize], unsigned);
            op2 = Int(Elem[D[m+r],e,esize], unsigned);
            result = if add then op1+op2 else op1-op2;
            Elem[D[d+r],e,esize] = result<esize:1>;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VLD1 (multiple single elements)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 8*regs);
    endif

    for r = 0 to regs-1
        for e = 0 to elements-1
            if ebytes != 8 then
                set_bits(data, esize-1, 0, MemU[address,ebytes]);
            else
                set_bits(data, 31, 0, if BigEndian() then MemU[address+4,4] else MemU[address,4]);
                set_bits(data, 63, 32, if BigEndian() then MemU[address,4] else MemU[address+4,4]);
            endif

            Elem[D[d+r],e,esize] = data<esize-1:0>;
            address = address + ebytes;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VLD1 (single element to one lane)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else ebytes);
    endif

    Elem[D[d],index,esize] = MemU[address,ebytes];
endif
"""
}, { 
    "name" : "VLD1 (single element to all lanes)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then 
        R[n] = R[n] + (if register_index then R[m] else ebytes);
    endif

    replicated_element = Replicate(MemU[address,ebytes], elements);
    for r = 0 to regs-1
        D[d+r] = replicated_element;
    endfor
endif
"""
}, { 
    "name" : "VLD2 (multiple 2-element structures)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];

    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 16*regs);
    endif

    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = MemU[address,ebytes];
            Elem[D[d2+r],e,esize] = MemU[address+ebytes,ebytes];
            address = address + 2*ebytes;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VLD2 (single 2-element structure to one lane)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 2*ebytes);
    endif

    Elem[D[d],index,esize] = MemU[address,ebytes];
    Elem[D[d2],index,esize] = MemU[address+ebytes,ebytes];
endif
"""
}, { 
    "name" : "VLD2 (single 2-element structure to all lanes)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 2*ebytes);
    endif

    D[d] = Replicate(MemU[address,ebytes], elements);
    D[d2] = Replicate(MemU[address+ebytes,ebytes], elements);
endif
"""
}, { 
    "name" : "VLD3 (multiple 3-element structures)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];

    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 24);
    endif

    for e = 0 to elements-1
        Elem[D[d],e,esize] = MemU[address,ebytes];
        Elem[D[d2],e,esize] = MemU[address+ebytes,ebytes];
        Elem[D[d3],e,esize] = MemU[address+2*ebytes,ebytes];
        address = address + 3*ebytes;
    endfor
endif
"""
}, { 
    "name" : "VLD3 (single 3-element structure to one lane)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if wback then
        R[n] = R[n] + (if register_index then R[m] else 3*ebytes);
    endif

    Elem[D[d],index,esize] = MemU[address,ebytes];
    Elem[D[d2],index,esize] = MemU[address+ebytes,ebytes];
    Elem[D[d3],index,esize] = MemU[address+2*ebytes,ebytes];
endif
"""
}, { 
    "name" : "VLD3 (single 3-element structure to all lanes)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if wback then
        R[n] = R[n] + (if register_index then R[m] else 3*ebytes);
    endif

    D[d] = Replicate(MemU[address,ebytes], elements);
    D[d2] = Replicate(MemU[address+ebytes,ebytes], elements);
    D[d3] = Replicate(MemU[address+2*ebytes,ebytes], elements);
endif
"""
}, { 
    "name" : "VLD4 (multiple 4-element structures)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 32);
    endif

    for e = 0 to elements-1
        Elem[D[d],e,esize] = MemU[address,ebytes];
        Elem[D[d2],e,esize] = MemU[address+ebytes,ebytes];
        Elem[D[d3],e,esize] = MemU[address+2*ebytes,ebytes];
        Elem[D[d4],e,esize] = MemU[address+3*ebytes,ebytes];
        address = address + 4*ebytes;
    endfor
endif
"""
}, { 
    "name" : "VLD4 (single 4-element structure to one lane)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 4*ebytes);
    endif

    Elem[D[d],index,esize] = MemU[address,ebytes];
    Elem[D[d2],index,esize] = MemU[address+ebytes,ebytes];
    Elem[D[d3],index,esize] = MemU[address+2*ebytes,ebytes];
    Elem[D[d4],index,esize] = MemU[address+3*ebytes,ebytes];
endif
"""
}, { 
    "name" : "VLD4 (single 4-element structure to all lanes)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 4*ebytes);
    endif

    D[d] = Replicate(MemU[address,ebytes], elements);
    D[d2] = Replicate(MemU[address+ebytes,ebytes], elements);
    D[d3] = Replicate(MemU[address+2*ebytes,ebytes], elements);
    D[d4] = Replicate(MemU[address+3*ebytes,ebytes], elements);
endif
"""
}, { 
    "name" : "VLDM",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    NullCheckIfThumbEE(n);
    address = if add then R[n] else R[n]-imm32;
    if wback then
        R[n] = if add then R[n]+imm32 else R[n]-imm32;
    endif

    for r = 0 to regs-1
        if single_regs then
            S[d+r] = MemA[address,4];
            address = address+4;
        else
            word1 = MemA[address,4];
            word2 = MemA[address+4,4];
            address = address+8;
            D[d+r] = if BigEndian() then word1:word2 else word2:word1;
        endif
    endfor
endif
"""
}, { 
    "name" : "VLDR",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    NullCheckIfThumbEE(n);
    base = if n == 15 then Align(R[15],4) else R[n];
    address = if add then (base + imm32) else (base - imm32);
    if single_reg then
        S[d] = MemA[address,4];
    else
        word1 = MemA[address,4];
        word2 = MemA[address+4,4];
        D[d] = if BigEndian() then word1:word2 else word2:word1;
    endif
endif
"""
}, { 
    "name" : "VMAX, VMIN (integer)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Int(Elem[D[n+r],e,esize], unsigned);
            op2 = Int(Elem[D[m+r],e,esize], unsigned);
            result = if maximum then Max(op1,op2) else Min(op1,op2);
            Elem[D[d+r],e,esize] = result<esize-1:0>;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VMAX, VMIN (floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Elem[D[n+r],e,esize];
            op2 = Elem[D[m+r],e,esize];
            Elem[D[d+r],e,esize] = if maximum then FPMax(op1,op2,FALSE) else FPMin(op1,op2,FALSE);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VMLA, VMLAL, VMLS, VMLSL (integer)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            product = Int(Elem[Din[n+r],e,esize],unsigned) * Int(Elem[Din[m+r],e,esize],unsigned);
            addend = if add then product else -product;
            if long_destination then
                Elem[Q[d>>1],e,2*esize] = Elem[Qin[d>>1],e,2*esize] + addend;
            else
                Elem[D[d+r],e,esize] = Elem[Din[d+r],e,esize] + addend;
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VMLA, VMLS (floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if advsimd then
        for r = 0 to regs-1
            for e = 0 to elements-1
                product = FPMul(Elem[D[n+r],e,esize], Elem[D[m+r],e,esize], FALSE);
                addend = if add then product else FPNeg(product);
                Elem[D[d+r],e,esize] = FPAdd(Elem[D[d+r],e,esize], addend, FALSE);
            endfor
        endfor
    else
        if dp_operation then
            addend = if add then FPMul(D[n], D[m], TRUE) else FPNeg(FPMul(D[n], D[m], TRUE));
            D[d] = FPAdd(D[d], addend, TRUE);
        else
            addend = if add then FPMul(S[n], S[m], TRUE) else FPNeg(FPMul(S[n], S[m], TRUE));
            S[d] = FPAdd(S[d], addend, TRUE);
        endif
    endif
endif
"""
}, { 
    "name" : "VMLA, VMLAL, VMLS, VMLSL (by scalar)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    op2 = Elem[Din[m],index,esize];
    op2val = Int(op2, unsigned);
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Elem[Din[n+r],e,esize];
            op1val = Int(op1, unsigned);

            if floating_point then
                fp_addend = if add then FPMul(op1,op2,FALSE) else FPNeg(FPMul(op1,op2,FALSE));
                Elem[D[d+r],e,esize] = FPAdd(Elem[Din[d+r],e,esize], fp_addend, FALSE);
            else
                addend = if add then op1val*op2val else -op1val*op2val;
                if long_destination then
                    Elem[Q[d>>1],e,2*esize] = Elem[Qin[d>>1],e,2*esize] + addend;
                else
                    Elem[D[d+r],e,esize] = Elem[Din[d+r],e,esize] + addend;
                endif
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VMOV (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if single_register then
        S[d] = imm32;
    else
        for r = 0 to regs-1
            D[d+r] = imm64;
        endfor
    endif
endif
"""
}, { 
    "name" : "VMOV (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if single_register then
        S[d] = S[m];
    else
        for r = 0 to regs-1
            D[d+r] = D[m+r];
        endfor
    endif
endif
"""
}, { 
    "name" : "VMOV (ARM core register to scalar)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    Elem[D[d],index,esize] = R[t]<esize-1:0>;
endif
"""
}, { 
    "name" : "VMOV (scalar to ARM core register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if unsigned_ then
        R[t] = ZeroExtend(Elem[D[n],index,esize], 32);
    else
        R[t] = SignExtend(Elem[D[n],index,esize], 32);
    endif
endif
"""
}, { 
    "name" : "VMOV (between ARM core register and single-precision register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if to_arm_register then
        R[t] = S[n];
    else
        S[n] = R[t];
    endif
endif
"""
}, { 
    "name" : "VMOV (between two ARM core registers and two single-precision registers)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if to_arm_registers then
        R[t] = S[m];
        R[t2] = S[m+1];
    else
        S[m] = R[t];
        S[m+1] = R[t2];
    endif
endif
"""
}, { 
    "name" : "VMOV (between two ARM core registers and a doubleword extension register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    if to_arm_registers then
        R[t] = D[m]<31:0>;
        R[t2] = D[m]<63:32>;
    else
        tmp_val = D[m];
        set_bits(tmp_val, 31, 0, R[t]);
        set_bits(tmp_val, 63, 32, R[t2]);
        D[m] = tmp_val;
    endif
endif
"""
}, { 
    "name" : "VMOVL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for e = 0 to elements-1
        result = Int(Elem[Din[m],e,esize], unsigned);
        Elem[Q[d>>1],e,2*esize] = result<2*esize-1:0>;
    endfor
endif
"""
}, { 
    "name" : "VMOVN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for e = 0 to elements-1
        Elem[D[d],e,esize] = Elem[Qin[m>>1],e,2*esize]<esize-1:0>;
    endfor
endif
"""
}, { 
    "name" : "VMRS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    SerializeVFP();
    VFPExcBarrier();
    
    if t != 15 then
        R[t] = FPSCR;
    else
        APSR.N = FPSCR.N;
        APSR.Z = FPSCR.Z;
        APSR.C = FPSCR.C;
        APSR.V = FPSCR.V;
    endif
endif
"""
}, { 
    "name" : "VMSR",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    SerializeVFP();
    VFPExcBarrier();
    FPSCR = R[t];
endif
"""
}, { 
    "name" : "VMUL, VMULL (integer and polynomial)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Elem[Din[n+r],e,esize];
            op1val = Int(op1, unsigned);
            op2 = Elem[Din[m+r],e,esize];
            op2val = Int(op2, unsigned);

            if polynomial then
                product = PolynomialMult(op1,op2);
            else
                tmp = (op1val*op2val);
                product = tmp<2*esize-1:0>;
            endif

            if long_destination then
                Elem[Q[d>>1],e,2*esize] = product;
            else
                Elem[D[d+r],e,esize] = product<esize-1:0>;
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VMUL (floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if advsimd then
        for r = 0 to regs-1
            for e = 0 to elements-1
                Elem[D[d+r],e,esize] = FPMul(Elem[D[n+r],e,esize], Elem[D[m+r],e,esize], FALSE);
            endfor
        endfor
    else
        if dp_operation then
            D[d] = FPMul(D[n], D[m], TRUE);
        else
            S[d] = FPMul(S[n], S[m], TRUE);
        endif
    endif
endif
"""
}, { 
    "name" : "VMUL, VMULL (by scalar)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    op2 = Elem[Din[m],index,esize];
    op2val = Int(op2, unsigned);

    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Elem[Din[n+r],e,esize];
            op1val = Int(op1, unsigned);

            if floating_point then
                Elem[D[d+r],e,esize] = FPMul(op1, op2, FALSE);
            else
                tmp = (op1val*op2val);
                if long_destination then
                    Elem[Q[d>>1],e,2*esize] = tmp<2*esize-1:0>;
                else
                    Elem[D[d+r],e,esize] = tmp<esize-1:0>;
                endif
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VMVN (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        D[d+r] = NOT(imm64);
    endfor
endif
"""
}, { 
    "name" : "VMVN (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        D[d+r] = NOT(D[m+r]);
    endfor
endif
"""
}, { 
    "name" : "VNEG",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    
    if advsimd then
        for r = 0 to regs-1
            for e = 0 to elements-1
                if floating_point then
                    Elem[D[d+r],e,esize] = FPNeg(Elem[D[m+r],e,esize]);
                else
                    result = -SInt(Elem[D[m+r],e,esize]);
                    Elem[D[d+r],e,esize] = result<esize-1:0>;
                endif
            endfor
        endfor
    else
        if dp_operation then
            D[d] = FPNeg(D[m]);
        else
            S[d] = FPNeg(S[m]);
        endif
    endif
endif
"""
}, { 
    "name" : "VNMLA, VNMLS, VNMUL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);

    if dp_operation then
        product = FPMul(D[n], D[m], TRUE);
        case type of
            when VFPNegMul_VNMLA D[d] = FPAdd(FPNeg(D[d]), FPNeg(product), TRUE);
            when VFPNegMul_VNMLS D[d] = FPAdd(FPNeg(D[d]), product, TRUE);
            when VFPNegMul_VNMUL D[d] = FPNeg(product);
        endcase
    else
        product = FPMul(S[n], S[m], TRUE);
        case type of
            when VFPNegMul_VNMLA S[d] = FPAdd(FPNeg(S[d]), FPNeg(product), TRUE);
            when VFPNegMul_VNMLS S[d] = FPAdd(FPNeg(S[d]), product, TRUE);
            when VFPNegMul_VNMUL S[d] = FPNeg(product);
        endcase
    endif
endif
"""
}, { 
    "name" : "VORN (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        D[d+r] = D[n+r] OR NOT(D[m+r]);
    endfor
endif
"""
}, { 
    "name" : "VORR (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        D[d+r] = D[d+r] OR imm64;
    endfor
endif
"""
}, { 
    "name" : "VORR (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        D[d+r] = D[n+r] OR D[m+r];
    endfor
endif
"""
}, { 
    "name" : "VPADAL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    h = elements/2;
    for r = 0 to regs-1
        for e = 0 to h-1
            op1 = Elem[D[m+r],2*e,esize];
            op2 = Elem[D[m+r],2*e+1,esize];
            result = Int(op1, unsigned) + Int(op2, unsigned);
            Elem[D[d+r],e,2*esize] = Elem[D[d+r],e,2*esize] + result;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VPADD (integer)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    dest = 0;
    h = elements/2;
    for e = 0 to h-1
        Elem[dest,e,esize] = Elem[D[n],2*e,esize] + Elem[D[n],2*e+1,esize];
        Elem[dest,e+h,esize] = Elem[D[m],2*e,esize] + Elem[D[m],2*e+1,esize];
    endfor

    D[d] = dest;
endif
"""
}, { 
    "name" : "VPADD (floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    dest = 0;
    h = elements/2;
    for e = 0 to h-1
        Elem[dest,e,esize] = FPAdd(Elem[D[n],2*e,esize], Elem[D[n],2*e+1,esize], FALSE);
        Elem[dest,e+h,esize] = FPAdd(Elem[D[m],2*e,esize], Elem[D[m],2*e+1,esize], FALSE);
    endfor

    D[d] = dest;
endif
"""
}, { 
    "name" : "VPADDL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    h = elements/2;
    for r = 0 to regs-1
        for e = 0 to h-1
            op1 = Elem[D[m+r],2*e,esize];
            op2 = Elem[D[m+r],2*e+1,esize];
            result = Int(op1, unsigned) + Int(op2, unsigned);
            Elem[D[d+r],e,2*esize] = result<2*esize-1:0>;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VPMAX, VPMIN (integer)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    dest = 0;
    h = elements/2;
    for e = 0 to h-1
        op1 = Int(Elem[D[n],2*e,esize], unsigned);
        op2 = Int(Elem[D[n],2*e+1,esize], unsigned);
        result = if maximum then Max(op1,op2) else Min(op1,op2);
        Elem[dest,e,esize] = result<esize-1:0>;
        op1 = Int(Elem[D[m],2*e,esize], unsigned);
        op2 = Int(Elem[D[m],2*e+1,esize], unsigned);
        result = if maximum then Max(op1,op2) else Min(op1,op2);
        Elem[dest,e+h,esize] = result<esize-1:0>;
        D[d] = dest;
    endfor
endif
"""
}, { 
    "name" : "VPMAX, VPMIN (floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    dest = 0;
    h = elements/2;
    for e = 0 to h-1
        op1 = Elem[D[n],2*e,esize];
        op2 = Elem[D[n],2*e+1,esize];
        Elem[dest,e,esize] = if maximum then FPMax(op1,op2,FALSE) else FPMin(op1,op2,FALSE);
        op1 = Elem[D[m],2*e,esize];
        op2 = Elem[D[m],2*e+1,esize];
        Elem[dest,e+h,esize] = if maximum then FPMax(op1,op2,FALSE) else FPMin(op1,op2,FALSE);
        D[d] = dest;
    endfor
endif
"""
}, { 
    "name" : "VPOP",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    NullCheckIfThumbEE(13);
    
    address = R[13];
    R[13] = address + imm32;
    
    if single_regs then
        for r = 0 to regs-1
            S[d+r] = MemA[address,4];
            address = address+4;
        endfor
    else
        for r = 0 to regs-1
            word1 = MemA[address,4];
            word2 = MemA[address+4,4];
            address = address+8;
            D[d+r] = if BigEndian() then word1:word2 else word2:word1;
        endfor
    endif
endif
"""
}, { 
    "name" : "VPUSH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    NullCheckIfThumbEE(13);
    
    address = R[13] - imm32;
    R[13] = R[13] - imm32;
    
    if single_regs then
        for r = 0 to regs-1
            MemA[address,4] = S[d+r];
            address = address+4;
        endfor
    else
        for r = 0 to regs-1
            MemA[address,4] = if BigEndian() then D[d+r]<63:32> else D[d+r]<31:0>;
            MemA[address+4,4] = if BigEndian() then D[d+r]<31:0> else D[d+r]<63:32>;
            address = address+8;
        endfor
    endif
endif
"""
}, { 
    "name" : "VQABS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            result = Abs(SInt(Elem[D[m+r],e,esize]));
            (Elem[D[d+r],e,esize], sat) = SignedSatQ(result, esize);
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VQADD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for r = 0 to regs-1
        for e = 0 to elements-1
            sum = Int(Elem[D[n+r],e,esize], unsigned) + Int(Elem[D[m+r],e,esize], unsigned);
            (Elem[D[d+r],e,esize], sat) = SatQ(sum, esize, unsigned);
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VQDMLAL, VQDMLSL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    if scalar_form then
        op2 = SInt(Elem[Din[m],index,esize]);
    endif

    for e = 0 to elements-1
        if !scalar_form then
            op2 = SInt(Elem[Din[m],e,esize]);
        endif

        op1 = SInt(Elem[Din[n],e,esize]);
        (product, sat1) = SignedSatQ(2*op1*op2, 2*esize);
        if add then
            result = SInt(Elem[Qin[d>>1],e,2*esize]) + SInt(product);
        else
            result = SInt(Elem[Qin[d>>1],e,2*esize]) - SInt(product);
        endif

        (Elem[Q[d>>1],e,2*esize], sat2) = SignedSatQ(result, 2*esize);
        
        if sat1 || sat2 then
            FPSCR.QC = '1';
        endif
    endfor
endif
"""
}, { 
    "name" : "VQDMULH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    if scalar_form then
        op2 = SInt(Elem[D[m],index,esize]);
    endif

    for r = 0 to regs-1
        for e = 0 to elements-1
            if !scalar_form then
                op2 = SInt(Elem[D[m+r],e,esize]);
            endif

            op1 = SInt(Elem[D[n+r],e,esize]);
            (result, sat) = SignedSatQ((2*op1*op2) >> esize, esize);
            Elem[D[d+r],e,esize] = result;
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VQDMULL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    if scalar_form then
        op2 = SInt(Elem[Din[m],index,esize]);
    endif

    for e = 0 to elements-1
        if !scalar_form then
            op2 = SInt(Elem[Din[m],e,esize]);
        endif

        op1 = SInt(Elem[Din[n],e,esize]);
        (product, sat) = SignedSatQ(2*op1*op2, 2*esize);
        Elem[Q[d>>1],e,2*esize] = product;
        if sat then
            FPSCR.QC = '1';
        endif
    endfor
endif
"""
}, { 
    "name" : "VQMOVN, VQMOVUN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for e = 0 to elements-1
        operand = Int(Elem[Qin[m>>1],e,2*esize], src_unsigned);
        (Elem[D[d],e,esize], sat) = SatQ(operand, esize, dest_unsigned);
        if sat then
            FPSCR.QC = '1';
        endif
    endfor
endif
"""
}, { 
    "name" : "VQNEG",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            result = -SInt(Elem[D[m+r],e,esize]);
            (Elem[D[d+r],e,esize], sat) = SignedSatQ(result, esize);
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VQRDMULH",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    round_const = 1 << (esize-1);
    if scalar_form then
        op2 = SInt(Elem[D[m],index,esize]);
    endif

    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = SInt(Elem[D[n+r],e,esize]);
            if !scalar_form then
                op2 = SInt(Elem[D[m+r],e,esize]);
            endif

            (result, sat) = SignedSatQ((2*op1*op2 + round_const) >> esize, esize);
            Elem[D[d+r],e,esize] = result;
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VQRSHL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            shift = SInt(Elem[D[n+r],e,esize]<7:0>);
            round_const = 1 << (-1-shift);
            operand = Int(Elem[D[m+r],e,esize], unsigned);
            (result, sat) = SatQ((operand + round_const) << shift, esize, unsigned);
            Elem[D[d+r],e,esize] = result;
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VQRSHRN, VQRSHRUN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    round_const = 1 << (shift_amount - 1);
    for e = 0 to elements-1
        operand = Int(Elem[Qin[m>>1],e,2*esize], src_unsigned);
        (result, sat) = SatQ((operand + round_const) >> shift_amount, esize, dest_unsigned);
        Elem[D[d],e,esize] = result;
        if sat then
            FPSCR.QC = '1';
        endif
    endfor
endif
"""
}, { 
    "name" : "VQSHL (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            shift = SInt(Elem[D[n+r],e,esize]<7:0>);
            operand = Int(Elem[D[m+r],e,esize], unsigned);
            (result,sat) = SatQ(operand << shift, esize, unsigned);
            Elem[D[d+r],e,esize] = result;
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VQSHL, VQSHLU (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            operand = Int(Elem[D[m+r],e,esize], src_unsigned);
            (result, sat) = SatQ(operand << shift_amount, esize, dest_unsigned);
            Elem[D[d+r],e,esize] = result;
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VQSHRN, VQSHRUN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for e = 0 to elements-1
        operand = Int(Elem[Qin[m>>1],e,2*esize], src_unsigned);
        (result, sat) = SatQ(operand >> shift_amount, esize, dest_unsigned);
        Elem[D[d],e,esize] = result;
        if sat then
            FPSCR.QC = '1';
        endif
    endfor
endif
"""
}, { 
    "name" : "VQSUB",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            diff = Int(Elem[D[n+r],e,esize], unsigned) - Int(Elem[D[m+r],e,esize], unsigned);
            (Elem[D[d+r],e,esize], sat) = SatQ(diff, esize, unsigned);
            if sat then
                FPSCR.QC = '1';
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VRADDHN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    round_const = 1 << (esize-1);
    for e = 0 to elements-1
        result = Elem[Qin[n>>1],e,2*esize] + Elem[Qin[m>>1],e,2*esize] + round_const;
        Elem[D[d],e,esize] = result<2*esize-1:esize>;
    endfor
endif
"""
}, { 
    "name" : "VRECPE",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            if floating_point then
                Elem[D[d+r],e,esize] = FPRecipEstimate(Elem[D[m+r],e,esize]);
            else
                Elem[D[d+r],e,esize] = UnsignedRecipEstimate(Elem[D[m+r],e,esize]);
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VRECPS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = FPRecipStep(Elem[D[n+r],e,esize], Elem[D[m+r],e,esize]);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VREV16, VREV32, VREV64",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    dest = 0;
    for r = 0 to regs-1
        for e = 0 to elements-1
            e_bits = e<esize-1:0>;
            d_bits = e_bits EOR reverse_mask;
            d = UInt(d_bits);
            Elem[dest,d,esize] = Elem[D[m+r],e,esize];
        endfor

        D[d+r] = dest;
    endfor
endif
"""
}, { 
    "name" : "VRHADD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            op1 = Int(Elem[D[n+r],e,esize], unsigned);
            op2 = Int(Elem[D[m+r],e,esize], unsigned);
            result = op1 + op2 + 1;
            Elem[D[d+r],e,esize] = result<esize:1>;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VRSHL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            shift = SInt(Elem[D[n+r],e,esize]<7:0>);
            round_const = 1 << (-shift-1);
            result = (Int(Elem[D[m+r],e,esize], unsigned) + round_const) << shift;
            Elem[D[d+r],e,esize] = result<esize-1:0>;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VRSHR",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    round_const = 1 << (shift_amount - 1);
    for r = 0 to regs-1
        for e = 0 to elements-1
            result = (Int(Elem[D[m+r],e,esize], unsigned) + round_const) >> shift_amount;
            Elem[D[d+r],e,esize] = result<esize-1:0>;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VRSHRN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    round_const = 1 << (shift_amount-1);
    for e = 0 to elements-1
        result = LSR(Elem[Qin[m>>1],e,2*esize] + round_const, shift_amount);
        Elem[D[d],e,esize] = result<esize-1:0>;
    endfor
endif
"""
}, { 
    "name" : "VRSQRTE",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            if floating_point then
                Elem[D[d+r],e,esize] = FPRSqrtEstimate(Elem[D[m+r],e,esize]);
            else
                Elem[D[d+r],e,esize] = UnsignedRSqrtEstimate(Elem[D[m+r],e,esize]);
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VRSQRTS",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = FPRSqrtStep(Elem[D[n+r],e,esize], Elem[D[m+r],e,esize]);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VRSRA",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    round_const = 1 << (shift_amount - 1);
    for r = 0 to regs-1
        for e = 0 to elements-1
            result = (Int(Elem[D[m+r],e,esize], unsigned) + round_const) >> shift_amount;
            Elem[D[d+r],e,esize] = Elem[D[d+r],e,esize] + result;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VRSUBHN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    round_const = 1 << (esize-1);
    for e = 0 to elements-1
        result = Elem[Qin[n>>1],e,2*esize] - Elem[Qin[m>>1],e,2*esize] + round_const;
        Elem[D[d],e,esize] = result<2*esize-1:esize>;
    endfor
endif
"""
}, { 
    "name" : "VSHL (immediate)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = LSL(Elem[D[m+r],e,esize], shift_amount);
        endfor
    endfor
endif
"""
}, { 
    "name" : "VSHL (register)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            shift = SInt(Elem[D[n+r],e,esize]<7:0>);
            result = Int(Elem[D[m+r],e,esize], unsigned) << shift;
            Elem[D[d+r],e,esize] = result<esize-1:0>;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VSHLL",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    for e = 0 to elements-1
        result = Int(Elem[Din[m],e,esize], unsigned) << shift_amount;
        Elem[Q[d>>1],e,2*esize] = result<2*esize-1:0>;
    endfor
endif
"""
}, { 
    "name" : "VSHR",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            result = Int(Elem[D[m+r],e,esize], unsigned) >> shift_amount;
            Elem[D[d+r],e,esize] = result<esize-1:0>;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VSHRN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for e = 0 to elements-1
        result = LSR(Elem[Qin[m>>1],e,2*esize], shift_amount);
        Elem[D[d],e,esize] = result<esize-1:0>;
    endfor
endif
"""
}, { 
    "name" : "VSLI",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    mask = LSL(Ones(esize), shift_amount);
    for r = 0 to regs-1
        for e = 0 to elements-1
            shifted_op = LSL(Elem[D[m+r],e,esize], shift_amount);
            Elem[D[d+r],e,esize] = (Elem[D[d+r],e,esize] AND NOT(mask)) OR shifted_op;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VSQRT",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    
    if dp_operation then
        D[d] = FPSqrt(D[m]);
    else
        S[d] = FPSqrt(S[m]);
    endif
endif
"""
}, { 
    "name" : "VSRA",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        for e = 0 to elements-1
            result = Int(Elem[D[m+r],e,esize], unsigned) >> shift_amount;
            Elem[D[d+r],e,esize] = Elem[D[d+r],e,esize] + result;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VSRI",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    mask = LSR(Ones(esize), shift_amount);
    for r = 0 to regs-1
        for e = 0 to elements-1
            shifted_op = LSR(Elem[D[m+r],e,esize], shift_amount);
            Elem[D[d+r],e,esize] = (Elem[D[d+r],e,esize] AND NOT(mask)) OR shifted_op;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VST1 (multiple single elements)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);

    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 8*regs);
    endif
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            if ebytes != 8 then
                MemU[address,ebytes] = Elem[D[d+r],e,esize];
            else
                data =Elem[D[d+r],e,esize];
                MemU[address,4] = if BigEndian() then data<63:32> else data<31:0>;
                MemU[address+4,4] = if BigEndian() then data<31:0> else data<63:32>;
            endif

            address = address + ebytes;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VST1 (single element from one lane)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);

    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else ebytes);
    endif

    MemU[address,ebytes] = Elem[D[d],index,esize];
endif
"""
}, { 
    "name" : "VST2 (multiple 2-element structures)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    address = R[n];

    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 16*regs);
    endif

    for r = 0 to regs-1
        for e = 0 to elements-1
            MemU[address,ebytes] = Elem[D[d+r],e,esize];
            MemU[address+ebytes,ebytes] = Elem[D[d2+r],e,esize];
            address = address + 2*ebytes;
        endfor
    endfor
endif
"""
}, { 
    "name" : "VST2 (single 2-element structure from one lane)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);

    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 2*ebytes);
    endif

    MemU[address,ebytes] = Elem[D[d],index,esize];
    MemU[address+ebytes,ebytes] = Elem[D[d2],index,esize];
endif
"""
}, { 
    "name" : "VST3 (multiple 3-element structures)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);

    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 24);
    endif

    for e = 0 to elements-1
        MemU[address,ebytes] = Elem[D[d],e,esize];
        MemU[address+ebytes,ebytes] = Elem[D[d2],e,esize];
        MemU[address+2*ebytes,ebytes] = Elem[D[d3],e,esize];
        address = address + 3*ebytes;
    endfor
endif
"""
}, { 
    "name" : "VST3 (single 3-element structure from one lane)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);

    address = R[n];
    if wback then
        R[n] = R[n] + (if register_index then R[m] else 3*ebytes);
    endif

    MemU[address,ebytes] = Elem[D[d],index,esize];
    MemU[address+ebytes,ebytes] = Elem[D[d2],index,esize];
    MemU[address+2*ebytes,ebytes] = Elem[D[d3],index,esize];
endif
"""
}, { 
    "name" : "VST4 (multiple 4-element structures)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE(n);
    
    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 32);
    endif

    for e = 0 to elements-1
        MemU[address,ebytes] = Elem[D[d],e,esize];
        MemU[address+ebytes,ebytes] = Elem[D[d2],e,esize];
        MemU[address+2*ebytes,ebytes] = Elem[D[d3],e,esize];
        MemU[address+3*ebytes,ebytes] = Elem[D[d4],e,esize];
        address = address + 4*ebytes;
    endfor
endif
"""
}, { 
    "name" : "VST4 (single 4-element structure from one lane)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    NullCheckIfThumbEE();

    address = R[n];
    if (address MOD alignment) != 0 then
        GenerateAlignmentException();
    endif

    if wback then
        R[n] = R[n] + (if register_index then R[m] else 4*ebytes);
    endif

    MemU[address,ebytes] = Elem[D[d],index,esize];
    MemU[address+ebytes,ebytes] = Elem[D[d2],index,esize];
    MemU[address+2*ebytes,ebytes] = Elem[D[d3],index,esize];
    MemU[address+3*ebytes,ebytes] = Elem[D[d4],index,esize];
endif
"""
}, { 
    "name" : "VSTM",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    NullCheckIfThumbEE(n);
    address = if add then R[n] else R[n]-imm32;
    if wback then
        R[n] = if add then R[n]+imm32 else R[n]-imm32;
    endif

    for r = 0 to regs-1
        if single_regs then
            MemA[address,4] = S[d+r];
            address = address+4;
        else
            MemA[address,4] = if BigEndian() then D[d+r]<63:32> else D[d+r]<31:0>;
            MemA[address+4,4] = if BigEndian() then D[d+r]<31:0> else D[d+r]<63:32>;
            address = address+8;
        endif
    endfor
endif
"""
}, { 
    "name" : "VSTR",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckVFPEnabled(TRUE);
    NullCheckIfThumbEE(n);

    address = if add then (R[n] + imm32) else (R[n] - imm32);
    if single_reg then
        MemA[address,4] = S[d];
    else
        MemA[address,4] = if BigEndian() then D[d]<63:32> else D[d]<31:0>;
        MemA[address+4,4] = if BigEndian() then D[d]<31:0> else D[d]<63:32>;
    endif
endif
"""
}, { 
    "name" : "VSUB (integer)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            Elem[D[d+r],e,esize] = Elem[D[n+r],e,esize] - Elem[D[m+r],e,esize];
        endfor
    endfor
endif
"""
}, { 
    "name" : "VSUB (floating-point)",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDOrVFPEnabled(TRUE, advsimd);
    if advsimd then
        for r = 0 to regs-1
            for e = 0 to elements-1
                Elem[D[d+r],e,esize] = FPSub(Elem[D[n+r],e,esize], Elem[D[m+r],e,esize], FALSE);
            endfor
        endfor
    else
        if dp_operation then
            D[d] = FPSub(D[n], D[m], TRUE);
        else
            S[d] = FPSub(S[n], S[m], TRUE);
        endif
    endif
endif
"""
}, { 
    "name" : "VSUBHN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for e = 0 to elements-1
        result = Elem[Qin[n>>1],e,2*esize] - Elem[Qin[m>>1],e,2*esize];
        Elem[D[d],e,esize] = result<2*esize-1:esize>;
    endfor
endif
"""
}, { 
    "name" : "VSUBL, VSUBW",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for e = 0 to elements-1
        if is_vsubw then
            op1 = Int(Elem[Qin[n>>1],e,2*esize], unsigned);
        else
            op1 = Int(Elem[Din[n],e,esize], unsigned);
        endif

        result = op1 - Int(Elem[Din[m],e,esize], unsigned);
        Elem[Q[d>>1],e,2*esize] = result<2*esize-1:0>;
    endfor
endif
"""
}, { 
    "name" : "VSWP",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    for r = 0 to regs-1
        if d == m then
            D[d+r] = UNKNOWN_VALUE;
        else
            D[d+r] = Din[m+r];
            D[m+r] = Din[d+r];
        endif
    endfor
endif
"""
}, { 
    "name" : "VTBL, VTBX",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    table3 = if length == 4 then D[n+3] else Zeros(64);
    table2 = if length >= 3 then D[n+2] else Zeros(64);
    table1 = if length >= 2 then D[n+1] else Zeros(64);
    table = table3 : table2 : table1 : D[n];
    
    for i = 0 to 7
        index = UInt(Elem[D[m],i,8]);
        
        if index < 8*length then
            Elem[D[d],i,8] = Elem[table,index,8];
        else
            if is_vtbl then
                Elem[D[d],i,8] = Zeros(8);
            endif
        endif
    endfor
endif
"""
}, { 
    "name" : "VTRN",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    h = elements/2;
    for r = 0 to regs-1
        if d == m then
            D[d+r] = UNKNOWN_VALUE;
        else
            for e = 0 to h-1
                Elem[D[d+r],2*e+1,esize] = Elem[Din[m+r],2*e,esize];
                Elem[D[m+r],2*e,esize] = Elem[Din[d+r],2*e+1,esize];
            endfor
        endif
    endfor
endif
"""
}, { 
    "name" : "VTST",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    for r = 0 to regs-1
        for e = 0 to elements-1
            if !IsZero(Elem[D[n+r],e,esize] AND Elem[D[m+r],e,esize]) then
                Elem[D[d+r],e,esize] = Ones(esize);
            else
                Elem[D[d+r],e,esize] = Zeros(esize);
            endif
        endfor
    endfor
endif
"""
}, { 
    "name" : "VUZP",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();
    
    if quadword_operation then
        if d == m then
            Q[d>>1] = UNKNOWN_VALUE;
            Q[m>>1] = UNKNOWN_VALUE;
        else
            zipped_q = Q[m>>1]:Q[d>>1];
    
            for e = 0 to (128 DIV esize) - 1
                Elem[Q[d>>1],e,esize] = Elem[zipped_q,2*e,esize];
                Elem[Q[m>>1],e,esize] = Elem[zipped_q,2*e+1,esize];
            endfor
        endif
    else
        if d == m then
            D[d] = UNKNOWN_VALUE;
            D[m] = UNKNOWN_VALUE;
        else
            zipped_d = D[m]:D[d];
            for e = 0 to (64 DIV esize) - 1
                Elem[D[d],e,esize] = Elem[zipped_d,2*e,esize];
                Elem[D[m],e,esize] = Elem[zipped_d,2*e+1,esize];
            endfor
        endif
    endif
endif
"""
}, { 
    # XXX: bits(256) zipped_q; & bits(128) zipped_d;
    "name" : "VZIP",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    CheckAdvSIMDEnabled();

    if quadword_operation then
        if d == m then
            Q[d>>1] = UNKNOWN_VALUE;
            Q[m>>1] = UNKNOWN_VALUE;
        else
            zipped_q = 0;
            for e = 0 to (128 DIV esize) - 1
                Elem[zipped_q,2*e,esize] = Elem[Q[d>>1],e,esize];
                Elem[zipped_q,2*e+1,esize] = Elem[Q[m>>1],e,esize];
            endfor

            Q[d>>1] = zipped_q<127:0>;
            Q[m>>1] = zipped_q<255:128>;
        endif
    else
        if d == m then
            D[d] = UNKNOWN_VALUE;
            D[m] = UNKNOWN_VALUE;
        else
            zipped_d = 0;
            for e = 0 to (64 DIV esize) - 1
                Elem[zipped_d,2*e,esize] = Elem[D[d],e,esize];
                Elem[zipped_d,2*e+1,esize] = Elem[D[m],e,esize];
            endfor

            D[d] = zipped_d<63:0>;
            D[m] = zipped_d<127:64>;
        endif
    endif
endif
"""
}, { 
    "name" : "WFE",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    
    if EventRegistered() then
        ClearEventRegister();
    else
        if HaveVirtExt() && !IsSecure() && !CurrentModeIsHyp() && HCR.TWE == '1' then
            HSRString = Zeros(25);
            set_bit(HSRString, 0, '1');
            WriteHSR('000001', HSRString);
            TakeHypTrapException();
        else
            WaitForEvent();
        endif
    endif
endif
"""
}, { 
    "name" : "WFI",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    
    if HaveVirtExt() && !IsSecure() && !CurrentModeIsHyp() && HCR.TWI == '1' then
        HSRString = Zeros(25);
        set_bit(HSRString, 0, '1');
        WriteHSR('000001', HSRString);
        TakeHypTrapException();
    else
        WaitForInterrupt();
    endif
endif
"""
}, { 
    "name" : "YIELD",
    "operation" : """
if ConditionPassed() then
    EncodingSpecificOperations();
    Hint_Yield();
endif"""
}]