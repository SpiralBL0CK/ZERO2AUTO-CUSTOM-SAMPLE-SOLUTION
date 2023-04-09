from dumpulator import Dumpulator
from pwn import *
import inspect
import sys

"""
.rdata:010F3C7C xmmword_10F3C7C xmmword 0BACA7A0A1B6B4A5BAEAEFF6B5B1B1BDAh
.rdata:010F3C7C                                         ; DATA XREF: dga+6Er
.rdata:010F3C8C xmmword_10F3C8C xmmword 2818CF8A0A988AAE2B4A7BAE8AAA6ABEh
.rdata:010F3C8C                                         ; DATA XREF: dga+8Br
.rdata:010F3C9C word_10F3C9C    dw 0EAh                 ; DATA XREF: dga+7Ar
.rdata:010F3C9E                 align 10h
.rdata:010F3CA0 ; const char Delimiter[2]
.rdata:010F3CA0 Delimiter       db '\',0                ; DATA XREF: _main+2Eo
.rdata:010F3CA0                                         ; _main:loc_10E1EE2o
.rdata:010F3CA2                 align 4
.rdata:010F3CA4 qword_10F3CA4   dq 13B6A6F6B6A60734h    ; DATA XREF: sub_10E13A0+1Br
.rdata:010F3CAC dword_10F3CAC   dd 87F657h              ; DATA XREF: sub_10E13A0+30r
.rdata:010F3CB0 dword_10F3CB0   dd 720063h              ; DATA XREF: sub_10E13A0+DFr
.rdata:010F3CB4 dword_10F3CB4   dd 6C0075h              ; DATA XREF: sub_10E13A0+E6r
.rdata:010F3CB8 dword_10F3CB8   dd 61006Fh              ; DATA XREF: sub_10E13A0+EEr
.rdata:010F3CBC dword_10F3CBC   dd 650064h              ; DATA XREF: sub_10E13A0+F6r
.rdata:010F3CC0 dword_10F3CC0   dd 72h                  ; DATA XREF: sub_10E13A0+FEr
.rdata:010F3CC4 qword_10F3CC4   dq 8EFE6F5FBFEFFF8Eh    ; DATA XREF: sub_10E13A0+191r
.rdata:010F3CCC word_10F3CCC    dw 9Fh                  ; DATA XREF: sub_10E13A0+189r
.rdata:010F3CCE                 align 10h
.rdata:010F3CD0 xmmword_10F3CD0 xmmword 61616161616161616161616161616161h
.rdata:010F3CD0                                         ; DATA XREF: sub_10E13A0+205r
.rdata:010F3CE0 xmmword_10F3CE0 xmmword 659B537ED2F05B7D47742A227C6FFE70h
.rdata:010F3CE0                                         ; DATA XREF: sub_10E1000+13r
.rdata:010F3CF0 ; Debug Directory entries
.rdata:010F3CF0                 dd 0                    ; Characteristics
.rdata:010F3CF4                 dd 5EE8C20Ch            ; TimeDateStamp: Tue Jun 16 12:58:52 2020
.rdata:010F3CF8                 dw 0                    ; MajorVersion
.rdata:010F3CFA                 dw 0                    ; MinorVersion
.rdata:010F3CFC                 dd 0Dh                  ; Type: IMAGE_DEBUG_TYPE_POGO
.rdata:010F3D00                 dd 268h                 ; SizeOfData
.rdata:010F3D04                 dd rva aGctl            ; AddressOfRawData
.rdata:010F3D08                 dd 12BECh               ; PointerToRawData
.rdata:010F3D0C                 dd 0                    ; Characteristics
.rdata:010F3D10                 dd 5EE8C20Ch            ; TimeDateStamp: Tue Jun 16 12:58:52 2020
.rdata:010F3D14                 dw 0                    ; MajorVersion
.rdata:010F3D16                 dw 0                    ; MinorVersion
.rdata:010F3D18                 dd 0Eh                  ; Type: IMAGE_DEBUG_TYPE_ILTCG
.rdata:010F3D1C                 dd 0                    ; SizeOfData
.rdata:010F3D20                 dd 0                    ; AddressOfRawData
.rdata:010F3D24                 dd 0                    ; PointerToRawData
.rdata:010F3D28 __load_config_used dd 0B8h              ; Size
.rdata:010F3D2C                 dd 0                    ; Time stamp
.rdata:010F3D30                 dw 2 dup(0)             ; Version: 0.0
.rdata:010F3D34                 dd 0                    ; GlobalFlagsClear
.rdata:010F3D38                 dd 0                    ; GlobalFlagsSet
.rdata:010F3D3C                 dd 0                    ; CriticalSectionDefaultTimeout
.rdata:010F3D40                 dd 0                    ; DeCommitFreeBlockThreshold
.rdata:010F3D44                 dd 0                    ; DeCommitTotalFreeThreshold
.rdata:010F3D48                 dd 0                    ; LockPrefixTable
.rdata:010F3D4C                 dd 0                    ; MaximumAllocationSize
.rdata:010F3D50                 dd 0                    ; VirtualMemoryThreshold
.rdata:010F3D54                 dd 0                    ; ProcessAffinityMask
.rdata:010F3D58                 dd 0                    ; ProcessHeapFlags
.rdata:010F3D5C                 dw 0                    ; CSDVersion
.rdata:010F3D5E                 dw 0                    ; Reserved1
.rdata:010F3D60                 dd 0                    ; EditList
.rdata:010F3D64                 dd offset ___security_cookie ; SecurityCookie
.rdata:010F3D68                 dd offset ___safe_se_handler_table ; SEHandlerTable
.rdata:010F3D6C                 dd 3                    ; SEHandlerCount
.rdata:010F3D70                 dd offset ___guard_check_icall_fptr ; GuardCFCheckFunctionPointer
.rdata:010F3D74                 dd 0                    ; GuardCFDispatchFunctionPointer
.rdata:010F3D78                 dd 0                    ; GuardCFFunctionTable
.rdata:010F3D7C                 dd 0                    ; GuardCFFunctionCount
.rdata:010F3D80                 dd 100h                 ; GuardFlags
"""

def decrypt_one_string():
    string="0x13B6A6F6B6A60734"
    rez = ""
    for i in range(2,len(string),2):
        rez +=(chr(int(string[i:i+2][::-1],base=16)^ 0x1f ))
    print(rez[::-1])

def decrypt_string_two():
    string="0xE8FFFEFBF5F6EFE8F9"
    rez = ""
    for i in range(2,len(string),2):
        rez +=(chr(int(string[i:i+2],base=16)^ 0x9A ))
    print(rez[::-1])

def decrypt_string_three():
    s1 = "0x7C6D1DBD1FEF1D5DDC6CCCBC5FEF891E"
    s2 = "0x7CAD7CC86D1DDCAC1C4D1DEF0919FC" 
    rez = ""
    rez2 = ""
    for i in range(2,len(s1),2):
        rez +=(chr(int(s1[i:i+2][::-1],base=16)^ 0xA2 ))
    print(rez[::-1])
    
    for i in range(2,len(s2),2):
        rez2 +=(chr(int(s2[i:i+2][::-1],base=16)^ 0xA2 ))
    print(rez2[::-1])

def decrypt_string_four():
    """
    Fking decrypt this after finding where tf is isdebuggerpresent // peb->isprocessdebugged???
    LABEL_16:
    v21 = dword_10F6AA8;
  }
  else
  {
    while ( 1 )
    {
      v15 = String;
      if ( *String == *v17 && *&String[4] == *(v17 + 4) && v35 == *(v17 + 8) )
        break;
      ++v20;
      ++v17;
      if ( v20 >= dwSize )
        goto LABEL_16;
    }
    v1 = (v17 + 9);
    v21 = dwSize - v20 - 9;
    dword_10F6AA8 = v21;
  }
  v22 = 0;
  if ( v21 && v21 >= 0x40 )
  {
    v23 = v1 + 32;
    v17 = v21 & 0xFFFFFFC0;
    do
    {
      v24 = *(v23 - 2);
      v23 += 64;
      v22 += 64;
      *(v23 - 6) = _mm_xor_si128(xmmword_10F3CD0, v24);
      *(v23 - 5) = _mm_xor_si128(*(v23 - 5), xmmword_10F3CD0);
      *(v23 - 4) = _mm_xor_si128(*(v23 - 4), xmmword_10F3CD0);
      *(v23 - 3) = _mm_xor_si128(*(v23 - 3), xmmword_10F3CD0);
    }
    while ( v22 < v17 );
  }
  for ( ; v22 < v21; ++v22 )
    v1[v22] ^= 0x61u;
    """ 
    v21 = 0
    file = open(sys.argv[1],"rb")
    v14 = file.read()
    print(hexdump(v14[v14.index(b'redaolurc')+9:]))
    s = ""
    k = v14[v14.index(b'redaolurc')+9:]
    print(type(k))
    for i in k:
        s+= chr(i ^ 0x61)
    print("=======================================")
    print(hexdump(s))
    print("!!!!!!!!!!!!!!saving final stage to .dll file!!!!!!!!!!\n")
    print("!!!!!!!!!!!!!!please stad by!!!!!!!!!!!!!!!!!!!!!!!\n")
    z = open("final_stage_payload.dll","wb")
    decrypted = bytearray()
    for i in k:
        decrypted.append(i ^ 0x61)
    z.write(decrypted)
    z.close()
    file.close()

def decrypt_string_five():
    s2="0x2818CF8A0A988AAE2B4A7BAE8AAA6ABE"
    s1="0xBACA7A0A1B6B4A5BAEAEFF6B5B1B1BDA"
    rez = ""
    for i in range(2,len(s1),2):
        rez +=(chr(int(s1[i:i+2][::-1],base=16)^ 0xC5 ))
    print(rez[::-1])

    rez2 = ""
    for i in range(2,len(s2),2):
        rez2 +=(chr(int(s2[i:i+2][::-1],base=16)^ 0xC5 ))
    print(rez2[::-1])


def anti_analysis_decryption_check():
    """
    bottom line is this :
    659B537ED2F05B7D47742A227C6FFE70

    this is actually an concatenation of the 4 byte hash-es which break down to

   | 65 9B 53 7E |D2 F0 5B 7D |47 74 2A 22| 7C 6F FE 70


    so by definition/ canonicall function call looks like this
    sub_1351000(v3, v4, v5), where args are 
    003EF4A4  00715F38  &"C:\\Users\\pwn\\Desktop\\stage2_challenge_mal_analysis.dll" v5
    003EF4A8  003EF580   v4
    003EF4AC  00000000   v3
    """
    dp = Dumpulator("2nd_stage.dmp")
    prolog_start = 0x13510D0
    prolog_stop  = 0x135118A
    crc_lookup_table = []
    dp.start(begin=prolog_start,end=prolog_stop)
    print(dir(dp))
    print("!!!!!!!!!!!dumping crc lookup tablen!!!!!!!!\n")
    print("!!!!!!please stand by!!!!!!!!\n")
    for i in range(0,256):
        iterator = i * 4
        crc_lookup_table.append(hex(dp.read_ptr(0x1366290+iterator)))
    #print(crc_lookup_table)
    process_list_input = ["system","smss.exe","crss.exe",]
    v7  = "s\x00y\x00s\x00t\x00e\00m\x00\x00"
    v6 = len(v7)-1
    v1 = v7[v6]
    eax = "0xffffffff"
    ctr_eax = 2
    cnt_eax = 0
    cnt_shift_idx_eax = 0
    crn_shift_idx_eax = 2
    res_tmp = ""
    rez_final = 0
    for j in range(0,v6):
        if(cnt_shift_idx_eax == 4):
            ctr_shift_idx_eax = 2
        if(cnt_eax == 4):
            ctr_eax = 2
        print(eax[ctr_eax:ctr_eax+2])
        cur_eax = int(eax[ctr_eax:ctr_eax+2],base=16)
        print(cur_eax)
        res_tmp =  ord(v7[j]) ^ cur_eax 
        print(res_tmp)
        shift_rez = cur_eax >> 8
        print(shift_rez)
        if(shift_rez == 0):
            print("aci")
            print(type(eax[crn_shift_idx_eax]))
            print(eax[crn_shift_idx_eax])
            print(eax[crn_shift_idx_eax+1])
            eax = eax.replace(eax[crn_shift_idx_eax],"0").replace(eax[crn_shift_idx_eax+1],"0")
            print(eax)
        else:
            print("aici2")
            to_reaplace_one = hex(shift_rez)[2]
            to_replace_two  = hex(shift_rez)[3]
            eax = eax.replace(eax[crn_shift_idx_eax],to_replace_one).replace(eax[crn_shft_idx_eax],to_replace_two)
        print(eax)
        print(hex(res_tmp))
        rez_final = int(eax,base=16) ^ int(crc_lookup_table[res_tmp],base=16)
        print(hex(rez_final))
        eax=hex(rez_final)
        ctr_eax+=2
        cnt_eax+=1
        crn_shift_idx_eax+=2
        cnt_shift_idx_eax+=1
        enc_process = "0x659B537ED2F05B7D47742A227C6FFE70"
        for i in range(2,len(enc_process),8):
            if(enc_process[i] != rez_final):
                print(enc_process[i:i+8])
                print("ye,we are not being debugged")

decrypt_string_four()
anti_analysis_decryption_check()
