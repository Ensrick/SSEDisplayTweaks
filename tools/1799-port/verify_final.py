import struct, os
import capstone

root = os.path.dirname(os.path.abspath(__file__))
EXE = r'C:\Program Files (x86)\Steam\steamapps\common\Skyrim Special Edition\SkyrimSE.exe'
db = open(os.path.join(root, 'dbtest', 'Data', 'SKSE', 'Plugins', 'versionlib-1-7-99-0.bin'), 'rb').read()
cnt = struct.unpack_from('<i', db, 92)[0]
offs = struct.unpack_from('<%dI' % cnt, db, 96)
rev = {}
for i, o in enumerate(offs):
    if o:
        rev.setdefault(o, i)
exe = open(EXE, 'rb').read()
e = struct.unpack_from('<I', exe, 0x3C)[0]
nsec = struct.unpack_from('<H', exe, e+6)[0]
secs = e+24+struct.unpack_from('<H', exe, e+20)[0]
sections = [struct.unpack_from('<IIII', exe, secs+i*40+8) for i in range(nsec)]
def rva2fo(rva):
    for vsz, va, rsz, ro in sections:
        if va <= rva < va+vsz:
            return ro + (rva - va)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def rd(rva, n):
    return exe[rva2fo(rva):rva2fo(rva)+n]

fails = 0
def chk(name, cond, detail=''):
    global fails
    print('%-38s %s %s' % (name, 'OK' if cond else 'FAIL', detail))
    if not cond:
        fails += 1

# ported sites (1.7.99 arms now in code)
site = offs[36547]+0xB06; b = rd(site, 6)
chk('LoadPluginINI_C +0xB06', b[0] == 0xE8 and rev.get(site+5+struct.unpack_from('<i', b, 1)[0]) == 36102, 'E8 -> id36102')
site = offs[36547]+0xDBE; b = rd(site, 6)
chk('PopulateUIStringHolder_C +0xDBE', b[0] == 0xE8 and rev.get(site+5+struct.unpack_from('<i', b, 1)[0]) == 82485, 'E8 -> id82485')
chk('bFullscreen_Patch +0xBDF movzx', rd(offs[36547]+0xBDF, 3)[:2] == b'\x0f\xb6')
chk('bBorderless_Patch +0xBEA movzx', rd(offs[36547]+0xBEA, 3)[:2] == b'\x0f\xb6')
chk('iSizeW_Patch +0xBF5 mov eax,[rip]', rd(offs[36547]+0xBF5, 2) == b'\x8b\x05')
chk('iSizeH_Patch +0xBFF mov eax,[rip]', rd(offs[36547]+0xBFF, 2) == b'\x8b\x05')
chk('DisplayRefreshRate +0xC1D imm60@+4', rd(offs[36547]+0xC1D, 8) == bytes.fromhex('c74424703c000000'))
site = offs[77245]+0x1DC; b = rd(site, 6)
chk('GetClientRect1_C +0x1DC ff15', b[0] == 0xFF and b[1] == 0x15)
chk('MT_Inject_AE1 +0x398 comiss', rd(offs[41996]+0x398, 3) == b'\x0f\x2f\x35')
chk('MT_Inject_AE2 +0x8A1 comiss', rd(offs[41996]+0x8A1, 3) == b'\x0f\x2f\x35')
chk('Vanity +0xED subss xmm0,[rip]', rd(offs[50709]+0xED, 4) == b'\xf3\x0f\x5c\x05')
chk('DialogueLook +0x41E movss xmm1,[rip]', rd(offs[42338]+0x41E, 4) == b'\xf3\x0f\x10\x0d')
chk('FMHS site +0x125 addss', rd(offs[50724]+0x125, 4) == b'\xf3\x0f\x58\xc1')
# FMHS resume +0x33 -> +0x158 must be a boundary reachable by the convergence jmps
code = rd(offs[50724]+0x125, 0x40)
tgt_ok = False
for ins in md.disasm(code, offs[50724]+0x125):
    if ins.mnemonic == 'jmp' and ins.op_str == hex(offs[50724]+0x158):
        tgt_ok = True
chk('FMHS resume +0x33 (=+0x158) is jmp tgt', tgt_ok)

# key as-is sites re-checked
chk('presentAddr +0x9F 7-byte shape', rd(offs[77246]+0x9F, 3) == b'\x8b\x50\x30' and rd(offs[77246]+0xA2, 2) == b'\x41\xff')
chk('UpdateBudgetGame +0x90 movss xmm6 8B', rd(offs[53928]+0x90, 4) == b'\xf3\x0f\x10\x35')
chk('UpdateBudgetUI +0x90 movss xmm6 8B', rd(offs[53929]+0x90, 4) == b'\xf3\x0f\x10\x35')
chk('SkipNoINI +0x319 pattern', rd(offs[36725]+0x319, 9) == bytes.fromhex('488b07488bcfff5048'))
chk('MaxFrameLatency imm==2 then vcall60', struct.unpack_from('<I', rd(offs[77226]+0x2FE, 4))[0] == 2 and rd(offs[77226]+0x302, 3) == b'\xff\x50\x60')
chk('ResizeBuffersDisable je tgt == payload tgt', rd(offs[77238]+0x26, 6) == bytes.fromhex('0f8444040000'))
chk('ResizeTargetDisable je tgt == payload tgt', rd(offs[77239]+0x24, 6) == bytes.fromhex('0f842f010000'))
chk('PhysCalc_AE jae tgt == payload tgt', rd(offs[77850]+0x75, 2) == b'\x0f\x2f' and rd(offs[77850]+0x7C, 2) == b'\x73\x18')
chk('Lockpick +0x42 mulss[rip->frameTimer]', rd(offs[51955]+0x42, 4) == b'\xf3\x0f\x59\x0d')
chk('PlayerFade +0x4DD movss 8B', rd(offs[50832]+0x4DD, 4) == b'\xf3\x0f\x10\x35')
chk('SEO lea site +0x1A bytes 41 FF', rd(offs[54748]+0x1A, 2) == b'\x41\xff')
chk('SEO cmp imm 0x0F at +0x2A', rd(offs[54748]+0x2A, 1) == b'\x0f')

print()
print('RESULT:', 'PASS' if fails == 0 else 'FAIL (%d)' % fails)
