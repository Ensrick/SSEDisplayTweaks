import struct, os, sys
import capstone

root = os.path.dirname(os.path.abspath(__file__))
EXE = r'C:\Program Files (x86)\Steam\steamapps\common\Skyrim Special Edition\SkyrimSE.exe'
DB = os.path.join(root, 'dbtest', 'Data', 'SKSE', 'Plugins', 'versionlib-1-7-99-0.bin')

db = open(DB, 'rb').read()
cnt = struct.unpack_from('<i', db, 92)[0]
offs = struct.unpack_from('<%dI' % cnt, db, 96)
rev = {}
for i, o in enumerate(offs):
    if o:
        rev.setdefault(o, i)

exe = open(EXE, 'rb').read()
e_lfanew = struct.unpack_from('<I', exe, 0x3C)[0]
nsec = struct.unpack_from('<H', exe, e_lfanew+6)[0]
secs = e_lfanew + 24 + struct.unpack_from('<H', exe, e_lfanew+20)[0]
sections = []
for i in range(nsec):
    s = secs + i*40
    vsz, va, rsz, ro = struct.unpack_from('<IIII', exe, s+8)
    sections.append((va, vsz, ro, rsz))

def rva2fo(rva):
    for va, vsz, ro, rsz in sections:
        if va <= rva < va + vsz:
            return ro + (rva - va)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = False

def read(rva, n):
    fo = rva2fo(rva)
    return exe[fo:fo+n]

def dis(rva, nbytes=48, maxinstr=10):
    out = []
    code = read(rva, nbytes)
    for ins in md.disasm(code, rva):
        out.append((ins.address, ins.size, ins.mnemonic, ins.op_str, code[ins.address-rva:ins.address-rva+ins.size]))
        if len(out) >= maxinstr:
            break
    return out

def idname(rva):
    return 'id%d' % rev[rva] if rva in rev else 'rva:0x%X' % rva

# site table: (label, anchor_id, disp, kind, extra)
SITES = [
    ('events.LoadPluginINI_C',        36547, 0xAB1, 'CALL5', None),
    ('events.PopulateUIStringHolder', 36547, 0xEC4, 'CALL5', None),
    ('render.CreateDXGIFactory_C',    77396, 0x25,  'CALL5', None),
    ('render.D3D11CreateDevAndSC_C',  77396, 0x2C0, 'CALL5', None),
    ('render.presentAddr',            77246, 0x9F,  'BOUNDARY', 6),
    ('render.bFullscreen_Patch',      36547, 0xCEF, 'DUMP', 7),
    ('render.bBorderless_Patch',      36547, 0xCFA, 'DUMP', 7),
    ('render.iSizeW_Patch',           36547, 0xD05, 'DUMP', 6),
    ('render.iSizeH_Patch',           36547, 0xD0F, 'DUMP', 6),
    ('render.DisplayRefreshRate',     36547, 0xD2D, 'DUMP', None),
    ('render.MaxFrameLatency',        77226, 0x2FE, 'DUMP', None),
    ('render.ResizeBuffers_Inject',   77238, 0x2C4, 'BOUNDARY', 6),
    ('render.ResizeBuffersDisable',   77238, 0x26,  'DUMP', None),
    ('render.ResizeTargetDisable',    77239, 0x24,  'DUMP', None),
    ('render.ResizeTarget',           77239, 0xF9,  'BOUNDARY', 6),
    ('window.CreateWindowEx_C',       77226, 0x22C, 'CALL6', None),
    ('window.GetClientRect1_C',       77245, 0x18B, 'CALL6', None),
    ('controls.MT_Inject_AE1',        41996, 0x389, 'BOUNDARY', 8),
    ('controls.MT_Inject_AE2',        41996, 0x880, 'BOUNDARY', 8),
    ('controls.FMHS_Inject',          50724, 0x125, 'BOUNDARY', 6),
    ('controls.MapLook_Up',           53062, 0xC6,  'DUMP', None),
    ('controls.MapLook_Down',         53062, 0xF2,  'DUMP', None),
    ('controls.MapLook_Left',         53062, 0x122, 'DUMP', None),
    ('controls.MapLook_Right',        53062, 0x14F, 'DUMP', None),
    ('controls.MapLook_Add',          53062, 0x164, 'CALL5', None),
    ('controls.Vanity_IncrAngle',     50709, 0xE2,  'DUMP', None),
    ('controls.PC_LoadDLSpeed',       42338, 0x574, 'DUMP', None),
    ('controls.PC_movssix',           42338, 0x58C, 'DUMP', None),
    ('controls.Cursor_timer',         82540, 0x49,  'DISPFIELD', (410199, 410200)),
    ('controls.Cursor_MulCS',         82540, 0x5A,  'DUMP', None),
    ('controls.Lockpick_MulFT',       51955, 0x42,  'DUMP', None),
    ('controls.FreeCam_0x9D',         50749, 0x9D,  'DUMP', None),
    ('controls.FreeCam_0x8A',         50749, 0x8A,  'DUMP', None),
    ('controls.FreeCam_0x2DC',        50749, 0x2DC, 'DUMP', None),
    ('controls.FreeCam_0x285',        50749, 0x285, 'DUMP', None),
    ('controls.VLS_3P_0x65',          50914, 0x65,  'DUMP', None),
    ('controls.VLS_3P_0x71',          50914, 0x71,  'DUMP', None),
    ('controls.VLS_Dragon_0x53',      33119, 0x53,  'DUMP', None),
    ('controls.VLS_Dragon_0x5F',      33119, 0x5F,  'DUMP', None),
    ('controls.VLS_Horse_0x53',       50770, 0x53,  'DUMP', None),
    ('controls.VLS_Horse_0x5F',       50770, 0x5F,  'DUMP', None),
    ('controls.ST_Fix1_0x3F',         50913, 0x3F,  'DISPFIELD', (410199, 410200)),
    ('controls.ST_Fix1_0xA1',         50913, 0xA1,  'DISPFIELD', (410199, 410200)),
    ('controls.ST_Fix1_0x1BA',        50913, 0x1BA, 'DISPFIELD', (410199, 410200)),
    ('controls.ST_Fix2_0x268',        50911, 0x268, 'DISPFIELD', (410199, 410200)),
    ('controls.ST_Fix3_0x17',         50921, 0x17,  'DISPFIELD', (410199, 410200)),
    ('havok.PhysCalcMaxTime',         36577, 0xA6,  'CALL5', None),
    ('havok.PhysCalc_AE_patch',       77850, 0x75,  'DUMP', None),
    ('havok.PhysDamageCalc',          26018, 0x5F,  'BOUNDARY', 5),
    ('misc.SkipNoINI',                36725, 0x319, 'DUMP', None),
    ('misc.LoadScreen_inj',           21830, 0x36,  'BOUNDARY', 6),
    ('misc.LoadScreen_retn',          21830, 0x4ED, 'DUMP', None),
    ('misc.ActorFade_0x4CA',          33007, 0x4CA, 'DUMP', None),
    ('misc.ActorFade_0x4BA',          33007, 0x4BA, 'DUMP', None),
    ('misc.PlayerFade',               50832, 0x4DD, 'DUMP', None),
    ('papyrus.SEO_lea',               54748, 0x18,  'DUMP', None),
    ('papyrus.SEO_cmp',               54748, 0x28,  'DUMP', None),
    ('papyrus.UpdateBudgetGame',      53928, 0x90,  'BOUNDARY', 8),
    ('papyrus.UpdateBudgetUI',        53929, 0x90,  'BOUNDARY', 8),
]

only = sys.argv[1] if len(sys.argv) > 1 else None

for (label, aid, disp, kind, extra) in SITES:
    if only and only not in label:
        continue
    if aid >= cnt or offs[aid] == 0:
        print('%-34s ANCHOR-MISSING id %d' % (label, aid))
        continue
    fn = offs[aid]
    site = fn + disp
    b = read(site, 16)
    status = ''
    if kind == 'CALL5':
        if b[0] == 0xE8:
            tgt = site + 5 + struct.unpack_from('<i', b, 1)[0]
            status = 'OK E8 -> %s' % idname(tgt)
        else:
            status = 'FAIL not E8 (%02X)' % b[0]
    elif kind == 'CALL6':
        if b[0] == 0xFF and b[1] == 0x15:
            tgt = site + 6 + struct.unpack_from('<i', b, 2)[0]
            status = 'OK FF15 -> iat rva 0x%X' % tgt
        else:
            status = 'FAIL not FF15 (%02X %02X)' % (b[0], b[1])
    elif kind == 'BOUNDARY':
        n = extra
        acc = 0
        ok = False
        for ins in dis(site, 32, 8):
            acc += ins[1]
            if acc == n:
                ok = True
                break
            if acc > n:
                break
        status = ('OK boundary@%d' % n) if ok else ('FAIL no boundary@%d' % n)
    elif kind == 'DISPFIELD':
        val = struct.unpack_from('<i', b, 0)[0]
        tgt = site + 4 + val
        names = extra
        hit = rev.get(tgt)
        status = ('OK disp -> id%d' % hit) if hit in names else ('FAIL disp -> %s' % idname(tgt))
    else:
        status = 'DUMP'
    print('%-34s fn=0x%-8X site=0x%-8X %s' % (label, fn, site, status))
    if 'FAIL' in status or kind == 'DUMP':
        for (a, sz, mn, op, raw) in dis(site, 40, 6):
            print('      0x%08X  %-24s %s %s' % (a, raw.hex(), mn, op))
