import re, os, struct, json

root = os.path.dirname(os.path.abspath(__file__))
scan_dirs = [
    os.path.join(root, 'SSEDisplayTweaks', 'SSETweaks'),
    os.path.join(root, 'sse-build-resources', 'ext'),
    os.path.join(root, 'sse-build-resources', 'skse64'),
]
pat_memberfn = re.compile(r'DEFINE_MEMBER_FN(?:_LONG)?\(\s*(?:(\w+)\s*,\s*)?(\w+)\s*,\s*[\w:<>*&\s]+?,\s*([\w:]+)\s*,\s*(\d+)')
pat_addr = re.compile(r'IAL::Add(?:r|ress)\s*(?:<[^;()]{0,200}?>)?\s*[({]\s*([\w:]+)\s*,\s*(\d+)')
pairs = []
for d in scan_dirs:
    for dirpath, _, files in os.walk(d):
        for fn in files:
            if not fn.endswith(('.h', '.cpp', '.inl', '.hpp')):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            txt = open(p, encoding='utf-8', errors='replace').read()
            txt = re.sub(r'//[^\n]*', '', txt)  # drop commented-out bindings
            for m in pat_memberfn.finditer(txt):
                line = txt[:m.start()].count('\n') + 1
                pairs.append((rel, line, 'MEMBER_FN', m.group(2) or m.group(1), m.group(3), int(m.group(4))))
            for m in pat_addr.finditer(txt):
                line = txt[:m.start()].count('\n') + 1
                pairs.append((rel, line, 'IAL', '?', m.group(1), int(m.group(2))))
            # version-gated AE ids: verify the >=1.6.1130 arm (what 1.7.99 uses)
            for m in re.finditer(r'IAL::ver\(\)\s*>=\s*0x00010006046A0000ULL\s*\?\s*(\d+)\s*:\s*(\d+)', txt):
                line = txt[:m.start()].count('\n') + 1
                pairs.append((rel, line, 'VERGATED', 'post1130-arm', m.group(2), int(m.group(1))))

db = open(os.path.join(root, 'dbtest', 'Data', 'SKSE', 'Plugins', 'versionlib-1-7-99-0.bin'), 'rb').read()
cnt = struct.unpack_from('<i', db, 92)[0]
offs = struct.unpack_from('<%dI' % cnt, db, 96)

sdt = [p for p in pairs if p[0].startswith('SSEDisplayTweaks')]
print('total pairs:', len(pairs), '| SSETweaks own:', len(sdt))

absent = [p for p in pairs if p[5] != 0 and (p[5] >= cnt or offs[p[5]] == 0)]
print('=== absent (nonzero AE id):', len(absent))
for a in absent:
    print(a)

print('=== SSETweaks own AE ids:')
seen = set()
for p in sdt:
    if p[5] in seen:
        continue
    seen.add(p[5])
    ok = p[5] < cnt and offs[p[5]] != 0
    print(('ok  ' if ok else 'MISS'), p[5], os.path.basename(p[0]), 'L%d' % p[1])

json.dump(pairs, open(os.path.join(root, 'id_inventory2.json'), 'w'))
