#!/usr/bin/env python3
"""SHA-256 file, directory, range and block manifests; Python 3.10+."""
from __future__ import annotations
import hashlib, os, re, stat, struct, sys, time, zlib
from dataclasses import dataclass, field
from datetime import date
from typing import BinaryIO
HEADER=64
MAX_PATH=16*1024*1024
MAGIC1,MAGIC2=b"HCHKBN1\0",b"HCHKBN2\0"
END1,END2=b"HCHKEND1",b"HCHKEND2"
BASE_FLAGS=0x1f
RANGE_FLAG,BLOCK_FLAG,COMPRESSED_FLAG=0x40,0x80,0x20
COMP_NONE,COMP_FIXED=0,1
OS_NAMES={0:"Unknown",1:"Linux",2:"macOS",3:"Windows"}
FILE,DIR,LINK,BLOCK=1,2,3,4
TYPE_NAMES={FILE:"FILE",DIR:"DIR ",LINK:"LINK",BLOCK:"BLOCK"}
CHUNK=16*1024*1024
DATA_RATE=256_000_000

class HashcheckError(Exception): pass

@dataclass
class Record:
    kind:int
    size:int
    digest:bytes
    path:str
    flags:int=0

@dataclass
class Manifest:
    version:int
    flags:int
    os_id:int
    hash_alg:int
    path_fmt:int
    compression:int
    created:int
    root_count:int
    records:list[Record]=field(default_factory=list)
    raw_size:int=0
    stored_size:int=0
    range_offset:int=0
    checksum_ok:bool=False

def utf8(s:str)->bytes:
    try:return s.encode("utf-8","strict")
    except UnicodeEncodeError as e:raise HashcheckError(f"path is not valid UTF-8: {s!r}") from e

def basename(path:str)->str:
    if os.name=="nt":
        s=path.rstrip("/\\")
        if not s:return "root"
        if len(s)==2 and s[1]==":":return "drive-"+s[0]
        return re.split(r"[/\\]",s)[-1] or "root"
    s=path.rstrip("/")
    return os.path.basename(s) if s else "root"

def os_id()->int:
    if sys.platform.startswith("linux"):return 1
    if sys.platform=="darwin":return 2
    if os.name=="nt":return 3
    return 0


def fmt_bytes(value: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    unit = 0
    while value >= 1024 and unit < len(units)-1:
        value /= 1024
        unit += 1
    return f"{value:.0f} {units[unit]}" if unit == 0 else f"{value:.1f} {units[unit]}"

def fmt_eta(seconds: float) -> str:
    if seconds < 0 or seconds > 315360000:
        return "--:--:--"
    value = int(seconds + 0.5)
    return f"{value//3600:02d}:{(value%3600)//60:02d}:{value%60:02d}"

class Progress:
    def __init__(self, label: str, total: int, units: int = 0):
        self.label, self.total, self.units_total = label, total, units
        self.done = self.units_done = 0
        self.start = self.last = time.monotonic()
        self.tty = sys.stderr.isatty()
        self.active = total > 0

    def draw(self, force: bool = False) -> None:
        if not self.active:
            return
        now = time.monotonic()
        if not force and now-self.last < (0.25 if self.tty else 10.0):
            return
        self.last = now
        elapsed = now-self.start
        speed = self.done/elapsed if elapsed > 0 else 0.0
        eta = (self.total-self.done)/speed if speed > 0 and self.done < self.total else 0.0
        pct = 100.0*self.done/self.total if self.total else 100.0
        line = (f"{self.label} {pct:6.2f}%  {fmt_bytes(self.done)}/{fmt_bytes(self.total)}"
                f"  {speed/(1024*1024):7.1f} MiB/s  ETA {fmt_eta(eta)}")
        if self.units_total:
            line += f"  blocks {self.units_done}/{self.units_total}"
        if self.tty:
            sys.stderr.write("\r" + line + "        ")
            sys.stderr.flush()
            if force:
                sys.stderr.write("\n")
        else:
            print(line, file=sys.stderr)

    def add(self, count: int) -> None:
        if self.active:
            self.done = min(self.total, self.done+count)
            self.draw()

    def unit_done(self) -> None:
        if self.active:
            self.units_done = min(self.units_total, self.units_done+1)
            self.draw()

    def finish(self) -> None:
        if self.active:
            self.done = self.total
            self.units_done = self.units_total
            self.draw(True)
            self.active = False

def sha_file(path: str, offset: int | None = None, length: int | None = None) -> tuple[bytes, int]:
    h, total = hashlib.sha256(), 0
    with open(path, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        progress = Progress("Hashing", length if offset is not None else size)
        if offset is None:
            for data in iter(lambda: f.read(CHUNK), b""):
                h.update(data)
                total += len(data)
                progress.add(len(data))
        else:
            assert length is not None
            if offset > size or length > size-offset:
                raise HashcheckError(f"requested range is outside file: {path}")
            f.seek(offset)
            remain = length
            while remain:
                data = f.read(min(CHUNK, remain))
                if not data:
                    raise HashcheckError(f"cannot read range: {path}")
                h.update(data)
                total += len(data)
                remain -= len(data)
                progress.add(len(data))
        progress.finish()
    return h.digest(), total

def parse_exclude(value: str) -> tuple[str, str]:
    if not value: raise HashcheckError("--exclude value must not be empty")
    if value.startswith("ext:"):
        pattern = value[4:]
        if len(pattern) < 2 or not pattern.startswith(".") or "/" in pattern or chr(92) in pattern:
            raise HashcheckError("extension exclusions must look like ext:.tmp")
        return "extension", pattern
    if value.startswith("file:"):
        pattern = value[5:]
        if not pattern or "/" in pattern or chr(92) in pattern:
            raise HashcheckError("file exclusions must name a basename")
        return "basename", pattern
    if value.startswith("path:"):
        pattern = value[5:].replace(chr(92), "/")
        if pattern.startswith("./"): pattern = pattern[2:]
        if not pattern: raise HashcheckError("path exclusion must not be empty")
        return "path", pattern
    if value.startswith(".") and "/" not in value and chr(92) not in value:
        return "extension", value
    if "/" in value or chr(92) in value:
        pattern = value.replace(chr(92), "/")
        if pattern.startswith("./"): pattern = pattern[2:]
        return "path", pattern
    return "basename", value

def excluded_file(logical: str, root: str, rules: list[tuple[str, str]]) -> bool:
    if logical == root:
        relative = logical
    elif logical.startswith(root + "/"):
        relative = logical[len(root) + 1:]
    else:
        relative = logical
    name = relative.rsplit("/", 1)[-1]
    for kind, pattern in rules:
        if kind == "extension":
            dot = name.rfind(".")
            if dot > 0 and name[dot:].isascii() and pattern.isascii() and name[dot:].lower() == pattern.lower(): return True
        elif kind == "basename" and name == pattern: return True
        elif kind == "path" and relative == pattern: return True
    return False

def walk(path:str,logical:str,records:list[Record],root:str,excludes:list[tuple[str,str]])->tuple[int,bytes,int]|None:
    try:st=os.lstat(path)
    except OSError as e:raise HashcheckError(f"cannot stat {path!r}: {e.strerror}") from e
    if (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)) and excluded_file(logical,root,excludes):return None
    if stat.S_ISREG(st.st_mode):
        try:digest,size=sha_file(path)
        except OSError as e:raise HashcheckError(f"cannot read {path!r}: {e.strerror}") from e
        records.append(Record(FILE,size,digest,logical));return FILE,digest,size
    if stat.S_ISLNK(st.st_mode):
        try:target=os.fsencode(os.readlink(path))
        except OSError as e:raise HashcheckError(f"cannot read symlink {path!r}: {e.strerror}") from e
        digest=hashlib.sha256(b"HASHCHECK-LINK-v1\0"+target).digest()
        records.append(Record(LINK,len(target),digest,logical));return LINK,digest,len(target)
    if stat.S_ISDIR(st.st_mode):
        try:names=os.listdir(path)
        except OSError as e:raise HashcheckError(f"cannot open directory {path!r}: {e.strerror}") from e
        names.sort(key=utf8);h=hashlib.sha256(b"HASHCHECK-DIR-v1\0")
        for name in names:
            encoded=utf8(name)
            child=walk(os.path.join(path,name),logical+"/"+name,records,root,excludes)
            if child is None:continue
            kind,digest,_=child
            h.update(bytes((kind,))+struct.pack("<I",len(encoded))+encoded+digest)
        digest=h.digest();records.append(Record(DIR,0,digest,logical));return DIR,digest,0
    raise HashcheckError(f"unsupported special file: {path}")

def serialize(records:list[Record])->bytes:
    records.sort(key=lambda r:utf8(r.path));out=bytearray()
    for r in records:
        name=utf8(r.path)
        if not name or len(name)>0xffffffff:raise HashcheckError("manifest path is empty or too long")
        out.extend(struct.pack("<BBHIQ32s",r.kind,r.flags,0,len(name),r.size,r.digest));out.extend(name)
    return bytes(out)

def write_manifest(path:str,records:list[Record],roots:int,extra:int=0,range_offset:int=0)->None:
    raw=serialize(records);stored=raw;comp=COMP_NONE;flags=BASE_FLAGS|extra
    if raw:
        z=zlib.compressobj(9,zlib.DEFLATED,-15,8,zlib.Z_FIXED);candidate=z.compress(raw)+z.flush()
        if len(candidate)<len(raw):stored,comp=candidate,COMP_FIXED;flags|=COMPRESSED_FLAG
    h=bytearray(HEADER);h[:8]=MAGIC2
    struct.pack_into("<HHI",h,8,2,HEADER,flags);h[16:20]=bytes((os_id(),1,1,comp))
    struct.pack_into("<QQIQQ",h,20,int(time.time()),len(records),roots,len(raw),len(stored))
    if extra&RANGE_FLAG:struct.pack_into("<Q",h,56,range_offset)
    else:h[56:61]=b"hc-v2"
    digest=hashlib.sha256(h+stored).digest()
    try:
        with open(path,"wb") as f:f.write(h+stored+END2+digest)
    except OSError as e:raise HashcheckError(f"cannot create {path!r}: {e.strerror}") from e

def read_exact(f:BinaryIO,n:int)->bytes:
    data=f.read(n)
    if len(data)!=n:raise HashcheckError("truncated manifest")
    return data

def parse_payload(raw:bytes,count:int)->list[Record]:
    out=[];pos=0
    for _ in range(count):
        if len(raw)-pos<48:raise HashcheckError("invalid manifest record header")
        kind,flags,_,n,size,digest=struct.unpack_from("<BBHIQ32s",raw,pos);pos+=48
        if n==0 or n>MAX_PATH or len(raw)-pos<n:raise HashcheckError("invalid manifest path length")
        try:name=raw[pos:pos+n].decode("utf-8","strict")
        except UnicodeDecodeError as e:raise HashcheckError("manifest path is not valid UTF-8") from e
        pos+=n;out.append(Record(kind,size,digest,name,flags))
    if pos!=len(raw):raise HashcheckError("invalid manifest payload size")
    return sorted(out,key=lambda r:utf8(r.path))

def read_manifest(path:str)->Manifest:
    try:f=open(path,"rb")
    except OSError as e:raise HashcheckError(f"cannot open manifest {path!r}: {e.strerror}") from e
    with f:
        h=read_exact(f,HEADER);ver,hs=struct.unpack_from("<HH",h,8)
        if hs!=HEADER or (h[:8],ver) not in ((MAGIC1,1),(MAGIC2,2)):raise HashcheckError("not a supported hashcheck manifest")
        flags=struct.unpack_from("<I",h,12)[0];osid,alg,pathfmt,comp=h[16:20]
        created,count=struct.unpack_from("<QQ",h,20);roots=struct.unpack_from("<I",h,36)[0]
        if ver==1:
            checksum=hashlib.sha256(h);records=[]
            for _ in range(count):
                rh=read_exact(f,48);checksum.update(rh)
                kind,rf,_,n,size,digest=struct.unpack("<BBHIQ32s",rh)
                if not 0<n<=MAX_PATH:raise HashcheckError("invalid manifest path length")
                name=read_exact(f,n);checksum.update(name)
                try:logical=name.decode("utf-8","strict")
                except UnicodeDecodeError as e:raise HashcheckError("manifest path is not valid UTF-8") from e
                records.append(Record(kind,size,digest,logical,rf))
            if read_exact(f,8)!=END1:raise HashcheckError("invalid v1 manifest trailer")
            ok=checksum.digest()==read_exact(f,32);rawsize=storedsize=range_offset=0
        else:
            rawsize,storedsize=struct.unpack_from("<QQ",h,40)
            range_offset=struct.unpack_from("<Q",h,56)[0] if flags&RANGE_FLAG else 0
            if max(rawsize,storedsize)>sys.maxsize:raise HashcheckError("manifest payload is too large")
            stored=read_exact(f,storedsize)
            if read_exact(f,8)!=END2:raise HashcheckError("invalid v2 manifest trailer")
            ok=hashlib.sha256(h+stored).digest()==read_exact(f,32)
            if comp==COMP_NONE:
                raw=stored
                if len(raw)!=rawsize:raise HashcheckError("manifest payload size mismatch")
            elif comp==COMP_FIXED:
                try:
                    z=zlib.decompressobj(-15);raw=z.decompress(stored,rawsize+1)+z.flush()
                except zlib.error as e:raise HashcheckError("invalid compressed manifest payload") from e
                if len(raw)!=rawsize or not z.eof or z.unused_data or z.unconsumed_tail:raise HashcheckError("manifest decompressed size mismatch")
            else:raise HashcheckError("unsupported manifest compression")
            records=parse_payload(raw,count)
        records.sort(key=lambda r:utf8(r.path))
        return Manifest(ver,flags,osid,alg,pathfmt,comp,created,roots,records,rawsize,storedsize,range_offset,ok)

def os_name(i:int)->str:return OS_NAMES.get(i,"Unknown")

def root_name(m:Manifest)->str|None:
    if m.root_count!=1 or not m.records:return None
    roots=[r.path for r in m.records if "/" not in r.path]
    return min(roots,key=lambda s:(len(utf8(s)),utf8(s))) if roots else None

def compare_key(path:str,root:str|None)->str:
    if root is None:return path
    if path==root:return "."
    return path[len(root)+1:] if path.startswith(root+"/") else path

def compare(a:Manifest,b:Manifest)->int:
    ar,br=root_name(a),root_name(b)
    print(f"A: {os_name(a.os_id)}, {len(a.records)} records, manifest={'OK' if a.checksum_ok else 'BAD'}"+(f", root={ar}" if ar else ""))
    print(f"B: {os_name(b.os_id)}, {len(b.records)} records, manifest={'OK' if b.checksum_ok else 'BAD'}"+(f", root={br}" if br else "")+"\n")
    if not a.checksum_ok or not b.checksum_ok:
        print("ERROR: one or both manifest files are corrupted.");return 2
    left=sorted(((compare_key(r.path,ar),r) for r in a.records),key=lambda p:utf8(p[0]))
    right=sorted(((compare_key(r.path,br),r) for r in b.records),key=lambda p:utf8(p[0]))
    i=j=same=changed=onlya=onlyb=typechg=0;mismatch=False
    while i<len(left) or j<len(right):
        if i==len(left):c=1
        elif j==len(right):c=-1
        else:
            x,y=utf8(left[i][0]),utf8(right[j][0]);c=(x>y)-(x<y)
        if c<0:print(f"ONLY-A   {left[i][0]}");onlya+=1;mismatch=True;i+=1
        elif c>0:print(f"ONLY-B   {right[j][0]}");onlyb+=1;mismatch=True;j+=1
        else:
            key,x=left[i];y=right[j][1]
            if x.kind!=y.kind:
                print(f"TYPE      {key}  ({TYPE_NAMES.get(x.kind,'????')} -> {TYPE_NAMES.get(y.kind,'????')})");typechg+=1;mismatch=True
            elif x.digest!=y.digest or (x.kind in (FILE,BLOCK) and x.size!=y.size):
                print(f"CHANGED   {key}\n          A {x.digest.hex()}  size={x.size}\n          B {y.digest.hex()}  size={y.size}");changed+=1;mismatch=True
            else:same+=1
            i+=1;j+=1
    print(f"\nSummary: SAME={same} CHANGED={changed} TYPE={typechg} ONLY-A={onlya} ONLY-B={onlyb}")
    print(f"Result : {'DIFFERENT' if mismatch else 'IDENTICAL'}");return 1 if mismatch else 0

def inspect(m:Manifest)->int:
    try:created=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(m.created))
    except (OverflowError,OSError,ValueError):created="unknown"
    print("hashcheck binary manifest")
    print(f"  version      : {m.version}\n  source OS    : {os_name(m.os_id)}\n  flags        : 0x{m.flags:08x}")
    print("  algorithm    : SHA-256\n  path format  : UTF-8, '/' separated, relative logical roots")
    if m.version>=2:
        comp="DEFLATE (fixed Huffman)" if m.compression==COMP_FIXED else "none"
        ratio=f" ({100*m.stored_size/m.raw_size:.1f}%)" if m.raw_size else ""
        print(f"  compression  : {comp}\n  payload      : {m.raw_size} -> {m.stored_size} bytes{ratio}")
    print(f"  created      : {created}\n  roots        : {m.root_count}\n  records      : {len(m.records)}")
    if m.flags&RANGE_FLAG:print(f"  range offset : {m.range_offset} bytes\n  range length : {sum(r.size for r in m.records)} bytes")
    if m.flags&BLOCK_FLAG and m.records:
        line=f"  block size   : {m.records[0].size} bytes"
        if len(m.records)>1 and m.records[-1].size!=m.records[0].size:line+=f" (last={m.records[-1].size})"
        print(line)
    print(f"  manifest SHA : {'OK' if m.checksum_ok else 'FAILED'}\n")
    for r in m.records:
        digest=r.digest.hex()
        if r.kind==FILE:
            label="RANGE " if m.flags&RANGE_FLAG and len(m.records)==1 else "FILE  "
            print(f"{label}  {digest}  {r.size:12d}  {r.path}")
        elif r.kind==BLOCK:print(f"BLOCK  {digest}  {r.size:12d}  {r.path}")
        else:print(f"{TYPE_NAMES.get(r.kind,'????')}  {digest}  {'-':>12}  {r.path}")
    return 0 if m.checksum_ok else 2

def parse_time(s:str)->tuple[int,str]:
    if len(s)==11:
        year=2000+int(s[:2]);doy,hh,mm,ss=int(s[2:5]),int(s[5:7]),int(s[7:9]),int(s[9:11])
    elif len(s)==13:
        year=int(s[:4]);doy,hh,mm,ss=int(s[4:7]),int(s[7:9]),int(s[9:11]),int(s[11:13])
    else:raise ValueError("time must be YYDOYhhmmss or YYYYDOYhhmmss")
    if not (1970<=year<=9999 and 1<=doy<=date(year,12,31).timetuple().tm_yday and 0<=hh<=23 and 0<=mm<=59 and 0<=ss<=60):raise ValueError("time field out of range")
    secs=(date(year,1,1).toordinal()-date(1970,1,1).toordinal()+doy-1)*86400+hh*3600+mm*60+ss
    return secs,f"{year:04d}{doy:03d}{hh:02d}{mm:02d}{ss:02d}"

def record_start(log:str)->tuple[int,str]:
    try:
        with open(log,"rb") as f:lines=f.read().decode("utf-8","replace").splitlines()
    except OSError as e:raise HashcheckError(f"cannot open log {log!r}: {e.strerror}") from e
    for line in lines:
        u=line.upper()
        if "REQRECSTART" not in u and "RECSTART" not in u and not ("RECORD" in u and "START" in u):continue
        for token in re.findall(r"\d+",line):
            if len(token) in (11,13):
                try:return parse_time(token)
                except ValueError:pass
    raise HashcheckError(f"recording start not found in log {log!r} (REQRECSTART/RECSTART required)")

def duration_bytes(s:str)->int:
    try:seconds=float(s)
    except ValueError as e:raise HashcheckError(f"invalid DRG DUR {s!r}") from e
    result=seconds*DATA_RATE
    if not seconds>0 or result>0xffffffffffffffff:raise HashcheckError(f"invalid DRG DUR {s!r}")
    return int(result+0.5)

def make_shell(drg:str,log:str,output:str,every:int)->int:
    rec_sec,rec13=record_start(log)
    try:
        with open(drg,encoding="utf-8",errors="replace") as f:lines=f.readlines()
    except OSError as e:raise HashcheckError(f"cannot open DRG {drg!r}: {e.strerror}") from e
    d="$"
    out=["#!/bin/sh","set -eu","","# Generated by hashcheck --mksh",f"# DRG: {drg}",f"# LOG: {log}",
         f"# Recording start: {rec13}",f"# Data rate: {DATA_RATE} bytes/s","",
         'if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then','    echo "Usage: $0 DATAFILE [PREFIX]" >&2',
         '    echo "  DATAFILE : original recorded file" >&2','    echo "  PREFIX   : output hash prefix (default: DATAFILE basename)" >&2',
         "    exit 2","fi","","INPUT=$1","PREFIX="+d+"{2:-}",'if [ -z "$PREFIX" ]; then',
         "    base="+d+"{INPUT##*/}","    PREFIX="+d+"{base%.*}","fi","HASHCHECK="+d+"{HASHCHECK:-hashcheck}",
         'command -v "$HASHCHECK" >/dev/null 2>&1 || { echo "hashcheck not found: $HASHCHECK" >&2; exit 2; }',
         '[ -f "$INPUT" ] || { echo "input file not found: $INPUT" >&2; exit 2; }',""]
    inside=False;count=0
    for line in lines:
        s=line.lstrip(" \t")
        if not inside:
            if s.startswith("$SKED"):inside=True
            continue
        if s.startswith("$"):break
        if not s.strip() or s.startswith("*"):continue
        t=s.split()
        if len(t)<6:continue
        try:scan_sec,start=parse_time(t[4])
        except ValueError as e:raise HashcheckError(f"invalid DRG START {t[4]!r}") from e
        length=duration_bytes(t[5]);delta=scan_sec-rec_sec
        if delta<0:raise HashcheckError(f"DRG scan {start} starts before recording start {rec13}")
        off=delta*DATA_RATE
        if off>0xffffffffffffffff:raise HashcheckError(f"DRG offset overflow at {start}")
        count+=1
        out.extend((f"# scan {count}  target={t[0]}  start={start}  dur={t[5]} s",
                    f'"$HASHCHECK" -o "{d}{{PREFIX}}_{start}.hash" --offset {off} --length {length} --block {DATA_RATE} --every {every} "$INPUT"',""))
    if not count:raise HashcheckError(f"no scans found in $SKED section of {drg}")
    out.append(f'echo "hashcheck: completed {count} scan ranges (1-second blocks sampled every {every} seconds)"')
    try:
        with open(output,"w",encoding="utf-8",newline="\n") as f:f.write("\n".join(out)+"\n")
        os.chmod(output,0o755)
    except OSError as e:raise HashcheckError(f"cannot write {output!r}: {e.strerror}") from e
    print(f"Wrote {output} : {count} scan ranges (1-second blocks, every {every} seconds), recording start={rec13}, data rate={DATA_RATE} bytes/s")
    return 0

USAGE="""hashcheck.py - SHA-256 file/tree/range/block manifests (Python 3.10+)
Usage:
  hashcheck.py PATH
  hashcheck.py [--exclude RULE]... -o OUTPUT.hash PATH [PATH ...]
  hashcheck.py [ -o OUTPUT.hash ] --offset OFFSET --length LENGTH FILE
  hashcheck.py [ -o OUTPUT.hash ] [--offset OFFSET --length LENGTH] --block BYTES [--every N] FILE
  hashcheck.py --mksh SCHEDULE.DRG --log RECORD.log [--every N] [ -o OUTPUT.sh ]
  hashcheck.py MANIFEST.hash
  hashcheck.py A.hash B.hash
  hashcheck.py -c A.hash B.hash
Options:
  -o FILE             Output manifest; with --mksh, shell script.
  -c, --compare       Explicit manifest comparison mode.
  --offset N          Start byte offset; requires --length.
  --length N          Number of bytes; requires --offset.
  --exclude RULE      Omit files by extension (.tmp), basename (name.tmp), or root-relative path (sub/name.tmp); repeatable.
                      Use file:.gitignore for an exact dotfile name or ext:.gz for an explicit extension.
  --block N           Split data into independent N-byte SHA-256 blocks.
  --every N           Hash every Nth block (default 10); with --mksh, every N seconds.
  --mksh DRG          Generate 1-second hash commands from DRG $SKED.
  --log LOG           Recording log for --mksh (REQRECSTART/RECSTART required).
  -h, --help          Show help. v1 manifests remain readable; new manifests use v2.
Exit code: 0 success/identical, 1 different, 2 error.
"""

def u64(s:str)->int:
    if not s or not s.isascii() or not s.isdigit():raise ValueError
    n=int(s,10)
    if n>0xffffffffffffffff:raise ValueError
    return n

def is_manifest(path:str)->bool:
    try:
        with open(path,"rb") as f:return f.read(8) in (MAGIC1,MAGIC2)
    except OSError:return False

def whole(output:str,paths:list[str],excludes:list[tuple[str,str]])->int:
    roots=[basename(p) for p in paths]
    if len(set(roots))!=len(roots):raise HashcheckError("duplicate logical root name")
    records:list[Record]=[]
    root_hashes=[];included_roots=0
    for path,root in zip(paths,roots):
        result=walk(path,root,records,root,excludes)
        if result is None:continue
        _,digest,_=result
        root_hashes.append((root,digest));included_roots+=1
    write_manifest(output,records,included_roots)
    for root,digest in root_hashes:
        print(f"SHA-256  {digest.hex()}  {root}")
    print(f"Wrote {output} : {len(records)} records ({os_name(os_id())})");return 0

def hash_range(output:str,path:str,offset:int,length:int)->int:
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):raise HashcheckError(f"range input must be a regular file: {path}")
        digest,_=sha_file(path,offset,length)
    except OSError as e:raise HashcheckError(f"cannot read range {path!r}: {e.strerror}") from e
    write_manifest(output,[Record(FILE,length,digest,basename(path))],1,RANGE_FLAG,offset)
    print(f"SHA-256  {digest.hex()}  {basename(path)} (range offset={offset} length={length})")
    print(f"Wrote {output} : range offset={offset} length={length}");return 0

def hash_blocks(output:str,path:str,offset:int,length:int,block_size:int,every:int)->int:
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):raise HashcheckError(f"block input must be a regular file: {path}")
        size=os.path.getsize(path)
        if offset>size or length>size-offset:raise HashcheckError(f"requested block range is outside file: {path}")
        records=[]
        units=(length+block_size-1)//block_size
        sample_units=(units-1)//every+1 if units else 0
        last_index=(sample_units-1)*every if sample_units else 0
        sampled_bytes=(sample_units-1)*block_size+min(block_size,length-last_index*block_size) if sample_units else 0
        progress=Progress("Hashing",sampled_bytes,sample_units)
        with open(path,"rb") as f:
            f.seek(offset)
            block_index=0
            while block_index<units:
                relative=block_index*block_size
                if every>1:f.seek(offset+relative)
                n=min(block_size,length-relative);h=hashlib.sha256();todo=n
                while todo:
                    data=f.read(min(CHUNK,todo))
                    if not data:raise HashcheckError(f"cannot read block range: {path}")
                    h.update(data);todo-=len(data);progress.add(len(data))
                records.append(Record(BLOCK,n,h.digest(),f"+{relative:020d}"))
                progress.unit_done()
                block_index+=every
        progress.finish()
    except OSError as e:raise HashcheckError(f"cannot read block range {path!r}: {e.strerror}") from e
    write_manifest(output,records,0,RANGE_FLAG|BLOCK_FLAG,offset)
    for record in records:
        print(f"SHA-256  {record.digest.hex()}  {record.path} (block size={record.size})")
    print(f"Wrote {output} : {len(records)} sampled blocks, offset={offset} length={length} block={block_size} every={every}");return 0
def main(argv:list[str]|None=None)->int:
    args=list(sys.argv[1:] if argv is None else argv)
    if not args:sys.stderr.write(USAGE);return 0
    output=mksh=log=None;offset=length=block=every=None;compare_mode=False;paths:list[str]=[];exclude_values:list[str]=[];i=0
    while i<len(args):
        a=args[i]
        if a in ("-h","--help"):sys.stdout.write(USAGE);return 0
        if a in ("-c","--compare"):
            if compare_mode:sys.stderr.write(USAGE);return 2
            compare_mode=True
        elif a in ("-o","--mksh","--log","--offset","--length","--block","--every","--exclude"):
            if i+1>=len(args):sys.stderr.write(USAGE);return 2
            i+=1;v=args[i]
            if a=="--exclude":
                exclude_values.append(v)
            elif a=="-o":
                if output is not None:sys.stderr.write(USAGE);return 2
                output=v
            elif a=="--mksh":
                if mksh is not None:sys.stderr.write(USAGE);return 2
                mksh=v
            elif a=="--log":
                if log is not None:sys.stderr.write(USAGE);return 2
                log=v
            else:
                try:n=u64(v)
                except ValueError:sys.stderr.write(USAGE);return 2
                if a=="--offset":
                    if offset is not None:sys.stderr.write(USAGE);return 2
                    offset=n
                elif a=="--length":
                    if length is not None:sys.stderr.write(USAGE);return 2
                    length=n
                elif a=="--every":
                    if every is not None or n==0:sys.stderr.write(USAGE);return 2
                    every=n
                else:
                    if block is not None or n==0:sys.stderr.write(USAGE);return 2
                    block=n
        elif a=="--":paths.extend(args[i+1:]);break
        elif a.startswith("-"):sys.stderr.write(USAGE);return 2
        else:paths.append(a)
        i+=1
    try:
        excludes=[parse_exclude(value) for value in exclude_values]
        if mksh is not None:
            if compare_mode or offset is not None or length is not None or block is not None or excludes or paths or not log:
                if not log:print("hashcheck: --mksh requires --log RECORD.log",file=sys.stderr)
                sys.stderr.write(USAGE);return 2
            out=output or "hashcheck_"+os.path.splitext(basename(mksh))[0]+".sh"
            return make_shell(mksh,log,out,every or 10)
        if log is not None:raise HashcheckError("--log is only valid with --mksh")
        if compare_mode:
            if output is not None or offset is not None or length is not None or block is not None or every is not None or excludes or len(paths)!=2:
                sys.stderr.write(USAGE);return 2
            return compare(read_manifest(paths[0]),read_manifest(paths[1]))
        if every is not None and block is None:raise HashcheckError("--every requires --block or --mksh")
        if (offset is None)!=(length is None):raise HashcheckError("--offset and --length must be specified together")
        if block is not None:
            if excludes or len(paths)!=1:sys.stderr.write(USAGE);return 2
            off=offset or 0
            if length is None:
                if not stat.S_ISREG(os.lstat(paths[0]).st_mode):raise HashcheckError(f"block input must be a regular file: {paths[0]}")
                size=os.path.getsize(paths[0])
            else:size=length
            out=output or (f"{basename(paths[0])}.{off}+{size}.block{block}.hash" if offset is not None else f"{basename(paths[0])}.block{block}.hash")
            return hash_blocks(out,paths[0],off,size,block,every or 10)
        if offset is not None:
            if excludes or len(paths)!=1:sys.stderr.write(USAGE);return 2
            return hash_range(output or f"{basename(paths[0])}.{offset}+{length}.hash",paths[0],offset,length)
        if output is None and len(paths)==1 and is_manifest(paths[0]):
            if excludes:sys.stderr.write(USAGE);return 2
            return inspect(read_manifest(paths[0]))
        if output is None and len(paths)==2 and all(is_manifest(p) for p in paths):
            if excludes:sys.stderr.write(USAGE);return 2
            return compare(read_manifest(paths[0]),read_manifest(paths[1]))
        if not paths:sys.stderr.write(USAGE);return 2
        out=output or (basename(paths[0])+".hash" if len(paths)==1 else "hashcheck.hash")
        return whole(out,paths,excludes)
    except HashcheckError as e:
        print(f"hashcheck: error: {e}",file=sys.stderr);return 2
    except OSError as e:
        print(f"hashcheck: error: {e}",file=sys.stderr);return 2
    except RecursionError:
        print("hashcheck: error: directory nesting is too deep",file=sys.stderr);return 2

if __name__=="__main__":raise SystemExit(main())
