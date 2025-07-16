#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path
from typing import Dict

def load_kallsyms(path: Path) -> Dict[str, int]:
    syms = {}  # type: Dict[str, int]
    line_re = re.compile(r"^([0-9a-fA-F]+)\s+\w\s+(\S+)")
    with path.open() as fp:
        for line in fp:
            m = line_re.match(line.strip())
            if m:
                addr_hex, name = m.groups()
                syms[name] = int(addr_hex, 16)
    return syms

if __name__ == "__main__":
    # Get arguments from sys.argv (excluding script name)
    actions = sys.argv[1:]
    
    # 1) load kernel symbol JSON
    vmlinux_symbol_path = Path("./linux_kernel_5.4.233.json")
    with vmlinux_symbol_path.open() as jf:
        data = json.load(jf)

    user_types = data.get("user_types", {})
    symbols = data.get("symbols", {})

    if 'banner' in actions:
        symbols["linux_banner"]["constant_data"] = "TGludXggdmVyc2lvbiA1LjQuMjMzLXFna2ktZGVidWcgKHNjbUBkOGYzMzNhNjZiMGIpIChBbmRyb2lkICg2ODc3MzY2IGJhc2VkIG9uIHIzODM5MDJiMSkgY2xhbmcgdmVyc2lvbiAxMS4wLjIgKGh0dHBzOi8vYW5kcm9pZC5nb29nbGVzb3VyY2UuY29tL3Rvb2xjaGFpbi9sbHZtLXByb2plY3QgYjM5N2Y4MTA2MGNlNmQ3MDEwNDJiNzgyMTcyZWQxM2JlZTg5OGI3OSksIExMRCAxMS4wLjIgKGh0dHBzOi8vYW5kcm9pZC5nb29nbGVzb3VyY2UuY29tL3Rvb2xjaGFpbi9sbHZtLXByb2plY3QgYjM5N2Y4MTA2MGNlNmQ3MDEwNDJiNzgyMTcyZWQxM2JlZTg5OGI3OSkpICMxIFNNUCBQUkVFTVBUIFRodSBKYW4gOSAyMDoxNzoyNyBDU1QgMjAyNQ=="
    else:
        # 2) kallsyms load
        kallsyms_symbol_path = Path("./kallsyms_5.4.233")
        kallsyms = load_kallsyms(kallsyms_symbol_path)

        # 3) symbols virtual address update
        patched = 0
        for name, entry in symbols.items():
            if name in kallsyms and isinstance(entry, dict) and "address" in entry:
                entry["address"] = kallsyms[name]
                patched += 1
        print(f"[+] Patched {patched} symbols")

        # 4) symbols struct update
        if 'struct' in actions:
            # task_struct
            if user_types["task_struct"]["fields"]["comm"]["offset"] == 1888:
                task_struct = user_types["task_struct"]["fields"]
                for name, entry in task_struct.items():
                    if entry["offset"] >= 1160:
                        entry["offset"] += 200
            
            # mm_struct
            mm_struct = user_types["mm_struct"]["fields"]
            mm_struct_name = mm_struct["unnamed_field_0"]["type"]["name"]
            mm_struct_real = user_types[mm_struct_name]["fields"]
            mm_struct_real["pgd"]["offset"] = 88

    # 5) save
    out_path = vmlinux_symbol_path
    with out_path.open("w") as jf:
        json.dump(data, jf, indent=2)

    print(f"[+] Written to {out_path.resolve()}")