#!/usr/bin/env python3

# TODO: find data
# TODO: modify data

import sys

def get_maps(pid: str) -> list[tuple[int, int]]:
    addr_maps: list[tuple] = []
    
    with open("/proc/"+pid+"/maps") as f:
        for line in f:
            addr, attr, *_ = line.split()
            if "r" not in attr:
                continue
            start, end = [int(x, 16) for x in addr.split("-")]
            addr_maps.append((start, end))

    return addr_maps
            
def find_target(addr_maps: list[tuple[int, int]], target: bytes) -> list[str]:
    target_list: list[str] = []
    with open("/proc/"+pid+"/mem", "rb") as mem:
        offset = 0
        for addr_map in addr_maps:
            start: int = addr_map[0]
            end  : int = addr_map[1]
            size : int = end - start

            try:
                mem.seek(start)
                buf: bytes = mem.read(size)
            except OSError:
                pass

            while True:
                off: int = buf.find(target, offset)
                if off == -1: break
                target_list.append(hex(start + off))
                offset = off + 1
                
    return target_list

def find_text(addr_maps: list[tuple[int, int]], target: str) -> list[str]:
    return find_target(addr_maps, bytes(target, "utf-8"))

def find_int(addr_maps: list[tuple[int, int]], target: int) -> list[str]:
    return find_target(addr_maps, target.to_bytes(4, "little"))
    
def modify_target(target_list: list[str], value: bytes):
    with open("/proc/"+pid+"/mem", "rb+") as mem:
        for addr in target_list:
            try:
                mem.seek(int(addr, 16))
                mem.write(value)
            except OSError:
                continue
    return
            
def modify_text(target_list: list[str], value: str, target_length: int):
    assert len(value) <= target_length, "Length of value should less then target_length."
    return modify_target(target_list, bytes(value, "utf-8"))

def modify_int(target_list: list[str], value: int):
    return modify_target(target_list, value.to_bytes(4, "little"))

def read_line(addr_maps):
    target_list = []
    data_type   = "string"
    while True:
        try:
            command = input("> ").split()
        except EOFError:
            print("\nexit."); sys.exit(0)
        except KeyboardInterrupt:
            print("\nexit."); sys.exit(0)
            
        if command[0] == "set":
            match data_type:
                case "string":
                    modify_text(target_list, command[1], len(command[1]))
                case "int":
                    modify_int(target_list, int(command[1]))
        elif command[0] == "list":
            for target in target_list:
                print(f"find it at {target}.")
        else:
            match command[0]:
                case "string":
                    data_type   = "string"
                    target_list = find_text(addr_maps, command[1])
                case "int":
                    data_type   = "int"
                    target_list = find_int(addr_maps, int(command[1]))
                case _:
                    print("UnkownWord. Please input string/int to find data or set to set value.")
                    
            if target_list:
                for target in target_list:
                    print(f"find it at {target}.")
            else:
                print("not found.")
                
if __name__ == "__main__":
    
    assert len(sys.argv) == 2, "Script accepts two args, script_name and pid."
    pid       = sys.argv[1]
    addr_maps = get_maps(pid)
    read_line(addr_maps)
