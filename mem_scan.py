#!/usr/bin/env python3

import sys
import readline

DEBUG_V = False
def DEBUG(debug_warning: str, run_warning: str):
    if DEBUG_V: assert False, debug_warning
    else: print(run_warning)

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
            
def find_target(addr_maps: list[tuple[int, int]], target_value: bytes) -> list[str]:
    target_list: list[str] = []
    with open("/proc/"+pid+"/mem", "rb") as mem:
        for addr_map in addr_maps:
            offset     = 0
            start: int = addr_map[0]
            end  : int = addr_map[1]
            size : int = end - start
            try:
                mem.seek(start)
                buf: bytes = mem.read(size)
            except OSError:
                pass
            while True:
                off: int = buf.find(target_value, offset)
                if off == -1: break
                target_list.append(hex(start + off))
                offset = off + 1
    return target_list

def find_text(addr_maps: list[tuple[int, int]], target_value: str) -> list[str]:
    b_value = bytes(target_value, "utf-8")
    return find_target(addr_maps, b_value)

def find_uint(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(4, "little")
    return find_target(addr_maps, b_value)
    
def find_int(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(4, "little", signed=True)
    return find_target(addr_maps, b_value)

def modify_target(target_list: list[str], new_value: bytes):
    with open("/proc/"+pid+"/mem", "rb+") as mem:
        for addr in target_list:
            try:
                mem.seek(int(addr, 16))
                mem.write(new_value)
            except OSError:
                continue
    return
            
def modify_text(target_list: list[str], mod_value: str, value_len: int):
    b_value = bytes(mod_value, "utf-8")
    if len(b_value) > value_len:
        print("Length of string value should not be longer than original.", file=sys.stderr)
        return
    return modify_target(target_list, b_value)

def modify_uint(target_list: list[str], mod_value: int):
    if mod_value > (1 << 32 - 1):
        print("Num value over than 4 bytes have not be supposed yet.", file=sys.stderr)
        return
    b_value = mod_value.to_bytes(4, "little")
    return modify_target(target_list, b_value)

def modify_int(target_list: list[str], mod_value: int):
    if mod_value > (1 << 31 - 1) or mod_value < -(1 << 31 - 1):
        print("Num value over than 4 bytes have not be supposed yet.", file=sys.stderr)
        return
    b_value = mod_value.to_bytes(4, "little", signed=True)
    return modify_target(target_list, b_value)

def find_again(pid: str, addr_list: list[str], new_value: bytes, value_len: int):
    new_list = []
    with open("/proc/"+pid+"/mem", "rb") as mem:
        for addr in addr_list:
            try:
                mem.seek(int(addr, 16))
                if mem.read(value_len) == new_value:
                    new_list.append(addr)
            except OSError:
                continue
                    
    return new_list

def list_addr(addr_list: list[str]):
    if addr_list:
        for addr in addr_list:
            print(f"find it at {addr}.")

def read_line(pid, addr_maps):
    ori_value  = None
    addr_list  = []
    value_type = "string"
    value_len  = 0
    
    while True:
        try:
            command = input("> ").split()
        except EOFError:
            print("\nexit."); sys.exit(0)
        except KeyboardInterrupt:
            print("\nexit."); sys.exit(0)

        if not command:
            continue
            
        elif command[0] == "help":
            print("help message:")
            print("- string/int: \tsearch string/int value in mem.")
            print("- set:\t\tmodify value(s) which was/were found in string/int.")
            print("- list:\t\tlist the address(es) which was/were found in string/int.")
            print("- help:\t\tprint this message.")
            
        elif command[0] == "string":
            if len(command) < 2:
                print("Must accept 1 str argument.", file=sys.stderr)
                continue
            ori_value = " ".join(command[1:])
            value_type= "string"
            value_len = len(bytes(ori_value, "utf-8"))
            addr_list = find_text(addr_maps, ori_value)
            list_addr(addr_list)
            
        elif command[0] == "uint":
            if len(command) != 2:
                print("Must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("The `uint` accept a num value.", file=sys.stderr)
                continue
            value_type = "uint"
            value_len  = 4
            addr_list  = find_uint(addr_maps, ori_value)
            list_addr(addr_list)
                
        elif command[0] == "int":
            if len(command) != 2:
                print("Must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("The `int` accept a num value.", file=sys.stderr)
                continue
            value_type = "int"
            value_len  = 4
            addr_list  = find_int(addr_maps, ori_value)
            list_addr(addr_list)


        elif command[0] == "again":
            if len(command) == 1:
                command.append(ori_value)
            match value_type:
                case "string":
                    new_value  = bytes(" ".join(command[1:]), "utf-8")
                    value_tyep = "string"
                    value_len  = len(new_value)
                    addr_list  = find_again(pid, addr_list, new_value, value_len)
                    ori_value  = new_value.decode("utf-8")
                case "uint":
                    if len(command) > 2: print("Must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(4, "little")
                    value_type = "uint"
                    value_len  = 4
                    addr_list  = find_again(pid, addr_list, new_value, 4)
                    ori_value  = int.from_bytes(new_value, byteorder="little")
                case "int":
                    if len(command) > 2: print("Must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(4, "little", signed=True)
                    value_type = "int"
                    value_len  = 4
                    addr_list  = find_again(pid, addr_list, new_value, 4)
                    ori_value  = int.from_bytes(new_value, "little", signed=True)
                case _:
                    DEBUG(f"again {value_type} have not achieved.",
                          "Here should not be arrive.")
            for target_addr in addr_list:
                print(f"find it at {target_addr}")
                
        elif command[0] == "list":
            list_addr(addr_list)

        elif command[0] == "set":
            if not addr_list:
                print("Please use string/int to search value first.", file=sys.stderr)
                continue
            if len(command) < 2:
                print("Please input a value to modify.", file=sys.stderr)
                continue
            match value_type:
                case "string":
                    mod_value = " ".join(command[1:])
                    modify_text(addr_list, mod_value, value_len)
                case "uint":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("The `int` accept a num value.", file=sys.stderr)
                        continue
                    modify_uint(addr_list, mod_value)
                case "int":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("The `int` accept a num value.", file=sys.stderr)
                        continue
                    modify_int(addr_list, mod_value)
                case _:
                    DEBUG(f"set {value_type} have not achieved.",
                          "Here should not be arrived.")

        else:
            DEBUG(f"{command[0]} have not achieved.",
                  "UnkownCommand. Please input `string/int` to find data or `set` to modify value.")

if __name__ == "__main__":
    assert len(sys.argv) == 2, "Script accepts two args, script_name and pid."
    pid       = sys.argv[1]
    addr_maps = get_maps(pid)
    for addr_map in addr_maps:
        print(f"Scaned {addr_map}.")
    read_line(pid, addr_maps)
