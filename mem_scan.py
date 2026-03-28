#!/usr/bin/env python3

import sys
import readline
import struct

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
    addr_list: list[str] = []
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
                addr_list.append(hex(start + off))
                offset = off + 1
    return addr_list

def find_text(addr_maps: list[tuple[int, int]], target_value: str) -> list[str]:
    b_value = bytes(target_value, "utf-8")
    return find_target(addr_maps, b_value)

def find_uint(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(4, "little")
    return find_target(addr_maps, b_value)
    
def find_int(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(4, "little", signed=True)
    return find_target(addr_maps, b_value)

def find_uint64(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(8, "little")
    return find_target(addr_maps, b_value)

def find_int64(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(8, "little", signed=True)
    return find_target(addr_maps, b_value)

def find_double(addr_maps: list[tuple[int, int]], target_value: float) -> list[str]:
    b_value = struct.pack("<d", target_value)
    return find_target(addr_maps, b_value)

def find_again(pid: str, addr_list: list[str], new_value: bytes, value_len: int):
    new_addr_list = []
    with open("/proc/"+pid+"/mem", "rb") as mem:
        for addr in addr_list:
            try:
                mem.seek(int(addr, 16))
                if mem.read(value_len) == new_value:
                    new_addr_list.append(addr)
            except OSError:
                continue
                    
    return new_addr_list

def list_addr(addr_list: list[str]):
    if addr_list:
        for addr in addr_list:
            print(f"find it at {addr}.")
    else:
        print("not found.")

def modify_target(target_list: list[str], new_value: bytes):
    with open("/proc/"+pid+"/mem", "rb+") as mem:
        for addr in target_list:
            try:
                mem.seek(int(addr, 16))
                mem.write(new_value)
            except OSError:
                continue
    return
            
def modify_text(target_list: list[str], mod_value: str):
    b_value = bytes(mod_value, "utf-8")
    return modify_target(target_list, b_value)

def modify_uint(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(4, "little")
    return modify_target(target_list, b_value)

def modify_int(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(4, "little", signed=True)
    return modify_target(target_list, b_value)

def modify_uint64(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(8, "little")
    return modify_target(target_list, b_value)

def modify_int64(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(8, "little", signed=True)
    return modify_target(target_list, b_value)

def modify_double(target_list: list[str], mod_value: float):
    b_value = struct.pack("<d", mod_value)
    return modify_target(target_list, b_value)

def read_line(pid, addr_maps):
    ori_value  = None
    addr_list  = []
    value_type = "string"
    ori_value_len  = 0
    
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
            print("- string: \tsearch string value in memory.")
            print("- int: \t\tsearch signed 4 bytes int number value in memory.")
            print("- uint: \tsearch unsigned 4 bytes int number value in memory.")
            print("- int64: \tsearch signed 8 bytes int number value in memory.")
            print("- uint64: \tsearch unsigned 8 bytes int number value in memory.")
            print("- double: \tsearch 8 bytes float number value in memory.")
            print("- set: \t\tmodify value(s) which was/were search command.")
            print("- list: \tlist the address(es) which was/were found in search command.")
            print("- help: \tprint this message.")
            
        elif command[0] == "string":
            if len(command) < 2:
                print("`string` must accept 1 str argument.", file=sys.stderr)
                continue
            ori_value     = " ".join(command[1:])
            value_type    = "string"
            ori_value_len = len(bytes(ori_value, "utf-8"))
            addr_list     = find_text(addr_maps, ori_value)
            list_addr(addr_list)
            
        elif command[0] == "uint":
            if len(command) != 2:
                print("`uint` must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`uint` accept a num value.", file=sys.stderr)
                continue
            value_type    = "uint"
            ori_value_len = 4
            addr_list     = find_uint(addr_maps, ori_value)
            list_addr(addr_list)
                
        elif command[0] == "int":
            if len(command) != 2:
                print("`int` must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`int` accept a num value.", file=sys.stderr)
                continue
            value_type    = "int"
            ori_value_len = 4
            addr_list     = find_int(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "uint64":
            if len(command) != 2:
                print("`uint64` must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`uint64` accept a num value.", file=sys.stderr)
                continue
            value_type    = "uint64"
            ori_value_len = 8
            addr_list     = find_uint64(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "int64":
            if len(command) != 2:
                print("`int64` must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`int64` accept a num value.", file=sys.stderr)
                continue
            value_type    = "int64"
            ori_value_len = 8
            addr_list     = find_int64(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "double":
            if len(command) != 2:
                print("`double` must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = float(command[1])
            except ValueError:
                print("`double` accept a num value.", file=sys.stderr)
                continue
            value_type    = "double"
            ori_value_len = 8
            addr_list     = find_double(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "again":
            if len(command) == 1:
                command.append(ori_value)
            match value_type:
                case "string":
                    new_value  = bytes(" ".join(command[1:]), "utf-8")
                    value_tyep = "string"
                    ori_value_len  = len(new_value)
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_len)
                    ori_value  = new_value.decode("utf-8")
                case "uint":
                    if len(command) > 2: print("`uint` must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(4, "little")
                    value_type = "uint"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_len)
                    ori_value  = int.from_bytes(new_value, "little")
                case "int":
                    if len(command) > 2: print("`int` must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(4, "little", signed=True)
                    value_type = "int"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_len)
                    ori_value  = int.from_bytes(new_value, "little", signed=True)
                case "uint64":
                    if len(command) > 2: print("`uint64` must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(8, "little")
                    value_type = "uint64"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_len)
                    ori_value  = int.from_bytes(new_value, "little")
                case "int64":
                    if len(command) > 2: print("`int64` must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(8, "little", signed=True)
                    value_type = "int64"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_len)
                    ori_value  = int.from_bytes(new_value, "little", signed=True)
                case "double":
                    if len(command) > 2: print("`double` must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = struct.pack("<d", float(command[1]))
                    value_type = "double"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_len)
                    ori_value  = struct.unpack("<d", new_value)[0]
                case _:
                    DEBUG(f"again {value_type} have not achieved.",
                          "Here should not be arrive.")
            list_addr(addr_list)
                
        elif command[0] == "list":
            list_addr(addr_list)

        elif command[0] == "set":
            if not addr_list:
                print("Please use search command to search value first.", file=sys.stderr)
                continue
            if len(command) < 2:
                print("Please input a value to modify.", file=sys.stderr)
                continue
            match value_type:
                case "string":
                    mod_value = " ".join(command[1:])
                    if len(bytes(mod_value, "utf-8")) > ori_value_len:
                        print("Length of string value should not be longer than original.", file=sys.stderr)
                        continue
                    modify_text(addr_list, mod_value)
                case "uint":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`uint` command accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > (1 << 32 - 1):
                        print("`uint` type do not accept a num value more than 4 bytes, please use `uint64`", file=sys.stderr)
                        return
                    modify_uint(addr_list, mod_value)
                case "int":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`int` command accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > (1 << 31 - 1) or mod_value < -(1 << 31 - 1):
                        print("`int` type do not accept a num value more than 4 bytes, please use `int64`.", file=sys.stderr)
                        continue
                    modify_int(addr_list, mod_value)
                case "uint64":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`uint64` command accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > (1 << 64 - 1):
                        print("`uint64` type do not accept a num value more than 8 bytes.", file=sys.stderr)
                        continue
                    modify_uint64(addr_list, mod_value)
                case "int64":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`int64` command accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > (1 << 63 - 1) or mod_value < -(1 << 63 - 1):
                        print("`int64` tyep do not accept a num value more than 8 bytes.", file=sys.stderr)
                        continue
                    modify_int64(addr_list, mod_value)
                case "double":
                    try:
                        mod_value = float(command[1])
                    except ValueError:
                        print("`double` command accept a num value.", file=sys.stderr)
                        continue
                    if (mod_value > sys.float_info.max
                        or mod_value < -sys.float_info.max
                        or -sys.float_info.min < mod_value < 0
                        or 0 < mod_value < sys.float_info.min):
                        print("`double` tyep do not accept a num value more than 8 bytes.", file=sys.stderr)
                        continue
                    modify_double(addr_list, mod_value)
                case _:
                    DEBUG(f"set {value_type} have not achieved.",
                          "Here should not be arrived.")
        else:
            DEBUG(f"{command[0]} have not achieved.",
                  "UnkownCommand. Please input `string/int` to find data or `set` to modify value.")

if __name__ == "__main__":
    assert len(sys.argv) == 2, "Script need a pid as argv."
    pid       = sys.argv[1]
    addr_maps = get_maps(pid)
    for addr_map in addr_maps:
        print(f"Scaned {addr_map}.")
    read_line(pid, addr_maps)
