#!/usr/bin/env python3

# TODO: 合并int类，float类操作
# TODO: 修缮反馈文本
import sys
import time
import readline
import struct

DEBUG_V = True
def DEBUG(debug_warning: str, run_warning: str):
    if DEBUG_V:
        assert False, debug_warning
    else:
        print(run_warning, file=sys.stderr)

MAX_INT32   = (1 << 31) - 1
MAX_UINT32  = (1 << 32) - 1
MAX_INT64   = (1 << 63) - 1
MAX_UINT64  = (1 << 64) - 1
MAX_FLOAT32 = (2 - 2**(-23)) * (2 ** 127)
MIN_FLOAT32 = 2 ** -126
MAX_FLOAT64 = sys.float_info.max
MIN_FLOAT64 = sys.float_info.min

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

def find_str(addr_maps: list[tuple[int, int]], target_value: str) -> list[str]:
    b_value = bytes(target_value, "utf-8")
    return find_target(addr_maps, b_value)

def find_int(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(4, "little", signed=True)
    return find_target(addr_maps, b_value)

def find_uint(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(4, "little")
    return find_target(addr_maps, b_value)
    
def find_int64(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(8, "little", signed=True)
    return find_target(addr_maps, b_value)

def find_uint64(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(8, "little")
    return find_target(addr_maps, b_value)

def find_float(addr_maps: list[tuple[int, int]], target_value: float) -> list[str]:
    b_value = struct.pack("<f", target_value)
    return find_target(addr_maps, b_value)

def find_double(addr_maps: list[tuple[int, int]], target_value: float) -> list[str]:
    b_value = struct.pack("<d", target_value)
    return find_target(addr_maps, b_value)

def find_again(pid: str, addr_list: list[str], new_value: bytes, value_width: int) -> list[str]:
    new_addr_list = []
    with open("/proc/"+pid+"/mem", "rb") as mem:
        for addr in addr_list:
            try:
                mem.seek(int(addr, 16))
                if mem.read(value_width) == new_value:
                    new_addr_list.append(addr)
            except OSError:
                continue
                    
    return new_addr_list

def watch_value(addr: str, value_width: int) -> bytes:
    with open("/proc/"+pid+"/mem", "rb") as mem:
            try:
                mem.seek(int(addr, 16))
                return mem.read(value_width)
            except OSError:
                assert False, "Don't know how to deal yet."

def watch_str(addr: str, value_width: int) -> str:
    b_value = watch_value(addr, value_width)
    return b_value.decode("utf-8")

def watch_int(addr: str) -> int:
    b_value = watch_value(addr, 4)
    return int.from_bytes(b_value, "little", signed=True)

def watch_uint(addr: str) -> int:
    b_value = watch_value(addr, 4)
    return int.from_bytes(b_value, "little")

def watch_int64(addr: str) -> int:
    b_value = watch_value(addr, 8)
    return int.from_bytes(b_value, "little", signed=True)

def watch_uint64(addr: str) -> int:
    b_value = watch_value(addr, 8)
    return int.from_bytes(b_value, "little")

def watch_float(addr: str) -> float:
    b_value = watch_value(addr, 4)
    return struct.unpack("<f", b_value)[0]

def watch_double(addr: str) -> float:
    b_value = watch_value(addr, 8)
    return struct.unpack("<d", b_value)[0]

def list_addr(addr_list: list[str]):
    if addr_list:
        for addr in enumerate(addr_list):
            print(f"[{addr[0]}] find it at {addr[1]}.")
    else:
        print("not found.", file=sys.stderr)

def modify_target(target_list: list[str], new_value: bytes):
    with open("/proc/"+pid+"/mem", "rb+") as mem:
        for addr in target_list:
            try:
                mem.seek(int(addr, 16))
                mem.write(new_value)
            except OSError:
                continue
            
def modify_str(target_list: list[str], mod_value: str):
    b_value = bytes(mod_value, "utf-8")
    return modify_target(target_list, b_value)

def modify_int(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(4, "little", signed=True)
    return modify_target(target_list, b_value)

def modify_uint(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(4, "little")
    return modify_target(target_list, b_value)

def modify_int64(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(8, "little", signed=True)
    return modify_target(target_list, b_value)

def modify_uint64(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(8, "little")
    return modify_target(target_list, b_value)

def modify_float(target_list: list[str], mod_value: float):
    b_value = struct.pack("<f", mod_value)
    return modify_target(target_list, b_value)

def modify_double(target_list: list[str], mod_value: float):
    b_value = struct.pack("<d", mod_value)
    return modify_target(target_list, b_value)

# TODO: 手动清理一些临时变量, 清理不会带出分支的变量
def parse_command(pid, addr_maps):
    ori_value  = None
    addr_list  = []
    value_type = "string"
    ori_value_width = 0
    
    while True:
        try:
            command = input("> ").split()
        except EOFError:
            print("\nexit."); sys.exit(0)
        except KeyboardInterrupt:
            print("\nexit."); sys.exit(0)

        if not command:
            continue
            
        elif command[0] == "list":
            list_addr(addr_list)

        elif command[0] == "help":
            print("HELP MESSAGE:")
            print("- string: \tSearch string value in memory.")
            print("- int: \t\tSearch signed 4 bytes int number value in memory.")
            print("- uint: \tSearch unsigned 4 bytes int number value in memory.")
            print("- int64: \tSearch signed 8 bytes int number value in memory.")
            print("- uint64: \tSearch unsigned 8 bytes int number value in memory.")
            print("- float: \tSearch 4 bytes float number value in memory.")
            print("- double: \tSearch 8 bytes float number value in memory.")
            print("- again: \tSearch value again. It accepts 0 arg for search original value or 1 arg for search a new value with same type.")
            print("- set: \t\tModify value(s) which was/were search command.")
            print("- list: \tList the address(es) which was/were found in search command.")
            print("- watch: \tView values in the addresses list. Accepts no arguments to view all list values, or a number to view a specific value. You can monitor values in real time by appending a `[/[time]]` parameter (default: 2 seconds).")
            print("- delete: \tDelete the `number` addr of list.")
            print("- help: \tPrint this message.")
            
        elif command[0] == "again":
            if len(command) == 1:
                command.append(ori_value)
            match value_type:
                case "string":
                    new_value  = bytes(" ".join(command[1:]), "utf-8")
                    value_tyep = "string"
                    ori_value_width  = len(new_value)
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = new_value.decode("utf-8")
                case "int":
                    if len(command) > 2: print("`int` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(4, "little", signed=True)
                    value_type = "int"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = int.from_bytes(new_value, "little", signed=True)
                case "uint":
                    if len(command) > 2: print("`uint` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(4, "little")
                    value_type = "uint"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = int.from_bytes(new_value, "little")
                case "int64":
                    if len(command) > 2: print("`int64` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(8, "little", signed=True)
                    value_type = "int64"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = int.from_bytes(new_value, "little", signed=True)
                case "uint64":
                    if len(command) > 2: print("`uint64` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(8, "little")
                    value_type = "uint64"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = int.from_bytes(new_value, "little")
                case "float":
                    if len(command) > 2: print("`float` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = struct.pack("<f", float(command[1]))
                    value_type = "float"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = struct.unpack("<f", new_value)[0]
                case "double":
                    if len(command) > 2: print("`double` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = struct.pack("<d", float(command[1]))
                    value_type = "double"
                    addr_list  = find_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = struct.unpack("<d", new_value)[0]
                case _:
                    DEBUG(f"again `{value_type}` have not achieved.",
                          "Here should not be arrived.")
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
                    if len(bytes(mod_value, "utf-8")) > ori_value_width:
                        print("Length of string value should not be longer than original.", file=sys.stderr)
                        continue
                    modify_str(addr_list, mod_value)
                case "int":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`int` type must accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > MAX_INT32 or mod_value < -MAX_INT32:
                        print("`int` type do not accept a num value more than 4 bytes, please use `int64`.", file=sys.stderr)
                        continue
                    modify_int(addr_list, mod_value)
                case "uint":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`uint` type must accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > MAX_UINT32 or mod_value < 0:
                        print("`uint` type do not accept a num value more than 4 bytes, please use `uint64`. Or negative num value for int", file=sys.stderr)
                        continue
                    modify_uint(addr_list, mod_value)
                case "int64":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`int64` type must accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > MAX_INT64 or mod_value < -MAX_INT64:
                        print("`int64` tyep do not accept a num value more than 8 bytes.", file=sys.stderr)
                        continue
                    modify_int64(addr_list, mod_value)
                case "uint64":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`uint64` type must accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > MAX_UINT64 or mod_value < 0:
                        print("`uint64` type do not accept a num value more than 8 bytes or negative num value.", file=sys.stderr)
                        continue
                    modify_uint64(addr_list, mod_value)
                case "float":
                    try:
                        mod_value = float(command[1])
                    except ValueError:
                        print("`float` type must accept a num value.", file=sys.stderr)
                        continue
                    if (mod_value > MAX_FLOAT32
                        or mod_value < -MAX_FLOAT32
                        or -MIN_FLOAT32 < mod_value < 0
                        or 0 < mod_value < MIN_FLOAT32):
                        print("`float` type do not accept a num value more than 4 bytes.", file=sys.stderr)
                        continue
                    modify_float(addr_list, mod_value)
                case "double":
                    try:
                        mod_value = float(command[1])
                    except ValueError:
                        print("`double` type must accept a num value.", file=sys.stderr)
                        continue
                    if (mod_value > MAX_FLOAT64
                        or mod_value < -MAX_FLOAT64
                        or -MIN_FLOAT64 < mod_value < 0
                        or 0 < mod_value < MIN_FLOAT64):
                        print("`double` type do not accept a num value more than 8 bytes.", file=sys.stderr)
                        continue
                    modify_double(addr_list, mod_value)
                case _:
                    DEBUG(f"set `{value_type}` have not achieved.",
                          "Here should not be arrived.")

        elif command[0] == "string":
            if len(command) < 2:
                print("`string` command must accept 1 str argument.", file=sys.stderr)
                continue
            ori_value  = " ".join(command[1:])
            value_type = "string"
            ori_value_width = len(bytes(ori_value, "utf-8"))
            addr_list  = find_str(addr_maps, ori_value)
            list_addr(addr_list)
            
        elif command[0] == "int":
            if len(command) != 2:
                print("`int` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`int` command must accept a num value.", file=sys.stderr)
                continue
            if ori_value > MAX_INT32 or ori_value < -MAX_INT32:
                print("`int` command do not accept a num value more than 4 bytes, please use `int64`.", file=sys.stderr)
                continue
            value_type = "int"
            ori_value_width = 4
            addr_list  = find_int(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "uint":
            if len(command) != 2:
                print("`uint` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`uint` command must accept a num value.", file=sys.stderr)
                continue
            if ori_value > MAX_UINT32 or ori_value < 0:
                print("`uint` command do not accept a num value more than 4 bytes, please use `uint64`. Or negative num value for int", file=sys.stderr)
                continue
            value_type = "uint"
            ori_value_width = 4
            addr_list  = find_uint(addr_maps, ori_value)
            list_addr(addr_list)
                
        elif command[0] == "int64":
            if len(command) != 2:
                print("`int64` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`int64` command must accept a num value.", file=sys.stderr)
                continue
            if ori_value > MAX_INT64 or ori_value < -MAX_INT64:
                print("`int64` command do not accept a num value more than 8 bytes.", file=sys.stderr)
                continue
            value_type = "int64"
            ori_value_width = 8
            addr_list  = find_int64(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "uint64":
            if len(command) != 2:
                print("`uint64` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`uint64` command must accept a num value.", file=sys.stderr)
                continue
            if ori_value > MAX_UINT64 or ori_value < 0:
                print("`uint64` command do not accept a num value more than 8 bytes or negative num value.", file=sys.stderr)
                continue
            value_type = "uint64"
            ori_value_width = 8
            addr_list  = find_uint64(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "float":
            if len(command) != 2:
                print("`float` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = float(command[1])
            except ValueError:
                print("`float` command must accept a num value.", file=sys.stderr)
                continue
            if (ori_value > MAX_FLOAT32
                or ori_value < -MAX_FLOAT32
                or -MIN_FLOAT32 < ori_value < 0
                or 0 < ori_value < MIN_FLOAT32):
                print("`float` command do not accept a num value more than 4 bytes.", file=sys.stderr)
                continue
            value_type = "float"
            ori_value_width = 4
            addr_list  = find_float(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "double":
            if len(command) != 2:
                print("`double` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = float(command[1])
            except ValueError:
                print("`double` command must accept a num value.", file=sys.stderr)
                continue
            if (ori_value > MAX_FLOAT64
                or ori_value < -MAX_FLOAT64
                or -MIN_FLOAT64 < ori_value < 0
                or 0 < ori_value < MIN_FLOAT64):
                print("`double` command do not accept a num value more than 8 bytes.", file=sys.stderr)
                continue
            value_type = "double"
            ori_value_width = 8
            addr_list  = find_double(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "watch":
            if not addr_list:
                print("Please use search command to search value first.", file=sys.stderr)
                continue
            temp_addr_list = list(enumerate(addr_list))
            refresh = False
            refresh_time = 2
            if len(command) == 2:
                watch_arg_value = command[1].split("/")
                # watch 1 || watch 1/ || watch /78 || watch /
                def __get_single_addr():
                    try:
                        number = int(watch_arg_value[0])
                    except ValueError:
                        print("`watch` must accept a number in the list.", file=sys.stderr)
                        return
                    if number > len(addr_list) - 1 or number < 0:
                        print(f"{number} is out of addr_list, use `list` to checkout.", file=sys.stderr)
                        return
                    return [(number, addr_list[number]),]
                if len(watch_arg_value) == 1:
                    if not (temp_addr_list := __get_single_addr()): continue
                elif len(watch_arg_value) == 2:
                    refresh = True
                    if watch_arg_value[0]:
                        if not (temp_addr_list := __get_single_addr()): continue
                    if watch_arg_value[1]:
                        try:
                            refresh_time = int(watch_arg_value[1])
                        except ValueError:
                            print("refresh time of `watch` must accept a num value.", file=sys.stderr)
                            continue
                        if refresh_time < 0:
                            print(f"refresh time of `watch` should not be negative.", file=sys.stderr)
                            continue
                else:
                    print("`watch` get too much args. Please checkout.", file=sys.stderr)
                    continue
            elif len(command) > 2:
                print("`watch` get too much args. Please checkout.", file=sys.stderr)
                continue
            def __refresher(func):
                def wrapper():
                    while True:
                        try:
                            func()
                            if not refresh: break
                            time.sleep(refresh_time)
                        except KeyboardInterrupt:
                            print()
                            break
                return wrapper
            # __string_refresher = __refresher(__string_refresher) -> wrapper
            # __string_refresher() -> wrapper() ->...func()...
            match value_type:
                case "string":
                    @__refresher
                    def __string_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_str(addr[1], ori_value_width)}")
                    __string_refresher()
                case "int":
                    @__refresher
                    def __int_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_int(addr[1])}")
                    __int_refresher()
                case "uint":
                    @__refresher
                    def __uint_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_uint(addr[1])}")
                    __uint_refresher()
                case "int64":
                    @__refresher
                    def __int64_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_int64(addr[1])}")
                    __int64_refresher()
                case "uint64":
                    @__refresher
                    def __uint64_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_uint64(addr[1])}")
                    __uint64_refresher()
                case "float":
                    @__refresher
                    def __float_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_float(addr[1])}")
                    __float_refresher()
                case "double":
                    @__refresher
                    def __double_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_double(addr[1])}")
                    __double_refresher()
                case _:
                    DEBUG(f"`{value_type}` have not achieved.",
                              "Here should not be arrived.")
            del temp_addr_list    
            
        elif command[0] == "delete":
            if len(command) != 2:
                print("`delete` command must accept 1 argv.", file=sys.stderr)
                continue
            try:
                temp_addr_number = int(command[1])
            except ValueError:
                print("`delete` command must accept a number in the list.", file=sys.stderr)
                continue
            if temp_addr_number > len(addr_list) - 1 or temp_addr_number < 0:
                print(f"{temp_addr_number} is out of addr_list, use `list` to checkout.", file=sys.stderr)
                continue
            print(f"[{temp_addr_number}] {addr_list.pop(temp_addr_number)} has been deleted.")
            del temp_addr_number

        else:
            DEBUG(f"`{command[0]}` have not achieved.",
                  "UnkownCommand. Please input `string/int` to find data or `set` to modify value.")

if __name__ == "__main__":
    assert len(sys.argv) == 2, "Script need a pid as argv."
    pid       = sys.argv[1]
    addr_maps = get_maps(pid)
    for addr_map in addr_maps:
        print(f"Scaned {addr_map}.")
    parse_command(pid, addr_maps)
