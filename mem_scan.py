#!/usr/bin/env python3

# TODO: 合并int类，float类操作
# TODO: 修缮反馈文本
import sys
import time
import readline
import struct
import subprocess
import signal

DEBUG_V = True
def DEBUG(debug_warning: str, run_warning: str):
    if DEBUG_V:
        assert False, debug_warning
    else:
        print(run_warning, file=sys.stderr)

MAX_I32   = (1 << 31) - 1
MAX_U32  = (1 << 32) - 1
MAX_I64   = (1 << 63) - 1
MAX_U64  = (1 << 64) - 1
MAX_F32 = (2 - 2**(-23)) * (2 ** 127)
MIN_F32 = 2 ** -126
MAX_F64 = sys.float_info.max
MIN_F64 = sys.float_info.min

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
            
def search_target(addr_maps: list[tuple[int, int]], target_value: bytes) -> list[str]:
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

def search_str(addr_maps: list[tuple[int, int]], target_value: str) -> list[str]:
    b_value = bytes(target_value, "utf-8")
    return search_target(addr_maps, b_value)

def search_i32(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(4, "little", signed=True)
    return search_target(addr_maps, b_value)

def search_u32(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(4, "little")
    return search_target(addr_maps, b_value)
    
def search_i64(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(8, "little", signed=True)
    return search_target(addr_maps, b_value)

def search_u64(addr_maps: list[tuple[int, int]], target_value: int) -> list[str]:
    b_value = target_value.to_bytes(8, "little")
    return search_target(addr_maps, b_value)

def search_f32(addr_maps: list[tuple[int, int]], target_value: float) -> list[str]:
    b_value = struct.pack("<f", target_value)
    return search_target(addr_maps, b_value)

def search_f64(addr_maps: list[tuple[int, int]], target_value: float) -> list[str]:
    b_value = struct.pack("<d", target_value)
    return search_target(addr_maps, b_value)

def search_again(pid: str, addr_list: list[str], new_value: bytes, value_width: int) -> list[str]:
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

def watch_i32(addr: str) -> int:
    b_value = watch_value(addr, 4)
    return int.from_bytes(b_value, "little", signed=True)

def watch_u32(addr: str) -> int:
    b_value = watch_value(addr, 4)
    return int.from_bytes(b_value, "little")

def watch_i64(addr: str) -> int:
    b_value = watch_value(addr, 8)
    return int.from_bytes(b_value, "little", signed=True)

def watch_u64(addr: str) -> int:
    b_value = watch_value(addr, 8)
    return int.from_bytes(b_value, "little")

def watch_f32(addr: str) -> float:
    b_value = watch_value(addr, 4)
    return struct.unpack("<f", b_value)[0]

def watch_f64(addr: str) -> float:
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

def modify_i32(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(4, "little", signed=True)
    return modify_target(target_list, b_value)

def modify_u32(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(4, "little")
    return modify_target(target_list, b_value)

def modify_i64(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(8, "little", signed=True)
    return modify_target(target_list, b_value)

def modify_u64(target_list: list[str], mod_value: int):
    b_value = mod_value.to_bytes(8, "little")
    return modify_target(target_list, b_value)

def modify_f32(target_list: list[str], mod_value: float):
    b_value = struct.pack("<f", mod_value)
    return modify_target(target_list, b_value)

def modify_f64(target_list: list[str], mod_value: float):
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
            print("- i32: \t\tSearch signed 4 bytes int number value in memory.")
            print("- u32: \tSearch unsigned 4 bytes int number value in memory.")
            print("- i64: \tSearch signed 8 bytes int number value in memory.")
            print("- u64: \tSearch unsigned 8 bytes int number value in memory.")
            print("- f32: \tSearch 4 bytes float number value in memory.")
            print("- f64: \tSearch 8 bytes float number value in memory.")
            print("- again: \tSearch value again. It accepts 0 arg for search original value or 1 arg for search a new value with same type.")
            print("- list: \tList the address(es) which was/were found in search command.")
            print("- watch: \tView values in the addresses list. Accepts no arguments to view all list values, or a number to view a specific value. You can monitor values in real time by appending a `[/[time]]` parameter (default: 2 seconds).")
            print("- delete: \tDelete the `number` addr of list.")
            print("- set: \t\tModify value(s) which was/were search command.")
            print("- sh:\t\tRun a shell command temply.")
            print("- help: \tPrint this message.")
            
        elif command[0] == "sh":
            if len(command) < 2:
                print("`sh` must accept a command.", file=sys.stderr)
                continue
            try:
                temp_p = subprocess.Popen(command[1:])
                temp_p.wait()
            except KeyboardInterrupt:
                temp_p.send_signal(signal.SIGINT)
                temp_p.wait()
                print()
            del temp_p

        elif command[0] == "again":
            if len(command) == 1:
                command.append(ori_value)
                # 抽离成各类型的单独函数
            match value_type:
                case "string":
                    new_value  = bytes(" ".join(command[1:]), "utf-8")
                    value_tyep = "string"
                    ori_value_width  = len(new_value)
                    addr_list  = search_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = new_value.decode("utf-8")
                case "i32":
                    if len(command) > 2: print("`i32` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(4, "little", signed=True)
                    value_type = "i32"
                    addr_list  = search_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = int.from_bytes(new_value, "little", signed=True)
                case "u32":
                    if len(command) > 2: print("`u32` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(4, "little")
                    value_type = "u32"
                    addr_list  = search_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = int.from_bytes(new_value, "little")
                case "i64":
                    if len(command) > 2: print("`i64` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(8, "little", signed=True)
                    value_type = "i64"
                    addr_list  = search_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = int.from_bytes(new_value, "little", signed=True)
                case "u64":
                    if len(command) > 2: print("`u64` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = int(command[1]).to_bytes(8, "little")
                    value_type = "u64"
                    addr_list  = search_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = int.from_bytes(new_value, "little")
                case "f32":
                    if len(command) > 2: print("`f32` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = struct.pack("<f", float(command[1]))
                    value_type = "f32"
                    addr_list  = search_again(pid, addr_list, new_value, ori_value_width)
                    ori_value  = struct.unpack("<f", new_value)[0]
                case "f64":
                    if len(command) > 2: print("`f64` type must accept 1 num argument or none.", file=sys.stderr)
                    new_value  = struct.pack("<d", float(command[1]))
                    value_type = "f64"
                    addr_list  = search_again(pid, addr_list, new_value, ori_value_width)
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
                case "i32":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`i32` type must accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > MAX_I32 or mod_value < -MAX_I32:
                        print("`i32` type do not accept a num value more than 4 bytes, please use `i64`.", file=sys.stderr)
                        continue
                    modify_i32(addr_list, mod_value)
                case "u32":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`u32` type must accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > MAX_U32 or mod_value < 0:
                        print("`u32` type do not accept a num value more than 4 bytes, please use `u64`. Or negative num value for i32", file=sys.stderr)
                        continue
                    modify_u32(addr_list, mod_value)
                case "i64":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`i64` type must accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > MAX_I64 or mod_value < -MAX_I64:
                        print("`i64` tyep do not accept a num value more than 8 bytes.", file=sys.stderr)
                        continue
                    modify_i64(addr_list, mod_value)
                case "u64":
                    try:
                        mod_value = int(command[1])
                    except ValueError:
                        print("`u64` type must accept a num value.", file=sys.stderr)
                        continue
                    if mod_value > MAX_U64 or mod_value < 0:
                        print("`u64` type do not accept a num value more than 8 bytes or negative num value.", file=sys.stderr)
                        continue
                    modify_u64(addr_list, mod_value)
                case "f32":
                    try:
                        mod_value = float(command[1])
                    except ValueError:
                        print("`f32` type must accept a num value.", file=sys.stderr)
                        continue
                    if (mod_value > MAX_F32
                        or mod_value < -MAX_F32
                        or -MIN_F32 < mod_value < 0
                        or 0 < mod_value < MIN_F32):
                        print("`f32` type do not accept a num value more than 4 bytes.", file=sys.stderr)
                        continue
                    modify_f32(addr_list, mod_value)
                case "f64":
                    try:
                        mod_value = float(command[1])
                    except ValueError:
                        print("`f64` type must accept a num value.", file=sys.stderr)
                        continue
                    if (mod_value > MAX_F64
                        or mod_value < -MAX_F64
                        or -MIN_F64 < mod_value < 0
                        or 0 < mod_value < MIN_F64):
                        print("`f64` type do not accept a num value more than 8 bytes.", file=sys.stderr)
                        continue
                    modify_f64(addr_list, mod_value)
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
            addr_list  = search_str(addr_maps, ori_value)
            list_addr(addr_list)
            
        elif command[0] == "i32":
            if len(command) != 2:
                print("`i32` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`i32` command must accept a num value.", file=sys.stderr)
                continue
            if ori_value > MAX_I32 or ori_value < -MAX_I32:
                print("`i32` command do not accept a num value more than 4 bytes, please use `i64`.", file=sys.stderr)
                continue
            value_type = "i32"
            ori_value_width = 4
            addr_list  = search_i32(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "u32":
            if len(command) != 2:
                print("`u32` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`u32` command must accept a num value.", file=sys.stderr)
                continue
            if ori_value > MAX_U32 or ori_value < 0:
                print("`u32` command do not accept a num value more than 4 bytes, please use `u64`. Or negative num value for int", file=sys.stderr)
                continue
            value_type = "u32"
            ori_value_width = 4
            addr_list  = search_u32(addr_maps, ori_value)
            list_addr(addr_list)
                
        elif command[0] == "i64":
            if len(command) != 2:
                print("`i64` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`i64` command must accept a num value.", file=sys.stderr)
                continue
            if ori_value > MAX_I64 or ori_value < -MAX_I64:
                print("`i64` command do not accept a num value more than 8 bytes.", file=sys.stderr)
                continue
            value_type = "i64"
            ori_value_width = 8
            addr_list  = search_i64(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "u64":
            if len(command) != 2:
                print("`u64` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = int(command[1])
            except ValueError:
                print("`u64` command must accept a num value.", file=sys.stderr)
                continue
            if ori_value > MAX_U64 or ori_value < 0:
                print("`u64` command do not accept a num value more than 8 bytes or negative num value.", file=sys.stderr)
                continue
            value_type = "u64"
            ori_value_width = 8
            addr_list  = search_u64(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "f32":
            if len(command) != 2:
                print("`f32` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = float(command[1])
            except ValueError:
                print("`f32` command must accept a num value.", file=sys.stderr)
                continue
            if (ori_value > MAX_F32
                or ori_value < -MAX_F32
                or -MIN_F32 < ori_value < 0
                or 0 < ori_value < MIN_F32):
                print("`f32` command do not accept a num value more than 4 bytes.", file=sys.stderr)
                continue
            value_type = "f32"
            ori_value_width = 4
            addr_list  = search_f32(addr_maps, ori_value)
            list_addr(addr_list)

        elif command[0] == "f64":
            if len(command) != 2:
                print("`f64` command must accept 1 num argument.", file=sys.stderr)
                continue
            try:
                ori_value = float(command[1])
            except ValueError:
                print("`f64` command must accept a num value.", file=sys.stderr)
                continue
            if (ori_value > MAX_F64
                or ori_value < -MAX_F64
                or -MIN_F64 < ori_value < 0
                or 0 < ori_value < MIN_F64):
                print("`f64` command do not accept a num value more than 8 bytes.", file=sys.stderr)
                continue
            value_type = "f64"
            ori_value_width = 8
            addr_list  = search_f64(addr_maps, ori_value)
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
                        print("`watch` must accept a number from the list.", file=sys.stderr)
                        return
                    if number > len(addr_list) - 1 or number < 0:
                        print(f"{number} is out of list, use `list` to checkout.", file=sys.stderr)
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
                case "i32":
                    @__refresher
                    def __i32_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_i32(addr[1])}")
                    __i32_refresher()
                case "u32":
                    @__refresher
                    def __u32_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_u32(addr[1])}")
                    __u32_refresher()
                case "i64":
                    @__refresher
                    def __i64_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_i64(addr[1])}")
                    __i64_refresher()
                case "u64":
                    @__refresher
                    def __u64_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_u64(addr[1])}")
                    __u64_refresher()
                case "f32":
                    @__refresher
                    def __f32_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_f32(addr[1])}")
                    __f32_refresher()
                case "f64":
                    @__refresher
                    def __f64_refresher():
                        for addr in temp_addr_list:
                            print(f"[{addr[0]}] {addr[1]}: {watch_f64(addr[1])}")
                    __f64_refresher()
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
                print("`delete` command must accept a number from the list.", file=sys.stderr)
                continue
            if temp_addr_number > len(addr_list) - 1 or temp_addr_number < 0:
                print(f"{temp_addr_number} is out of addr_list, use `list` to checkout.", file=sys.stderr)
                continue
            print(f"[{temp_addr_number}] {addr_list.pop(temp_addr_number)} has been deleted.")
            del temp_addr_number

        else:
            DEBUG(f"`{command[0]}` have not achieved.",
                  "UnkownCommand. Please input `string/i32` to search data or `set` to modify value.")

if __name__ == "__main__":
    assert len(sys.argv) == 2, "Script need a pid as argv."
    pid       = sys.argv[1]
    addr_maps = get_maps(pid)
    for addr_map in addr_maps:
        print(f"Scaned {addr_map}.")
    parse_command(pid, addr_maps)
