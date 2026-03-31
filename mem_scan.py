#!/usr/bin/env python3

# TODO: 修缮反馈文本
import sys
import time
import readline
import struct
import subprocess
import signal
from typing import Any

DEBUG_V = False
def DEBUG(debug_warning: str, run_warning: str):
    if DEBUG_V:
        assert False, debug_warning
    else:
        print(run_warning, file=sys.stderr)

FAILURE = False
SUCCESS = True

MAX_I32 = (1 << 31) - 1
MAX_U32 = (1 << 32) - 1
MAX_I64 = (1 << 63) - 1
MAX_U64 = (1 << 64) - 1
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
            
# TODO: 尝试4/其他字节作为步长
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

def search_i32_again(pid: str, addr_list: list[str], new_value: int) -> list[str]:
    b_value = new_value.to_bytes(4, "little", signed=True)
    return search_again(pid, addr_list, b_value, 4)

def search_u32_again(pid: str, addr_list: list[str], new_value: int) -> list[str]:
    b_value = new_value.to_bytes(4, "little")
    return search_again(pid, addr_list, b_value, 4)

def search_i64_again(pid: str, addr_list: list[str], new_value: int) -> list[str]:
    b_value = new_value.to_bytes(8, "little", signed=True)
    return search_again(pid, addr_list, b_value, 8)

def search_u64_again(pid: str, addr_list: list[str], new_value: int) -> list[str]:
    b_value = new_value.to_bytes(8, "little")
    return search_again(pid, addr_list, b_value, 8)

def search_f32_again(pid: str, addr_list: list[str], new_value: float) -> list[str]:
    b_value = struct.pack("<f", new_value)
    return search_again(pid, addr_list, b_value, 4)

def search_f64_again(pid: str, addr_list: list[str], new_value: float) -> list[str]:
    b_value = struct.pack("<d", new_value)
    return search_again(pid, addr_list, b_value, 8)

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
        print("Not found.", file=sys.stderr)

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

def print_help():
    help_message = [
        "HELP MESSAGE:",
        "- str: \t\tSearch string value in memory.",
        "- i32: \t\tSearch signed 4 bytes int number value in memory.",
        "- u32: \t\tSearch unsigned 4 bytes int number value in memory.",
        "- i64: \t\tSearch signed 8 bytes int number value in memory.",
        "- u64: \t\tSearch unsigned 8 bytes int number value in memory.",
        "- f32: \t\tSearch 4 bytes float number value in memory.",
        "- f64: \t\tSearch 8 bytes float number value in memory.",
        "- again: \tSearch value again. It accepts 0 arg for search original value or 1 arg for search a new value with same type.",
        "- list: \tList the address(es) which was/were found in search command.",
        "- watch: \tView values in the addresses list. Accepts no arguments to view all list values, or a number to view a specific value. You can monitor values in real time by appending a `[/[time]]` parameter (default: 2 seconds).",
        "- delete: \tDelete the `number` addr of list.",
        "- set: \t\tModify values in the addresses list. You can modify values continuously by appending a `[/[time]]` parameter (default: 1 seconds).",
        "- sh:\t\tRun a shell command temply.",
        "- help: \tPrint this message.",
    ]
    for line in help_message:
        print(line)

def run_sh(command) -> bool:
    if len(command) < 2:
        print("`sh` must accept a command.", file=sys.stderr)
        return FAILURE
    try:
        temp_sh = subprocess.Popen(command[1:])
        temp_sh.wait()
    except KeyboardInterrupt:
        temp_sh.send_signal(signal.SIGINT)
        temp_sh.wait()
        print()
    return SUCCESS

def __trans_int(argv: str, exp: str) -> int|bool:
    try:
        value = int(argv)
    except ValueError:
        print(exp, file=sys.stderr)
        return FAILURE
    return value

def __trans_float(argv: str, exp: str) -> float|bool:
    try:
        value = float(argv)
    except ValueError:
        print(exp, file=sys.stderr)
        return FAILURE
    return value

def __check_lenght(v_type, command) -> bool:
    if len(command) != 2:
        print(f"`{v_type}` command must accept 1 num argument.", file=sys.stderr)
        return FAILURE
    else:
        return SUCCESS

SEARCH_COMMAND = ["str", "i32", "i64", "u32", "u64", "f32", "f64"]
def parse_search(ori_value_info: dict, command: list[str]) -> bool:
    ori_value: str|int|float = ori_value_info["value"]
    value_type: str = ori_value_info["type"]
    ori_value_width: int = ori_value_info["width"]
    addr_list: list[str] = ori_value_info["addr_list"]
    match command[0]:
        case "str":
            if len(command) < 2:
                print("`string` command must accept 1 str argument.", file=sys.stderr)
                return FAILURE
            ori_value  = " ".join(command[1:])
            value_type = "str"
            ori_value_width = len(bytes(ori_value, "utf-8"))
            addr_list  = search_str(addr_maps, ori_value)
        case "i32":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (ori_value := __trans_int(command[1], "`i32` command must accept a num value.")) and ori_value != 0:
                return FAILURE
            if ori_value > MAX_I32 or ori_value < -MAX_I32:
                print("`i32` command do not accept a num value more than 4 bytes, please use `i64`.", file=sys.stderr)
                return FAILURE
            value_type = "i32"
            ori_value_width = 4
            addr_list  = search_i32(addr_maps, ori_value)
        case "u32":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (ori_value := __trans_int(command[1], "`u32` command must accept a num value.")) and ori_value != 0:
                return FAILURE
            if ori_value > MAX_U32 or ori_value < 0:
                print("`u32` command do not accept a num value more than 4 bytes, please use `u64`. Or negative num value for int", file=sys.stderr)
                return FAILURE
            value_type = "u32"
            ori_value_width = 4
            addr_list  = search_u32(addr_maps, ori_value)
        case "i64":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (ori_value := __trans_int(command[1], "`i64` command must accept a num value.")) and ori_value != 0:
                return FAILURE
            if ori_value > MAX_I64 or ori_value < -MAX_I64:
                print("`i64` command do not accept a num value more than 8 bytes.", file=sys.stderr)
                return FAILURE
            value_type = "i64"
            ori_value_width = 8
            addr_list  = search_i64(addr_maps, ori_value)
        case "u64":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (ori_value := __trans_int(command[1], "`u64` command must accept a num value.")) and ori_value != 0:
                return FAILURE
            if ori_value > MAX_U64 or ori_value < 0:
                print("`u64` command do not accept a num value more than 8 bytes or negative num value.", file=sys.stderr)
                return FAILURE
            value_type = "u64"
            ori_value_width = 8
            addr_list  = search_u64(addr_maps, ori_value)
        case "f32":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (ori_value := __trans_float(command[1], "`f32` command must accept a num value.")) and ori_value != 0:
                return FAILURE
            if (ori_value > MAX_F32 or ori_value < -MAX_F32
                or -MIN_F32 < ori_value < 0 or 0 < ori_value < MIN_F32):
                print("`f32` command do not accept a num value more than 4 bytes.", file=sys.stderr)
                return FAILURE
            value_type = "f32"
            ori_value_width = 4
            addr_list  = search_f32(addr_maps, ori_value)
        case "f64":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (ori_value := __trans_float(command[1], "`f64` command must accept a num value.")) and ori_value != 0:
                return FAILURE
            if (ori_value > MAX_F64 or ori_value < -MAX_F64
                or -MIN_F64 < ori_value < 0 or 0 < ori_value < MIN_F64):
                print("`f64` command do not accept a num value more than 8 bytes.", file=sys.stderr)
                return FAILURE
            value_type = "f64"
            ori_value_width = 8
            addr_list  = search_f64(addr_maps, ori_value)
        case _:
            DEBUG(f"The `{command[0]}` have not achived.",
                  "Here should not be arrived.")
            return FAILURE
    ori_value_info["value"] = ori_value
    ori_value_info["type"] = value_type
    ori_value_info["width"] = ori_value_width
    ori_value_info["addr_list"] = addr_list
    return SUCCESS

def parse_again(ori_value_info: dict, command: list[str]) -> bool:
    ori_value: str|int|float = ori_value_info["value"]
    value_type: str = ori_value_info["type"]
    ori_value_width: int = ori_value_info["width"]
    addr_list: list[str] = ori_value_info["addr_list"]
    new_value: Any
    if len(command) == 1:
        command.append(str(ori_value))
    match value_type:
        case "str":
            ori_value = " ".join(command[1:])
            new_value = bytes(ori_value, "utf-8")
            ori_value_width  = len(new_value)
            addr_list = search_again(pid, addr_list, new_value, ori_value_width)
        case "i32":
            if len(command) > 2: print("`i32` type must accept 1 num argument.", file=sys.stderr)
            if not (new_value := __trans_int(command[1], "`i32` type must accept 1 num value.")):
                return FAILURE
            ori_value = new_value
            addr_list = search_i32_again(pid, addr_list, new_value)
        case "u32":
            if len(command) > 2: print("`u32` type must accept 1 num argument or none.", file=sys.stderr)
            if not (new_value := __trans_int(command[1], "`u32` type must accept 1 num value.")):
                return FAILURE
            ori_value = new_value
            addr_list = search_u32_again(pid, addr_list, new_value)
        case "i64":
            if len(command) > 2: print("`i64` type must accept 1 num argument or none.", file=sys.stderr)
            if not (new_value := __trans_int(command[1], "`i64` type must accept 1 num value.")):
                return FAILURE
            ori_value = new_value
            addr_list = search_i64_again(pid, addr_list, new_value)
        case "u64":
            if len(command) > 2: print("`u64` type must accept 1 num argument or none.", file=sys.stderr)
            if not (new_value := __trans_int(command[1], "`u64` type must accept 1 num value.")):
                return FAILURE
            ori_value = new_value
            addr_list = search_u64_again(pid, addr_list, new_value)
        case "f32":
            if len(command) > 2: print("`f32` type must accept 1 num argument or none.", file=sys.stderr)
            if not (new_value := __trans_float(command[1], "`f32` type must accept 1 num value.")):
                return FAILURE
            ori_value = new_value
            addr_list = search_f32_again(pid, addr_list, new_value)
        case "f64":
            if len(command) > 2: print("`f64` type must accept 1 num argument or none.", file=sys.stderr)
            if not (new_value := __trans_float(command[1], "`f64` type must accept 1 num value.")):
                return FAILURE
            ori_value = new_value
            addr_list = search_f64_again(pid, addr_list, new_value)
        case _:
            DEBUG(f"again `{value_type}` have not achieved.",
                  "Here should not be arrived.")
            return FAILURE
    ori_value_info["value"] = ori_value
    ori_value_info["type"] = value_type
    ori_value_info["width"] = ori_value_width
    ori_value_info["addr_list"] = addr_list
    return SUCCESS

def __refresher(refresh: bool, refresh_time: int):
    def wrapper(func):
        def inner():
            while True:
                try:
                    func()
                    if not refresh: break
                    time.sleep(refresh_time)
                except KeyboardInterrupt:
                    print(); break
        return inner
    return wrapper

def parse_watch(ori_value_info: dict, command: list[str]) -> bool:
    ori_value: str|int|float = ori_value_info["value"]
    value_type: str = ori_value_info["type"]
    ori_value_width: int = ori_value_info["width"]
    addr_list: list[str] = ori_value_info["addr_list"]
    if not addr_list:
        print("Please use search command to search value first.", file=sys.stderr)
        return FAILURE
    ord_addr_list: list[tuple[int, str]]|bool = list(enumerate(addr_list))
    refresh = False
    refresh_time = 2
    if len(command) == 2:
        watch_arg_value = command[1].split("/")
        # watch 1 || watch 1/ || watch /78 || watch /
        def __get_single_addr() -> list[tuple[int, str]]|bool:
            if (number := __trans_int(watch_arg_value[0], "`watch` must accept a number from the list.")):
                return FAILURE
            if number > len(addr_list) - 1 or number < 0:
                print(f"{number} is out of list, use `list` to checkout.", file=sys.stderr)
                return FAILURE
            return [(number, addr_list[number]),]
        if len(watch_arg_value) == 1:
            if not (ord_addr_list := __get_single_addr()): return FAILURE
        elif len(watch_arg_value) == 2:
            refresh = True
            if watch_arg_value[0]:
                if not (ord_addr_list := __get_single_addr()): return FAILURE
            if watch_arg_value[1]:
                if (refresh_time := __trans_int(watch_arg_value[1], "refresh time of `watch` must accept a num value.")):
                    return FAILURE
                if refresh_time < 0:
                    print(f"refresh time of `watch` should not be negative.", file=sys.stderr)
                    return FAILURE
        else:
            print("`watch` get too much args. Please checkout.", file=sys.stderr)
            return FAILURE
    elif len(command) > 2:
        print("`watch` get too much args. Please checkout.", file=sys.stderr)
        return FAILURE
    # __refresher(refresh, refresh_time) -> wrapper
    # __str_refresher = wrapper(__str_refresher) -> inner
    # __str_refresher() -> inner()
    match value_type:
        case "str":
            @__refresher(refresh, refresh_time)
            def __str_refresher():
                for addr in ord_addr_list:
                    print(f"[{addr[0]}] {addr[1]}: {watch_str(addr[1], ori_value_width)}")
            __str_refresher()
        case "i32":
            @__refresher(refresh, refresh_time)
            def __i32_refresher():
                for addr in ord_addr_list:
                    print(f"[{addr[0]}] {addr[1]}: {watch_i32(addr[1])}")
            __i32_refresher()
        case "u32":
            @__refresher(refresh, refresh_time)
            def __u32_refresher():
                for addr in ord_addr_list:
                    print(f"[{addr[0]}] {addr[1]}: {watch_u32(addr[1])}")
            __u32_refresher()
        case "i64":
            @__refresher(refresh, refresh_time)
            def __i64_refresher():
                for addr in ord_addr_list:
                    print(f"[{addr[0]}] {addr[1]}: {watch_i64(addr[1])}")
            __i64_refresher()
        case "u64":
            @__refresher(refresh, refresh_time)
            def __u64_refresher():
                for addr in ord_addr_list:
                    print(f"[{addr[0]}] {addr[1]}: {watch_u64(addr[1])}")
            __u64_refresher()
        case "f32":
            @__refresher(refresh, refresh_time)
            def __f32_refresher():
                for addr in ord_addr_list:
                    print(f"[{addr[0]}] {addr[1]}: {watch_f32(addr[1])}")
            __f32_refresher()
        case "f64":
            @__refresher(refresh, refresh_time)
            def __f64_refresher():
                for addr in ord_addr_list:
                    print(f"[{addr[0]}] {addr[1]}: {watch_f64(addr[1])}")
            __f64_refresher()
        case _:
            DEBUG(f"`{value_type}` have not achieved.",
                      "Here should not be arrived.")
    ori_value_info["value"] = ori_value
    ori_value_info["type"] = value_type
    ori_value_info["width"] = ori_value_width
    ori_value_info["addr_list"] = addr_list
    return SUCCESS

def parse_delete(ori_value_info: dict, command: list[str]) -> bool:
    ori_value: str|int|float = ori_value_info["value"]
    value_type: str = ori_value_info["type"]
    ori_value_width: int = ori_value_info["width"]
    addr_list: list[str] = ori_value_info["addr_list"]
    if len(command) != 2:
        print("`delete` command must accept 1 argv.", file=sys.stderr)
        return FAILURE
    if (number := __trans_int(command[1], "`delete` command must accept a number from the list.")):
        return FAILURE
    if number > len(addr_list) - 1 or number < 0:
        print(f"{number} is out of addr_list, use `list` to checkout.", file=sys.stderr)
        return FAILURE
    print(f"[{number}] {addr_list.pop(number)} has been deleted.")
    ori_value_info["value"] = ori_value
    ori_value_info["type"] = value_type
    ori_value_info["width"] = ori_value_width
    ori_value_info["addr_list"] = addr_list
    return SUCCESS

def parse_set(ori_value_info: dict, command: list[str]) -> bool:
    ori_value: str|int|float = ori_value_info["value"]
    value_type: str = ori_value_info["type"]
    ori_value_width: int = ori_value_info["width"]
    addr_list: list[str] = ori_value_info["addr_list"]
    mod_value: Any
    if not addr_list:
        print("Please use search command to search value first.", file=sys.stderr)
        return FAILURE
    if len(command) < 2:
        print("Please input a value to modify.", file=sys.stderr)
        return FAILURE
    set_arg_value = " ".join(command[1:]).split("/")
    refresh = False
    refresh_time = 1
    if len(set_arg_value) == 2:
        refresh = True
        if set_arg_value[1]:
            if not (refresh_time := __trans_int(set_arg_value[1], "Refresh_time must be a num value.")):
                return FAILURE
    elif len(set_arg_value) > 2:
        print("`set` get too much args. Please checkout.", file=sys.stderr)
        return FAILURE
    match value_type:
        case "str":
            mod_value = " ".join(command[1:])
            if len(bytes(mod_value, "utf-8")) > ori_value_width:
                print("Length of string value should not be longer than original.", file=sys.stderr)
                return FAILURE
            @__refresher(refresh, refresh_time)
            def __modify_str():
                modify_str(addr_list, mod_value)
                print(f"Set value to {mod_value}.")
            __modify_str()
        case "i32":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (mod_value := __trans_int(command[1], "`i32` type must accept a num value.")) and mod_value != 0:
                return FAILURE
            if mod_value > MAX_I32 or mod_value < -MAX_I32:
                print("`i32` type do not accept a num value more than 4 bytes, please use `i64`.", file=sys.stderr)
                return FAILURE
            @__refresher(refresh, refresh_time)
            def __modify_i32():
                modify_i32(addr_list, mod_value)
                print(f"Set value to {mod_value}")
            __modify_i32()
        case "u32":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (mod_value := __trans_int(command[1], "`u32` type must accept a num value.")) and mod_value != 0:
                return FAILURE
            if mod_value > MAX_I32 or mod_value < -MAX_I32:
                print("`i32` type do not accept a num value more than 4 bytes, please use `i64`.", file=sys.stderr)
                return FAILURE
            if mod_value > MAX_U32 or mod_value < 0:
                print("`u32` type do not accept a num value more than 4 bytes, please use `u64`. Or negative num value for i32", file=sys.stderr)
                return FAILURE
            @__refresher(refresh, refresh_time)
            def __modify_u32():
                modify_u32(addr_list, mod_value)
                print(f"Set value to {mod_value}")
            __modify_u32()
        case "i64":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (mod_value := __trans_int(command[1], "`i64` type must accept a num value.")) and mod_value != 0:
                return FAILURE
            if mod_value > MAX_I64 or mod_value < -MAX_I64:
                print("`i64` tyep do not accept a num value more than 8 bytes.", file=sys.stderr)
                return FAILURE
            @__refresher(refresh, refresh_time)
            def __modify_i64():
                modify_i64(addr_list, mod_value)
                print(f"Set value to {mod_value}")
            __modify_i64()
        case "u64":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (mod_value := __trans_int(command[1], "`u64` type must accept a num value.")) and mod_value != 0:
                return FAILURE
            if mod_value > MAX_U64 or mod_value < 0:
                print("`u64` type do not accept a num value more than 8 bytes or negative num value.", file=sys.stderr)
                return FAILURE
            @__refresher(refresh, refresh_time)
            def __modify_u64():
                print(f"Set value to {mod_value}")
            __modify_u64()
            modify_u64(addr_list, mod_value)
        case "f32":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (mod_value := __trans_float(command[1], "`f32` type must accept a num value.")) and mod_value != 0:
                return FAILURE
            if (mod_value > MAX_F32 or mod_value < -MAX_F32
                or -MIN_F32 < mod_value < 0 or 0 < mod_value < MIN_F32):
                print("`f32` type do not accept a num value more than 4 bytes.", file=sys.stderr)
                return FAILURE
            @__refresher(refresh, refresh_time)
            def __modify_f32():
                modify_f32(addr_list, mod_value)
                print(f"Set value to {mod_value}")
            __modify_f32()
        case "f64":
            if not __check_lenght(value_type, command):
                return FAILURE
            if not (mod_value := __trans_float(command[1], "`f32` type must accept a num value.")) and mod_value:
                return FAILURE
            if (mod_value > MAX_F64 or mod_value < -MAX_F64
                or -MIN_F64 < mod_value < 0 or 0 < mod_value < MIN_F64):
                print("`f64` type do not accept a num value more than 8 bytes.", file=sys.stderr)
                return FAILURE
            @__refresher(refresh, refresh_time)
            def __modify_f64():
                modify_f64(addr_list, mod_value)
                print(f"Set value to {mod_value}")
            __modify_f64()
        case _:
            DEBUG(f"set `{value_type}` have not achieved.",
                  "Here should not be arrived.")
            return FAILURE
    ori_value_info["value"] = ori_value
    ori_value_info["type"] = value_type
    ori_value_info["width"] = ori_value_width
    ori_value_info["addr_list"] = addr_list
    return SUCCESS

def parse_command(pid, addr_maps):
    ori_value_info = {
        "value" : None,
        "type"  : "str",
        "width" : 0,
        "addr_list" : [],
    }
    
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
            list_addr(ori_value_info["addr_list"])

        elif command[0] == "help":
            print_help()

        elif command[0] == "sh":
            if not run_sh(command):
                continue

        elif command[0] == "again":
            if not parse_again(ori_value_info, command):
                continue
            list_addr(ori_value_info["addr_list"])

        elif command[0] == "set":
            if not parse_set(ori_value_info, command):
                continue

        elif command[0] == "watch":
            if not parse_watch(ori_value_info, command):
                continue

        elif command[0] == "delete":
            if not parse_delete(ori_value_info ,command):
                continue

            # TODO: 省略类型搜索符，改用类型设置搜索
        elif command[0] in SEARCH_COMMAND:
            if not parse_search(ori_value_info, command):
                continue
            list_addr(ori_value_info["addr_list"])

        else:
            DEBUG(f"`{command[0]}` have not achieved.",
                  "UnkownCommand. Please input `str/i32` to search data or `set` to modify value.")

if __name__ == "__main__":
    assert len(sys.argv) == 2, "Script need a pid as argv."
    pid       = sys.argv[1]
    addr_maps = get_maps(pid)
    for addr_map in addr_maps:
        print(f"Scaned {addr_map}.")
    parse_command(pid, addr_maps)
