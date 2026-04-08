#!/usr/bin/env python3

import sys
import time
import readline
import struct
import subprocess
import signal
from collections.abc import Callable
from typing import Any, Iterator

DEBUG_V = True
if DEBUG_V:
    def DEBUG(debug_warning: str, run_warning: str):
        assert False, debug_warning
else:
    def DEBUG(debug_warning: str, run_warning: str):
        print(run_warning, file=sys.stderr)

ALIGN   = True

FAILURE = False
SUCCESS = True
MAX_I8 = (1 << 7) - 1
MAX_U8 = (1 << 8) - 1
MAX_I16 = (1 << 15) - 1
MAX_U16 = (1 << 16) - 1
MAX_I32 = (1 << 31) - 1
MAX_U32 = (1 << 32) - 1
MAX_I64 = (1 << 63) - 1
MAX_U64 = (1 << 64) - 1
MAX_F32 = (2 - 2**(-23)) * (2 ** 127)
MIN_F32 = 2 ** -126
MAX_F64 = sys.float_info.max
MIN_F64 = sys.float_info.min
EPS32   = 1e-3
EPS64   = 1e-15

class __float(float):
    def __new__(cls, value, ex_type = "f32"):
        if ex_type not in ("f32", "f64"):
            raise TypeError("__float required `f32/f64` for second argv only.")
        obj = super().__new__(cls, value)
        obj.ex_type = ex_type
        return obj
    def __eq__(self, other):
        if isinstance(other, (float, int, self)):
            if self.ex_type == "f32":
                return abs(self - other) < EPS32
            elif self.ex_type == "f64":
                return abs(self - other) < EPS64
            else:
                return False
        else:
            return False

class __str(str):
    def __gt__(self, other):
        return self != other
    def __lt__(self, other):
        return self != other

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
            
def __bytes_search(buf: bytes, step: int, value: bytes) -> Iterator[int]:
    if ALIGN:
        for off in range(0, len(buf), step):
            if buf[off:off+step] == value:
                yield off
    else:
        offset = 0
        while True:
            off = buf.find(value, offset)
            if off == -1: break
            offset = off + step
            yield off

def search_target(addr_maps: list[tuple[int, int]], target_value: bytes, step: int) -> list[str]:
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
                continue
            addrs = map(lambda x: hex(start + x), __bytes_search(buf, step, target_value))
            addr_list.extend(list(addrs))
    return addr_list

def __bytes_trans(value_type: str, b_value: bytes) -> Any:
    normal_value: Any
    match value_type:
        case "str":
            normal_value = b_value.decode("utf-8")
        case "i8":
            normal_value = int.from_bytes(b_value, "little", signed=True)
        case "u8":
            normal_value = int.from_bytes(b_value, "little")
        case "i16":
            normal_value = int.from_bytes(b_value, "little", signed=True)
        case "u16":
            normal_value = int.from_bytes(b_value, "little")
        case "i32":
            normal_value = int.from_bytes(b_value, "little", signed=True)
        case "u32":
            normal_value = int.from_bytes(b_value, "little")
        case "i64":
            normal_value = int.from_bytes(b_value, "little", signed=True)
        case "u64":
            normal_value = int.from_bytes(b_value, "little")
        case "f32":
            normal_value = struct.unpack("<f", b_value)[0]
        case "f64":
            normal_value = struct.unpack("<d", b_value)[0]
    return normal_value
    
def search_cond(pid: str, value_info: dict, new_value: Any, op: Callable) -> list[str]:
    new_addr_list = []
    with open("/proc/"+pid+"/mem", "rb") as mem:
        for addr in value_info["addr_list"]:
            try:
                mem.seek(int(addr, 16))
                mem_value = __bytes_trans(value_info["type"], mem.read(value_info["width"]))
                if op(mem_value, new_value):
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
            
def print_help():
    help_message = [
        "HELP MESSAGE:",
        "- help: \tPrint help message.",
        "- sh cmd: \tRun a shell command temporarily.",
        "- type [i8|i16|i32|i64|u8|u16|u32|u64|f32|f64|str]`:",
        "\t\tSet the value type for search (default: `i32`).",
        "- str|num: \tSearch for the specified `str/num` value. Repeating is equivalent to using `=`.",
        "- = [str|num]: \tSearch again using the last search result. No argument means search for the original value; a new `str/num` argument means search for the new value of the same type.",
        "- >/< [str|num]:Search for values greater/less than the specified `num`. No argument means search relative to the original value. For `str`, these commands function the same as `!=`.",
        "- !=: \t\tSearch for values not equal to the specified `str/num`. No argument means search relative to the original value.",
        "- +/- [num]: \tSearch for values by adding or subtracting `num`. If no argument is provided, the behavior is the same as `>/<`. Not allowed for strings.",
        "- reset: \tReset the search results.",
        "- list: \tList all addresses found by search commands.",
        "- watch [[number][/[time]]]:",
        "\t\tView values in the address list. No argument: view all values; a number: view the specified value. Append `/[time]` for real-time monitoring (default interval: 2 seconds).",
        "- delete number:Delete the address at the specified index in the list.",
        "- align on|off: Toggle align mode (default: on).",
        "- status: \tShow current type, target value and align mode.",
        "- set value[/[time]]:",
        "\t\tModify values in the address list. Append `/[time]` for continuous modification (default interval: 1 second).",
    ]

    for line in help_message:
        print(line)

def run_sh(command):
    try:
        temp_sh = subprocess.Popen(command[1:])
        temp_sh.wait()
    except KeyboardInterrupt:
        temp_sh.send_signal(signal.SIGINT)
        temp_sh.wait()
        print()

def __trans_int(argv: str | __str, mes: str) -> int|bool:
    try:
        value = int(argv)
    except ValueError:
        print(mes, file=sys.stderr)
        return FAILURE
    return value

def __trans_float(argv: str | __str, mes: str, ex_type = "f32") -> __float|bool:
    try:
        value = __float(argv, ex_type)
    except ValueError:
        print(mes, file=sys.stderr)
        return FAILURE
    return value

def __auto_trans_value(value_type: str, ori_value: str | __str) -> Any:
    value: Any = ori_value
    match value_type:
        case "i8" | "i16" | "i32" | "i64" | "u8" | "u16" | "u32" | "u64":
            value = __trans_int(ori_value, f"`{value_type}` requires a non-negative numeric value.")
            if value is FAILURE:
                return FAILURE
        case "f32" | "f64":
            value = __trans_float(ori_value, f"`{value_type}` requires a non-negative numeric value.", value_type)
            if value is FAILURE:
                return FAILURE
        case "str":
            pass
        case _:
            DEBUG("type" + ori_value + "have not achived.",
                  "Here should not be arrived.")
            return FAILURE
    return value

def __auto_trans_ori(ori_value_info: dict) -> bool:
    check_value: Any
    match ori_value_info["type"]:
        case "i8" | "i16" | "i32" | "i64" | "u8" | "u16" | "u32" | "u64":
            check_value = __trans_int(ori_value_info["value"], "Unknown command. Please use `help` to check.")
            if check_value is FAILURE:
                return FAILURE
            ori_value_info["value"] = check_value
        case "f32" | "f64":
            check_value = __trans_float(ori_value_info["value"], "Unknown command. Please use `help` to check.", ori_value_info["type"])
            if check_value is FAILURE:
                return FAILURE
            ori_value_info["value"] = check_value
        case "str":
            pass
        case _:
            assert False, "Here should not be arrived."
    return SUCCESS

def __trans_bytes(value_type: str, value: Any) -> bytes:
    match value_type:
        case "str":
            b_value = bytes(value, "utf-8")
        case "i8":
            b_value = value.to_bytes(1, "little", signed=True)
        case "u8":
            b_value = value.to_bytes(1, "little")
        case "i16":
            b_value = value.to_bytes(2, "little", signed=True)
        case "u16":
            b_value = value.to_bytes(2, "little")
        case "i32":
            b_value = value.to_bytes(4, "little", signed=True)
        case "u32":
            b_value = value.to_bytes(4, "little")
        case "i64":
            b_value = value.to_bytes(8, "little", signed=True)
        case "u64":
            b_value = value.to_bytes(8, "little")
        case "f32":
            b_value = struct.pack("<f", value)
        case "f64":
            b_value = struct.pack("<d", value)
        case _:
            assert False, "Here should not be arrived."
    return b_value

def __check_lenght(token: str, command: list[str]) -> bool:
    if len(command) != 2:
        print(f"`{token}` requires exactly 1 argument.", file=sys.stderr)
        return FAILURE
    else:
        return SUCCESS

SEARCH_TYPE = ["str", "i8", "u8", "u16", "i16", "i32", "i64", "u32", "u64", "f32", "f64"]
def parse_search(ori_value_info: dict) -> bool:
    if __auto_trans_ori(ori_value_info) is FAILURE:
        return FAILURE
    target_value = __trans_bytes(ori_value_info["type"], ori_value_info["value"])
    match ori_value_info["type"]:
        case "str":
            print("`str` type must use align mode; automatically switching to align mode.")
            global ALIGN; ALIGN = False
            ori_value_info["width"] = len(bytes(ori_value_info["value"], "utf-8"))
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, ori_value_info["width"])
        case "i8":
            if ori_value_info["value"] > MAX_I8 or ori_value_info["value"] < -MAX_I8:
                print("`i8` only supports 1-byte values. Use `i16` for larger values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 1
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 1)
        case "u8":
            if ori_value_info["value"] > MAX_U8 or ori_value_info["value"] < 0:
                print("`u8` only supports 1-byte values. Use `u16` for larger values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 1
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 1)
        case "i16":
            if ori_value_info["value"] > MAX_I16 or ori_value_info["value"] < -MAX_I16:
                print("`i16` only supports 2-byte values. Use `i32` for larger values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 2
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 2)
        case "u16":
            if ori_value_info["value"] > MAX_I16 or ori_value_info["value"] < 0:
                print("`u16` only supports 2-byte values. Use `u32` for larger values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 2
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 2)
        case "i32":
            if ori_value_info["value"] > MAX_I32 or ori_value_info["value"] < -MAX_I32:
                print("`i32` only supports 4-byte values. Use `i64` for larger values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 4
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 4)
        case "u32":
            if ori_value_info["value"] > MAX_U32 or ori_value_info["value"] < 0:
                print("`u32` only supports 4-byte non-negative values. Use `i64/u64` for larger values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 4
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 4)
        case "i64":
            if ori_value_info["value"] > MAX_I64 or ori_value_info["value"] < -MAX_I64:
                print("`i64` only supports 8-byte values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 8
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 8)
        case "u64":
            if ori_value_info["value"] > MAX_U64 or ori_value_info["value"] < 0:
                print("`u64` only supports 8-byte non-negative values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 8
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 8)
        case "f32":
            if (ori_value_info["value"] > MAX_F32 or ori_value_info["value"] < -MAX_F32
                or -MIN_F32 < ori_value_info["value"] < 0 or 0 < ori_value_info["value"] < MIN_F32):
                print("`f32` only supports 4-byte values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 4
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 4)
        case "f64":
            if (ori_value_info["value"] > MAX_F64 or ori_value_info["value"] < -MAX_F64
                or -MIN_F64 < ori_value_info["value"] < 0 or 0 < ori_value_info["value"] < MIN_F64):
                print("`f64` only supports 8-byte values.", file=sys.stderr)
                return FAILURE
            ori_value_info["width"] = 8
            ori_value_info["addr_list"]  = search_target(addr_maps, target_value, 8)
        case _:
            DEBUG("Here should not be arrived.",
                  "Here should not be arrived.")
            return FAILURE
    return SUCCESS

def parse_cond(ori_value_info: dict, command: list[str], op: Callable) -> bool:
    if command[0] not in ["+", "-"]:
        if (new_value := __auto_trans_value(ori_value_info["type"], command[1])) is FAILURE:
            return FAILURE
    else:
        new_value = ori_value_info["value"]
    if ori_value_info["type"] == "str":
        if command[0] not in ["+", "-"]:
            ori_value_info["value"] = new_value = __str(" ".join(command[1:]))
            ori_value_info["width"] = len(new_value)
            ori_value_info["addr_list"] = search_cond(pid, ori_value_info, new_value, op)
        else:
            print("`str` type do not accept '+/-' oprator.", file=sys.stderr)
            return FAILURE
    elif ori_value_info["type"] in SEARCH_TYPE[1:]:
        ori_value_info["addr_list"] = search_cond(pid, ori_value_info, new_value, op)
    else:
        DEBUG(f"{op} `{ori_value_info["value_type"]}` have not achieved.",
              "Here should not be arrived.")
        return FAILURE
    return SUCCESS

def __refresher(refresh: bool, refresh_time: float):
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
    if not ori_value_info["addr_list"]:
        print("Please search a value first.", file=sys.stderr)
        return FAILURE
    ord_addr_list: list[tuple[int, str]]|bool = list(enumerate(ori_value_info["addr_list"]))
    refresh = False
    refresh_time = 2.0
    if len(command) == 2:
        watch_arg_value = command[1].split("/")
        # watch 1 || watch 1/ || watch /78 || watch /
        def __get_single_addr() -> list[tuple[int, str]]|bool:
            if (number := __trans_int(watch_arg_value[0], "`watch` must receive a number from the list.")) is FAILURE:
              return FAILURE
            if number > len(ori_value_info["addr_list"]) - 1 or number < 0:
                print(f"{number} is out of range. Use `list` to check valid values.", file=sys.stderr)
                return FAILURE
            return [(number, ori_value_info["addr_list"][number]),]
        if len(watch_arg_value) == 1:
            if not (ord_addr_list := __get_single_addr()): return FAILURE
        elif len(watch_arg_value) == 2:
            refresh = True
            if watch_arg_value[0]:
                if not (ord_addr_list := __get_single_addr()): return FAILURE
            if watch_arg_value[1]:
                if (refresh_time := __trans_float(watch_arg_value[1],
                                                  "Refresh time for `watch` requires a non-negative numeric value.")) is FAILURE:
                    return FAILURE
                if refresh_time < 0:
                    print("Refresh time for `watch` requires a non-negative numeric value.", file=sys.stderr)
                    return FAILURE
        else:
            print("`watch` received too many arguments. Please check.", file=sys.stderr)
            return FAILURE
    elif len(command) > 2:
        print("`watch` received too many arguments. Please check.", file=sys.stderr)
        return FAILURE
    # __refresher(refresh, refresh_time) -> wrapper
    # __str_refresher = wrapper(__str_refresher) -> inner
    # __str_refresher() -> inner()
    match ori_value_info["type"]:
        case "str":
            @__refresher(refresh, refresh_time)
            def __str_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], ori_value_info["width"])
                    if (value := __bytes_trans("str", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __str_refresher()
        case "i8":
            @__refresher(refresh, refresh_time)
            def __i8_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 1)
                    if (value := __bytes_trans("i8", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __i8_refresher()
        case "u8":
            @__refresher(refresh, refresh_time)
            def __u8_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 1)
                    if (value := __bytes_trans("u8", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __u8_refresher()
        case "i16":
            @__refresher(refresh, refresh_time)
            def __i16_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 2)
                    if (value := __bytes_trans("i16", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __i16_refresher()
        case "u16":
            @__refresher(refresh, refresh_time)
            def __u16_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 2)
                    if (value := __bytes_trans("u16", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __u16_refresher()
        case "i32":
            @__refresher(refresh, refresh_time)
            def __i32_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 4)
                    if (value := __bytes_trans("i32", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __i32_refresher()
        case "u32":
            @__refresher(refresh, refresh_time)
            def __u32_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 4)
                    if (value := __bytes_trans("u32", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __u32_refresher()
        case "i64":
            @__refresher(refresh, refresh_time)
            def __i64_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 8)
                    if (value := __bytes_trans("i64", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __i64_refresher()
        case "u64":
            @__refresher(refresh, refresh_time)
            def __u64_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 8)
                    if (value := __bytes_trans("u64", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __u64_refresher()
        case "f32":
            @__refresher(refresh, refresh_time)
            def __f32_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 4)
                    if (value := __bytes_trans("f32", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __f32_refresher()
        case "f64":
            @__refresher(refresh, refresh_time)
            def __f64_refresher():
                for addr in ord_addr_list:
                    b_value = watch_value(addr[1], 8)
                    if (value := __bytes_trans("f64", b_value)) is FAILURE:
                        return FAILURE
                    print(f"[{addr[0]}] {addr[1]}: {value}")
            __f64_refresher()
        case _:
            DEBUG("`" + ori_value_info["type"] + "` have not achieved.",
                      "Here should not be arrived.")
    return SUCCESS

def parse_delete(ori_value_info: dict, command: list[str]) -> bool:
    if __check_lenght("delete", command) is FAILURE:
        return FAILURE
    if (number := __trans_int(command[1], "`delete` must receive a number from the list.")) is FAILURE:
        return FAILURE
    if number > len(ori_value_info["addr_list"]) - 1 or number < 0:
        print(f"{number} is out of range. Use `list` to check valid values.", file=sys.stderr)
        return FAILURE
    print(f"[{number}]" + ori_value_info["addr_list"].pop(number) +" has been deleted.")
    return SUCCESS

def parse_set(ori_value_info: dict, command: list[str]) -> bool:
    if not ori_value_info["addr_list"]:
        print("Please search a value first.", file=sys.stderr)
        return FAILURE
    if len(command) < 2:
        print("`set` requires a value.", file=sys.stderr)
        return FAILURE
    set_arg_value = " ".join(command[1:]).split("/")
    refresh = False
    refresh_time = 1.0
    if len(set_arg_value) == 2:
        refresh = True
        if set_arg_value[1]:
            if (refresh_time := __trans_float(set_arg_value[1],
                                                  "Refresh time for `set` requires a non-negative numeric value.")) is FAILURE:
                return FAILURE
    elif len(set_arg_value) > 2:
        print("`set` received too many arguments. Please check.", file=sys.stderr)
        return FAILURE
    if __check_lenght(ori_value_info["type"], command) is FAILURE and ori_value_info["type"] != "str":
        return FAILURE
    if (mod_value := __auto_trans_value(ori_value_info["type"], set_arg_value[0])) is FAILURE:
        return FAILURE
    match ori_value_info["type"]:
        case "str":
            mod_value = set_arg_value[0]
            if len(bytes(mod_value, "utf-8")) > ori_value_info["width"]:
                print("String length must not exceed the original length.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_str():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_str()
        case "i8":
            if mod_value > MAX_I8 or mod_value < -MAX_I8:
                print("`i8` only supports 1-byte values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_i8():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_i8()
        case "u8":
            if mod_value > MAX_U8 or mod_value < 0:
                print("`u8` only supports 1-byte values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_u8():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_u8()
        case "i16":
            if mod_value > MAX_I16 or mod_value < -MAX_I16:
                print("`i16` only supports 2-byte values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_i16():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_i16()
        case "u16":
            if mod_value > MAX_U16 or mod_value < 0:
                print("`u16` only supports 2-byte values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_u16():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_u16()
        case "i32":
            if mod_value > MAX_I32 or mod_value < -MAX_I32:
                print("`i32` only supports 4-byte values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_i32():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_i32()
        case "u32":
            if mod_value > MAX_U32 or mod_value < 0:
                print("`u32` only supports 4-byte non-negative values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_u32():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_u32()
        case "i64":
            if mod_value > MAX_I64 or mod_value < -MAX_I64:
                print("`i64` only supports 8-byte values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_i64():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_i64()
        case "u64":
            if mod_value > MAX_U64 or mod_value < 0:
                print("`i64` only supports 8-byte non-negative values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_u64():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_u64()
        case "f32":
            if (mod_value > MAX_F32 or mod_value < -MAX_F32
                or -MIN_F32 < mod_value < 0 or 0 < mod_value < MIN_F32):
                print("`f32` only supports 4-byte values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_f32():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_f32()
        case "f64":
            if (mod_value > MAX_F64 or mod_value < -MAX_F64
                or -MIN_F64 < mod_value < 0 or 0 < mod_value < MIN_F64):
                print("`f64` only supports 8-byte values.", file=sys.stderr)
                return FAILURE
            b_value = __trans_bytes(ori_value_info["type"], mod_value)
            @__refresher(refresh, refresh_time)
            def __modify_f64():
                modify_target(ori_value_info["addr_list"], b_value)
                print(f"Set value to {mod_value}")
            __modify_f64()
        case _:
            DEBUG(f"set `" + ori_value_info["type"] + "` have not achieved.",
                  "Here should not be arrived.")
            return FAILURE

    ori_value_info["value"] = mod_value
    return SUCCESS

def parse_command(pid, addr_maps):
    ori_value_info = {
        "value" : None,
        "type"  : "i32",
        "width" : 0,
        "addr_list" : [],
    }
    global ALIGN
    
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
            if len(command) > 1:
                print("`list` does not need an argument.", file=sys.stderr)
                continue
            list_addr(ori_value_info["addr_list"])

        elif command[0] == "help":
            if len(command) > 1:
                print("`help` does not need an argument.", file=sys.stderr)
                continue
            print_help()

        elif command[0] == "sh":
            if len(command) < 2:
                print("`sh` must accept a command.", file=sys.stderr)
                continue
            run_sh(command)

        elif command[0] == "type":
            if command[1] in SEARCH_TYPE:
                ori_value_info["type"]  = command[1]
                ori_value_info["value"] = None
                ori_value_info["width"] = 0
                ori_value_info["addr_list"] = []
            else:
                DEBUG(f"`{command[1]}` have not achived.",
                      f"Unknown type `{command[1]}`. Valid types: i32, i64, u32, u64, f32, f64, str.")

                # TODO: 令其支持首次搜索
        elif command[0] in ["=", "!=", "<", ">", "+", "-"]:
            if not ori_value_info["addr_list"]:
                DEBUG(f"`{command[0]}` search for first time have not be achived.",
                      "Please search a value first.")
                continue
            if len(command) > 2 and ori_value_info["type"] != "str":
                print("`" + ori_value_info["type"] + "`" + " requires exactly 0 or 1 argument.", file=sys.stderr)
                continue
            if len(command) == 1:
                command.append(ori_value_info["value"])
                match command[0]:
                    case "=":
                        if parse_cond(ori_value_info, command, lambda x,y: x == y) is FAILURE:
                            continue
                    case "!=":
                        if parse_cond(ori_value_info, command, lambda x,y: x != y) is FAILURE:
                            continue
                    case "<" | "-":
                        if parse_cond(ori_value_info, command, lambda x,y: x < y) is FAILURE:
                            continue
                    case ">" | "+":
                        if parse_cond(ori_value_info, command, lambda x,y: x > y) is FAILURE:
                            continue
            elif len(command) == 2:
                if (cond_value := __auto_trans_value(ori_value_info["type"], command[1])) is FAILURE:
                    continue
                match command[0]:
                    case "=":
                        if parse_cond(ori_value_info, command, lambda x,y: x == y) is FAILURE:
                            continue
                    case "!=":
                        if parse_cond(ori_value_info, command, lambda x,y: x != y) is FAILURE:
                            continue
                    case "<":
                        if parse_cond(ori_value_info, command, lambda x,y: x < y) is FAILURE:
                            continue
                    case ">":
                        if parse_cond(ori_value_info, command, lambda x,y: x > y) is FAILURE:
                            continue
                    case "+":
                        if parse_cond(ori_value_info, command, lambda x,y: x == y + cond_value) is FAILURE:
                            continue
                        ori_value_info["value"] += cond_value
                    case "-":
                        if parse_cond(ori_value_info, command, lambda x,y: x == y - cond_value) is FAILURE:
                            continue
                        ori_value_info["value"] -= cond_value
            else:
                print(f"`{command[0]}` do not allow to accept so much value.", file=sys.stderr)
            list_addr(ori_value_info["addr_list"])


        elif command[0] == "set":
            if parse_set(ori_value_info, command) is FAILURE:
                continue

        elif command[0] == "watch":
            if parse_watch(ori_value_info, command) is FAILURE:
                continue

        elif command[0] == "delete":
            if parse_delete(ori_value_info ,command) is FAILURE:
                continue

        elif command[0] == "reset":
            ori_value_info["value"] = None
            ori_value_info["addr_list"] = []

        elif command[0] == "align":
            if len(command) != 2:
                print("`align` requires exactly 2 argument. Valid value: on or off.")
                continue
            if command[1] == "on":
                ALIGN = True
            elif command[1] == "off":
                ALIGN = False
            else:
                print("`align` only accept `on` or `off`.")
                continue

        elif command[0] == "status":
            if len(command) > 1:
                print("`status` does not need an argument.")
                continue
            print(f"type: \t{ori_value_info['type']}\n"
                  f"value:\t{ori_value_info['value']}")
            if ALIGN: print(f"align:\ton")
            else: print(f"align:\toff")

        else:
            if len(command) > 1 and ori_value_info["type"] != "str":
                DEBUG(f"{command[0]} have not achived.",
                      "Unknown command. Please use `help` to check.")
                continue
            temp_value_info = ori_value_info.copy()
            temp_value_info["value"] = __str(" ".join(command))
            if __auto_trans_ori(temp_value_info) is FAILURE:
                del temp_value_info
                continue
            ori_value_info = temp_value_info
            if not ori_value_info["addr_list"]:
                parse_search(ori_value_info)
            else:
                if parse_cond(ori_value_info, ["=", command[0]], lambda x,y: x == y) is FAILURE:
                    continue
            list_addr(ori_value_info["addr_list"])
            
if __name__ == "__main__":
    assert len(sys.argv) == 2, "Script requires a PID argument."
    pid       = sys.argv[1]
    addr_maps = get_maps(pid)
    for addr_map in addr_maps:
        print(f"Scaned {addr_map}.")
    parse_command(pid, addr_maps)
