# mem_scan
A simple memory scan program in python.  
Built on the Linux virtual memory system, the program implements its core functions by parsing `/proc/[pid]/maps` and `/proc/[pid]/mem`. It currently only supports data widths compatible with C programs.  
It supports search command like `int`/`str` to locate addresses. The non-search command rely on the preceding search command to determine data type, which is recorded during the first search. Specially, the search command - `again` also depends on preceding explicit search command.

## Feature
* [ ] memscan-like commands
* [ ] choose align
* [x] find and modify str
* [ ] find and modify i8/i16
* [ ] find and modify u8/u16
* [x] find and modify i32/i64
* [x] find and modify u32/u64
* [x] find and modify f32/f64
* [x] search many times
* [ ] condition search
* [x] delete addr
* [x] check value
* [x] modify value continuously
* [x] monitor value continuously
* [x] support shell command

## Command

`help`: Print help massage.  
`sh cmd`: Run a shell command temply.  
`str str_value`: Search `str` value in memory.  
`i32 num_value`: Search signed `num32` value in memory.  
`u32 num_value`: Search unsigned `num32` value in memory.  
`i64 num_value`: Search signed `num64` value in memory.  
`u64 num_value`: Search unsigned `num64` value in memory.  
`f32 num_value`: Search `float32` value in memory.  
`f64 num_value`: Search `float64` value in memory.  
`again [str|num]`: Search a value again by last type of search.It accepts 0 arg to search original value or a new value in same type to search again.  
`list`: List the addresses found in search command.  
`watch [[number][/[time]]]`: View values in the addresses list. Accepts no arguments to view all list values, or a number to view a specific value. You can monitor values in real time by appending a `[/[time]]` parameter (default: 2 seconds).  
`delete number`: Delete the `number` addr of list.  
`set value[/[time]]`: Modify values in the addresses list. You can modify values continuously by appending a `[/[time]]` parameter (default: 1 seconds).  

## Example

Open two session and run follow command:

```bash
$ ./test/test.out
2101.hello, world. Here is 8926518
2102.hello, world. Here is 8926518
2103.hello, foold. Here is 8926518
2104.hello, foold. Here is 8926518
2105.hello, foold. Here is 123
2106.hello, foold. Here is 123
...
```

```bash
# ./scanmem $(test1.out) 
> str hello
find it at 0x...
find it at 0x...
find it at 0x...
> set foo
> i32 8926518
find it at 0x...
find it at 0x...
find it at 0x...
> set 123
```
