# mem_scan
A simple memory scan program in python.  
Built on the Linux virtual memory system, the program implements its core functions by parsing `/proc/[pid]/maps` and `/proc/[pid]/mem`. It currently only supports data widths compatible with C programs.  
It supports search command like `int`/`string` to locate addresses. The non-search command rely on the preceding search command to determine data type, which is recorded during the first search. Specially, the search command - `again` also depends on preceding explicit search command.

## Feature

* [x] find text
* [x] modify text
* [x] find int32
* [x] modify int32
* [x] find int64
* [x] modify int64
* [x] find float32
* [x] modify float32
* [x] find float64
* [x] modify float64
* [x] search many times
* [ ] delete addr
* [x] check value
* [ ] modify value continuously
* [x] monitor value continueously
* [ ] support shell command

## Command

`help`: print help massage.  
`string str`: Search `str` value in memory.  
`int num`: Search signed `num32` value in memory.  
`uint num`: Search unsigned `num32` value in memory.  
`int64 num`: Search signed `num64` value in memory.  
`uint64 num`: Search unsigned `num64` value in memory.  
`float num`: Search `float32` value in memory.  
`double num`: Search `float64` value in memory.  
`again [str|num]`: Search a value again by last type of search.It accepts 0 arg to search original value or a new value in same type to search again.  
`list`: List the addresses found in search command.  
`watch [[number][/[time]]]`: View values in the addresses list. Accepts no arguments to view all list values, or a number to view a specific value. You can monitor values in real time by appending a `[/[time]]` parameter (default: 2 seconds).  
`set value`: modify the values in the `list`.  

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
> string hello
find it at 0x...
find it at 0x...
find it at 0x...
> set foo
> int 8926518
find it at 0x...
find it at 0x...
find it at 0x...
> set 123
```
