# mem_scan
A simple memory scan program in python.

## Target

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

## Command

`help`: print help massage.  
`string str`: Search `str` value in memory.  
`int num`: Search signed `num32` value in memory.  
`uint num`: Search unsigned `num32` value in memory.  
`int64 num`: Search signed `num64` value in memory.  
`uint64 num`: Search unsigned `num64` value in memory.  
`float num`: Search `float32` value in memory.  
`double num`: Search `float64` value in memory.  
`again [str|num]`: Search a value again by last type of search.It can accept 0 args to search original value.  
`list`: List the addresses found in search command.  
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
