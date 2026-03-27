# mem_scan
A simple memory scan program in python.

## Target

* [x] find text
* [x] modify text
* [x] find int32
* [x] modify int32
* [x] find int64
* [x] modify int64
* [ ] find float32
* [ ] find float64
* [x] search many times

## Command

`help`: print help massage.  
`string str`: search for the `str` in memory.  
`int num`: search for the signed `num` in memory.  
`uint num`: search for the unsigned `num` in memory.  
`int64 num`: search for the signed `num64` in memory.  
`uint64 num`: search for the unsigned `num64` in memory.  
`again [str|num]`: search `str/num` again by last type. It can also use with 0 args to search original value again.  
`list`: list the addresses that find in search command.  
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
