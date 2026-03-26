# Scanmem

## Target

* [x] find text
* [x] modify text
* [x] find data
* [x] modify data
* [x] search many times

## Command

`help`: print help massage.  
`string str`: search for the `str` in memary.  
`int num`: search for the `num` in memary.  
`again [str|num]`: search `str/num` again by last type. It can also use with 0 args to search original value again.  
`list`: list the addresses that find in command `string/int`.  
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
