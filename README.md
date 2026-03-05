# Scanmem #

## Target ##
  * [x] find text
  * [x] modify text
  * [x] find data
  * [ ] modify data

## Example ##
Open two session and run follow command:

``` bash
$ ./a.out
hello, world
hello, world
hello, foold
hello, foold
...
```
``` bash
$ ./scanmem $(a.out) 
> string hello
find it at 0x...
find it at 0x...
find it at 0x...
> set foo
```

