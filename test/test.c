#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int main()
{
  
  int i = 2101; unsigned int j = 2147483649; const int k = -189223; const uint64_t m= 8589934592; 
  while (1) {
    ++i;
    printf("%d.string: hello, world."
	   "unsigned int is %u."
	   "signed int is %d."
	   "long int is %llu.\n",
	   i, j, k, m);
    sleep(2);
  }
  
  return 0;
}
