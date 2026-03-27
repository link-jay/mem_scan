#include <stdio.h>
#include <unistd.h>

int main()
{
  
  int i = 2101; unsigned int j = 2147483649; const int k = -189223;
  while (1) {
    ++i;
    printf("%d.hello, world. unsigned int is %u. int is %d\n", i, j, k);
    sleep(2);
  }
  
  return 0;
}
