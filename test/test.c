#include <stdio.h>
#include <unistd.h>

int main()
{
  
  int i = 2101; const int j = 8926518;
  while (1) {
    ++i;
    printf("%d.%s. Here is %d\n", i, "hello, world", j);
    sleep(2);
  }
  
  return 0;
}
