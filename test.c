#include <stdio.h>
#include <unistd.h>

int main()
{
  int num    = 1234321;
  char buf[] = "hello, world"
  
  while (1) {
    printf("%d.%s", num, buf);
    sleep(2);
  }
  
  return 0;
}
