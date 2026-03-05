#include <stdio.h>
#include <unistd.h>

int main()
{
  
  while (1) {
    printf("%s\n", "hello, world");
    sleep(2);
  }
  
  return 0;
}
