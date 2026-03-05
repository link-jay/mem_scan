#include <stdio.h>
#include <unistd.h>

int main()
{
  int num = 1013;
  while (1) {
    for (int i = 0; i < 7; i++) {
      printf("%d\n", num);
      sleep(1);
    }
    num += 10;
  }
  
  return 0;
}
