#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int main()
{
  
  int i = 2101; const unsigned int j = 2147483647; const int k = -189223; const uint64_t m= 8589934592;
  const int64_t n = -7234567890; const double foo = 1.7382948908; const float bar = 3.14156;
  while (1) {
    ++i;
    printf("%d.string: hello, world."
	   "unsigned int is %u."
	   "signed int is %d."
	   "uint64 is %llu."
	   "int64 is %lld."
	   "double is %.15f."
	   "float is %f.\n",
	   i, j, k, m, n, foo, bar);
    sleep(2);
  }
  
  return 0;
}
