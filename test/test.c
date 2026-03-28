#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int main()
{
  
  int i = 2101; const unsigned int j = 2147483649; const int k = -189223; const uint64_t m= 8589934592;
  const int64_t n = -7234567890; const double foo = 1.7382948908;
  while (1) {
    ++i;
    printf("%d.string: hello, world."
	   "unsigned int is %u."
	   "signed int is %d."
	   "uint64 is %llu."
	   "int64 is %lld."
	   "double is %f\n",
	   i, j, k, m, n, foo);
    sleep(2);
  }
  
  return 0;
}
