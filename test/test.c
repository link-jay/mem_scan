#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int main()
{
  
  int i = 2101;
  const int j = -189223;
  const unsigned int k = 2147483647;
  const int64_t m = -7234567890;
  const uint64_t n= 8589934592;
  const float foo = 3.14156;
  const double bar = 1.7382948908;
  
  while (1) {
    ++i;
    printf("[%d]\n"
	   "string: hello, world.\n"
	   "i32 is %d.\n"
	   "u32 is %u.\n"
	   "i64 is %lld.\n"
	   "u64 is %llu.\n"
	   "f32 is %f.\n"
	   "f64 is %.15f.\n"
	   "--------------------\n",
	   i, j, k, m, n, foo, bar);
    sleep(2);
  }
  
  return 0;
}
