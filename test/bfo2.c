//Vulnerable code taken from wg6
#include <stdio.h>

#define header_size 8

int main() {
  char storage[32 + header_size] = {0};

  int len = 0;
  puts("How many chars would you like to store?");
  scanf("%d", &len);

  if (header_size + len > 32) {
    printf("no");
    return 1;
  }

  read(0, storage, len + header_size);
}
