#include <stdio.h>
#include <stdlib.h>

void vuln() {
  char buf[64];
  setbuf(stdout, NULL);
  printf("This is almost exactly the same as jump...\n");
  gets(buf);
}

int main(int argc, char **argv) { vuln(); }