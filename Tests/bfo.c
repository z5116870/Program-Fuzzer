#include <stdio.h>
#include <stdlib.h>

//Testing for buffer overflow
void vuln() {
  char buf[64];
  setbuf(stdout, NULL);
  gets(buf);
}

int main(int argc, char **argv) { vuln(); }