#include <stdio.h>
#include <stdlib.h>

//Testing for program hang
//If pass in EOF, this will cause an infinite loop
void vuln() {
    char c = getchar();
    while(c != ' '){
      putchar(c);
      c = getchar();
  }
}

int main(int argc, char **argv) { vuln(); }