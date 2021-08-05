#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Testing for known ints
//It allows users to pass in any number as the buffer index without checking
//Large indexs corrupt, while negative indexes have strange outputs
void vuln() {
    int storage[32];
    for(int i = 0; i < 32; i++){
        storage[i] = i;
    }
    int buffer_index;
    printf("What index would you like to read from my buffer? (0-31)\n");
    scanf("%d", &buffer_index);
    printf("%d is at index %d\n", storage[buffer_index], buffer_index);
}

int main(int argc, char **argv) { vuln(); }