#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Testing for known ints
//It allows users to pass in any number as the buffer size without checking
//Not error checking if malloc succeeds
void vuln() {
    int buffer_size;
    printf("Enter a size for your buffer\n");
    scanf("%d", &buffer_size);
    printf("Returning you a buffer %d bytes large\n", buffer_size);
    int *buffer = (int *)malloc(buffer_size);
    memset(buffer, 0, buffer_size);
}

int main(int argc, char **argv) { vuln(); }