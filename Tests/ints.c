#include <stdio.h>
#include <stdlib.h>

//Testing for known ints
//It allows users to pass in any number as the buffer size without checking
//Not error checking if malloc succeeds
void vuln() {
    int buffer_size;
    printf("Enter a size for your buffer\n");
    scanf("%d", &buffer_size);
    printf("Returning you a buffer %d bytes large\n", buffer_size);
    int *buffer = (int *)malloc(buffer_size);
    for(int i = 0; i < buffer_size; i++){
        buffer[i] = 0;
        printf("Index %d: %d\n", i, buffer[i]);
    }
}

int main(int argc, char **argv) { vuln(); }