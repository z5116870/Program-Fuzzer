#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void){
    FILE* file = fopen("jpeg1.jpg", "rb");
    fseek(file, 0, SEEK_END);
    unsigned long fileLen=ftell(file);
    char* file_data;
    rewind(file);
    file_data=malloc((fileLen)*sizeof(char));
    if (file_data == NULL){
        printf("Memory error"); exit (2);
    }
    int num_read=0;
    char s;
    while ((num_read = fread(&s, 1, 1, file))) {
        strncat(file_data,&s,1);
    }

    printf("file contents: %s", file_data);
    fclose(file);
}
