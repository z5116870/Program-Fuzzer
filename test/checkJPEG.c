#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
    if(argc != 2){
        printf("Usage: ./checkJPEG file.jpeg\n");
        exit(1);
    }

    FILE* file = fopen(argv[1], "rb");
    if(file == NULL){
        printf("Error opening file %s\n", argv[1]);
        exit(1);
    }
    
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

    return 0;
}
