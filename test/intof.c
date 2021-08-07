//Referenced from https://www.securecoding.com
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vuln() {
    int *student_grades;
    unsigned int num_items;
    scanf("%d", &num_items);
    //Vulnerable integer overflow
    if(num_items > 0){
        student_grades = (int *)malloc(num_items * sizeof(int));

        for (unsigned int i = 0; i < num_items; i++){
            student_grades[i] = 0;
        }
    }

}

int main(int argc, char **argv) { vuln(); }