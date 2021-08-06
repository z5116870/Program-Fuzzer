#include <stdio.h>

int isOperand(char c) { 
    if(c >= '0' && c <= '9'){
        return 1;
    }
    return 0; 
}

int value(char c) {  
    return (c - '0'); 
}

int evaluate(char *exp)
{
    // Base Case: Given expression is empty
    if (*exp == '\0')  return -1;
 
    // The first character must be an operand, find its value
    int res = value(exp[0]);
 
    // Traverse the remaining characters in pairs
    for (int i = 1; exp[i]; i += 2)
    {
        // The next character must be an operator, and
        // next to next an operand
        char opr = exp[i], opd = exp[i+1];
 
        // If next to next character is not an operand
        if (!isOperand(opd))  return -1;
 
        // Update result according to the operator
        if (opr == '+')       res += value(opd);
        else if (opr == '-')  res -= value(opd);
        else if (opr == '*')  res *= value(opd);
        else if (opr == '/')  res /= value(opd);
 
        // If not a valid operator
        else                  return -1;
    }
    return res;
}

int main(void){
    char expr[256];
    scanf("%s", expr);
    int res = evaluate(expr);
    printf("%d\n", res);

    return 0;
}