#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hash(char *input)
{
    long long p = 131;
    long long m;

    FILE *fp = fopen("modulus", "r");
    if (fp) {
        fscanf(fp, "%lld", &m);
        fclose(fp);
    }

    long long hashVal = 0;
    long long p_pow   = 1;
    for (int i = 0; i < 4; i++) {
        hashVal = (hashVal + (unsigned char)input[i] * p_pow) % m;
        p_pow   = (p_pow * p) % m;
    }
    return (int)hashVal;
}


int regcheck(char *password) {
    if (strlen(password) != 4)
        return 0;

    for (int i = 0; i < 4; i++) {
        char c = password[i];

        if (!((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z'))) {
            return 0;
            }
    }

    return 1;
}


int password_check(char *password){
    if(regcheck(password)== 0){
        printf("what did i tell you about the length and characters?\n");
        return 1;}
        FILE *fp = fopen("pass", "r");
        int whatevr;
        fscanf(fp, "%d\n", &whatevr);
        fclose(fp);
        if(hash(password) == whatevr){
            return 0;
        }
        else{
            return 1;
        }
}


int main(){
    char pass[21];
    printf("Enter password(4 letters ONLY not LESS not MORE): \n");
    scanf("%20s",&pass);

    if(password_check(pass) == 0){
        printf("correct password\n");
    }
    else{
        printf("wrong attempt try again later.\n");
        return 1;
    }

    printf("hi");


}
