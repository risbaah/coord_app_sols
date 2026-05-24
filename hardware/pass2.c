#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PENALTY_SECONDS 5


int hash(char *input)
{
    long long p     = 131;
    long long m     = 1000000007LL;
    long long hashVal   = 0;
    long long p_pow = 1;
    for (int i = 0; i < 4; i++) {
        hashVal = (hashVal + (unsigned char)input[i] * p_pow) % m;
        p_pow   = (p_pow * p) % m;
    }
    return (int)hashVal;
}

int regcheck(char *password)
{
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

static time_t penalty_read(void)
{
    FILE *fp = fopen("penalty_ts", "r");
    if (!fp) return 0;
    time_t wha = 0;
    fread(&wha, sizeof(wha), 1, fp);
    fclose(fp);
    return wha;
}

static void penalty_write(void)
{
    FILE *fp = fopen("penalty_ts", "w");
    if (!fp) return;
    time_t wha = time(NULL);
    fwrite(&wha, sizeof(wha), 1, fp);
    fflush(fp);
    fclose(fp);
}

static int penalty_remaining(void)
{
    time_t wha  = penalty_read();
    if (wha == 0) return 0;
    double elapsed  = difftime(time(NULL), wha);
    if (elapsed < PENALTY_SECONDS)
        return (int)(PENALTY_SECONDS - elapsed);
    return 0;
}

int password_check(char *password)
{

    if (regcheck(password) == 0) {
        printf("what did i tell you about the length and characters?\n");
        int wait = penalty_remaining();
        if(wait>0){
            printf("wait %d second(s) before you try again and get it wrong again\n", wait);
            return 1;
        }
        penalty_write();
        return 1;
    }
    else{
    int wait = penalty_remaining();

    if (wait > 0) {
        printf("wait %d second(s) before you try again and get it wrong again\n", wait);
        return 1;
    }


    FILE *fp = fopen("pass", "r");
    int whatevr;
    fscanf(fp, "%d\n", &whatevr);
    fclose(fp);

    if (hash(password) == whatevr) {
        return 0;
    } else {
        penalty_write();
        printf("wrong pass wait 5 seconds before you try again\n");
        return 1;
    }
    }
}

int main()
{
    char pass[21];
    printf("Enter password(4 letters ONLY not LESS not MORE: \n");
    scanf("%20s", &pass);
    if (password_check(pass) == 0) {
        printf("correct password\n");
    }
    else{
        return 1;
    }

    printf("hi");
}
