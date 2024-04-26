#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vuln()
{
    unsigned int tmp, 
		num, 
		res_one = 0xe0000020, 
		res_two = 0xe0000020;

    printf("> ");
    
    tmp = scanf("%d", &num);

    res_one = res_one + num;

	printf("Done!\n");

	printf("> ");

	tmp = scanf("%d", &num);

	res_two = res_two * num;

	printf("Done 2!");

    return 3;
}

int main(int argc, char* argv[]) 
{
    unsigned char a;

    a = 255;

    printf("%d\n", a);

    vuln();

    return 0;
 }
