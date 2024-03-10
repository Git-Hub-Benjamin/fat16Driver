#include <stdio.h>
#include <stdlib.h>

void testingFunction()
{
    int i = 0;
    int b = 1;

    if(b > i) goto here;
    int c = 10;
    int x = 100;



here:
    printf("%d\n", x);

    char* test = (char*)malloc(1);
    printf("%c-%d\n", *test, *test);
}

int main()
{
    testingFunction();


}
