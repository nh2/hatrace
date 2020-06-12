#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    printf(
        "%9s => %d\n"
        "%9s => %d\n"
        "%9s => %d\n"
        "%9s => %d\n",
        "getuid()", getuid(),
        "getgid()", getgid(),
        "geteuid()", geteuid(),
        "getegid()", getegid()
    );

    return 0;
}