#include <unistd.h>

int main(int argc, char const *argv[])
{
  access(argv[0], X_OK);
}
