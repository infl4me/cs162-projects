#include <syscall.h>

int main(int, char* []);
void _start(int argc, char* argv[]);

void _start(int argc, char* argv[]) { soft_exit(main(argc, argv)); }
