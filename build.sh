set -e

gcc main.c -o runner

as vm.s -o vm.o
ld --oformat binary -N -e _start -Ttext 0x10000 -o vm vm.o
