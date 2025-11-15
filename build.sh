set -e

gcc main.c -o runner

nasm vm.asm -o vm
