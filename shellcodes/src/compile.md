# Linux Assembly Code (NASM)

Commpile the bind shell assembly code:

```sh
nasm -f elf32 linux_bind_tcp_elf32.asm && ld -m elf_i386 linux_bind_tcp_elf32.asm.o -o linux_bind_tcp_elf32
```

Compile the reverse shell assembly code:

```sh
nasm -f elf32 linux_reverse_tcp_elf32.asm && ld -m elf_i386 linux_reverse_tcp_elf32.o -o linux_reverse_tcp_elf32
```