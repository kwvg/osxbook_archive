all:
	cc ota.c 02_decompress.c -o ota.macOS -I./liblzma-master/src/liblzma/api/ -llzma -g2
linux:
	cc -DLINUX ota.c 02_decompress.c -o ota.ELF64 -I./liblzma-master/src/liblzma/api/ -llzma -g2

