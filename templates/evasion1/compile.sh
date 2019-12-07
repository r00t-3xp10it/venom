#/bin/bash
file=$1

if [[ $file ]]; then
	i686-w64-mingw32-gcc -c -O3 -march=i686 $file.c
	i686-w64-mingw32-gcc $file.o -o $file.exe -O3 -march=i686 -Wl,-lws2_32
	/usr/i686-w64-mingw32/bin/strip $file.exe
	cat $file.exe |base64 > $file.base
else
	echo "Must specify a file. Example: ./compile.sh test"
fi

