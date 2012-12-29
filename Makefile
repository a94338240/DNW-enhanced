FLAGS = $(shell pkg-config libusb-1.0 --cflags --libs)

all:
	gcc dnw-enhanced.c -O2 -Werror $(FLAGS) -o dnw-enhanced

clean:
	rm *.o dnw-enhanced *~
