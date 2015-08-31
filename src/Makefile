SOURCES=base64.cpp daemon.cpp fusecode.cpp lib.cpp \
		libnss3_crypt.cpp main.cpp misc.cpp

PROGS=bimeil

OBJECTS=base64.o daemon.o fusecode.o lib.o libnss3_crypt.o main.o misc.o

CPP=g++
CPPFLAGS=--std=c++1y -D_FILE_OFFSET_BITS=64
INCLUDES=-I/usr/include/nspr -I/usr/include/nss

LD=g++
LIBS=-lnss3 -lfuse -lrt -lpthread


bimeil: $(OBJECTS)
	$(LD) $(OBJECTS) -o bimeil $(LIBS)

.cpp.o:
	$(CPP) -c $(CPPFLAGS) $(INCLUDES) $< -o $@
