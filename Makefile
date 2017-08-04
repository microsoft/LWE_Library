####  Makefile for compilation on Linux  ####

CC=gcc
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCH=x64
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
endif

AR=ar rcs
RANLIB=ranlib
LN=ln -s

CFLAGS= -O3 -std=gnu11 -Wall -Wextra -march=native -DLINUX -D $(ARCHITECTURE)
LDFLAGS=-lm
INCLUDES=-Iinclude

ifeq "$(ARCH)" "x64" 
ifeq "$(USE_AVX2)" "FALSE"
else
CFLAGS += -DAVX2
endif
ifeq "$(AES_NI)" "FALSE"
CFLAGS += -DAES_DISABLE_NI
else
CFLAGS += -maes -msse2 -DAES_ENABLE_NI
endif
else
CFLAGS += -DAES_DISABLE_NI
endif

ifeq "$(USE_REFERENCE)" "TRUE" 
CFLAGS += -DREFERENCE
endif

.PHONY: all check clean prettyprint

all: links lib tests

objs/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) -c  $(CFLAGS) $(INCLUDES) $< -o $@

links:
	rm -rf include/frodo
	mkdir -p include/frodo
	$(LN) ../../src/aes/aes.h include/frodo
	$(LN) ../../src/frodo.h include/frodo
	$(LN) ../../src/frodo_macrify.h include/frodo
	$(LN) ../../src/kex.h include/frodo
	$(LN) ../../src/kex_lwe_frodo.h include/frodo
	$(LN) ../../src/random/rand.h include/frodo
	$(LN) ../../src/random/rand_urandom_aesctr/rand_urandom_aesctr.h include/frodo
	$(LN) ../../src/sha3/fips202.h include/frodo
	$(LN) ../../src/sha3/fips202x4.h include/frodo

# RAND_URANDOM_AESCTR
RAND_URANDOM_AESCTR_OBJS :=  $(addprefix objs/random/rand_urandom_aesctr/, rand_urandom_aesctr.o)
$(RAND_URANDOM_AESCTR_OBJS): src/random/rand_urandom_aesctr/rand_urandom_aesctr.h

# RAND
objs/random/rand.o: src/random/rand.h

# KEX_LWE_FRODO
KEX_LWE_FRODO_OBJS := $(addprefix objs/, lwe.o kex_lwe_frodo.o lwe_noise.o)
KEX_LWE_FRODO_HEADERS := $(addprefix src/, kex_lwe_frodo.h frodo_macrify.h)
$(KEX_LWE_FRODO_OBJS): $(KEX_LWE_FRODO_HEADERS)

# AES
AES_OBJS := $(addprefix objs/aes/, aes.o aes_c.o aes_ni.o)
AES_HEADERS := $(addprefix src/aes/, aes.h)
$(AES_OBJS): $(AES_HEADERS)

# SHAKE
SHAKE_OBJS := $(addprefix objs/sha3/, fips202.o)
SHAKE_HEADERS := $(addprefix src/sha3/, fips202.h)
$(SHAKE_OBJS): $(SHAKE_HEADERS)

# SHAKEx4
ifneq "$(ARCH)" "ARM"
SHAKEx4_OBJS := $(addprefix objs/sha3/, fips202x4.o keccak4x/KeccakP-1600-times4-SIMD256.o)
SHAKEx4_HEADERS := $(addprefix src/sha3/, fips202x4.h keccak4x/KeccakP-1600-times4-SnP.h)
$(SHAKEx4_OBJS): $(SHAKEx4_HEADERS)
endif

# KEX
objs/kex/kex.o: src/kex.h

RAND_OBJS := $(RAND_URANDOM_AESCTR_OBJS) $(RAND_URANDOM_CHACHA_OBJS) objs/random/rand.o

KEX_OBJS := $(KEX_LWE_FRODO_OBJS) objs/kex.o

lib: $(RAND_OBJS) $(KEX_OBJS) $(AES_OBJS) $(SHAKE_OBJS) $(SHAKEx4_OBJS)
	rm -f libfrodo.a
	$(AR) libfrodo.a $^
	$(RANLIB) libfrodo.a

tests: lib src/random/test_rand.c tests/test_kex.c src/aes/test_aes.c tests/ds_benchmark.h
	$(CC) $(CFLAGS) $(INCLUDES) -L. src/random/test_rand.c -lfrodo $(LDFLAGS) -o test_rand 
	$(CC) $(CFLAGS) $(INCLUDES) -L. tests/test_kex.c -lfrodo $(LDFLAGS) -o test_kex
	$(CC) $(CFLAGS) $(INCLUDES) -L. src/aes/test_aes.c -lfrodo $(LDFLAGS) -o test_aes

docs: links
	doxygen

check: links tests
	./test_kex
	./test_rand
	./test_aes

clean:
	rm -rf docs objs include
	rm -f test_rand test_kex test_aes libfrodo.a
	find . -name .DS_Store -type f -delete

prettyprint:
	astyle --style=java --indent=tab --pad-header --pad-oper --align-pointer=name --align-reference=name --suffix=none src/*.h src/*/*.h src/*/*.c
