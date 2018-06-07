IDIR=src/
MENTO_IDIR=src/mentohust_encryption
CC=gcc
CFLAGS=-I$(IDIR)
MENTO_CFLAGS=-I$(MENTO_IDIR) 

ODIR=src/obj
LDIR=

LIBS=-lpcap

_DEPS = eap_frames_operations.h construct_eap_frames.h init.h functions.h  
#DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_MENTO_DEPS = ampheck.h byte_order.h md5.h mento_md5.h rjripemd128.h rjmd5.h rjtiger.h rjsha1.h rjwhirlpool.h ustd.h mento_myfun.h mentohustV4.h 
MENTO_DEPS = $(patsubst %,$(MENTO_IDIR)/%,$(_MENTO_DEPS))

_OBJ = mento_md5.o rjtiger.o rjwhirlpool_sbox.o md5.o rjripemd128.o byte_order.o rjtiger_sbox.o mentohustV4.o rjsha1.o rjwhirlpool.o rjmd5.o mento_myfun.o eap_frames_operations.o init.o functions.o construct_eap_frames.o main.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: src/%.c $(DEPS)
	      $(CC) -c -o $@ $< $(CFLAGS) 

$(ODIR)/%.o: src/mentohust_encryption/%.c $(MENTO_DEPS)
		$(CC) -c -o $@ $< $(MENTO_CFLAGS) 
test.out: $(OBJ)
	      gcc -g -Wall -o $@ $^ $(LIBS)

.PHONY: clean

clean:
	      rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
