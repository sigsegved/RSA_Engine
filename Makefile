CXX=gcc

CFLAGS=-g -c 

BASEDIR=.

INC=-I$(BASEDIR)

OBJDIR=$(BASEDIR)

BINDIR=$(BASEDIR)

SRCDIR=$(BASEDIR)

LIBS= -lgmp


HELPER_OBJS=rsa.o

all : rsa

rsa : $(HELPER_OBJS) 
	$(CXX) -g -o $@ $(HELPER_OBJS) $(INC) $(LIBS)

rsa.o : rsa.c
	$(CXX) $(CFLAGS) $(INC) $^

clean : 
	rm $(OBJDIR)/*.o
	rm rsa
