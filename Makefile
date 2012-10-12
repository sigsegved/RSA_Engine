CXX=gcc

CFLAGS=-g -c 

BASEDIR=.

INC=-I$(BASEDIR)

OBJDIR=$(BASEDIR)

BINDIR=$(BASEDIR)

SRCDIR=$(BASEDIR)

LIBS= -lgmp -lm -lssl -lcrypto


RSA_OBJS=rsa.o\
		main.o\
		pem_der.o\
		x509.o\
		base64.o

GENRSA_OBJS = rsa.o\
		pem_der.o\
		base64.o\
		genrsa.o 

all : rsa genrsa 

rsa : $(RSA_OBJS) 
	$(CXX) -g -o $@ $^ $(INC) $(LIBS)
genrsa : $(GENRSA_OBJS) 
	$(CXX) -g -o $@ $^ $(INC) $(LIBS)
verify : $(VERIFY_OBJS) 
	$(CXX) -g -o $@ $^ $(INC) $(LIBS)
x509.o : x509.c
	$(CXX) $(CFLAGS) $(INC) $^
verify.o : verify.c
	$(CXX) $(CFLAGS) $(INC) $^
genrsa.o : genrsa.c
	$(CXX) $(CFLAGS) $(INC) $^
rsa.o : rsa.c
	$(CXX) $(CFLAGS) $(INC) $^
main.o : main.c
	$(CXX) $(CFLAGS) $(INC) $^
pem_der.o : pem_der.c
	$(CXX) $(CFLAGS) $(INC) $^
base64.o : base64.c
	$(CXX) $(CFLAGS) $(INC) $^
clean : 
	rm $(OBJDIR)/*.o
	rm genrsa
	rm rsa
