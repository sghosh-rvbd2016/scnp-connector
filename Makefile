PROGRAM = scnp-connector
CXX = g++
CXXFLAGS = -Wall -std=c++0x -fno-exceptions -O3 -pthread
MNMP_CXX_FILES := $(wildcard mnmp/*.cc)
MNMP_OBJ_FILES := $(addprefix mnmp/,$(notdir $(MNMP_CXX_FILES:.cc=.o)))
BINDIR = /opt/npm/bin/flowlogging
ETCDIR = /etc/npm/flowlogging/ssl

all: $(PROGRAM)

install: $(PROGRAM) 
	mkdir -p $(BINDIR) 
	install -m 0755 $(PROGRAM) $(BINDIR) 
	mkdir -p $(ETCDIR)
	install -m 0400 ssl/mnmp.pem $(ETCDIR) 
	install -m 0644 ssl/*.0 $(ETCDIR) 
    
$(PROGRAM): mnmp netflowrelay.o udpserver.o $(wildcard *.hh) $(wildcard *.cc)
	$(CXX) $(CXXFLAGS) *.o mnmp/*.o -lstdc++ -lssl -lcrypto -lz -o $(PROGRAM) $(PROGRAM).cc	

mnmp: $(wildcard mnmp/*.hh) $(MNMP_CXX_FILES) $(MNMP_OBJ_FILES)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

mnmp/%.o: mnmp/%.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	$(RM) $(PROGRAM) mnmp/*.o *.o
