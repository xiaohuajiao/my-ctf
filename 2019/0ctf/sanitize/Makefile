#this makefile is from http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/
DEPDIR := .d
OBJDIR := ./obj

CC = clang
CXX = clang++

CPPSRCS = $(wildcard *.cpp)
CSRCS = $(wildcard *.c)
SRCS = $(CPPSRCS) $(CSRCS)
OBJS = $(patsubst %.o, $(OBJDIR)/%.o, $(CPPSRCS:.cpp=.o) $(CSRCS:.c=.o))

$(shell mkdir -p $(DEPDIR) >/dev/null)
$(shell mkdir -p $(OBJDIR) >/dev/null)

DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td
H_INCLUDE = 
LIB_INCLUDE = 
LIBS = 
TARGET=sanitize

CFLAGS = $(H_INCLUDE) -Wall
CPPFLAGS = $(H_INCLUDE) -Wall -std=c++11
LDFLAGS = 
LINKER = clang

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(TARGET_ARCH) -c
COMPILE.cc = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

RELEASE_DIR = ./release/

all: $(TARGET)

test: $(TARGET)
test: CFLAGS += -DTEST -DDEBUG -fsanitize=address

debug: $(TARGET)
debug: CFLAGS += -DRELEASE -DDEBUG -fsanitize-coverage=trace-pc-guard
debug: LDFLAGS += -fsanitize=address

release: $(TARGET)
release: CFLAGS += -DRELEASE -fsanitize-coverage=trace-pc-guard
release: LDFLAGS += -s

.PHONY : clean 
$(TARGET): $(OBJS)
	$(LINKER) $(LIB_INCLUDE) $(LDFLAGS) -o $(@) $(^) $(LIBS)
	strip $(@)
	# python patch_for_server.py $(@)
	#chmod +x $(@).server
	cp $(@) $(RELEASE_DIR)
	cp description.txt $(RELEASE_DIR)
	tar zcf $(TARGET)_release.tar.gz $(RELEASE_DIR)

$(OBJDIR)/%.o : %.c
$(OBJDIR)/%.o : %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(OBJDIR)/%.o : %.cc
$(OBJDIR)/%.o : %.cc $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(OBJDIR)/%.o : %.cxx
$(OBJDIR)/%.o : %.cxx $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(OBJDIR)/%.o : %.cpp
$(OBJDIR)/%.o : %.cpp $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

clean:
	-rm $(OBJS)
	-rm $(TARGET)
	-rm -rf $(DEPDIR)
test:
	echo $(OBJS)
	
include $(wildcard $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS))))

