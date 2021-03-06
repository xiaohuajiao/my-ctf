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
TARGET=wasabi

CFLAGS = $(H_INCLUDE) -Wall -m32
CPPFLAGS = $(H_INCLUDE) -Wall -std=c++11 -m32
LDFLAGS = -m32
LINKER = clang++

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(TARGET_ARCH) -c
COMPILE.cc = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

RELEASE_DIR = ./release/

all: $(TARGET)

test: $(TARGET)
test: CFLAGS += -DDEBUG -fsanitize=address

debug: $(TARGET)
debug: CFLAGS += -g -DDEBUG  -DWASI
debug: CPPFLAGS += -g -DDEBUG -DWASI
debug: LDFLAGS += -g

release: $(TARGET)
release: CFLAGS += -DRELEASE -DWASI
release: CPPFLAGS += -DRELEASE -DWASI
release: LDFLAGS += -s

.PHONY : clean 
$(TARGET): $(OBJS)
	$(LINKER) $(LIB_INCLUDE) $(LDFLAGS) -o $(@) $(^) $(LIBS)
	python generate_step2.py $(TARGET)
	#strip $(@)
	# python patch_for_server.py $(@)
	#chmod +x $(@).server
	#cp $(@) $(RELEASE_DIR)
	#cp description.txt $(RELEASE_DIR)
	#tar zcf $(TARGET)_release.tar.gz $(RELEASE_DIR)

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
	-rm -rf $(OBJDIR)
	-rm $(TARGET)
	-rm -rf $(DEPDIR)
test:
	echo $(OBJS)
	
include $(wildcard $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS))))

