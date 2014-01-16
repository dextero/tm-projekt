# foldery
SOURCE_DIR=./src
#EXTLIBS_DIR=./extlibs
INTERMEDIATE_DIR=obj/release
INTERMEDIATE_DIR_DEBUG=obj/debug
INTERMEDIATE_DIR_PREPROCESSED=obj/preprocessed
INTERMEDIATE_DIR_TESTS=obj/tests
OUTPUT_DIR=bin
TESTS_DIR=tests

CC=gcc
DEBUG_MACROS=-D_DEBUG
RELEASE_MACROS=
MACROS=-DHAVE_TYPEOF
CCFLAGS=-pedantic -Wall -Wextra $(MACROS) -Wno-language-extension-token -Wno-variadic-macros
LIBDIRS=
LIBS=
INCLUDES=-I$(SOURCE_DIR)

###
# zalezne od systemu
###
OS=$(shell uname)

WINDOWS_LIBS=
WINDOWS_MACROS=-DPLATFORM_WIN32
WINDOWS_INCLUDES=
WINDOWS_LINKER_OPTIONS=

LINUX_LIBS=
LINUX_MACROS=-DPLATFORM_LINUX
LINUX_INCLUDES=
LINUX_LINKER_OPTIONS=

ifeq ($(OS), Linux)
	OS_DEPENDANT_CC_OPTIONS=$(LINUX_MACROS) $(LINUX_INCLUDES)
	OS_DEPENDANT_LD_OPTIONS=$(LINUX_LINKER_OPTIONS) $(LINUX_LIBS)
else
	OS_DEPENDANT_CC_OPTIONS=$(WINDOWS_MACROS) $(WINDOWS_INCLUDES)
	OS_DEPENDANT_LD_OPTIONS=$(WINDOWS_LINKER_OPTIONS) $(WINDOWS_LIBS)
endif

###
# nazwa wynikowego pliku wykonywalnego
###
OUTPUT=server
DEBUG_OUTPUT=server_debug

TESTS_OUTPUTS=$(shell find $(TESTS_DIR) -name '*.c' | sed 's/\.c//g')

###
# sciezki do plikow wejsciowych/posrednich
###
SOURCE_EXT=c
OBJECT_EXT=o

# przeszukiwanie drzewa podfolderow w poszukiwaniu plikow .c do skompilowania
SOURCES=$(shell find $(SOURCE_DIR) -name '*.$(SOURCE_EXT)')
SOURCES_WITHOUT_MAIN=$(shell find $(SOURCE_DIR) -name '*.$(SOURCE_EXT)' | grep -v '.*/main.$(SOURCE_EXT)$$')

# skompilowane pliki obj laduja w osobnym podfolderze $(INTERMEDIATE_DIR)
ESCAPED_INTERMEDIATE_DIR=$(shell echo "$(INTERMEDIATE_DIR)" | sed 's/\//\\\//g')
ESCAPED_INTERMEDIATE_DIR_DEBUG=$(shell echo "$(INTERMEDIATE_DIR_DEBUG)" | sed 's/\//\\\//g')
ESCAPED_INTERMEDIATE_DIR_PREPROCESSED=$(shell echo "$(INTERMEDIATE_DIR_PREPROCESSED)" | sed 's/\//\\\//g')

OBJECTS=$(shell echo "$(SOURCES:.$(SOURCE_EXT)=.$(OBJECT_EXT))" | sed 's/\.\//.\/$(ESCAPED_INTERMEDIATE_DIR)\//g')
OBJECTS_DEBUG=$(shell echo "$(SOURCES:.$(SOURCE_EXT)=.$(OBJECT_EXT))" | sed 's/\.\//.\/$(ESCAPED_INTERMEDIATE_DIR_DEBUG)\//g')
OBJECTS_PREPROCESSED=$(shell echo "$(SOURCES)" | sed 's/\.\//.\/$(ESCAPED_INTERMEDIATE_DIR_PREPROCESSED)\//g')
OBJECTS_TESTS=$(shell echo "$(SOURCES_WITHOUT_MAIN:.$(SOURCE_EXT)=.$(OBJECT_EXT))" | sed 's/\.\//.\/$(ESCAPED_INTERMEDIATE_DIR_DEBUG)\//g')

# podkatalogi do utworzenia w $(INTERMEDIATE_DIR)
INTERMEDIATE_SUBDIRS=$(shell echo "$(OBJECTS) " | sed 's/\/[^\/]\+\ /\n/g' | sort | uniq)
INTERMEDIATE_SUBDIRS_DEBUG=$(shell echo "$(OBJECTS_DEBUG) " | sed 's/\/[^\/]\+\ /\n/g' | sort | uniq)
INTERMEDIATE_SUBDIRS_PREPROCESSED=$(shell echo "$(OBJECTS_PREPROCESSED) " | sed 's/\/[^\/]\+\ /\n/g' | sort | uniq)

###
#	reguly
###
# domyslna regula
default: all

# tworzenie odpowiednich podfolderow
prepare:
	@echo Preparing folders...
	@echo "> output: $(OUTPUT_DIR)"
	@mkdir -p $(OUTPUT_DIR)
	@echo "> intermediate: $(INTERMEDIATE_DIR)"
	@mkdir -p $(INTERMEDIATE_DIR)
	@mkdir -p $(INTERMEDIATE_SUBDIRS)
	@mkdir -p $(INTERMEDIATE_SUBDIRS_DEBUG)
	@mkdir -p $(INTERMEDIATE_SUBDIRS_PREPROCESSED)
	@echo "...done!"

# czyszczenie pliku wykonywalnego i wszystkich wygenerowanych plikow posrednich
clean:
	@echo Cleaning...
	@echo "> output"
	@rm -rf $(OUTPUT_DIR)
	@echo "> intermediate"
	@rm -rf $(INTERMEDIATE_DIR)
	@rm -rf $(INTERMEDIATE_DIR_DEBUG)
	@rm -rf $(INTERMEDIATE_DIR_PREPROCESSED)
	@echo "> tests"
	@rm -f $(TESTS_OUTPUTS)
	@echo "...done!"


# wypisywanie polecenia kompilacji
print_compile_cmd:
	@echo "$(CC) $(OS_DEPENDANT_CC_OPTIONS) $(CCFLAGS) $(RELEASE_MACROS) $(INCLUDES) -c -o OUTPUT INPUT"

print_compile_cmd_debug:
	@echo "$(CC) -ggdb $(OS_DEPENDANT_CC_OPTIONS) $(CCFLAGS) $(DEBUG_MACROS) $(INCLUDES) -c -o OUTPUT INPUT"

print_compile_cmd_preprocess:
	@echo "$(CC) -E $(CCFLAGS) $(INCLUDES) -o OUTPUT INPUT"

print_compile_cmd_tests:
	@echo "$(CC) $(OS_DEPENDANT_CC_OPTIONS) $(CCFLAGS) $(DEBUG_MACROS) $(INCLUDES) -o OUTPUT INPUT $(OBJECTS_DEBUG) $(OS_DEPENDANT_LD_OPTIONS) $(LIBS)"

###
#	kompilacja
###

# chain rule do kompilowania .c do .o
$(INTERMEDIATE_DIR)/%.$(OBJECT_EXT): %.$(SOURCE_EXT)
	@echo "CC  $@"
	@$(CC) $(OS_DEPENDANT_CC_OPTIONS) $(CCFLAGS) $(RELEASE_MACROS) $(INCLUDES) -c -o $@ $<

$(INTERMEDIATE_DIR_DEBUG)/%.$(OBJECT_EXT): %.$(SOURCE_EXT)
	@echo "CC  $@"
	@$(CC) -ggdb $(OS_DEPENDANT_CC_OPTIONS) $(CCFLAGS) $(DEBUG_MACROS) $(INCLUDES) -c -o $@ $<

# preprocesor
$(INTERMEDIATE_DIR_PREPROCESSED)/%.$(SOURCE_EXT): %.$(SOURCE_EXT)
	$(CC) -E $(CCFLAGS) $(INCLUDES) -o $@ $<

# linkowanie
debug: prepare print_compile_cmd_debug $(OBJECTS_DEBUG)
	$(CC) -o $(OUTPUT_DIR)/$(DEBUG_OUTPUT) $(OBJECTS_DEBUG) $(OS_DEPENDANT_LD_OPTIONS) $(LIBS)

release: prepare print_compile_cmd $(OBJECTS)
	$(CC) -o $(OUTPUT_DIR)/$(OUTPUT) $(OBJECTS) $(OS_DEPENDANT_LD_OPTIONS) $(LIBS)

preprocess: prepare print_compile_cmd_preprocess $(OBJECTS_PREPROCESSED)

# rekompilacja calosci
rebuild: clean all

$(TESTS_DIR)/%: $(TESTS_DIR)/%.$(SOURCE_EXT) $(OBJECTS_DEBUG)
	@echo "dupa"
	$(CC) $(OS_DEPENDANT_CC_OPTIONS) $(CCFLAGS) $(DEBUG_MACROS) $(INCLUDES) -o $@ $< $(OBJECTS_TESTS) $(OS_DEPENDANT_LD_OPTIONS) $(LIBS)

build_tests: prepare $(TESTS_OUTPUTS)

tests: build_tests
	for TEST in $(TESTS_OUTPUTS); do ./$${TEST}; done

# kompilacja projektu
all: debug release tests

###
# do debugowania makefile
###
debug_makefile:
	@echo "SOURCES: $(SOURCES)"
	@echo "INCLUDES: $(INCLUDES)"
	@echo "LIBS: $(LIBS)"
	@echo "OBJECTS: $(OBJECTS)"
	@echo "OBJECTS_DEBUG: $(OBJECTS_DEBUG)"
	@echo "OBJECTS_TESTS: $(OBJECTS_TESTS)"
	@echo "INTERMEDIATE_SUBDIRS: $(INTERMEDIATE_SUBDIRS)"
	@echo "INTERMEDIATE_SUBDIRS_DEBUG: $(INTERMEDIATE_SUBDIRS_DEBUG)"
	@echo "INTERMEDIATE_SUBDIRS_PREPROCESSED: $(INTERMEDIATE_SUBDIRS_PREPROCESSED)"
	@echo "ESCAPED_INTERMEDIATE_DIR: $(ESCAPED_INTERMEDIATE_DIR)"
	@echo "ESCAPED_INTERMEDIATE_DIR_DEBUG: $(ESCAPED_INTERMEDIATE_DIR_DEBUG)"
	@echo "ESCAPED_INTERMEDIATE_DIR_PREPROCESSED: $(ESCAPED_INTERMEDIATE_DIR_PREPROCESSED)"
	@echo "INTERMEDIATE_SUBDIRS: $(INTERMEDIATE_SUBDIRS)"
	@echo "INTERMEDIATE_SUBDIRS_DEBUG: $(INTERMEDIATE_SUBDIRS)"
	@echo "INTERMEDIATE_SUBDIRS_PREPROCESSED: $(INTERMEDIATE_SUBDIRS_PREPROCESSED)"
	@echo "OS: $(OS)"

