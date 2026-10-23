TEMPLATE = app
QT =
CONFIG -= qt
CONFIG += use_c_linker
CONFIG += console cmdline
#CONFIG += static
#CONFIG += strict_c
#CONFIG += c11

SOURCES += src/preloadpatchmanager-test.c
TARGET = preload-test

QMAKE_CFLAGS += -std=c11
QMAKE_CFLAGS += -Wextra -Werror
QMAKE_CFLAGS += -pedantic


PRELOAD_LOCATION = $${_PRO_FILE_PWD_}/../../src/preload
PRELOAD_LIB = $${PRELOAD_LOCATION}/libpreloadpatchmanager.so

# !system(rpm -q strace > /dev/null) {
#     message(strace does not exist)
# }

QMAKE_EXTRA_TARGETS  += test-preload

test-preload.depends += first
test-preload.depends += $$TARGET
test-preload.commands = ./runtest.sh $$PRELOAD_LIB $$TARGET $$OUT_PWD

QMAKE_CLEAN += $$OUT_PWD/*.log \
               $$OUT_PWD/*.err
