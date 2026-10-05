TEMPLATE = lib
QT =
CONFIG -= qt
CONFIG += plugin
CONFIG += thread
CONFIG += use_c_linker
#CONFIG += warn_on
QMAKE_CFLAGS += -std=c11
QMAKE_CFLAGS += -Wextra -Werror
QMAKE_CFLAGS += -pedantic

CONFIG += link_pkgconfig
PKGCONFIG += libshadowutils
INCLUDEPATH += /usr/include/libshadowutils

LIBS = -ldl

SOURCES += \
    src/preloadpatchmanager.c

TARGET = preloadpatchmanager
target.path = $$LIBDIR

INSTALLS = target
