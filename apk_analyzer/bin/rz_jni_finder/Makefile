CFLAGS=$(shell pkg-config --cflags rz_core)
LDFLAGS=$(shell pkg-config --libs rz_core)
PLUGDIR=$(shell rizin -H RZ_USER_PLUGINS)
LIBEXT=$(shell rizin -H LIBEXT)
PLUGNAME=jni_finder
TARGET=$(PLUGNAME).$(LIBEXT)


# ifndef VERBOSE
# .SILENT:
# endif


all:
	$(CXX) $(CFLAGS) -g -O3 -shared -fPIC jni_finder.cpp -o jni_finder.$(LIBEXT) $(LDFLAGS)
	$(MAKE) install

.PHONY : install
install:
	rm -rf $(PLUGDIR)/$(TARGET)
	cp -rf $(TARGET) $(PLUGDIR)/

.PHONY : uninstall
uninstall:
	rm -rf $(PLUGDIR)/$(TARGET)

.PHONY : clean
clean:
	rm -rf $(TARGET)
