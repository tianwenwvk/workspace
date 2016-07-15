CXXFLAGS =	-O2 -g -Wall -fmessage-length=0

OBJS =		SecureConnectionTest.o

LIBS =

TARGET =	SecureConnectionTest

$(TARGET):	$(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LIBS)

all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
