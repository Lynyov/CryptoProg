CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
LIBS = -lcryptopp

TARGET = cipher
SOURCES = main.cpp

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET) *.o

.PHONY: clean
