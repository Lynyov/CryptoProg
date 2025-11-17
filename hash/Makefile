CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
LIBS = -lcrypto++

TARGET = hash_tool
SOURCES = main.cpp

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCES) $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: clean
