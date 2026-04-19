CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -std=gnu11
LDFLAGS ?=

BIN     := pbit_req_tester
SRCS    := pbit_req_tester.c

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(BIN) $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: clean
