#
# makefile for elfss
#
# (C) Li hsilin
#  

TG = elfss
all: $(TG)
readph: elfss.c
	$(CC) -o $@ $^
clean:
	$(RM) $(TG)

.PHONY: all clean
