BINS=netmon

netmon:	netmon.c log.c ini.c
	 $(CC) $+ -lpcap -pthread -o $@ -I.

clean:
	rm -rf $(BINS)

