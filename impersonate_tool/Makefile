# impersonate_tool
#
# examples:
# ./impersonate_tool client@realm out_cache
#

impersonate_tool: impersonate_tool.c
	g++ -g -o impersonate_tool impersonate_tool.c -lgssapi_krb5

clean:
	rm -f impersonate_tool

.PHONY: clean
