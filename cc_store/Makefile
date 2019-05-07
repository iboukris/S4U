# cc_store
#
# examples:
# ./cc_store init cc avi zubur1 CIFS@ms.frenche.cp
# or:
# ./cc_store impersonate cc ola apache.kt apache
#

cc_store: cc_store.h cc_store.cpp cc_store_app.cpp
	g++ -g -o cc_store cc_store_app.cpp cc_store.cpp -lgssapi_krb5

clean:
	rm -f cc_store

.PHONY: clean
