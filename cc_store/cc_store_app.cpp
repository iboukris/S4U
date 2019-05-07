#include "cc_store.h"
#include <iostream>
#include <string>

void print_usage(const char *s)
{
    std::cout << "usage: " << s << " <init | impersonate> "
                 "<out-ccache> <principal-name> "
                 "<password | impersonator-keytab> "
                 "[target-server]" << std::endl;
}

int main (int argc, char* argv[])
{
    if (argc < 5) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd(argv[1]);
    if (cmd == "init") {
        if (argc == 6)
            cc_store::init_creds(argv[2], argv[3], argv[4], argv[5]);
        else
            cc_store::init_creds(argv[2], argv[3], argv[4]);
    }
    else if (cmd == "impersonate") {
        if (argc == 6)
            cc_store::impersonate_creds(argv[2], argv[3], argv[4], argv[5]);
        else
            cc_store::impersonate_creds(argv[2], argv[3], argv[4]);
    }
    else {
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}
