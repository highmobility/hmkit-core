#include <stdio.h>
#include "hmkit_core.h"
#include <fcntl.h>

int main(int argc, char *argv[]) {
    /*FILE *ps;

    ps = popen("./hmsensing/hmsensing", "r+");
    if (!ps) {
        puts("Can't connect to copy");
        return 1;
    }*/

    hmkit_core_init();

    for(;;){        
        /*char *ln = NULL;
        size_t len = 0;

        while (getline(&ln, &len, ps) != -1)
            fputs(ln, stdout);*/
    }

    //pclose(ps);

    return 0;
}
