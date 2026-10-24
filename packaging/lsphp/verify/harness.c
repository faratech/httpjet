#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lsapilib.h"

/* Minimal LSAPI app: reads QUERY_STRING bytes of the request body (like a PHP script
 * that reads php://input partially), logs the script it ran, and answers. */
int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    int fd = LSAPI_CreateListenSock(argv[1], 16);
    if (fd < 0) return 3;
    if (fd != 0) { dup2(fd, 0); close(fd); }
    if (LSAPI_Init() == -1) return 4;
    LSAPI_Init_Env_Parameters(NULL);
    while (LSAPI_Prefork_Accept_r(&g_req) >= 0) {
        const char *sf = LSAPI_GetScriptFileName();
        const char *qs = LSAPI_GetQueryString();
        long want = qs ? atol(qs) : 0;
        char buf[65536];
        long got = 0;
        while (got < want) {
            long n = LSAPI_ReadReqBody(buf, (size_t)((want - got) < (long)sizeof buf ? (want - got) : (long)sizeof buf));
            if (n <= 0) break;
            got += n;
        }
        FILE *log = fopen(argv[2], "a");
        if (log) { fprintf(log, "%s\n", sf ? sf : "(null)"); fclose(log); }
        char hdr[] = "Content-Type: text/plain";
        LSAPI_AppendRespHeader(hdr, (int)strlen(hdr));
        LSAPI_Write(sf ? sf : "", sf ? strlen(sf) : 0);
        LSAPI_Finish_r(&g_req);
    }
    return 0;
}
