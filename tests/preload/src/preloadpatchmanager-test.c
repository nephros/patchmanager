#include <stdio.h>
#include <stdlib.h>
int main()
{
    int fail = 0;
    if (getenv("NO_PM_PRELOAD") != NULL)
        fprintf(stdout, "NO_PM_PRELOAD is set\n");
    else
        fprintf(stdout, "NO_PM_PRELOAD is not set\n");

    fprintf(stdout, "Opening a file in tmp\n");

    FILE *fp = fopen("/tmp/does-not-exist", "r");
    if (fp) {
        fprintf(stdout, "Opening succeeded\n");
        fclose(fp);
    } else fprintf(stdout, "Opening failed\n");

    fprintf(stdout, "Opening a file in etc\n");
    fp = fopen("/etc/passwd", "r");
    if (fp) {
        fprintf(stdout, "Opening succeeded\n");
        fclose(fp);
    } else fprintf(stdout, "Opening failed\n");

    fprintf(stdout, "Opening a file in proc\n");
    fp = fopen("/proc/uptime", "r");
    if (fp) {
        fprintf(stdout, "Opening succeeded\n");
        fclose(fp);
    } else fprintf(stdout, "Opening failed\n");


    fprintf(stdout, "Opening a file in dev\n");
    fp = fopen("/dev/zero", "r");
    if (fp) {
        fprintf(stdout, "Opening succeeded\n");
        fclose(fp);
    } else fprintf(stdout, "Opening failed\n");

    return fail;
}
