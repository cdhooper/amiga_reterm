#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos/datetime.h>
#include <clib/dos_protos.h>
#include <inline/dos.h>
#include <inline/exec.h>
#include <rexx/rexxio.h>

static const char version[] =
    "\0$VER: conperf 1.2 (13-Jul-2026) \xA9 Chris Hooper";

static const char usage[] =
    "\t-d  more details (verbose)\n"
    "\t-v  display program version\n"
    "\t-h  help\n";

extern struct Library *SysBase;
extern struct Library *DOSBase;
BOOL __check_abort_enabled = 0;

BOOL verbose = FALSE;
void *argument = "";  // Generic test function argument

#define STR_ESC "\x1b"
#define STR_CSI "\x9b"

/*
 * Collect a terminal reply until its final byte shows up, the terminal goes
 * quiet, or the buffer is full. Returns the number of bytes captured, which
 * the caller still needs to validate.
 */
static LONG
read_response(BPTR in, unsigned char *buf, size_t bufsize, unsigned char final)
{
    LONG len = 0;

    while ((size_t) len < bufsize) {
        if (WaitForChar(in, 500000) == FALSE)
            break;
        LONG got = Read(in, buf + len, bufsize - len);
        if (got <= 0)
            break;
        len += got;
        if (buf[len - 1] == final)
            break;
    }

    return (len);
}

static BOOL
test_window_bounds_report(int maxcount)
{
    int count;
    BOOL fail = FALSE;
    BPTR in = Output();
    BPTR out = Output();
    unsigned char inbuf[32];
    unsigned char outbuf[] = STR_CSI "0 q";  // Window Bounds Report

    for (count = 0; count < maxcount; count++) {
        LONG len = 0;
        Write(out, outbuf, sizeof (outbuf) - 1);

        /* Read until the terminating 'r' arrives: over a serial line the
           reply trickles in, so a byte count is not a reliable stop
           condition (a wide window makes it up to 14 bytes long). */
        len = read_response(in, inbuf, sizeof (inbuf), 'r');
        if ((len < 11) || (len > 14) ||
            (strncmp(inbuf, STR_CSI "1;1;", 4) != 0) ||
            (inbuf[len - 1] != 'r')) {
            const char *extradigit1 = (inbuf[8] == ';') ? " xx" : "";
            const char *extradigit2 = (inbuf[11] == ' ') ? " xx" : "";
            int pos;
            printf("Window Bounds Report\n"
                   "Unexpected response len=%d at count=%d of %d\n"
                   "           CSI 1  ;  1  ;  Pr    ;  Pc   SPACE r\n"
                   "should be: 9b 31 3b 31 3b xx xx%s 3b xx xx%s 20 72\n"
                   "received: ",
                   len, count, maxcount, extradigit1, extradigit2);
            if (len == 0) {
                printf("Nothing");
            } else {
                for (pos = 0; pos < len; pos++)
                    printf(" %02x", inbuf[pos]);
            }
            printf("\n");
            fail = TRUE;
            break;
        }
    }

    return (fail);
}

static BOOL
test_device_status_report(int maxcount)
{
    int count;
    BOOL fail = FALSE;
    BPTR in = Output();
    BPTR out = Output();
    unsigned char inbuf[32];
    unsigned char outbuf[] = STR_CSI "6n";  // Device Status Report

    for (count = 0; count < maxcount; count++) {
        LONG len = 0;
        Write(out, outbuf, sizeof (outbuf) - 1);

        /* Read until the terminating 'R' arrives (see above) */
        len = read_response(in, inbuf, sizeof (inbuf), 'R');
        if ((len < 5) || (len > 6) ||
            ((inbuf[2] != ';') && (inbuf[3] != ';')) ||
            (inbuf[len - 1] != 'R')) {
            const char *extradigit = (inbuf[3] == ';') ? " xx" : "";
            int pos;
            printf("Device Status Report (Cursor Position)\n"
                   "Unexpected response len=%d at count=%d of %d\n"
                   "           CSI   Pr    ;  Pc      R\n"
                   "should be: 9b xx%s 3b 31 48\n"
                   "received: ",
                   len, count, maxcount, extradigit);
            if (len == 0) {
                printf("Nothing");
            } else {
                for (pos = 0; pos < len; pos++)
                    printf(" %02x", inbuf[pos]);
            }
            printf("\n");
            fail = TRUE;
            break;
        }
    }

    return (fail);
}

static LONG
do_paste(const char *buf, LONG action)
{
    struct FileHandle *fh = (struct FileHandle *) BADDR(Input());

    return (DoPkt3(fh->fh_Type, action, (LONG) fh->fh_Arg1,
                   (LONG)buf, strlen(buf)));
}

static BOOL
test_paste_stack_queue(int maxcount)
{
    unsigned char inbuf[32];
    int           count;
    BPTR          in = Input();

    for (count = 0; count < maxcount; count++)
        do_paste("", (int) argument);
    do_paste("\n", (int) argument);

    /* Discard any input */
    while (WaitForChar(in, 1000))
        if (Read(in, inbuf, sizeof (inbuf)) <= 0)
            return (TRUE);

    return (FALSE);
}

static BOOL
test_misc(int maxcount, UBYTE *str)
{
    int  count;
    LONG len = strlen(str);
    BPTR out = Output();

    for (count = 0; count < maxcount; count++)
        if (Write(out, str, len) < 0)
            return (TRUE);

    return (FALSE);
}

static BOOL
test_strcmd(int maxcount)
{
    return (test_misc(maxcount, argument));
}

static void
diffstamp(struct DateStamp *ds1, struct DateStamp *ds2, struct DateStamp *res)
{
    res->ds_Tick   = ds2->ds_Tick   - ds1->ds_Tick;
    res->ds_Minute = ds2->ds_Minute - ds1->ds_Minute;
    res->ds_Days   = ds2->ds_Days   - ds1->ds_Days;
    if ((res->ds_Tick < 0) &&
        ((res->ds_Minute != 0) || (res->ds_Days != 0))) {
        res->ds_Tick += TICKS_PER_SECOND * 60;
        res->ds_Minute--;
    }
    if ((res->ds_Minute < 0) && (res->ds_Days != 0)) {
        res->ds_Minute += 60 * 24;
        res->ds_Days--;
    }
}

static void
printstamp(struct DateStamp *ds)
{
    if (ds->ds_Days != 0)
        printf(" %d Days", ds->ds_Days);
    if (ds->ds_Minute != 0)
        printf(" %d Minutes", ds->ds_Minute);
    printf(" %d ticks", ds->ds_Tick);
}

/* converts a timestamp to milliseconds */
static unsigned long
convstamp(struct DateStamp *ds)
{
    unsigned long total = ds->ds_Tick * 20;  // 20 ms per tick
    total += ds->ds_Minute * 60 * 1000;      // 60 seconds * 1000 ms per minute
    if (ds->ds_Days > 49) {
        /* Would cause rollover */
        total = 0xffffffff;
    } else {
        total += ds->ds_Days * 24 * 60 * 60 * 1000;
    }
    return (total);
}

/*
 * This code implements msec * 1000 / iters, staying within the bounds
 * of 32 bits.
 */
static unsigned long
usec_per_iter(unsigned long msec, unsigned long iters)
{
    unsigned long div;
    unsigned long mul = 1000;

    /* Eliminate any common factors */
    for (div = 2; div * div < iters; ) {
        if ((iters % div) == 0) {
            if ((mul % div) == 0) {
                mul /= div;
                iters /= div;
                continue;
            }
            if ((msec % div) == 0) {
                msec /= div;
                iters /= div;
                continue;
            }
        }
        div++;
    }

    /* Lose precision to keep our result within 32 bits */
    while ((msec * mul) / mul != msec) {
        if ((msec & 1) == 0)
            msec >>= 1;
        else if ((mul & 1) == 0)
            mul >>= 1;
        else if (msec > mul)
            msec >>= 1;
        else
            mul >>= 1;
        div >>= 1;
    }
    return (msec * mul / iters);
}

static void
cleanup(void)
{
    SetMode(Output(), FALSE);
}

static void
check_break(void)
{
    if (SetSignal(0, 0) & SIGBREAKF_CTRL_C) {
        printf("^C\n");
        exit(1);
    }
}

/*
 * Discard any pending console input, so responses generated by a previous
 * test (e.g. on terminals which reply to sequences the AmigaOS console
 * ignores) are not misread as responses to the current test.
 */
static void
drain_input(void)
{
    unsigned char inbuf[32];
    BPTR in = Input();

    while (WaitForChar(in, 1000))
        if (Read(in, inbuf, sizeof (inbuf)) <= 0)
            break;
}

static BOOL
measure(const char *test_name, BOOL (*func)(int count), void *arg)
{
    struct DateStamp start_ds;
    struct DateStamp end_ds;
    struct DateStamp result;
    unsigned long msec;
    unsigned long usec;
    unsigned long iters;
    unsigned long total_iters = 0;
    BOOL fail;

    argument = arg;
    check_break();

    SetMode(Output(), TRUE);
    drain_input();
    DateStamp(&start_ds);
    for (iters = 1; iters < 1000000; iters *= 2) {
        fail = func(iters);
        total_iters += iters;
        DateStamp(&end_ds);
        diffstamp(&start_ds, &end_ds, &result);
        if (fail) {
            SetMode(Output(), FALSE);
            return (TRUE);
        }
        if ((result.ds_Days != 0) ||
            (result.ds_Minute != 0) ||
            (result.ds_Tick > 40))
            break;
    }
    SetMode(Output(), FALSE);
    msec = convstamp(&result);
    usec = usec_per_iter(msec, total_iters);
    if (verbose) {
        printf("%7s: %lu iters in", test_name, total_iters);
        printstamp(&result);
        printf(" (%lu msec) = %lu usec / iter\n", msec, usec);
    } else {
        printf("%7s: %lu usec\n", test_name, usec);
    }
    return (FALSE);
}

int
main(int argc, char *argv[])
{
    int arg;
    BOOL fail = FALSE;

    for (arg = 1; arg < argc; arg++) {
        char *ptr = argv[arg];
        if (*ptr == '-') {
            while (*(++ptr) != '\0') {
                switch (*ptr) {
                    case 'd':
                        verbose = TRUE;
                        break;
                    case 'v':
                        printf("%s\n", version + 7);
                        exit(0);
                    default:
                        printf("Unknown: -%s\n", ptr);
                        /* FALLTHROUGH */
                    case 'h':
                        printf(usage);
                        exit(1);
                }
            }
        } else {
            printf(usage);
            exit(1);
        }
    }
    atexit(cleanup);
    /* CSI R (CPR) is a read-stream-only sequence: every console parses
     * and discards it with no reply and no rendering-state work (CSI c
     * is DA1, which VT-compliant terminals such as ViNCEd answer).
     * sgr0 additionally measures pen/drawmode/minterm recomputation. */
    fail |= measure("nop",     test_strcmd, STR_CSI "R");
    fail |= measure("sgr0",    test_strcmd, STR_CSI "0m");
    fail |= measure("WinBRep", test_window_bounds_report, "");
    fail |= measure("CrsrPos", test_device_status_report, "");
    fail |= measure("QueueIn", test_paste_stack_queue, (void *)ACTION_QUEUE);
    fail |= measure("StackIn", test_paste_stack_queue, (void *)ACTION_STACK);
    fail |= measure("InsC1",   test_strcmd, STR_CSI "@");
    fail |= measure("InsC40",  test_strcmd, STR_CSI "40@");
    fail |= measure("InsC80",  test_strcmd, STR_CSI "80@");
    fail |= measure("DelCh1",  test_strcmd, STR_CSI "P");
    fail |= measure("DelCh40", test_strcmd, STR_CSI "40P");
    fail |= measure("DelCh80", test_strcmd, STR_CSI "80P");
    fail |= measure("InsLn1",  test_strcmd, STR_CSI "L");
    fail |= measure("InsLn20", test_strcmd, STR_CSI "20L");
    fail |= measure("DelLn1",  test_strcmd, STR_CSI "M");
    fail |= measure("DelLn20", test_strcmd, STR_CSI "20M");
    fail |= measure("EraseLn", test_strcmd, STR_CSI "K");
    fail |= measure("EraseDs", test_strcmd, STR_CSI "J");
    exit(fail ? 10 : 0);
}
