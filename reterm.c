#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#ifdef LIBNIX
#include <sys/signal.h>
#include <sys/unistd.h>
#endif
#include <sys/select.h>
#include <sys/filio.h>
#include <netinet/in.h>

#include <exec/exec.h>
#include <exec/types.h>
#include <exec/memory.h>
#include <exec/execbase.h>
#include <dos/dosextens.h>
#include <dos/dostags.h>
#include <dos/exall.h>
#include <devices/conunit.h>
#include <rexx/rexxio.h>
#include <intuition/intuition.h>
#include <intuition/intuitionbase.h>
#include <intuition/gadgetclass.h>
#include <graphics/gfxbase.h>
#include <graphics/text.h>
#include <graphics/layers.h>
#ifdef __lint
#include <clib/exec_protos.h>
#include <clib/dos_protos.h>
#include <clib/intuition_protos.h>
#include <clib/graphics_protos.h>
#include <clib/layers_protos.h>
#include <clib/alib_protos.h>
#define __NO_NET_API
#include <clib/bsdsocket_protos.h>
#else
#include <sys/socket.h>
#include <inline/exec.h>
#include <inline/dos.h>
#include <inline/alib.h>
#include <inline/intuition.h>
#include <inline/graphics.h>
#include <inline/layers.h>
#include <inline/bsdsocket.h>
#endif


static const char version[] =
    "\0$VER: reterm " VERSION " ("BUILD_DATE" "BUILD_TIME") \xA9 Chris Hooper";

static const char usage[] =
    "\t-a         List abandoned console ports (programs left by a reterm)\n"
    "\t-A <cli>   Attach to the abandoned console of CLI process <cli>\n"
    "\t-c <file>  Capture app input/output to file\n"
    "\t-C <file>  Capture xterm input/output to file\n"
    "\t-d <count> Daemon mode (cnt = simultaneous daemons)\n"
    "\t-D[D]      Debug output\n"
    "\t-E         Avoid xterm escape sequences where possible\n"
    "\t-F         Fake xterm cursor position / window size\n"
    "\t-h         This help\n"
    "\t-i         Capture only input\n"
    "\t-M         Tab complete match characters only to the left of cursor\n"
    "\t-o         Capture only output\n"
    "\t-p <port>  Open a TCP socket\n"
    "\t-P         Don't show program path when tab completing\n"
    "\t-q         Quiet (don't announce connect/disconnect)\n"
    "\t-r <ascii> Requester abort key (default ^C=3)\n"
    "\t-R         Disable ^C requester abort\n"
    "\t-s <size>  Stack size for child application\n"
    "\t-t         Enable telnet protocol\n"
    "\t-u         Convert between xterm UTF-8 encoding and Amiga ISO 8859-1\n"
    "\t-v         Display program version\n"
    "\t-x         Force terminal to xterm (usually not needed)";

#define DEBUG
#ifdef __lint
#undef DEBUG
#endif
#ifdef DEBUG
#define DPRINT(fmt, ...) dprintf(glob, 0, fmt, ##__VA_ARGS__)
#define DPRINT1(fmt, ...) dprintf(glob, 1, fmt, ##__VA_ARGS__)
#define DPRINT2(fmt, ...) dprintf(glob, 2, fmt, ##__VA_ARGS__)
#else
#define DPRINT(fmt, ...)
#define DPRINT1(fmt, ...)
#define DPRINT2(fmt, ...)
#endif

/* Escape and CSI characters */
#define KEY_ESC               0x1b   // Escape key character
#define KEY_CSI               0x9b   // Amiga CSI entry char (CSI 8-bit code)
#define STR_ESC               "\x1b" // String version of Escape key character
#define STR_CSI               "\x9b" // String version of Amiga CSI

/* RFC-1123 specifies telnet protocol requirements */
#define TELNET_EOF            0xec  // End of file (EOF)
#define TELNET_SUSP           0xed  // Suspend process (SUSP)
#define TELNET_ABORT_PROC     0xee  // Abort process (ABORT)
#define TELNET_EOR            0xef  // End of record for transparent mode (EOR)
#define TELNET_SE             0xf0  // End of subnegotiation parameters (SE)
#define TELNET_NOP            0xf1  // No operation (NOP)
#define TELNET_DATA           0xf2  // Data mark (sync urgent)
#define TELNET_BRK            0xf3  // Break interrupt (BRK)
#define TELNET_IP             0xf4  // Interrupt process (IP)
#define TELNET_AO             0xf5  // Abort output (AO)
#define TELNET_AYT            0xf6  // Are you there? (AYT)
#define TELNET_EC             0xf7  // Erase character (EC)
#define TELNET_EL             0xf8  // Erase line (EL)
#define TELNET_GO             0xf9  // Go ahead (GA)
#define TELNET_SB             0xfa  // Sub-Negotiation Begin
#define TELNET_WILL           0xfb  // Local Will Do                    RFC-855
#define TELNET_WONT           0xfc  // Local Will Not Do                RFC-855
#define TELNET_DO             0xfd  // Remote Must Do                   RFC-855
#define TELNET_DONT           0xfe  // Remote Must Not Do               RFC-855
#define TELNET_IAC            0xff  // Next byte is code (WILL/WONT/DO/DONT/etc)

#define TELNET_OP_ECHO        0x01  // RFC-857  Echo data to sender     (ECHO)
#define TELNET_OP_NO_GO_AHEAD 0x03  // RFC-858  Suppress go-ahead signal (SGA)
#define TELNET_OP_NAOL        0x08  // NIC20196 Negotiate output line width
#define TELNET_OP_OUTMRK      0x1b  // RFC-933  Output marking
#define TELNET_OP_LINEMODE    0x22  // RFC-1184 Linemode option
#define TELNET_OP_EXT_LIST    0xff  // RFC-861  Extended list

#define MAKE_ID(a, b, c, d) \
        ((ULONG) (a)<<24 | (ULONG) (b)<<16 | (ULONG) (c)<<8 | (ULONG) (d))

#define ID_CON    MAKE_ID('C', 'O', 'N', 0)  /* When in Cooked mode */
#define ID_RAWCON MAKE_ID('R', 'A', 'W', 0)  /* When in Raw mode */

#define ACTION_ABORT       0x200   // ViNCEd-specific? Abort asynchronous I/O

#ifndef ACTION_UNDISK_INFO
#define ACTION_UNDISK_INFO 0x201   // Give back ACTION_DISK_INFO window pointer
#endif

extern struct Library *SysBase;
extern struct Library *DOSBase;
struct Library *IntuitionBase = NULL;
struct GfxBase *GfxBase       = NULL;  // For gadget label recognition
struct Library *LayersBase    = NULL;  // For gadget label recognition

BOOL __check_abort_enabled = 0;     // Disable clib2 ^C break handling

/*
 * reterm_exiting is set when the user forces reterm to exit (a second break)
 * while applications still have a reterm console open. Session reader
 * threads then stop waiting for the application to close its console, and
 * leak the console port so that reterm can exit.
 */
static volatile BOOL reterm_exiting = FALSE;

/* ticks_since() returns the number of ticks (1/50 s) since the DateStamp */
static LONG
ticks_since(const struct DateStamp *start)
{
    struct DateStamp now;
    DateStamp(&now);
    return (((now.ds_Days - start->ds_Days) * 1440 +
             (now.ds_Minute - start->ds_Minute)) * 60 * TICKS_PER_SECOND +
            (now.ds_Tick - start->ds_Tick));
}
unsigned int __stack_size  = 4096;  // Minimum stack size for main

typedef struct {
    struct Node node;
    LONG        len;
    UBYTE       buf[1];  // Actually longer (length = len)
} pastenode_t;

typedef struct {
    struct Node node;
    UBYTE      *name;
    BYTE        data;
} namelist_t;

typedef enum {
    TERM_TYPE_UNKNOWN = 0,
    TERM_TYPE_AMIGA   = 1,
    TERM_TYPE_XTERM   = 2,
} termtype_t;

typedef struct {
    struct MinNode      node;
    struct IOStdReq     id_inuse_req;
    struct ConUnit      con_unit;
    struct ConUnit     *con_unit_ptr;  // Might point direct to parent con_unit
    struct DosPacket   *pending_app_packet;
    struct DosPacket   *reader_dos_packet;
    struct Library     *socketbase_reader;
    struct MsgPort     *reader_msgport;
    struct MsgPort     *reader_timer_msgport;
    struct MsgPort     *xterm_timer_msgport;
    struct MsgPort     *app_cons_msgport;  // for client app to do console I/O
    struct MsgPort     *child_rtask_mp;
    struct MsgPort     *child_wtask_mp;
    struct MsgPort     *child_stask_mp;
    struct Task        *reader_task;
    struct timerequest *xterm_timer_request;
    struct Window      *fake_window;
    termtype_t          term_type;
    LONG   debug_mode;
    LONG   open_count;
    LONG   orphan_count;          // Handles held by suspended (crashed) apps
    struct MsgPort *adopt_port;   // Abandoned console port to attach (-A)
    struct Process *adopt_proc;   // Process using the abandoned port
    LONG   adopt_handles;         // Handles found referencing adopt_port
    BOOL   adopted;               // app_cons_msgport is an adopted port
    BOOL   keep_for_app;          // App still running: keep window and glob
    ULONG  magic;                 // GLOB_MAGIC while valid
    BOOL   kept_unlinked;         // Kept glob removed from reterm's list
    BOOL   kept_released;         // Kept glob no longer needed by the app
    void  *kept_prev;             // Earlier kept glob(s) for the same app
    char   fake_title[8];         // Fake window title (app may keep pointer)
    ULONG  amiga_console_eventmask;
    ULONG  tab_comp_maxlen;       // Maximum length of path completion string
    ULONG  tab_comp_spos;         // Tab completion start position (consumer)
    ULONG  tab_comp_epos;         // Tab completion end position (producer)
    ULONG  reader_wake_signal;
    ULONG  reader_timer_signal;
    ULONG  xterm_timer_signal;
    ULONG  tcp_read_signal;
    ULONG  requester_abort_key;   // Introducer key for requester abort prompt
    UBYTE  unproc_buf[32];        // Unprocessed xterm/user input
    UBYTE  proc_buf[256];         // Processed xterm/user input to Amiga console
    UBYTE  cmdline[250];          // MUST be smaller than proc_buf[]
    UBYTE  history_buf[1024];     // cmdline history circular buffer
    UBYTE *history_cur;           // cmdline history current position
    UBYTE  history_cur_line;      // cmdline history current line number
    UBYTE  atx_last_ch;           // amiga-to-xterm last output character
    UBYTE  atc_mode;              // amiga-to-xterm state machine
    UBYTE  atc_cmdbuf_pos;        // amiga-to-xterm CSI buffer position
    UBYTE  atc_cmdbuf[32];        // amiga-to-xterm CSI sequence buffer
    UBYTE  xta_mode;              // xterm-to-Amiga state machine
    UBYTE  xta_cmdbuf_pos;        // xterm-to-Amiga CSI buffer position
    UBYTE  xta_cmdbuf[32];        // xterm to Amiga CSI sequence buffer
    ULONG  cmdline_len;           // Input command line length
    ULONG  cmdline_pos;           // Input command cursor position
    ULONG  unproc_spos;           // unprocessed input start pos (consumer)
    ULONG  unproc_epos;           // unprocessed input end pos (producer)
    ULONG  proc_spos;             // processed input buffer start pos (consumer)
    ULONG  proc_epos;             // processed input buffer end pos (producer)
    ULONG  stack_size;            // stack size of child shell
    BOOL   support_xterm;         // Enable xterm console handling
    BOOL   support_telnet;        // Enable telnet protocol negotiation
    BOOL   disable_telnet;        // Disable telnet protocol negotiation
    BOOL   support_utf8;          // Convert to/from xterm UTF-8
    UBYTE  utf8_lead;             // Pending UTF-8 lead byte (0xc2 or 0xc3)
    BOOL   tab_comp_no_exec_path; // don't show program path on tab
    BOOL   capture_input;         // Capture input to file
    BOOL   capture_output;        // Capture output to file
    BOOL   raw_mode;              // TRUE=App wants terminal in RAW mode
    BOOL   reader_thread_alive;   // TRUE=Reader thread still running
    BOOL   runner_thread_alive;   // TRUE=Runner thread still running (stuck?)
    BOOL   child_process_alive;   // TRUE=Child application still running
    BOOL   got_zero_read_count;   // Propagate "end of file" to application
    UBYTE  device_eof_count;      // Consecutive 0-length reads from device
    BOOL   nl_crlf;               // TRUE=Newline emits CRLF (FALSE=just LF)
    BOOL   stopping;              // Shutting down reader and message loop
    BOOL   reader_read_pending;   // Read from xterm console is pending
    BOOL   tcp_readable;          // WaitSelect() reported socket readable
    BOOL   reader_close_FHs;      // Reader needs to close Filehandles at exit
    LONG   reader_timer_pending;  // Reader timer is active
    BOOL   xterm_request_pending; // App asked for cursor pos / screen size
    BOOL   fake_xterm_reply;      // Reply immediately with fake position / size
    BOOL   tab_match_pre_only;    // Tab match only before cursor
    BOOL   tab_have_post_chars;   // Tab name completion is matching post chars
    BOOL   tab_comp_staged;       // Tab name completion is staged active
    BOOL   tab_comp_running;      // Tab name completion is active
    BOOL   requester_abort_active;  // Next keystroke goes to task window kill
    UBYTE  wk_level;              // Window control prompt level (WK_*)
    UBYTE  wk_pass;               // Window found in pass 0 (own) or 1 (helper)
    UBYTE  wk_menu;               // Selected menu number
    UBYTE  wk_item;               // Selected (listed) item with sub-items
    int    wk_helpers;            // Number of helper windows found (pass 1)
    struct Window *wk_window;     // Window being controlled
    int    wk_glabels;            // Number of recognized gadget labels
    struct {
        struct Gadget *gadget;
        char           text[24];
    } wk_glabel[64];              // Labels recognized from gadget pixels
    UBYTE  wk_page;               // Page of gadget options shown
    struct {
        UBYTE  type;              // WK_OPT_*, or WK_OPT_NONE
        APTR   ptr;               // Gadget, Menu, or MenuItem shown
        UWORD  id;                // Gadget fingerprint, to detect another
        UWORD  gtype;             //   gadget allocated at the same address
        UWORD  activation;
        APTR   text;
        APTR   special;
    } wk_shown[36];               // Option of each key, as shown (WK_MAX_OPTS)
    APTR   wk_shown_menu;         // Menu whose items are shown
    APTR   wk_shown_parent;       // Item whose sub-items are shown
    struct MsgPort *wk_reply_mp;  // Replies to IDCMP messages sent to app
    int    wk_outstanding;        // IDCMP messages not yet replied
    struct Gadget *wk_sgad;       // String gadget being edited (WK_TEXT)
    UWORD  wk_tlen;               // Length of text being entered
    UWORD  wk_tmax;               // Maximum length of text
    BOOL   wk_tint;               // Text is for an integer gadget
    BOOL   wk_eat_nl;             // Discard LF or NUL following CR
    UBYTE  wk_esc;                // ESC in prompt: WK_ESC_*
    char   wk_text[256];          // Text being entered for string gadget
    BOOL   no_cooked_esc_sequences; // Use slow method for cooked cmdline
    BOOL   did_query_term_type;     // Sent query for terminal type
    BOOL   did_telnet_linemode;     // Initiated telnet linemode
    BOOL   did_telnet_will_echo;    // Said telnet will echo
    BOOL   did_telnet_do_linemode;  // Said telnet do linemode
    UBYTE  did_telnet_no_go_ahead;  // Said telnet no go ahead
    UBYTE  did_telnet_wont_echo;    // Said telnet wont echo
    UBYTE  did_telnet_wont_extlist; // Said telnet wont ext list
    UBYTE  did_telnet_wont_outmark; // Said telnet wont outmark
    UWORD  tcp_port;                // TCP/IP port for socket
    UWORD  client_number;           // Connection number
    LONG   tcp_socket_master;       // master file descriptor for open socket
    LONG   tcp_socket_id;           // id of socket to be acquired by reader
    LONG   tcp_socket_reader;       // file descriptor for open socket
    BPTR   reader_IFH;              // xterm input file handle (from user)
    BPTR   reader_OFH;              // xterm output file handle (to display)
    BPTR   capture_AFH;             // Save application I/O in this file
    BPTR   capture_XFH;             // Save xterm I/O in this file
    struct List  pending_reads;     // Pending reads and waits for input
    struct List  pending_pastes;    // Pending input (pasted in to console)
    struct List  completion_list;   // Current tab completion names
    struct Node *completion_cur;    // Current tab completion node
    pastenode_t *paste_cur;         // Current buffer being pasted
    LONG         paste_pos;         // Current position of paste
    LONG         reply_pos;         // Current position of reply
    LONG         last_ssize_time;   // Last time the screen size was updated
    char        *runner_cmd;        // Command to execute
} glob_t;

#ifdef DEBUG
__attribute__((format(printf, 3, 4)))
static void
dprintf(glob_t *glob, int level, const char *fmt, ...)
{
    va_list ap;

    if (glob->debug_mode <= level)
        return;

    if (level > 0)
        printf("   ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (level > 0)
        printf("\n");
}
#endif

__attribute__((format(printf, 1, 2)))
static void
warnx(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

__attribute__((format(printf, 2, 3)))
static void
err(int exit_code, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    exit(exit_code);
}

static void
debug_print_char(UBYTE ch, BOOL addspace)
{
    if (addspace)
        printf(" ");
    switch (ch) {
        case KEY_ESC:
            printf("ESC");
            break;
        case KEY_CSI:
            printf("CSI");
            break;
        case ' ':
            if (addspace)
                printf("SPACE");
            else
                printf(" ");
            break;
        case '\t':
            printf("\\t");
            break;
        case '\r':
            printf("\\r");
            break;
        case '\n':
            printf("\\n");
            break;
        case 0 ... 8:
        case 11 ... 12:
        case 14 ... 26:
            printf("^%c", ch + '@');
            break;
        case 28 ... 31:
        case 127 ... 154:
        case 156 ... 255:
            printf("%02x", ch);
            break;
        default:
            printf("%c", ch);
            break;
    }
}

static void
debug_print_sequence(const char *msg, const UBYTE *buf, int len, BOOL addspace)
{
    UBYTE last  = 0;
    int   count = 0;

    printf(msg);
    for (; len-- > 0; buf++) {
        UBYTE ch = *buf;
        if ((ch == last) && addspace) {
            count++;
            continue;
        }
        if (count != 0) {
            if (count < 3) {
                while (count-- > 0)
                    debug_print_char(last, addspace);
            } else {
                printf("x%d", count + 1);
            }
            count = 0;
        }
        last = ch;
        debug_print_char(ch, addspace);
    }
    if (count != 0) {
        if (count < 3) {
            while (count-- > 0)
                debug_print_char(last, addspace);
        } else {
            printf("x%d", count + 1);
        }
    }
    printf("\n");
}

#define MP(xx) ((struct MsgPort *)((struct FileHandle *) (BADDR(xx)))->fh_Type)

static void
get_con_unit(glob_t *glob)
{
    struct InfoData  id;
    struct ConUnit  *con_unit;
    BPTR             output = glob->reader_OFH;

    if (glob->tcp_port != 0)
        return;

#ifdef __AROS__
    if (!Info(output, &id))
        return;
#else
    if (DoPkt(MP(output), ACTION_DISK_INFO, MKBADDR(&id), 0, 0, 0, 0) == 0)
        return;
#endif

    if ((id.id_InUse == 0) || (id.id_InUse == -1))
        return;

    con_unit = (struct ConUnit *) ((struct IOStdReq *) id.id_InUse)->io_Unit;
    if (con_unit == NULL)
        return;

    /* We are able to share our parent's con_unit with the child process */
    glob->con_unit_ptr         = con_unit;
    glob->id_inuse_req.io_Unit = (struct Unit *) glob->con_unit_ptr;
}

/* Verify this is a valid task by walking the run and wait queues */
static BOOL
is_valid_task(void *task)
{
    struct ExecBase *execbase = (struct ExecBase *) SysBase;
    struct Node *n;

    if (task == NULL)
        return (FALSE);

    Disable();
    /* Search the ready list */
    for (n = execbase->TaskReady.lh_Head; n->ln_Succ != NULL; n = n->ln_Succ) {
        if (n == task) {
            Enable();
            return (TRUE);
        }
    }

    /* Search the wait list */
    for (n = execbase->TaskWait.lh_Head; n->ln_Succ != NULL; n = n->ln_Succ) {
        if (n == task) {
            Enable();
            return (TRUE);
        }
    }
    Enable();

    return (FALSE);
}

static void
signal_readers(glob_t *glob_p, ULONG sigval)
{
    struct MinNode *node = &glob_p->node;

    Forbid();
    for (node = node->mln_Succ; node != NULL; node = node->mln_Succ) {
        glob_t *glob = (glob_t *) node;
        ULONG sig = sigval;
        if (sig == 0)
            sig = glob->reader_wake_signal;
        Signal(glob->reader_task, sig);
    }
    Permit();
}

static void
stop_readers(glob_t *glob_p)
{
    struct MinNode *node;
    for (node = &glob_p->node; node != NULL; node = node->mln_Succ) {
        glob_t *glob = (glob_t *) node;
        glob->stopping = TRUE;
    }
}

static struct Process *
get_task_from_mp(struct MsgPort *mp)
{
    if ((mp != NULL) && (is_valid_task(mp->mp_SigTask)))
        return (mp->mp_SigTask);
    return (NULL);
}

static struct Process *
get_recent_process(glob_t *glob)
{
    return (get_task_from_mp(glob->child_rtask_mp) ?:
            get_task_from_mp(glob->child_wtask_mp) ?:
            get_task_from_mp(glob->child_stask_mp) ?: NULL);
}

/*
 * Abandoned console ports
 *
 * When reterm is forced to exit while an application still has its console
 * open, the console message port is left behind (abandoned) with no task to
 * receive packets: mp_Flags is PA_IGNORE and mp_SigTask is NULL. Older
 * versions of reterm also did this when a client disconnected. The
 * application then hangs at its next console I/O. reterm -a lists such
 * ports, and reterm -A attaches a new session to one, so that the
 * application may continue.
 */

/*
 * An abandoned port records whether the console was in raw mode, so that
 * a session attaching to it can restore the mode. The port is private, so
 * its node priority is otherwise unused.
 */
#define PORT_PRI_RAW_MODE 1
#define GLOB_MAGIC        0x5254524d  // "RTRM"

/*
 * A kept glob (session state kept for an application which was still
 * running when its session detached) is linked in the session list of the
 * reterm which created it until that reterm's main() notices the session
 * ended. It may only be freed once it is both unlinked from that list
 * and no longer needed by the application. Whichever happens last frees
 * it. The flags are tested and set under Forbid(), as the two may be in
 * different reterm processes.
 */
static void
free_kept_glob(glob_t *glob)
{
    if (glob->fake_window != NULL)
        CloseWindow(glob->fake_window);
    glob->magic = 0;
    FreeVec(glob);
}

/*
 * free_kept_globs() releases session state which was kept for an
 *                   application which has since exited.
 */
static void
free_kept_globs(glob_t *glob)
{
    while (glob != NULL) {
        glob_t *prev = (glob_t *) glob->kept_prev;
        BOOL    can_free;
        if (glob->magic != GLOB_MAGIC)
            break;
        Forbid();
        can_free = glob->kept_unlinked;
        if (can_free == FALSE)
            glob->kept_released = TRUE;  // Creating reterm will free it
        Permit();
        if (can_free)
            free_kept_glob(glob);
        glob = prev;
    }
}

static BOOL
port_is_abandoned(struct MsgPort *mp)
{
    return ((mp != NULL) && (mp->mp_Node.ln_Type == NT_MSGPORT) &&
            ((mp->mp_Flags & PF_ACTION) == PA_IGNORE) &&
            (mp->mp_SigTask == NULL));
}

/*
 * task_is_suspended() returns TRUE if the task is waiting for no signals,
 *                     which is the state of a task which crashed and was
 *                     suspended at the "Software Failure" requester.
 */
static BOOL
task_is_suspended(struct Task *task)
{
    return ((task->tc_State == TS_WAIT) && (task->tc_SigWait == 0));
}

/*
 * proc_port_refs() checks whether a process references a console port,
 *                  through its console task or standard file handles.
 *                  If *portp is NULL, the first abandoned port referenced
 *                  is used and returned in *portp. The number of distinct
 *                  file handles referencing the port is returned in
 *                  *handles. Caller must Forbid().
 */
static BOOL
proc_port_refs(struct Process *proc, struct MsgPort **portp, LONG *handles)
{
    struct CommandLineInterface *cli = BADDR(proc->pr_CLI);
    struct MsgPort *port = *portp;
    struct MsgPort *ct   = (struct MsgPort *) proc->pr_ConsoleTask;
    BPTR fhs[7];
    int  nfh = 0;
    int  cur;
    int  prev;

    *handles = 0;
    fhs[nfh++] = proc->pr_CIS;
    fhs[nfh++] = proc->pr_COS;
    fhs[nfh++] = proc->pr_CES;
    if (cli != NULL) {
        fhs[nfh++] = cli->cli_StandardInput;
        fhs[nfh++] = cli->cli_StandardOutput;
        fhs[nfh++] = cli->cli_CurrentInput;
        fhs[nfh++] = cli->cli_CurrentOutput;
    }

    if (port == NULL) {
        if (port_is_abandoned(ct)) {
            port = ct;
        } else {
            for (cur = 0; cur < nfh; cur++) {
                struct FileHandle *fh = BADDR(fhs[cur]);
                if ((fh != NULL) && port_is_abandoned(fh->fh_Type)) {
                    port = fh->fh_Type;
                    break;
                }
            }
        }
        if (port == NULL)
            return (FALSE);
    }

    for (cur = 0; cur < nfh; cur++) {
        struct FileHandle *fh = BADDR(fhs[cur]);
        if ((fh == NULL) || (fh->fh_Type != port))
            continue;
        for (prev = 0; prev < cur; prev++)
            if (fhs[prev] == fhs[cur])
                break;
        if (prev == cur)
            (*handles)++;  // Not seen before
    }
    if ((*handles == 0) && (ct != port))
        return (FALSE);
    *portp = port;
    return (TRUE);
}

/*
 * port_users() counts the processes referencing a console port, and the
 *              distinct file handles they hold. Suspended processes are
 *              counted only if count_suspended is TRUE. Caller must
 *              Forbid().
 */
static int
port_users(struct MsgPort *port, BOOL count_suspended, LONG *handles)
{
    struct List *lists[2];
    struct Node *node;
    int          users = 0;
    int          list;

    lists[0] = &((struct ExecBase *) SysBase)->TaskWait;
    lists[1] = &((struct ExecBase *) SysBase)->TaskReady;
    if (handles != NULL)
        *handles = 0;
    for (list = 0; list < 2; list++) {
        for (node = lists[list]->lh_Head; node->ln_Succ != NULL;
             node = node->ln_Succ) {
            struct MsgPort *mp = port;
            LONG            count;
            if (node->ln_Type != NT_PROCESS)
                continue;
            if ((count_suspended == FALSE) &&
                task_is_suspended((struct Task *) node))
                continue;
            if (proc_port_refs((struct Process *) node, &mp, &count)) {
                users++;
                if (handles != NULL)
                    *handles += count;
            }
        }
    }
    return (users);
}

/* port_in_use() returns TRUE if a running process references the port */
static BOOL
port_in_use(struct MsgPort *port)
{
    int users;
    Forbid();
    users = port_users(port, FALSE, NULL);
    Permit();
    return (users > 0);
}

/* proc_command_name() gets the name of the command a CLI process runs */
static void
proc_command_name(struct Process *proc, char *name, int namelen)
{
    struct CommandLineInterface *cli = BADDR(proc->pr_CLI);
    UBYTE *bstr = (cli != NULL) ? BADDR(cli->cli_CommandName) : NULL;

    if ((bstr != NULL) && (bstr[0] != 0)) {
        int len = (bstr[0] < namelen) ? bstr[0] : namelen - 1;
        memcpy(name, bstr + 1, len);
        name[len] = '\0';
    } else if (cli != NULL) {
        strncpy(name, "(shell)", namelen);
        name[namelen - 1] = '\0';
    } else {
        strncpy(name, proc->pr_Task.tc_Node.ln_Name ?: "?", namelen);
        name[namelen - 1] = '\0';
    }
}

/*
 * list_abandoned_ports() displays the processes which are using an
 *                        abandoned console port.
 */
static void
list_abandoned_ports(void)
{
    typedef struct {
        struct MsgPort *port;
        LONG            cli_num;
        LONG            queued;
        BOOL            suspended;
        char            name[32];
    } abandoned_t;
    abandoned_t  *ent;
    struct List  *lists[2];
    struct Node  *node;
    int           count = 0;
    int           max   = 64;
    int           list;
    int           cur;

    ent = AllocVec(sizeof (*ent) * max, MEMF_PUBLIC | MEMF_CLEAR);
    if (ent == NULL) {
        warnx("Out of memory");
        return;
    }
    lists[0] = &((struct ExecBase *) SysBase)->TaskWait;
    lists[1] = &((struct ExecBase *) SysBase)->TaskReady;

    Forbid();
    for (list = 0; list < 2; list++) {
        for (node = lists[list]->lh_Head;
             (node->ln_Succ != NULL) && (count < max); node = node->ln_Succ) {
            struct Process *proc = (struct Process *) node;
            struct MsgPort *port = NULL;
            LONG            handles;
            if (node->ln_Type != NT_PROCESS)
                continue;
            if (proc_port_refs(proc, &port, &handles) == FALSE)
                continue;
            ent[count].port      = port;
            ent[count].cli_num   = proc->pr_TaskNum;
            ent[count].suspended = task_is_suspended(&proc->pr_Task);
            ent[count].queued    = 0;
            {
                struct Node *msg;
                for (msg = port->mp_MsgList.lh_Head; msg->ln_Succ != NULL;
                     msg = msg->ln_Succ)
                    ent[count].queued++;
            }
            proc_command_name(proc, ent[count].name, sizeof (ent[count].name));
            count++;
        }
    }
    Permit();

    if (count == 0) {
        printf("No abandoned console ports found\n");
    } else {
        printf("CLI  Port        State      Queued  Command\n");
        for (cur = 0; cur < count; cur++) {
            char cli_str[12];
            if (ent[cur].cli_num == 0) {
                /*
                 * A non-CLI process (such as the reader thread of a reterm
                 * which was run in the session) inherits the console task
                 * of its parent. It can not be attached with -A, so it is
                 * shown only if no CLI process uses the same port.
                 */
                int other;
                for (other = 0; other < count; other++)
                    if ((ent[other].port == ent[cur].port) &&
                        (ent[other].cli_num != 0))
                        break;
                if (other < count)
                    continue;
                strcpy(cli_str, "-");
            } else {
                sprintf(cli_str, "%ld", (long) ent[cur].cli_num);
            }
            printf("%3s  %08lx    %-9s  %6ld  %s\n",
                   cli_str, (unsigned long) ent[cur].port,
                   ent[cur].suspended ? "suspended" : "waiting",
                   (long) ent[cur].queued, ent[cur].name);
        }
        printf("Use \"reterm -A <cli>\" to attach to a waiting program.\n");
    }
    FreeVec(ent);
}

/*
 * claim_abandoned_port() finds the abandoned console port used by the
 *                        specified CLI process, and marks it as claimed
 *                        by this task so that no other reterm will attach
 *                        to it. The reader thread later takes it over.
 */
static BOOL
claim_abandoned_port(glob_t *glob, LONG cli_num)
{
    struct Process *proc;
    struct MsgPort *port = NULL;
    LONG            handles;
    const char     *errmsg = NULL;

    Forbid();
    proc = FindCliProc(cli_num);
    if (proc == NULL) {
        errmsg = "There is no CLI process %ld";
    } else if (proc_port_refs(proc, &port, &handles) == FALSE) {
        errmsg = "CLI %ld does not have an abandoned console";
    } else if (task_is_suspended(&proc->pr_Task)) {
        errmsg = "CLI %ld is suspended (crashed) and can not be resumed";
    } else {
        (void) port_users(port, TRUE, &handles);
        port->mp_SigTask   = FindTask(NULL);  // Claimed; still PA_IGNORE
        glob->adopt_port    = port;
        glob->adopt_proc    = proc;
        glob->adopt_handles = handles;
    }
    Permit();

    if (errmsg != NULL) {
        warnx(errmsg, (long) cli_num);
        return (FALSE);
    }
    return (TRUE);
}

/* unclaim_abandoned_port() releases a port claimed but not yet adopted */
static void
unclaim_abandoned_port(glob_t *glob)
{
    struct MsgPort *port = glob->adopt_port;
    Forbid();
    if ((port != NULL) && (port->mp_SigTask == FindTask(NULL)) &&
        ((port->mp_Flags & PF_ACTION) == PA_IGNORE))
        port->mp_SigTask = NULL;
    Permit();
}

/*
 * session_app_active() returns TRUE if the session application may still
 *                      use the console.
 */
static BOOL
session_app_active(glob_t *glob)
{
    if (glob->adopted)
        return (port_in_use(glob->app_cons_msgport));
    return (glob->open_count > glob->orphan_count);
}

/*
 * report_detach() announces that a session has detached from a program
 *                 which is still using its console.
 */
static void
report_detach(glob_t *glob)
{
    struct MsgPort *port    = glob->app_cons_msgport;
    LONG            cli_num = 0;
    char            name[32];
    struct List    *lists[2];
    struct Node    *node;
    int             list;

    name[0]  = '\0';
    lists[0] = &((struct ExecBase *) SysBase)->TaskWait;
    lists[1] = &((struct ExecBase *) SysBase)->TaskReady;
    Forbid();
    for (list = 0; (list < 2) && (cli_num == 0); list++) {
        for (node = lists[list]->lh_Head; node->ln_Succ != NULL;
             node = node->ln_Succ) {
            struct Process *proc = (struct Process *) node;
            struct MsgPort *mp   = port;
            LONG            handles;
            if ((node->ln_Type != NT_PROCESS) ||
                (proc->pr_TaskNum == 0) ||
                task_is_suspended(&proc->pr_Task) ||
                (proc_port_refs(proc, &mp, &handles) == FALSE))
                continue;
            cli_num = proc->pr_TaskNum;
            proc_command_name(proc, name, sizeof (name));
            break;
        }
    }
    Permit();

    if (cli_num != 0) {
        warnx("Client %d: CLI %ld (%s) still using console; detached "
              "(reattach with \"reterm -A %ld\")", glob->client_number,
              (long) cli_num, name, (long) cli_num);
    } else {
        warnx("Client %d: program still using console; detached",
              glob->client_number);
    }
}

static void
SignalTask(struct Task *task, ULONG signal_set)
{
    if (is_valid_task(task))
        Signal(task, signal_set);
}

static void
signal_child(glob_t *glob, ULONG signal_set)
{
    Forbid();
    if (glob->child_stask_mp != NULL)
        SignalTask(glob->child_stask_mp->mp_SigTask, signal_set);

    if ((glob->child_rtask_mp != NULL) &&
        (glob->child_rtask_mp != glob->child_stask_mp))
        SignalTask(glob->child_rtask_mp->mp_SigTask, signal_set);

    if ((glob->child_wtask_mp != NULL) &&
        (glob->child_wtask_mp != glob->child_stask_mp) &&
        (glob->child_wtask_mp != glob->child_rtask_mp))
        SignalTask(glob->child_wtask_mp->mp_SigTask, signal_set);
    Permit();
}

/* unsignal_task() clears signals pending (received but not yet seen) */
static void
unsignal_task(struct Task *task, ULONG signal_set)
{
    if (is_valid_task(task)) {
        Disable();  // Signal() may be called from interrupts
        task->tc_SigRecvd &= ~signal_set;
        Enable();
    }
}

/*
 * unsignal_child() clears signals sent by signal_child() which the
 *                  application has not yet seen. This is a little unusual,
 *                  but a detached application must not be left with a
 *                  pending break, as many programs (those using the C
 *                  library's break checking) would then exit without
 *                  cleanup (leaking windows) at their next stdio call
 *                  after reattach.
 */
static void
unsignal_child(glob_t *glob, ULONG signal_set)
{
    Forbid();
    if (glob->child_stask_mp != NULL)
        unsignal_task(glob->child_stask_mp->mp_SigTask, signal_set);
    if (glob->child_rtask_mp != NULL)
        unsignal_task(glob->child_rtask_mp->mp_SigTask, signal_set);
    if (glob->child_wtask_mp != NULL)
        unsignal_task(glob->child_wtask_mp->mp_SigTask, signal_set);
    Permit();
}

static LONG
do_paste(glob_t *glob, LONG action, LONG buf, LONG len)
{
    pastenode_t *node;

    if (len == 0)
        return (0);

    node = AllocVec(sizeof (*node) + len, MEMF_PUBLIC);
    if (node == NULL)
        return (-1);

    node->len = len;
    memcpy(node->buf, (void *) buf, len);

    Forbid();
    switch (action) {
        default:
        case ACTION_QUEUE:
            AddTail(&glob->pending_pastes, &node->node);
            break;
        case ACTION_STACK:
            AddHead(&glob->pending_pastes, &node->node);
            break;
    }
    Permit();
    return (len);
}

/*
 * reader_consume() will consume up to the specified number of bytes from
 *                  either the pending read buffer or the paste buffer.
 *                  If the supplied buffer is NULL, this function will
 *                  only report whether bytes are available. Data is
 *                  headed to the user application from this function.
 */
static int
reader_consume(glob_t *glob, UBYTE *buf, LONG bytes_req)
{
    UBYTE *obuf = buf;
    LONG bytes_avail;
    LONG len = 0;

    if (buf == NULL) {   // Just report if input is available
        /* Likely this is ACTION_WAIT_CHAR */
        if ((glob->proc_epos != glob->proc_spos) ||
            (glob->pending_pastes.lh_Head->ln_Succ != NULL))
            return (1);  // Input available
        else
            return (0);  // Input not available
    }

    bytes_avail = glob->proc_epos - glob->proc_spos;
    if (bytes_avail != 0) {
        LONG new_spos;

        /* User input or reply from console handler */
        if (bytes_avail < 0)
            bytes_avail += sizeof (glob->proc_buf);  // wrap
        if (bytes_avail > bytes_req)
            bytes_avail = bytes_req;  // limit transfer to request

        len      = bytes_avail;
        new_spos = glob->proc_spos;

        if (glob->proc_spos + bytes_avail >= sizeof (glob->proc_buf)) {
            /* Buffer wrap -- probably need two memcpy() calls */
            len = sizeof (glob->proc_buf) - glob->proc_spos;
            memcpy(buf, glob->proc_buf + new_spos, len);
            buf     += len;
            len      = bytes_avail - len;
            new_spos = 0;
        }
        /* Copy remainder */
        if (len > 0) {
            memcpy(buf, glob->proc_buf + new_spos, len);
            new_spos += len;
        }
        glob->proc_spos = new_spos;
        len = bytes_avail;
        goto finish;
    }

    if (glob->pending_pastes.lh_Head->ln_Succ != NULL) {
        /* Paste buffer data available */
        pastenode_t *node;

        Forbid();
        if (glob->paste_cur == NULL)
            node = (pastenode_t *) glob->pending_pastes.lh_Head;
        else
            node = glob->paste_cur;
        Permit();

        bytes_avail = node->len - glob->paste_pos;

        len = bytes_avail;
        if (len > bytes_req)
            len = bytes_req;
        memcpy(buf, node->buf + glob->paste_pos, len);

        if (len == bytes_avail) {
            /* Paste buffer is Fully consumed */
            Forbid();
            Remove(&node->node);
            Permit();
            FreeVec(node);
            glob->paste_pos = 0;
            glob->paste_cur = NULL;
        } else {
            /* Not fully consumed yet -- save for next time */
            glob->paste_pos += len;
            glob->paste_cur = node;
        }
    }

finish:
    if (len > 0) {
        if ((glob->capture_AFH != 0) && glob->capture_input) {
            Write(glob->capture_AFH, "{", 1);
            Write(glob->capture_AFH, obuf, len);
            Write(glob->capture_AFH, "}", 1);
        }
#ifdef DEBUG
        if (glob->debug_mode) {
            int pos;
            DPRINT(" READ");
            for (pos = 0; pos < len; pos++)
                DPRINT(" %02x", obuf[pos]);
            DPRINT("\n");
        }
#endif
    }
    return (len);
}

/* Input and Output mode states */
#define XT_MODE_NONE      0  /* Normal output */
#define XT_MODE_ESC       1  /* ESC */
#define XT_MODE_CSI       2  /* ESC [  (CSI mode) */
#define XT_MODE_OSC       3  /* ESC ]  (OSC mode) */
#define XT_MODE_HASH      4  /* ESC #  (DEC mode) */
#define XT_MODE_DISCARD_1 5  /* Discard ESC sequence trailing character */
#define XT_MODE_IAC       6  /* Telnet IAC (start of sequence) */
/*
 * NOTE: Other input states (for telnet negotiation) are
 *     TELNET_WILL
 *     TELNET_WONT
 *     TELNET_DO
 *     TELNET_DONT
 */

static int
getnum(const char *buf, int *num)
{
    int pos = 0;
    while (buf[pos] >= 8 && buf[pos] <= 13)
        pos++;  /* BS HT LF VT FF CR */
    (void) sscanf(buf + pos, "%d%n", num, &pos);

    /* Ignore cursor controls (these were processed earlier) */
    while (buf[pos] >= 8 && buf[pos] <= 13)
        pos++;  /* BS HT LF VT FF CR */

    if (buf[pos] == ';')
        pos++;
    return (pos);
}

/*
 * tcp_wait_writable() waits for the (non-blocking) reader socket to have
 *                     send buffer space. It returns FALSE if reterm is
 *                     stopping, in which case the caller should give up.
 *                     The wait is interruptible by stop_readers().
 */
static BOOL
tcp_wait_writable(glob_t *glob)
{
    struct Library *SocketBase = glob->socketbase_reader;
    LONG            sock       = glob->tcp_socket_reader;

    while (glob->stopping == FALSE) {
        fd_set         wrset;
        struct timeval tv;
        ULONG          signals = glob->reader_wake_signal;
        LONG           rc;

        FD_ZERO(&wrset);
        FD_SET(sock, &wrset);
        tv.tv_sec  = 1;
        tv.tv_usec = 0;
        rc = WaitSelect(sock + 1, NULL, &wrset, NULL, &tv, &signals);
        if (rc < 0) {
            if (Errno() == EINTR)
                continue;
            glob->stopping = TRUE;
            break;
        }
        if ((rc > 0) && FD_ISSET(sock, &wrset))
            return (TRUE);
    }
    return (FALSE);
}

/*
 * xterm_console_emit_raw() sends bytes to the remote terminal exactly as
 *                          given (no telnet IAC escaping, no capture).
 */
static void
xterm_console_emit_raw(glob_t *glob, const UBYTE *buf, LONG len)
{
    if (glob->tcp_port != 0) {
        /* TCP socket (non-blocking) */
        LONG            sock       = glob->tcp_socket_reader;
        struct Library *SocketBase = glob->socketbase_reader;
        while ((len > 0) && (SocketBase != NULL) && (sock >= 0)) {
            LONG count = send(sock, (UBYTE *)buf, len, 0);
            if (count < 0) {
                LONG error = Errno();
                if (((error == EWOULDBLOCK) || (error == EINTR)) &&
                    tcp_wait_writable(glob)) {
                    continue;  // Remote is slow; retry
                }
                glob->stopping = TRUE;
                break;
            }
            buf += count;
            len -= count;
        }
    } else {
        /* Amiga device */
        Write(glob->reader_OFH, (UBYTE *) buf, len);
    }
}

/*
 * telnet_emit() sends a telnet protocol command (which begins with IAC)
 *               to the remote. It must not be IAC-escaped.
 */
static void
telnet_emit(glob_t *glob, const UBYTE *buf, LONG len)
{
    if ((glob->capture_XFH != 0) && glob->capture_output)
        Write(glob->capture_XFH, (UBYTE *) buf, len);
    xterm_console_emit_raw(glob, buf, len);
}

/*
 * xterm_console_emit() sends data to the remote terminal. When the telnet
 *                      protocol is active, any data byte of 0xff must be
 *                      sent as IAC IAC (RFC-854), or the remote will
 *                      interpret it and following bytes as a telnet command.
 */
static void
xterm_console_emit(glob_t *glob, const UBYTE *buf, LONG len)
{
    static const UBYTE iac_iac[] = {TELNET_IAC, TELNET_IAC};
    LONG pos;
    LONG spos = 0;

    if ((glob->capture_XFH != 0) && glob->capture_output)
        Write(glob->capture_XFH, (UBYTE *) buf, len);

    if (glob->support_telnet == FALSE) {
        xterm_console_emit_raw(glob, buf, len);
        return;
    }

    for (pos = 0; pos < len; pos++) {
        if (buf[pos] != TELNET_IAC)
            continue;
        if (pos != spos)
            xterm_console_emit_raw(glob, buf + spos, pos - spos);
        xterm_console_emit_raw(glob, iac_iac, sizeof (iac_iac));
        spos = pos + 1;
    }
    if (pos != spos)
        xterm_console_emit_raw(glob, buf + spos, pos - spos);
}

/*
 * xterm_console_emit_text() sends ISO 8859-1 text (such as the user's
 *                           command line) to the remote terminal, converting
 *                           to UTF-8 if enabled. Latin-1 0xa0-0xff is
 *                           U+00A0-U+00FF, which is a two-byte sequence.
 */
static void
xterm_console_emit_text(glob_t *glob, const UBYTE *buf, LONG len)
{
    LONG pos;
    LONG spos = 0;

    if (glob->support_utf8 == FALSE) {
        xterm_console_emit(glob, buf, len);
        return;
    }
    for (pos = 0; pos < len; pos++) {
        UBYTE tbuf[2];
        if (buf[pos] < 0xa0)
            continue;
        if (pos != spos)
            xterm_console_emit(glob, buf + spos, pos - spos);
        tbuf[0] = 0xc0 | (buf[pos] >> 6);
        tbuf[1] = 0x80 | (buf[pos] & 0x3f);
        xterm_console_emit(glob, tbuf, sizeof (tbuf));
        spos = pos + 1;
    }
    if (pos != spos)
        xterm_console_emit(glob, buf + spos, pos - spos);
}

/*
 * task_window_collect() frees IDCMP messages which the application has
 *                       replied. If wait_ticks is non-zero, it waits up
 *                       to that long for outstanding replies. It returns
 *                       the number of messages still outstanding.
 */
static int
task_window_collect(glob_t *glob, int wait_ticks)
{
    struct Message *msg;

    if (glob->wk_reply_mp == NULL)
        return (0);
    for (;;) {
        while ((msg = GetMsg(glob->wk_reply_mp)) != NULL) {
            FreeVec(msg);
            glob->wk_outstanding--;
        }
        if ((glob->wk_outstanding <= 0) || (wait_ticks-- <= 0))
            break;
        Delay(1);
    }
    return (glob->wk_outstanding);
}

/*
 * task_window_send() sends an IDCMP message to the specified window, as
 *                    Intuition would when the user operates a gadget or
 *                    menu. It does not wait for the reply, as the
 *                    application may first do console I/O (such as
 *                    reporting the selection), which this (reader) thread
 *                    must handle. Replies are collected by
 *                    task_window_collect().
 */
static BOOL wk_window_open(struct Window *target);

/*
 * wk_input_problem() returns why the window's program can not now receive
 *                    input from the window, or NULL if it can. A program
 *                    may delete its IDCMP port (ModifyIDCMP(win, 0)) while
 *                    busy, or block the window with a requester, which on
 *                    the Amiga stops gadget and menu input from the user.
 *                    Caller holds LockIBase().
 */
static const char *
wk_input_problem(struct Window *window)
{
    if (window->UserPort == NULL)
        return ("The program is not accepting input from its window.");
    if (window->FirstRequest != NULL)
        return ("The window is blocked by a requester (the program may be "
                "busy).");
    return (NULL);
}

static BOOL
task_window_send(glob_t *glob, struct Window *window, ULONG class,
                 UWORD code, APTR iaddress)
{
    struct IntuiMessage *im;
    const char          *problem = NULL;
    ULONG                ilock;

    (void) task_window_collect(glob, 0);
    if (glob->wk_reply_mp == NULL) {
        glob->wk_reply_mp = CreateMsgPort();
        if (glob->wk_reply_mp == NULL) {
            warnx("Could not create gadget msgport");
            return (FALSE);
        }
    }
    im = AllocVec(sizeof (*im), MEMF_PUBLIC | MEMF_CLEAR);
    if (im == NULL) {
        warnx("Could not create intuimessage");
        return (FALSE);
    }
    im->ExecMessage.mn_ReplyPort    = glob->wk_reply_mp;
    im->ExecMessage.mn_Length       = sizeof (*im) - sizeof (im->ExecMessage);
    im->ExecMessage.mn_Node.ln_Type = NT_MESSAGE;
    im->Class       = class;
    im->Code        = code;
    im->Qualifier   = 0;  // ie_Qualifier
    im->IAddress    = iaddress;
    im->MouseX      = 0;
    im->MouseY      = 0;
    im->IDCMPWindow = window;
    im->SpecialLink = NULL;
    CurrentTime(&im->Seconds, &im->Micros);

    /*
     * The window can not close while Intuition is locked, and Forbid()
     * keeps the program from removing its IDCMP port (or changing what it
     * accepts) between the check and PutMsg().
     */
    ilock = LockIBase(0);
    Forbid();
    if (wk_window_open(window) == FALSE)
        problem = "The window has closed.";
    else if ((problem = wk_input_problem(window)) != NULL)
        ;
    else if ((window->IDCMPFlags & class) == 0)
        problem = "The program no longer accepts this input.";
    if (problem == NULL) {
        glob->wk_outstanding++;
        PutMsg(window->UserPort, &im->ExecMessage);
    }
    Permit();
    UnlockIBase(ilock);

    if (problem != NULL) {
        FreeVec(im);
        xterm_console_emit(glob, (UBYTE *) problem, strlen(problem));
        xterm_console_emit(glob, (UBYTE *) " Nothing was sent.\r\n", 20);
        return (FALSE);
    }
    return (TRUE);
}

static int __regargs
#ifdef FBASEREL
__saveds
#endif
runner_thread(register char *arg, register long len);

/*
 * gadget_label() returns the text label of a gadget, or NULL if it has none.
 */
static UBYTE *
gadget_label(struct Gadget *gadget)
{
    struct IntuiText *it;
    UBYTE            *str;
    switch (gadget->Flags & GFLG_LABELMASK) {
        case GFLG_LABELSTRING:
            str = (UBYTE *) gadget->GadgetText;
            break;
        case GFLG_LABELITEXT:
            it  = gadget->GadgetText;
            str = (it != NULL) ? it->IText : NULL;
            break;
        default:  // GFLG_LABELIMAGE: GadgetText is an Image
            str = NULL;
            break;
    }
    if ((str != NULL) && (str[0] == '\0'))
        str = NULL;  // Empty label (such as GadTools MX items)
    return (str);
}

/*
 * label_matches() compares a gadget label with a word, ignoring case and
 *                 keyboard shortcut underscores.
 */
static BOOL
label_matches(const UBYTE *label, const char *word)
{
    if (label == NULL)
        return (FALSE);
    while (*label != '\0') {
        UBYTE ch = *label++;
        if (ch == '_')
            continue;
        if ((ch >= 'A') && (ch <= 'Z'))
            ch += 'a' - 'A';
        if (ch != (UBYTE) *word++)
            return (FALSE);
    }
    return (*word == '\0');
}

/*
 * dup_path_list() returns a copy of a CLI command path list (cli_CommandDir)
 *                 suitable for NP_Path, or 0 if the list is empty.
 */
static BPTR
dup_path_list(BPTR list)
{
    BPTR  head = 0;
    BPTR *tail = &head;
    int   count = 0;

    /* Each node is { BPTR next; BPTR lock; }, allocated with AllocVec() */
    while ((list != 0) && (count++ < 100)) {
        BPTR *node = BADDR(list);
        BPTR *copy = AllocVec(2 * sizeof (BPTR), MEMF_PUBLIC | MEMF_CLEAR);
        if (copy == NULL)
            break;
        copy[1] = DupLock(node[1]);
        if (copy[1] == 0) {
            FreeVec(copy);
        } else {
            *tail = MKBADDR(copy);
            tail  = &copy[0];
        }
        list = node[0];
    }
    return (head);
}

/*
 * replace_suspended_shell() starts a new shell on the session console to
 *                           replace a shell process which crashed and was
 *                           suspended at the "Software Failure" requester.
 *                           The suspended process will never close its
 *                           console handles, so those are counted as
 *                           orphaned. The new shell inherits the command
 *                           path and current directory of the old one.
 */
static void
replace_suspended_shell(glob_t *glob, struct Process *proc)
{
    char  runner_name[64];
    BPTR  path    = 0;
    BPTR  curdir  = 0;
    struct CommandLineInterface *cli;

    if (glob->runner_thread_alive) {
        const char *msg = "Session is already starting a shell.\r\n";
        xterm_console_emit(glob, msg, strlen(msg));
        return;
    }

    Forbid();
    glob->orphan_count = glob->open_count;
    glob->child_rtask_mp = NULL;
    glob->child_wtask_mp = NULL;
    glob->child_stask_mp = NULL;
    Permit();

    /* The suspended process is frozen, so its CLI may be safely read */
    if (is_valid_task(proc) &&
        (proc->pr_Task.tc_Node.ln_Type == NT_PROCESS)) {
        cli = BADDR(proc->pr_CLI);
        if (cli != NULL)
            path = dup_path_list(cli->cli_CommandDir);
        if (proc->pr_CurrentDir != 0)
            curdir = DupLock(proc->pr_CurrentDir);
    }

    {
        const char *msg = "Starting a new shell to replace the suspended "
                          "one.\r\n";
        xterm_console_emit(glob, msg, strlen(msg));
    }

    sprintf(runner_name, "reterm-runner-%d", glob->client_number);
    glob->runner_thread_alive = TRUE;
    if (CreateNewProcTags(NP_Entry, (ULONG) runner_thread,
                          NP_Cli, TRUE,
                          (path != 0) ? NP_Path : TAG_IGNORE, (ULONG) path,
                          (curdir != 0) ? NP_CurrentDir : TAG_IGNORE,
                                          (ULONG) curdir,
                          NP_Name, (ULONG) runner_name,
                          NP_StackSize, 2000,
                          NP_ExitData, (ULONG) glob,
                          TAG_END) == NULL) {
        warnx("Failed to start replacement runner");
        glob->runner_thread_alive = FALSE;
        if (curdir != 0)
            UnLock(curdir);
        while (path != 0) {
            BPTR *node = BADDR(path);
            path = node[0];
            UnLock(node[1]);
            FreeVec(node);
        }
    }
}

/*
 * is_requester_helper() returns TRUE if the specified task opens requester
 *                       windows on behalf of other programs. The AmigaOS 3.2
 *                       AssignWedge task opens the "Volume Request" window
 *                       which would otherwise be opened by the program.
 *                       Caller must hold LockIBase() or Forbid().
 */
static BOOL
is_requester_helper(struct Task *task)
{
    const char *name;
    if (task == NULL)
        return (FALSE);
    name = task->tc_Node.ln_Name;
    return ((name != NULL) && (strstr(name, "AssignWedge") != NULL));
}

/*
 * Window control prompt
 *
 * When the requester abort key (^C) is pressed and the application has a
 * window open, the user is prompted to select one of the window's buttons,
 * one of its title bar gadgets, or its menu. Selecting the menu lists the
 * menu titles, then the items (and sub-items) of the selected menu.
 * Backspace returns to the previous list, and ESC cancels the prompt.
 */
#define WK_GADGETS    1  // Buttons, title bar gadgets and menu
#define WK_MENUS      2  // Menu titles
#define WK_ITEMS      3  // Items of the selected menu
#define WK_SUBITEMS   4  // Sub-items of the selected item
#define WK_TEXT       5  // Entering text for a string gadget

#define WK_OPT_GADGET 0  // Button gadget
#define WK_OPT_CLOSE  1  // Title bar close gadget
#define WK_OPT_DEPTH  2  // Title bar depth gadget
#define WK_OPT_ZOOM   3  // Title bar zoom gadget
#define WK_OPT_MENU   4  // Menu strip
#define WK_OPT_STRING 5  // String or integer gadget
#define WK_OPT_NONE   0xff  // No option for this key

#define WK_ESC_NONE   0
#define WK_ESC_WAIT   1  // ESC received; waiting to see if a sequence follows
#define WK_ESC_SEQ    2  // Discarding a cursor or function key sequence

#define WK_ACT_NONE   0
#define WK_ACT_FRONT  1  // WindowToFront()
#define WK_ACT_BACK   2  // WindowToBack()
#define WK_ACT_ZOOM   3  // ZipWindow()

#define WK_MAX_OPTS   36  // Keys available (menus and items)
#define WK_GAD_KEYS   26  // Keys for gadget options (A-Z)
#define WK_KEY_MENU   25  // 'Z' is always [Menu], if the window has one
#define WK_BUF_SIZE   4096
static const char wk_keys[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

typedef struct {
    UBYTE          type;    // WK_OPT_*
    struct Gadget *gadget;
} wk_opt_t;

typedef struct {
    char *buf;
    int   len;
} wk_buf_t;

static BOOL
wk_buf_init(wk_buf_t *wb)
{
    wb->len = 0;
    wb->buf = AllocVec(WK_BUF_SIZE, MEMF_ANY);
    return (wb->buf != NULL);
}

__attribute__((format(printf, 2, 3)))
static void
wk_add(wk_buf_t *wb, const char *fmt, ...)
{
    va_list ap;
    int     count;

    if (wb->len >= WK_BUF_SIZE - 1)
        return;
    va_start(ap, fmt);
    count = vsnprintf(wb->buf + wb->len, WK_BUF_SIZE - wb->len, fmt, ap);
    va_end(ap);
    if (count > 0)
        wb->len += count;
    if (wb->len > WK_BUF_SIZE - 1)
        wb->len = WK_BUF_SIZE - 1;
}

static void
wk_buf_emit(glob_t *glob, wk_buf_t *wb)
{
    if (wb->len > 0)
        xterm_console_emit(glob, (UBYTE *) wb->buf, wb->len);
    FreeVec(wb->buf);
    wb->buf = NULL;
}

static void xterm_esc_timer_start(glob_t *glob);
static void xterm_timer_cancel(glob_t *glob);

static void
wk_reset(glob_t *glob)
{
    if (glob->wk_esc == WK_ESC_WAIT)
        xterm_timer_cancel(glob);
    glob->wk_esc = WK_ESC_NONE;
    glob->requester_abort_active = FALSE;
    glob->wk_level  = 0;
    glob->wk_window = NULL;
    glob->wk_sgad   = NULL;
}

/* is_button_gadget() returns TRUE for a (non-system) button gadget */
static BOOL
is_button_gadget(struct Gadget *gadget)
{
    ULONG gtype = gadget->GadgetType;
    return (((gtype & GTYP_GADGETTYPE) == 0) &&
            (((gtype & GTYP_GTYPEMASK) == GTYP_CUSTOMGADGET) ||
             ((gtype & GTYP_GTYPEMASK) == GTYP_BOOLGADGET)));
}

/*
 * is_toggle_gadget() returns TRUE for a gadget which has a selected state:
 *                    a toggle (such as a checkbox), or one which only
 *                    reports being pressed (such as a GadTools MX item).
 */
static BOOL
is_toggle_gadget(struct Gadget *gadget)
{
    return ((gadget->Activation & GACT_TOGGLESELECT) ||
            (((gadget->Activation & GACT_RELVERIFY) == 0) &&
             (gadget->Activation & GACT_IMMEDIATE)));
}

/* is_string_gadget() returns TRUE for a (non-system) string gadget */
static BOOL
is_string_gadget(struct Gadget *gadget)
{
    ULONG              gtype = gadget->GadgetType;
    struct StringInfo *si    = (struct StringInfo *) gadget->SpecialInfo;
    return (((gtype & GTYP_GADGETTYPE) == 0) &&
            ((gtype & GTYP_GTYPEMASK) == GTYP_STRGADGET) &&
            (si != NULL) && (si->Buffer != NULL) && (si->MaxChars > 0));
}

/*
 * window_options() returns the number of options which a window offers:
 *                  title bar gadgets, then button and string gadgets,
 *                  then the menu
 *                  (always last). If want is a valid option number, that
 *                  option is returned in *opt. Caller holds LockIBase().
 */
static int
window_options(struct Window *window, int want, wk_opt_t *opt)
{
    struct Gadget *gadget;
    int            count = 0;
    int            pass;

    for (pass = 0; pass < 2; pass++) {
        for (gadget = window->FirstGadget; gadget != NULL;
             gadget = gadget->NextGadget) {
            UBYTE type;
            if (count >= 250)
                break;
            if (pass == 1) {
                if (is_button_gadget(gadget))
                    type = WK_OPT_GADGET;
                else if (is_string_gadget(gadget))
                    type = WK_OPT_STRING;
                else
                    continue;
            } else {
                if ((gadget->GadgetType & GTYP_SYSGADGET) == 0)
                    continue;
                switch (gadget->GadgetType & GTYP_SYSTYPEMASK) {
                    case GTYP_CLOSE:
                        /* The close gadget does nothing without this */
                        if ((window->IDCMPFlags & IDCMP_CLOSEWINDOW) == 0)
                            continue;
                        type = WK_OPT_CLOSE;
                        break;
                    case GTYP_WDEPTH:
                        type = WK_OPT_DEPTH;
                        break;
                    case GTYP_WZOOM:
                        type = WK_OPT_ZOOM;
                        break;
                    default:  // Sizing and drag bar gadgets
                        continue;
                }
            }
            if (count == want) {
                opt->type   = type;
                opt->gadget = gadget;
            }
            count++;
        }
    }
    if (window->MenuStrip != NULL) {
        if (count == want) {
            opt->type   = WK_OPT_MENU;
            opt->gadget = NULL;
        }
        count++;
    }
    return (count);
}

/*
 * wk_find_window() finds the window of the application to control.
 *                  Caller holds LockIBase().
 *
 * Pass 0 looks for a window opened by the application itself (such as a
 * DOS "System Request"). If there is none, pass 1 looks for a window
 * opened on the application's behalf by a requester helper task, such as
 * the AmigaOS 3.2 AssignWedge "Volume Request". Such a window can not be
 * tied to a specific application, so more than one may be open. Pass 1
 * is skipped if the application is waiting on console I/O, as it then can
 * not be waiting on a requester.
 */
static struct Window *
wk_find_window(glob_t *glob, struct Task *task, int *passp, int *countp)
{
    struct IntuitionBase *ibase = (struct IntuitionBase *) IntuitionBase;
    struct Screen        *screen;
    struct Window        *window;
    struct Window        *found = NULL;
    int                   count;
    int                   pass;

    for (pass = 0; pass < 2; pass++) {
        if ((pass == 1) &&
            ((glob->pending_reads.lh_Head->ln_Succ != NULL) ||
             (glob->pending_app_packet != NULL)))
            break;
        count = 0;
        for (screen = ibase->FirstScreen; screen != NULL;
             screen = screen->NextScreen) {
            for (window = screen->FirstWindow; window != NULL;
                 window = window->NextWindow) {
                struct Task *owner;
                if (window->UserPort == NULL)
                    continue;
                owner = (struct Task *) window->UserPort->mp_SigTask;
                if ((pass == 0) ? (owner != task) :
                                  (is_requester_helper(owner) == FALSE))
                    continue;
                if (window_options(window, -1, NULL) == 0)
                    continue;
                if (found == NULL)
                    found = window;  // First (most recent) matching window
                count++;
            }
        }
        if (found != NULL) {
            *passp  = pass;
            *countp = count;
            return (found);
        }
    }
    return (NULL);
}

/* wk_window_open() verifies the window is still open (holds LockIBase) */
static BOOL
wk_window_open(struct Window *target)
{
    struct IntuitionBase *ibase = (struct IntuitionBase *) IntuitionBase;
    struct Screen        *screen;
    struct Window        *window;

    for (screen = ibase->FirstScreen; screen != NULL;
         screen = screen->NextScreen)
        for (window = screen->FirstWindow; window != NULL;
             window = window->NextWindow)
            if (window == target)
                return (TRUE);
    return (FALSE);
}

static struct Menu *
wk_nth_menu(struct Menu *menu, int want)
{
    while ((menu != NULL) && (want-- > 0))
        menu = menu->NextMenu;
    return (menu);
}

/* wk_item_listed() is FALSE for separator bars (disabled image items) */
static BOOL
wk_item_listed(struct MenuItem *item)
{
    return ((item->Flags & (ITEMTEXT | ITEMENABLED)) != 0);
}

/*
 * wk_nth_item() returns the want'th listed item, and its position in the
 *               item list (as used for the menu number) in *realp.
 */
static struct MenuItem *
wk_nth_item(struct MenuItem *item, int want, int *realp)
{
    int real   = 0;
    int listed = 0;
    for (; item != NULL; item = item->NextItem, real++) {
        if (wk_item_listed(item) == FALSE)
            continue;
        if (listed++ == want) {
            *realp = real;
            return (item);
        }
    }
    return (NULL);
}

/*
 * Gadget label recognition
 *
 * Some programs draw button labels directly into the window (or as an
 * image) rather than giving the gadget a text label. Such text is drawn
 * with a bitmap font without anti-aliasing, so the pixels in the gadget
 * box exactly match the font glyphs. The pixels are read back from the
 * window, and for each candidate font, row offset and text pen, matched
 * against the glyph bitmaps of the font.
 *
 * Pixels which may not belong to the text are "wild" (ignored): the top
 * and bottom rows and two edge columns of the gadget box, where its frame
 * is drawn, and for a disabled gadget, the lattice of Intuition's ghosting
 * dot pattern (every fourth pixel, offset by two on alternate rows).
 *
 * For speed, glyphs are indexed by their first column which has ink
 * outside the wild rows, and the glyph matching at each position is found
 * once and then followed to decode lines of text.
 */
#define GR_MAX_W     320  // Largest gadget box examined
#define GR_MAX_H     40
#define GR_MAX_PENS  4    // Number of candidate text pens tried
#define GR_EDGE      2    // Text may not touch this many edge columns
#define GR_MAX_FONTS 3

typedef struct {
    WORD  d;              // Column offset (kern + column) from origin
    UWORD ch;             // Glyph number
    ULONG key;            // Non-wild bits of that column
} gr_ent_t;

typedef struct {
    int       lo;         // First character
    int       count;      // Number of characters
    int       ysize;
    int       xsize;
    ULONG    *mask;       // Column masks of all glyphs (bit 0 = top row)
    UWORD    *start;      // Index of first column mask of each glyph
    UBYTE    *width;      // Glyph bit width
    UBYTE    *ink;        // Number of set pixels (match preference)
    UBYTE    *ink_first;  // First column with ink (0xff if none)
    UBYTE    *ink_last;   // Last column with ink
    WORD     *kern;
    WORD     *space;
    gr_ent_t *ent;        // Index, sorted by d then key
    int       nent;
    WORD      dlist[32];  // Distinct d values in the index
    int       nd;
    ULONG     index_rmask;  // Wild row mask the index was built for
    BOOL      index_valid;
} gr_font_t;

typedef struct {
    gr_font_t *fonts[GR_MAX_FONTS];
    int        nfonts;
    UBYTE     *pix;       // Pixel pens of the gadget box
    ULONG     *col;       // Text pen column masks
    ULONG     *wild;      // Wild (ignored) bits of each column
    WORD      *gat;       // Glyph matching at each origin, or -1
    ULONG     *hist;      // Pen histogram
} gr_ctx_t;

typedef struct {
    WORD left;
    WORD top;
    WORD width;
    WORD height;
    BOOL disabled;
} gr_box_t;

/* gr_font_load() builds glyph column masks for a font */
static gr_font_t *
gr_font_load(struct TextFont *tf)
{
    gr_font_t *f;
    ULONG     *loc;
    UBYTE     *data;
    int        count;
    int        cols = 0;
    int        ch;
    UBYTE     *mem;

    if ((tf == NULL) || (tf->tf_YSize < 4) || (tf->tf_YSize > 32) ||
        (tf->tf_CharData == NULL) || (tf->tf_CharLoc == NULL) ||
        (tf->tf_HiChar < tf->tf_LoChar))
        return (NULL);
    count = tf->tf_HiChar - tf->tf_LoChar + 1;
    loc   = (ULONG *) tf->tf_CharLoc;
    data  = (UBYTE *) tf->tf_CharData;
    for (ch = 0; ch < count; ch++) {
        int width = loc[ch] & 0xffff;
        if (width <= 32)
            cols += width;
    }
    mem = AllocVec(sizeof (*f) + count * sizeof (gr_ent_t) +
                   cols * sizeof (ULONG) +
                   count * (sizeof (UWORD) + 2 * sizeof (WORD) + 4) + 4,
                   MEMF_ANY | MEMF_CLEAR);
    if (mem == NULL)
        return (NULL);
    f            = (gr_font_t *) mem;
    f->ent       = (gr_ent_t *) (mem + sizeof (*f));
    f->mask      = (ULONG *) (f->ent + count);
    f->kern      = (WORD *) (f->mask + cols);
    f->space     = f->kern + count;
    f->start     = (UWORD *) (f->space + count);
    f->width     = (UBYTE *) (f->start + count);
    f->ink       = f->width + count;
    f->ink_first = f->ink + count;
    f->ink_last  = f->ink_first + count;
    f->lo        = tf->tf_LoChar;
    f->count     = count;
    f->ysize     = tf->tf_YSize;
    f->xsize     = tf->tf_XSize;

    cols = 0;
    for (ch = 0; ch < count; ch++) {
        ULONG off   = loc[ch] >> 16;
        int   width = loc[ch] & 0xffff;
        int   col;
        int   row;
        int   ink = 0;

        if (width > 32)
            width = 0;
        f->start[ch]     = cols;
        f->width[ch]     = width;
        f->ink_first[ch] = 0xff;
        f->kern[ch]      = (tf->tf_CharKern != NULL) ?
                           ((WORD *) tf->tf_CharKern)[ch] : 0;
        f->space[ch]     = ((tf->tf_Flags & FPF_PROPORTIONAL) &&
                            (tf->tf_CharSpace != NULL)) ?
                           ((WORD *) tf->tf_CharSpace)[ch] : tf->tf_XSize;
        for (col = 0; col < width; col++) {
            ULONG bit  = off + col;
            ULONG mask = 0;
            for (row = 0; row < f->ysize; row++) {
                if (data[row * tf->tf_Modulo + (bit >> 3)] &
                    (0x80 >> (bit & 7))) {
                    mask |= 1UL << row;
                    ink++;
                }
            }
            f->mask[cols + col] = mask;
            if (mask != 0) {
                if (f->ink_first[ch] == 0xff)
                    f->ink_first[ch] = col;
                f->ink_last[ch] = col;
            }
        }
        f->ink[ch] = (ink > 255) ? 255 : ink;
        cols += width;
    }
    return (f);
}

/*
 * gr_index_build() indexes the glyphs by their first column with ink
 *                  outside the wild rows (rmask).
 */
static void
gr_index_build(gr_font_t *f, ULONG rmask)
{
    int ch;
    int cur;

    if (f->index_valid && (f->index_rmask == rmask))
        return;
    f->nent = 0;
    f->nd   = 0;
    for (ch = 0; ch < f->count; ch++) {
        ULONG *gm = f->mask + f->start[ch];
        int    c;
        for (c = 0; c < f->width[ch]; c++) {
            if (gm[c] & ~rmask) {
                gr_ent_t ent;
                int      pos = f->nent++;
                ent.d   = f->kern[ch] + c;
                ent.ch  = ch;
                ent.key = gm[c] & ~rmask;
                /* Insertion sort by d, then key */
                while ((pos > 0) &&
                       ((f->ent[pos - 1].d > ent.d) ||
                        ((f->ent[pos - 1].d == ent.d) &&
                         (f->ent[pos - 1].key > ent.key)))) {
                    f->ent[pos] = f->ent[pos - 1];
                    pos--;
                }
                f->ent[pos] = ent;
                break;
            }
        }
    }
    for (cur = 0; cur < f->nent; cur++) {
        if (((cur == 0) || (f->ent[cur].d != f->ent[cur - 1].d)) &&
            (f->nd < 32))
            f->dlist[f->nd++] = f->ent[cur].d;
    }
    f->index_rmask = rmask;
    f->index_valid = TRUE;
}

/*
 * gr_verify() returns TRUE if glyph ch exactly matches (ignoring wild
 *             bits) with its origin at x, and has ink outside wild bits.
 */
static BOOL
gr_verify(gr_font_t *f, int ch, const ULONG *col, const ULONG *wild,
          int width, int x)
{
    ULONG *gm = f->mask + f->start[ch];
    ULONG  ink = 0;
    int    gx = x + f->kern[ch];
    int    c;

    if ((gx < 0) || (gx + f->width[ch] > width))
        return (FALSE);
    for (c = 0; c < f->width[ch]; c++) {
        ULONG wm = wild[gx + c];
        if ((col[gx + c] ^ gm[c]) & ~wm)
            return (FALSE);
        ink |= gm[c] & ~wm;
    }
    return (ink != 0);
}

/*
 * gr_glyph_at() returns the glyph (preferring the most ink) which matches
 *               with its origin at x, or -1. If rmask is not ~0, the
 *               index is used: wild bits of non-edge columns must then be
 *               exactly rmask.
 */
static int
gr_glyph_at(gr_font_t *f, const ULONG *col, const ULONG *wild, int width,
            int x, BOOL indexed)
{
    int best     = -1;
    int best_ink = 0;
    int ch;

    if (indexed == FALSE) {
        for (ch = 0; ch < f->count; ch++) {
            if ((f->ink[ch] > best_ink) &&
                gr_verify(f, ch, col, wild, width, x)) {
                best     = ch;
                best_ink = f->ink[ch];
            }
        }
        return (best);
    }
    for (ch = 0; ch < f->nd; ch++) {
        int   d  = f->dlist[ch];
        int   px = x + d;
        ULONG key;
        int   low;
        int   high;
        if ((px < 0) || (px >= width) || (wild[px] != f->index_rmask))
            continue;  // Edge column: glyph would be rejected anyway
        key = col[px] & ~f->index_rmask;
        if (key == 0)
            continue;
        /* Binary search for the first entry with (d, key) */
        low  = 0;
        high = f->nent;
        while (low < high) {
            int       mid = (low + high) / 2;
            gr_ent_t *e   = &f->ent[mid];
            if ((e->d < d) || ((e->d == d) && (e->key < key)))
                low = mid + 1;
            else
                high = mid;
        }
        for (; (low < f->nent) && (f->ent[low].d == d) &&
               (f->ent[low].key == key); low++) {
            int gch = f->ent[low].ch;
            if ((f->ink[gch] > best_ink) &&
                gr_verify(f, gch, col, wild, width, x)) {
                best     = gch;
                best_ink = f->ink[gch];
            }
        }
    }
    return (best);
}

/*
 * gr_decode_rows() finds the text with the most characters in the pixels
 *                  of the specified pen at row offset y0.
 */
static int
gr_decode_rows(gr_ctx_t *ctx, gr_font_t *f, int width, int height, int y0,
               UBYTE pen, int ghost, char *out, int outlen)
{
    const UBYTE *pix  = ctx->pix;
    ULONG       *col  = ctx->col;
    ULONG       *wild = ctx->wild;
    WORD        *gat  = ctx->gat;
    ULONG        rmask = 0;
    int          best  = 0;
    int          step  = f->xsize;
    int          row;
    int          x;

    for (row = 0; row < f->ysize; row++)
        if ((y0 + row == 0) || (y0 + row == height - 1))
            rmask |= 1UL << row;  // Frame rows
    if (ghost < 0)
        gr_index_build(f, rmask);
    if ((' ' >= f->lo) && (' ' < f->lo + f->count) &&
        (f->space[' ' - f->lo] > 0))
        step = f->space[' ' - f->lo];

    for (x = 0; x < width; x++) {
        ULONG mask  = 0;
        ULONG wmask = rmask;
        for (row = 0; row < f->ysize; row++) {
            int y = y0 + row;
            if (pix[y * width + x] == pen)
                mask |= 1UL << row;
            if ((ghost >= 0) && (((x + ghost + 2 * (y & 1)) & 3) == 0))
                wmask |= 1UL << row;
        }
        if ((x < GR_EDGE) || (x >= width - GR_EDGE))
            wmask = ~0UL;  // Frame columns
        col[x]  = mask;
        wild[x] = wmask;
    }
    for (x = 0; x < width; x++)
        gat[x] = gr_glyph_at(f, col, wild, width, x, (ghost < 0));

    /* Follow matched glyphs from each origin to decode lines of text */
    for (x = 0; x < width; x++) {
        char text[24];
        int  len    = 0;
        int  chars  = 0;
        int  spaces = 0;
        int  left   = width;
        int  right  = 0;
        int  pos    = x;

        if (gat[x] < 0)
            continue;
        while ((pos < width) && (len + spaces < (int) sizeof (text) - 1)) {
            int ch = gat[pos];
            if (ch >= 0) {
                int gx = pos + f->kern[ch];
                while (spaces > 0) {
                    text[len++] = ' ';
                    spaces--;
                }
                text[len++] = (char) (f->lo + ch);
                chars++;
                if (gx + f->ink_first[ch] < left)
                    left = gx + f->ink_first[ch];
                if (gx + f->ink_last[ch] + 1 > right)
                    right = gx + f->ink_last[ch] + 1;
                pos += (f->space[ch] > 0) ? f->space[ch] : f->xsize;
            } else {
                /* A space is an empty cell */
                int c;
                if ((spaces >= 2) || (pos + step > width))
                    break;
                for (c = pos; c < pos + step; c++)
                    if (col[c] & ~wild[c])
                        break;
                if (c < pos + step)
                    break;  // Unrecognized ink
                spaces++;
                pos += step;
            }
        }
        text[len] = '\0';
        if ((left < GR_EDGE) || (right > width - GR_EDGE))
            continue;  // Touches the frame
        if (chars > best) {
            best = chars;
            strncpy(out, text, outlen);
            out[outlen - 1] = '\0';
        }
    }
    return (best);
}

/*
 * gr_recognize() decodes the label of one gadget box from its pixels
 *                (already in ctx->pix). It returns TRUE if text was found.
 */
static BOOL
gr_recognize(gr_ctx_t *ctx, int width, int height, BOOL disabled, char *out,
             int outlen)
{
    const UBYTE *pix   = ctx->pix;
    ULONG       *count = ctx->hist;
    UBYTE        pens[GR_MAX_PENS];
    int          npens = 0;
    int          best  = 0;
    int          ghost = -1;  // Ghosting pattern phase, if disabled
    int          pos;
    int          pen;
    int          font;

    if (disabled) {
        /* Find the phase where (nearly) all lattice pixels are one pen */
        int phase;
        for (phase = 0; phase < 4; phase++) {
            int total = 0;
            int x;
            int y;
            memset(count, 0, 256 * sizeof (ULONG));
            for (y = 0; y < height; y++) {
                for (x = (8 - phase - 2 * (y & 1)) & 3; x < width; x += 4) {
                    count[pix[y * width + x]]++;
                    total++;
                }
            }
            for (pen = 0; pen < 256; pen++)
                if ((total > 0) && (count[pen] * 10 >= (ULONG) total * 9))
                    ghost = phase;
            if (ghost >= 0)
                break;
        }
    }

    /*
     * Candidate text pens are the most common pens. The most common pen
     * is usually the background, but bold text with a border may have
     * more pixels than the background.
     */
    memset(count, 0, 256 * sizeof (ULONG));
    for (pos = 0; pos < width * height; pos++)
        count[pix[pos]]++;
    while (npens < GR_MAX_PENS) {
        int most = -1;
        for (pen = 0; pen < 256; pen++)
            if ((count[pen] != 0) && ((most < 0) || (count[pen] > count[most])))
                most = pen;
        if ((most < 0) || (count[most] < 2))
            break;
        pens[npens++] = most;
        count[most]   = 0;
    }

    for (font = 0; font < ctx->nfonts; font++) {
        gr_font_t *f = ctx->fonts[font];
        int        y0;
        for (y0 = 0; y0 + f->ysize <= height; y0++) {
            for (pen = 0; pen < npens; pen++) {
                char text[24];
                int  chars = gr_decode_rows(ctx, f, width, height, y0,
                                            pens[pen], ghost, text,
                                            sizeof (text));
                if (chars > best) {
                    best = chars;
                    strncpy(out, text, outlen);
                    out[outlen - 1] = '\0';
                }
            }
        }
    }
    return (best > 0);
}

static void
gr_ctx_free(gr_ctx_t *ctx)
{
    int cur;
    if (ctx == NULL)
        return;
    for (cur = 0; cur < ctx->nfonts; cur++)
        FreeVec(ctx->fonts[cur]);
    if (ctx->pix != NULL)
        FreeVec(ctx->pix);
    if (ctx->col != NULL)
        FreeVec(ctx->col);
    if (ctx->wild != NULL)
        FreeVec(ctx->wild);
    if (ctx->gat != NULL)
        FreeVec(ctx->gat);
    if (ctx->hist != NULL)
        FreeVec(ctx->hist);
    FreeVec(ctx);
}

/*
 * gr_ctx_create() allocates buffers and loads the candidate fonts: the
 *                 window font, the screen font and the system default.
 *                 Caller holds the screen's layer info lock, so the
 *                 window (and its font) remain valid.
 */
static gr_ctx_t *
gr_ctx_create(struct Window *window, struct TextFont *scrfont)
{
    struct TextFont *tfonts[GR_MAX_FONTS];
    gr_ctx_t        *ctx;
    int              cur;

    ctx = AllocVec(sizeof (*ctx), MEMF_ANY | MEMF_CLEAR);
    if (ctx == NULL)
        return (NULL);
    ctx->pix  = AllocVec(GR_MAX_W * GR_MAX_H, MEMF_ANY);
    ctx->col  = AllocVec(GR_MAX_W * sizeof (ULONG), MEMF_ANY);
    ctx->wild = AllocVec(GR_MAX_W * sizeof (ULONG), MEMF_ANY);
    ctx->gat  = AllocVec(GR_MAX_W * sizeof (WORD), MEMF_ANY);
    ctx->hist = AllocVec(256 * sizeof (ULONG), MEMF_ANY);
    if ((ctx->pix == NULL) || (ctx->col == NULL) || (ctx->wild == NULL) ||
        (ctx->gat == NULL) || (ctx->hist == NULL)) {
        gr_ctx_free(ctx);
        return (NULL);
    }
    tfonts[0] = window->RPort->Font;
    tfonts[1] = scrfont;
    tfonts[2] = GfxBase->DefaultFont;
    for (cur = 0; cur < GR_MAX_FONTS; cur++) {
        int other;
        if (tfonts[cur] == NULL)
            continue;
        for (other = 0; other < cur; other++)
            if (tfonts[other] == tfonts[cur])
                break;
        if (other < cur)
            continue;  // Duplicate
        ctx->fonts[ctx->nfonts] = gr_font_load(tfonts[cur]);
        if (ctx->fonts[ctx->nfonts] != NULL)
            ctx->nfonts++;
    }
    if (ctx->nfonts == 0) {
        gr_ctx_free(ctx);
        return (NULL);
    }
    return (ctx);
}

/*
 * gr_gadget_box() computes the box of a gadget in window coordinates.
 *                 It returns FALSE if the box is not suitable. Caller
 *                 holds LockIBase().
 */
static BOOL
gr_gadget_box(struct Window *window, struct Gadget *gadget, gr_box_t *box)
{
    WORD left   = gadget->LeftEdge;
    WORD top    = gadget->TopEdge;
    WORD width  = gadget->Width;
    WORD height = gadget->Height;

    if (gadget->Flags & GFLG_RELRIGHT)
        left += window->Width - 1;
    if (gadget->Flags & GFLG_RELBOTTOM)
        top += window->Height - 1;
    if (gadget->Flags & GFLG_RELWIDTH)
        width += window->Width;
    if (gadget->Flags & GFLG_RELHEIGHT)
        height += window->Height;
    if ((window->Flags & WFLG_GIMMEZEROZERO) &&
        ((gadget->Activation & (GACT_LEFTBORDER | GACT_RIGHTBORDER |
                                GACT_TOPBORDER | GACT_BOTTOMBORDER)) == 0)) {
        left -= window->BorderLeft;
        top  -= window->BorderTop;
    }
    if ((width < 4) || (height < 4) || (width > GR_MAX_W) ||
        (height > GR_MAX_H) || (left < 0) || (top < 0))
        return (FALSE);
    box->left     = left;
    box->top      = top;
    box->width    = width;
    box->height   = height;
    box->disabled = ((gadget->Flags & GFLG_DISABLED) != 0);
    return (TRUE);
}

/* gr_read_box() reads the box pixels. Caller holds the layer info lock. */
static void
gr_read_box(gr_ctx_t *ctx, struct Window *window, gr_box_t *box)
{
    int x;
    int y;
    for (y = 0; y < box->height; y++) {
        for (x = 0; x < box->width; x++) {
            LONG pen = ReadPixel(window->RPort, box->left + x, box->top + y);
            ctx->pix[y * box->width + x] = (pen < 0) ? 0 : (UBYTE) pen;
        }
    }
}

/* wk_recognized_label() returns the recognized label of a gadget */
static const char *
wk_recognized_label(glob_t *glob, struct Gadget *gadget)
{
    int cur;
    for (cur = 0; cur < glob->wk_glabels; cur++)
        if (glob->wk_glabel[cur].gadget == gadget)
            return (glob->wk_glabel[cur].text);
    return (NULL);
}

static void
wk_add_option(glob_t *glob, wk_buf_t *wb, struct Window *window,
              wk_opt_t *opt)
{
    struct Gadget *gadget = opt->gadget;
    UBYTE         *str;

    switch (opt->type) {
        case WK_OPT_GADGET:
            str = gadget_label(gadget);
            if (str == NULL)
                str = (UBYTE *) wk_recognized_label(glob, gadget);
            wk_add(wb, "ID=%d ", gadget->GadgetID);
            if (is_toggle_gadget(gadget)) {
                BOOL sel = (gadget->Flags & GFLG_SELECTED) ? TRUE : FALSE;
                if (gadget->Activation & GACT_TOGGLESELECT)
                    wk_add(wb, "%s", sel ? "[x] " : "[ ] ");  // Checkbox
                else
                    wk_add(wb, "%s", sel ? "(*) " : "( ) ");  // MX item
            }
            if (str != NULL) {
                wk_add(wb, "%.60s\r\n", str);
            } else {
                wk_add(wb, "(%d,%d) %dx%d\r\n",
                       gadget->LeftEdge, gadget->TopEdge,
                       gadget->Width, gadget->Height);
            }
            break;
        case WK_OPT_STRING: {
            struct StringInfo *si = (struct StringInfo *) gadget->SpecialInfo;
            int                pos;
            str = gadget_label(gadget);
            if (str != NULL) {
                wk_add(wb, "ID=%d %.40s = ", gadget->GadgetID, str);
            } else {
                wk_add(wb, "ID=%d (%d,%d) %dx%d = ", gadget->GadgetID,
                       gadget->LeftEdge, gadget->TopEdge,
                       gadget->Width, gadget->Height);
            }
            if (gadget->Activation & GACT_LONGINT) {
                wk_add(wb, "%ld", (long) si->LongInt);
            } else {
                /* Show printable ASCII only; the list is not converted */
                wk_add(wb, "\"");
                for (pos = 0; (pos < si->MaxChars) && (pos < 40) &&
                              (si->Buffer[pos] != '\0'); pos++) {
                    UBYTE ch = si->Buffer[pos];
                    wk_add(wb, "%c", ((ch >= 0x20) && (ch < 0x7f)) ? ch : '?');
                }
                wk_add(wb, "%s\"", ((pos == 40) && (pos < si->MaxChars) &&
                                     (si->Buffer[pos] != '\0')) ? "..." : "");
            }
            wk_add(wb, "%s\r\n",
                   (gadget->Flags & GFLG_DISABLED) ? " (disabled)" : "");
            break;
        }
        case WK_OPT_CLOSE:
            wk_add(wb, "[Close window]\r\n");
            break;
        case WK_OPT_DEPTH:
            if ((window->WLayer != NULL) && (window->WLayer->front == NULL))
                wk_add(wb, "[Depth: send window to back]\r\n");
            else
                wk_add(wb, "[Depth: bring window to front]\r\n");
            break;
        case WK_OPT_ZOOM:
            wk_add(wb, "[Zoom]\r\n");
            break;
        case WK_OPT_MENU:
            wk_add(wb, "[Menu]\r\n");
            break;
    }
}

static void
wk_add_item(wk_buf_t *wb, struct MenuItem *item)
{
    UBYTE *text = NULL;

    if ((item->Flags & ITEMTEXT) && (item->ItemFill != NULL))
        text = ((struct IntuiText *) item->ItemFill)->IText;
    if (item->Flags & CHECKIT)
        wk_add(wb, "%s", (item->Flags & CHECKED) ? "[x] " : "[ ] ");
    wk_add(wb, "%.50s", (text != NULL) ? (char *) text : "(image)");
    if (item->Flags & COMMSEQ)
        wk_add(wb, "  (Amiga-%c)", item->Command);
    if (item->SubItem != NULL)
        wk_add(wb, " >");
    if ((item->Flags & ITEMENABLED) == 0)
        wk_add(wb, " (disabled)");
    wk_add(wb, "\r\n");
}

/* wk_shown_clear() forgets the options shown */
static void
wk_shown_clear(glob_t *glob)
{
    int key;
    for (key = 0; key < WK_MAX_OPTS; key++) {
        glob->wk_shown[key].type = WK_OPT_NONE;
        glob->wk_shown[key].ptr  = NULL;
    }
}

/* wk_shown_set() records the option shown for a key */
static void
wk_shown_set(glob_t *glob, int key, UBYTE type, APTR ptr)
{
    struct Gadget *gadget = (struct Gadget *) ptr;
    if ((key < 0) || (key >= WK_MAX_OPTS))
        return;
    glob->wk_shown[key].type = type;
    glob->wk_shown[key].ptr  = ptr;
    if ((type != WK_OPT_MENU) && (gadget != NULL)) {
        glob->wk_shown[key].id         = gadget->GadgetID;
        glob->wk_shown[key].gtype      = gadget->GadgetType;
        glob->wk_shown[key].activation = gadget->Activation;
        glob->wk_shown[key].text       = gadget->GadgetText;
        glob->wk_shown[key].special    = gadget->SpecialInfo;
    }
}

/*
 * wk_shown_gadget() returns TRUE if the gadget shown for the key is still
 *                   in the window, and is the same gadget (not another
 *                   one which was allocated at the same address).
 *                   Caller holds LockIBase().
 */
static BOOL
wk_shown_gadget(glob_t *glob, struct Window *window, int key)
{
    struct Gadget *gadget = (struct Gadget *) glob->wk_shown[key].ptr;
    struct Gadget *cur;

    for (cur = window->FirstGadget; cur != NULL; cur = cur->NextGadget)
        if (cur == gadget)
            break;
    return ((cur != NULL) &&
            (gadget->GadgetID    == glob->wk_shown[key].id) &&
            (gadget->GadgetType  == glob->wk_shown[key].gtype) &&
            (gadget->Activation  == glob->wk_shown[key].activation) &&
            ((APTR) gadget->GadgetText == glob->wk_shown[key].text) &&
            (gadget->SpecialInfo == glob->wk_shown[key].special));
}

/* wk_show() lists the options of the current prompt level */
static void
wk_show(glob_t *glob, wk_buf_t *wb)
{
    struct Window   *window = glob->wk_window;
    struct Menu     *menu;
    struct MenuItem *item;
    int              cur;

    switch (glob->wk_level) {
        case WK_GADGETS:
            break;  // Shown by wk_show_gadget_page()
        case WK_MENUS:
            wk_add(wb, "Menus:\r\n");
            wk_shown_clear(glob);
            for (menu = window->MenuStrip, cur = 0;
                 (menu != NULL) && (cur < WK_MAX_OPTS);
                 menu = menu->NextMenu, cur++) {
                wk_shown_set(glob, cur, WK_OPT_MENU, menu);
                wk_add(wb, "    %c) %.50s%s\r\n", wk_keys[cur],
                       (menu->MenuName != NULL) ? (char *) menu->MenuName : "",
                       (menu->Flags & MENUENABLED) ? "" : " (disabled)");
            }
            wk_add(wb, "Select a menu (Backspace=back ESC=cancel).\r\n");
            break;
        case WK_ITEMS:
        case WK_SUBITEMS: {
            struct MenuItem *parent = NULL;
            int              real;
            menu = wk_nth_menu(window->MenuStrip, glob->wk_menu);
            if (menu == NULL) {
                wk_shown_clear(glob);
                wk_add(wb, "Menu is no longer present.\r\n");
                break;
            }
            item = menu->FirstItem;
            if (glob->wk_level == WK_SUBITEMS) {
                parent = wk_nth_item(item, glob->wk_item, &real);
                if (parent == NULL) {
                    wk_shown_clear(glob);
                    wk_add(wb, "Menu item is no longer present.\r\n");
                    break;
                }
                item = parent->SubItem;
            }
            wk_add(wb, "%.50s", (menu->MenuName != NULL) ?
                                (char *) menu->MenuName : "");
            if (parent != NULL) {
                UBYTE *text = NULL;
                if ((parent->Flags & ITEMTEXT) && (parent->ItemFill != NULL))
                    text = ((struct IntuiText *) parent->ItemFill)->IText;
                wk_add(wb, " > %.50s", (text != NULL) ? (char *) text : "");
            }
            wk_add(wb, ":\r\n");
            wk_shown_clear(glob);
            glob->wk_shown_menu   = menu;
            glob->wk_shown_parent = parent;
            for (cur = 0; (item != NULL) && (cur < WK_MAX_OPTS);
                 item = item->NextItem) {
                if (wk_item_listed(item) == FALSE)
                    continue;
                wk_shown_set(glob, cur, WK_OPT_MENU, item);
                wk_add(wb, "    %c) ", wk_keys[cur++]);
                wk_add_item(wb, item);
            }
            wk_add(wb, "Select an item (Space=next Backspace=back "
                       "ESC=cancel).\r\n");
            break;
        }
    }
}

/*
 * wk_menu_pick_prepare() updates a menu item which is about to be picked,
 *                        as Intuition would: the checkmark is toggled or
 *                        set (clearing mutually excluded items), and the
 *                        multi-select chain is terminated.
 */
static void
wk_menu_pick_prepare(struct MenuItem *first, struct MenuItem *item, int real)
{
    if (item->Flags & CHECKIT) {
        if (item->Flags & MENUTOGGLE)
            item->Flags ^= CHECKED;
        else
            item->Flags |= CHECKED;
        if ((item->Flags & CHECKED) && (item->MutualExclude != 0)) {
            struct MenuItem *other;
            int              pos = 0;
            for (other = first; (other != NULL) && (pos < 32);
                 other = other->NextItem, pos++) {
                if ((pos != real) && (item->MutualExclude & (1UL << pos)))
                    other->Flags &= ~CHECKED;
            }
        }
    }
    item->NextSelect = MENUNULL;
}

/* wk_buf_flush() emits buffered text, keeping the buffer for more */
static void
wk_buf_flush(glob_t *glob, wk_buf_t *wb)
{
    if (wb->len > 0)
        xterm_console_emit(glob, (UBYTE *) wb->buf, wb->len);
    wb->len = 0;
}

/*
 * Gadget options are selected by the letters A-Z, where 'Z' is always
 * [Menu] if the window has a menu. If a window has more gadget options
 * than letters, they are shown in pages: Space shows the next page
 * (cycling back to the first), and Backspace the previous page.
 */
typedef struct {
    int  start;     // First gadget option shown
    int  end;       // Last gadget option shown + 1
    BOOL paged;     // Options are shown in pages
    BOOL menu;      // Window has a menu
    int  menu_key;  // Key index of [Menu], or -1
    int  total;     // All options, including the menu
} wk_page_t;

/* wk_page_layout() computes the options of the page (holds LockIBase) */
static void
wk_page_layout(glob_t *glob, struct Window *window, wk_page_t *pg)
{
    int ngad;
    int slots;

    pg->total    = window_options(window, -1, NULL);
    pg->menu     = (window->MenuStrip != NULL);
    pg->menu_key = pg->menu ? WK_KEY_MENU : -1;
    ngad         = pg->total - (pg->menu ? 1 : 0);
    slots        = pg->menu ? WK_KEY_MENU : WK_GAD_KEYS;  // Letters for gadgets
    pg->paged    = (ngad > slots);
    if (pg->paged == FALSE)
        glob->wk_page = 0;
    pg->start = glob->wk_page * slots;
    if (pg->start >= ngad) {  // Past the last page: back to the first
        glob->wk_page = 0;
        pg->start     = 0;
    }
    pg->end = pg->start + slots;
    if (pg->end > ngad)
        pg->end = ngad;
}

/* wk_add_label() caches a recognized gadget label */
static void
wk_add_label(glob_t *glob, struct Gadget *gadget, const char *text)
{
    int n = glob->wk_glabels;
    if (n >= (int) (sizeof (glob->wk_glabel) / sizeof (glob->wk_glabel[0])))
        return;
    glob->wk_glabel[n].gadget = gadget;
    strncpy(glob->wk_glabel[n].text, text, sizeof (glob->wk_glabel[n].text));
    glob->wk_glabel[n].text[sizeof (glob->wk_glabel[n].text) - 1] = '\0';
    glob->wk_glabels++;
}

/*
 * wk_show_gadget_page() lists the gadget options of the current page.
 *                       Labels drawn as pixels are recognized as they are
 *                       listed, and each line is sent as soon as it is
 *                       known. Must be called without holding LockIBase().
 *                       While pixels are read, the screen's layer info is
 *                       locked (before LockIBase(), as Intuition does) so
 *                       that the window can not close.
 */
static void
wk_show_gadget_page(glob_t *glob)
{
    struct Screen   *screen;
    struct Window   *window  = glob->wk_window;
    struct TextFont *scrfont = NULL;
    gr_ctx_t        *ctx     = NULL;
    BOOL             gr_ok   = (GfxBase != NULL) && (LayersBase != NULL);
    wk_page_t        pg;
    wk_buf_t         wb;
    ULONG            ilock;
    int              key = 0;
    int              cur;

    if (wk_buf_init(&wb) == FALSE)
        return;
    ilock = LockIBase(0);
    if (wk_window_open(window) == FALSE) {
        UnlockIBase(ilock);
        wk_add(&wb, "Window has closed.\r\n");
        wk_buf_emit(glob, &wb);
        wk_reset(glob);
        return;
    }
    screen = window->WScreen;
    wk_page_layout(glob, window, &pg);
    wk_shown_clear(glob);
    wk_add(&wb, "Program has \"%.60s\" window open.\r\n",
           (window->Title != NULL) ? (char *) window->Title : "");
    if ((glob->wk_pass == 1) && (glob->wk_helpers > 1)) {
        wk_add(&wb, "Warning: %d windows are open; this one may belong "
               "to another program.\r\n", glob->wk_helpers);
    }
    UnlockIBase(ilock);
    wk_buf_flush(glob, &wb);

    if (gr_ok)
        scrfont = OpenFont(screen->Font);  // Not locked: may load from disk

    for (cur = pg.start; cur < pg.end; cur++, key++) {
        wk_opt_t opt;
        gr_box_t box  = { 0, 0, 0, 0, FALSE };
        BOOL     need = FALSE;
        BOOL     open;
        UWORD    id   = 0;
        const char *mark = "";

        if (gr_ok)
            LockLayerInfo(&screen->LayerInfo);
        ilock = LockIBase(0);
        open  = wk_window_open(window) &&
                (cur < window_options(window, cur, &opt));
        if (open) {
            wk_shown_set(glob, key, opt.type, opt.gadget);
            wk_add(&wb, "    %c) ", wk_keys[key]);
            if (gr_ok && (opt.type == WK_OPT_GADGET) &&
                (gadget_label(opt.gadget) == NULL) &&
                (wk_recognized_label(glob, opt.gadget) == NULL) &&
                gr_gadget_box(window, opt.gadget, &box)) {
                need = TRUE;
                id   = opt.gadget->GadgetID;
                mark = "";
                if (is_toggle_gadget(opt.gadget)) {
                    BOOL sel = (opt.gadget->Flags & GFLG_SELECTED) != 0;
                    if (opt.gadget->Activation & GACT_TOGGLESELECT)
                        mark = sel ? "[x] " : "[ ] ";
                    else
                        mark = sel ? "(*) " : "( ) ";
                }
            } else {
                wk_add_option(glob, &wb, window, &opt);
            }
        }
        UnlockIBase(ilock);
        if (need) {
            /* Window can not close while the layer info is locked */
            if (ctx == NULL)
                ctx = gr_ctx_create(window, scrfont);
            if (ctx != NULL)
                gr_read_box(ctx, window, &box);
        }
        if (gr_ok)
            UnlockLayerInfo(&screen->LayerInfo);
        if (open == FALSE) {
            wk_add(&wb, "Cancel (Window closed).\r\n");
            wk_buf_emit(glob, &wb);
            wk_reset(glob);
            gr_ctx_free(ctx);
            if (scrfont != NULL)
                CloseFont(scrfont);
            return;
        }
        if (need) {
            char text[24];
            if ((ctx != NULL) &&
                gr_recognize(ctx, box.width, box.height, box.disabled,
                             text, sizeof (text))) {
                wk_add_label(glob, opt.gadget, text);
                wk_add(&wb, "ID=%d %s%s\r\n", id, mark, text);
            } else {
                wk_add(&wb, "ID=%d %s(%d,%d) %dx%d\r\n", id, mark, box.left,
                       box.top, box.width, box.height);
            }
        }
        wk_buf_flush(glob, &wb);  // Show each option as it is known
    }
    gr_ctx_free(ctx);
    if (scrfont != NULL)
        CloseFont(scrfont);

    if (pg.menu_key >= 0) {
        wk_shown_set(glob, pg.menu_key, WK_OPT_MENU, NULL);
        wk_add(&wb, "    %c) [Menu]\r\n", wk_keys[pg.menu_key]);
    }
    wk_add(&wb, "Select an item (%s%sESC=cancel).\r\n",
           pg.paged ? "Space=next " : "",
           (glob->wk_page > 0) ? "Backspace=back " : "");
    wk_buf_emit(glob, &wb);
}

/*
 * wk_skip_esc_seq() discards the rest of an escape sequence (such as
 *                   that of a cursor key) which follows an ESC, if it has
 *                   already arrived. It returns TRUE if one was discarded,
 *                   meaning the ESC was not a lone ESC key press.
 */
static BOOL
wk_skip_esc_seq(glob_t *glob)
{
    ULONG pos = glob->unproc_spos;
    UBYTE ch;

    if (pos == glob->unproc_epos)
        return (FALSE);
    ch = glob->unproc_buf[pos];
    if ((ch != '[') && (ch != 'O'))
        return (FALSE);
    do {
        if (++pos == sizeof (glob->unproc_buf))
            pos = 0;
        if (pos == glob->unproc_epos)
            return (FALSE);  // Incomplete
        ch = glob->unproc_buf[pos];
    } while ((ch < 0x40) || (ch > 0x7e));
    if (++pos == sizeof (glob->unproc_buf))
        pos = 0;
    glob->unproc_spos = pos;
    return (TRUE);
}

/* wk_cancel() ends the prompt */
static void
wk_cancel(glob_t *glob)
{
    if (glob->wk_level == WK_TEXT)
        xterm_console_emit(glob, (UBYTE *) "\r\nCanceled.\r\n", 13);
    else
        xterm_console_emit(glob, (UBYTE *) "Canceled.\r\n", 11);
    wk_reset(glob);
}

/*
 * wk_esc_key() handles ESC in the prompt. A lone ESC key press cancels
 *              the prompt, but a cursor or function key (an escape
 *              sequence) is ignored. If nothing follows the ESC yet, the
 *              decision waits for more input or the ESC timer
 *              (wk_esc_timeout()).
 */
static void
wk_esc_key(glob_t *glob)
{
    if (wk_skip_esc_seq(glob)) {
        xterm_console_emit(glob, (UBYTE *) "\a", 1);
    } else if (glob->unproc_spos != glob->unproc_epos) {
        wk_cancel(glob);  // Something other than a sequence follows
    } else {
        glob->wk_esc = WK_ESC_WAIT;
        xterm_esc_timer_start(glob);
    }
}

/* wk_esc_timeout() is called when the ESC timer expires */
static BOOL
wk_esc_timeout(glob_t *glob)
{
    if (glob->wk_esc != WK_ESC_WAIT)
        return (FALSE);
    glob->wk_esc = WK_ESC_NONE;  // Timer already completed
    wk_cancel(glob);
    return (TRUE);
}

/*
 * wk_esc_follow() handles the input after an ESC in the prompt. It returns
 *                 TRUE if the input was consumed.
 */
static BOOL
wk_esc_follow(glob_t *glob, UBYTE cmd)
{
    if (glob->wk_esc == WK_ESC_SEQ) {
        if ((cmd >= 0x40) && (cmd <= 0x7e))
            glob->wk_esc = WK_ESC_NONE;  // Final byte of the sequence
        return (TRUE);
    }
    xterm_timer_cancel(glob);
    glob->wk_esc = WK_ESC_NONE;
    if ((cmd == '[') || (cmd == 'O')) {
        glob->wk_esc = WK_ESC_SEQ;
        xterm_console_emit(glob, (UBYTE *) "\a", 1);
        return (TRUE);
    }
    wk_cancel(glob);  // The ESC was a lone key press
    return (FALSE);   // This input is not part of the prompt
}

/* wk_gadget_present() is TRUE if the gadget is in the window (LockIBase) */
static BOOL
wk_gadget_present(struct Window *window, struct Gadget *gadget)
{
    struct Gadget *cur;
    for (cur = window->FirstGadget; cur != NULL; cur = cur->NextGadget)
        if (cur == gadget)
            return (TRUE);
    return (FALSE);
}

/*
 * wk_modify_begin() prepares to change a gadget of the window: it locks the
 *                   screen's layers (so the window can not close) and
 *                   verifies the gadget is still present. It returns the
 *                   locked screen, or NULL (with *problem set). The
 *                   caller must call wk_modify_end() with the screen.
 */
static struct Screen *
wk_modify_begin(struct Window *window, struct Gadget *gadget,
                const char **problem)
{
    struct Screen *screen = NULL;
    ULONG          ilock;
    BOOL           ok;

    *problem = "The gadget is no longer present.";
    ilock = LockIBase(0);
    if (wk_window_open(window) && wk_gadget_present(window, gadget))
        screen = window->WScreen;
    UnlockIBase(ilock);
    if (screen == NULL)
        return (NULL);

    LockLayerInfo(&screen->LayerInfo);  // Before LockIBase(), as Intuition
    ilock = LockIBase(0);
    ok = wk_window_open(window) && wk_gadget_present(window, gadget);
    UnlockIBase(ilock);
    if (ok == FALSE) {
        UnlockLayerInfo(&screen->LayerInfo);
        return (NULL);
    }
    *problem = NULL;
    return (screen);
}

static void
wk_modify_end(struct Screen *screen)
{
    UnlockLayerInfo(&screen->LayerInfo);
}

static void
wk_report_problem(glob_t *glob, const char *problem)
{
    xterm_console_emit(glob, (UBYTE *) problem, strlen(problem));
    xterm_console_emit(glob, (UBYTE *) "\r\n", 2);
}

/*
 * wk_toggle_gadget() changes the selected state of a toggle gadget (such
 *                    as a checkbox) or selects a gadget which only reports
 *                    being pressed (such as a GadTools MX item), as a
 *                    mouse click would. It returns FALSE if the state
 *                    could not be changed, after reporting why.
 */
static BOOL
wk_toggle_gadget(glob_t *glob, struct Window *window, struct Gadget *gadget)
{
    const char    *problem;
    struct Screen *screen = wk_modify_begin(window, gadget, &problem);
    BOOL           sel;

    if (screen == NULL) {
        wk_report_problem(glob, problem);
        return (FALSE);
    }
    if (gadget->Flags & GFLG_DISABLED) {
        wk_modify_end(screen);
        wk_report_problem(glob, "The gadget is disabled.");
        return (FALSE);
    }
    if (gadget->Activation & GACT_TOGGLESELECT)
        sel = (gadget->Flags & GFLG_SELECTED) ? FALSE : TRUE;  // Toggle
    else
        sel = TRUE;  // MX item: the program deselects the others

    if ((gadget->GadgetType & GTYP_GTYPEMASK) == GTYP_CUSTOMGADGET) {
        /* BOOPSI gadget: it manages (and renders) its own state */
        (void) SetGadgetAttrs(gadget, window, NULL, GA_Selected, sel,
                              TAG_END);
    } else {
        UWORD pos = RemoveGList(window, gadget, 1);
        if (pos != (UWORD) ~0) {
            if (sel)
                gadget->Flags |= GFLG_SELECTED;
            else
                gadget->Flags &= ~GFLG_SELECTED;
            (void) AddGList(window, gadget, pos, 1, NULL);
            RefreshGList(gadget, window, NULL, 1);
        }
    }
    wk_modify_end(screen);
    return (TRUE);
}

/*
 * wk_text_begin() starts text entry for a string gadget, with the current
 *                 contents as the initial text. Caller holds LockIBase().
 */
static BOOL
wk_text_begin(glob_t *glob, wk_buf_t *wb, struct Gadget *gadget)
{
    struct StringInfo *si = (struct StringInfo *) gadget->SpecialInfo;
    int                max;
    int                len;

    if (gadget->Flags & GFLG_DISABLED) {
        wk_add(wb, "The gadget is disabled.\r\n");
        return (FALSE);
    }
    max = si->MaxChars - 1;  // MaxChars includes the NUL
    if (max > (int) sizeof (glob->wk_text) - 1)
        max = sizeof (glob->wk_text) - 1;
    if (max < 1) {
        wk_add(wb, "The gadget does not accept text.\r\n");
        return (FALSE);
    }
    for (len = 0; (len < max) && (si->Buffer[len] != '\0'); len++)
        glob->wk_text[len] = si->Buffer[len];
    glob->wk_sgad  = gadget;
    glob->wk_tlen  = len;
    glob->wk_tmax  = max;
    glob->wk_tint  = (gadget->Activation & GACT_LONGINT) ? TRUE : FALSE;
    glob->wk_level = WK_TEXT;
    wk_add(wb, "Enter new %s (up to %d characters). Return sets it, "
           "^U clears, ESC cancels.\r\n> ",
           glob->wk_tint ? "number" : "text", max);
    return (TRUE);
}

/* wk_parse_long() converts a decimal number; it returns FALSE if invalid */
static BOOL
wk_parse_long(const char *str, int len, LONG *valuep)
{
    ULONG value = 0;
    BOOL  neg   = FALSE;
    int   pos   = 0;

    if ((len > 0) && ((str[0] == '-') || (str[0] == '+'))) {
        neg = (str[0] == '-');
        pos++;
    }
    if (pos >= len)
        return (FALSE);
    for (; pos < len; pos++) {
        if ((str[pos] < '0') || (str[pos] > '9'))
            return (FALSE);
        value = value * 10 + (str[pos] - '0');
        if (value > 0x80000000UL)
            return (FALSE);
    }
    if ((value == 0x80000000UL) && (neg == FALSE))
        return (FALSE);
    *valuep = neg ? (LONG) (0 - value) : (LONG) value;
    return (TRUE);
}

/* wk_format_long() writes a decimal number, returning its length */
static int
wk_format_long(char *str, LONG value)
{
    char  digits[12];
    ULONG uval = (value < 0) ? (ULONG) 0 - (ULONG) value : (ULONG) value;
    int   count = 0;
    int   len   = 0;

    do {
        digits[count++] = '0' + (uval % 10);
        uval /= 10;
    } while (uval != 0);
    if (value < 0)
        str[len++] = '-';
    while (count > 0)
        str[len++] = digits[--count];
    return (len);
}

/*
 * wk_text_commit() replaces the contents of the string gadget with the
 *                  entered text, refreshes the gadget, and notifies the
 *                  application as Intuition would when Return is pressed
 *                  in the gadget.
 */
static void
wk_text_commit(glob_t *glob)
{
    struct Window     *window = glob->wk_window;
    struct Gadget     *gadget = glob->wk_sgad;
    struct Screen     *screen = NULL;
    struct StringInfo *si;
    const char        *problem = NULL;
    char              *text    = glob->wk_text;  // Not on the small stack
    LONG               value   = 0;
    BOOL               notify  = FALSE;
    int                len     = glob->wk_tlen;

    if (glob->wk_tint) {
        if (wk_parse_long(text, len, &value) == FALSE) {
            xterm_console_emit(glob, (UBYTE *) "\a", 1);
            return;  // Stay in text entry
        }
        len = wk_format_long(text, value);  // Normalized ("+07" -> "7")
    }
    text[len] = '\0';

    screen = wk_modify_begin(window, gadget, &problem);
    if (screen != NULL) {
        /* The window can not close while its screen's layers are locked */
        si = (struct StringInfo *) gadget->SpecialInfo;
        if (gadget->Flags & GFLG_SELECTED)
            problem = "The gadget is being edited at the Amiga.";
        else if (gadget->Flags & GFLG_DISABLED)
            problem = "The gadget is disabled.";
        else if (len >= si->MaxChars)
            problem = "The text is too long for the gadget.";
        else
            problem = wk_input_problem(window);  // Not locked: checked again
        if (problem == NULL) {
            UWORD pos = RemoveGList(window, gadget, 1);
            if (pos == (UWORD) ~0) {
                problem = "The gadget is no longer present.";
            } else {
                if (si->UndoBuffer != NULL)
                    memcpy(si->UndoBuffer, si->Buffer, si->MaxChars);
                memcpy(si->Buffer, text, len + 1);
                si->NumChars  = len;
                si->BufferPos = len;
                si->DispPos   = 0;
                if (glob->wk_tint)
                    si->LongInt = value;
                (void) AddGList(window, gadget, pos, 1, NULL);
                RefreshGList(gadget, window, NULL, 1);
                notify = (gadget->Activation & GACT_RELVERIFY) &&
                         (window->IDCMPFlags & IDCMP_GADGETUP);
            }
        }
        wk_modify_end(screen);
    }

    if (problem != NULL) {
        xterm_console_emit(glob, (UBYTE *) "\r\n", 2);
        xterm_console_emit(glob, (UBYTE *) problem, strlen(problem));
        xterm_console_emit(glob, (UBYTE *) "\r\n", 2);
    } else {
        xterm_console_emit(glob, (UBYTE *) "\r\nSet.\r\n", 8);
    }
    wk_reset(glob);
    if (notify)
        (void) task_window_send(glob, window, IDCMP_GADGETUP, 0, gadget);
}

/* wk_text_key() handles a key while entering text for a string gadget */
static void
wk_text_key(glob_t *glob, UBYTE cmd)
{
    static const UBYTE rubout[] = "\b \b";

    switch (cmd) {
        case 0x1b:  // ESC (cursor and function keys are not supported)
            wk_esc_key(glob);
            return;
        case 0x03:  // ^C
            wk_cancel(glob);
            return;
        case '\r':
        case '\n':
            glob->wk_eat_nl = (cmd == '\r');  // Telnet sends CR LF or CR NUL
            wk_text_commit(glob);
            return;
        case 0x08:  // Backspace
        case 0x7f:  // Delete
            if (glob->wk_tlen == 0) {
                xterm_console_emit(glob, (UBYTE *) "\a", 1);
            } else {
                glob->wk_tlen--;
                xterm_console_emit(glob, rubout, 3);
            }
            return;
        case 0x15:  // ^U: clear
        case 0x18:  // ^X: clear
            while (glob->wk_tlen > 0) {
                glob->wk_tlen--;
                xterm_console_emit(glob, rubout, 3);
            }
            return;
    }
    if ((cmd < 0x20) || ((cmd >= 0x7f) && (cmd < 0xa0)) ||
        (glob->wk_tlen >= glob->wk_tmax) ||
        (glob->wk_tint && ((cmd < '0') || (cmd > '9')) &&
         (((cmd != '-') && (cmd != '+')) || (glob->wk_tlen != 0)))) {
        xterm_console_emit(glob, (UBYTE *) "\a", 1);
        return;
    }
    glob->wk_text[glob->wk_tlen++] = cmd;
    xterm_console_emit_text(glob, &cmd, 1);
}

/*
 * task_window_kill() prompts the user to activate (by selection) a gadget
 *                    or menu item of a window opened by the child
 *                    application. This is mostly useful to terminate
 *                    requesters which have popped up so the program can
 *                    continue. It returns TRUE if the key was consumed.
 */
static BOOL
task_window_kill(glob_t *glob, UBYTE cmd)
{
    struct Task   *task       = (struct Task *) get_recent_process(glob);
    struct Window *window;
    wk_buf_t       wb;
    ULONG          ilock;
    ULONG          send_class = 0;  // IDCMP message to send after unlocking
    UWORD          send_code  = 0;
    APTR           send_addr  = NULL;
    int            action     = WK_ACT_NONE;
    int            idx        = -1;
    BOOL           done       = FALSE;  // Prompt ends
    BOOL           suspend    = FALSE;
    BOOL           bell       = FALSE;
    BOOL           show_page  = FALSE;  // Show gadget options after unlock
    BOOL           show_text  = FALSE;  // Show text to edit after emit
    BOOL           toggle     = FALSE;  // Change gadget's selected state

    if (glob->requester_abort_active == FALSE) {
        /* The requester abort key was pressed */
        int pass;
        int count;
        if (is_valid_task(task) == FALSE)
            return (FALSE);
        ilock = LockIBase(0);
        window = wk_find_window(glob, task, &pass, &count);
        UnlockIBase(ilock);
        if (window == NULL)
            return (FALSE);  // Not consumed: key goes to the application
        glob->wk_window   = window;
        glob->wk_pass     = pass;
        glob->wk_helpers  = count;
        glob->wk_level    = WK_GADGETS;
        glob->wk_page     = 0;
        glob->wk_glabels  = 0;
        glob->requester_abort_active = TRUE;
        wk_show_gadget_page(glob);
        return (TRUE);
    }

    if (glob->wk_esc != WK_ESC_NONE) {
        /* FALSE: prompt was canceled, so the input goes to the application */
        return (wk_esc_follow(glob, cmd));
    }
    if (glob->wk_level == WK_TEXT) {
        wk_text_key(glob, cmd);
        return (TRUE);
    }
    if (cmd == 0x1b) {  // ESC: cancel, unless a cursor or function key
        wk_esc_key(glob);
        return (TRUE);
    }
    if (wk_buf_init(&wb) == FALSE) {
        wk_reset(glob);
        return (TRUE);
    }
    if ((cmd >= 'a') && (cmd <= 'z'))
        cmd = cmd - 'a' + 'A';
    if (cmd != '\0') {
        const char *ptr = strchr(wk_keys, cmd);
        if (ptr != NULL)
            idx = ptr - wk_keys;
    }

    ilock = LockIBase(0);
    window = glob->wk_window;
    if (wk_window_open(window) == FALSE) {
        wk_add(&wb, "The window has closed.\r\n");
        window = NULL;
        done   = TRUE;
        goto unlock;
    }
    if ((cmd == 0x08) || (cmd == 0x7f)) {  // Backspace: previous level
        if (glob->wk_level == WK_GADGETS) {
            if (glob->wk_page > 0) {
                glob->wk_page--;  // Previous page of options
                show_page = TRUE;
            } else {
                bell = TRUE;
            }
        } else if (glob->wk_level == WK_MENUS) {
            glob->wk_level = WK_GADGETS;
            show_page      = TRUE;
        } else {
            glob->wk_level--;
            wk_show(glob, &wb);
        }
        goto unlock;
    }
    if ((cmd == ' ') && (glob->wk_level == WK_GADGETS)) {
        wk_page_t pg;
        wk_page_layout(glob, window, &pg);
        if (pg.paged) {
            glob->wk_page++;  // Next page of options (wraps to first)
            show_page = TRUE;
        } else {
            bell = TRUE;
        }
        goto unlock;
    }
    if (idx < 0) {
        bell = TRUE;
        goto unlock;
    }

    switch (glob->wk_level) {
        case WK_GADGETS: {
            /* The option is the one shown for the key, never another */
            wk_opt_t opt;
            if ((idx >= WK_MAX_OPTS) ||
                (glob->wk_shown[idx].type == WK_OPT_NONE)) {
                bell = TRUE;
                break;
            }
            opt.type   = glob->wk_shown[idx].type;
            opt.gadget = (struct Gadget *) glob->wk_shown[idx].ptr;
            if (opt.type == WK_OPT_MENU) {
                if (window->MenuStrip == NULL) {
                    wk_add(&wb, "The menu is no longer present.\r\n");
                    done = TRUE;
                    break;
                }
                glob->wk_level = WK_MENUS;
                wk_show(glob, &wb);
                break;
            }
            if (wk_shown_gadget(glob, window, idx) == FALSE) {
                wk_add(&wb, "Selected:    %c) The gadget is no longer "
                       "present. Nothing was done.\r\n", wk_keys[idx]);
                done = TRUE;
                break;
            }
            wk_add(&wb, "Selected:    %c) ", wk_keys[idx]);
            wk_add_option(glob, &wb, window, &opt);
            done = TRUE;
            switch (opt.type) {
                case WK_OPT_GADGET:
                    /*
                     * Suspend at the "Software Failure" requester of the
                     * session's own application leaves that process
                     * (normally the shell, as CLI commands run in the shell
                     * process) frozen forever. Replace it.
                     */
                    suspend = (glob->wk_pass == 0) &&
                              (window->Title != NULL) &&
                              (strcmp((char *) window->Title,
                                      "Software Failure") == 0) &&
                              label_matches(gadget_label(opt.gadget),
                                            "suspend");
                    /* A gadget may report only being pressed (such as MX) */
                    if (((opt.gadget->Activation & GACT_RELVERIFY) == 0) &&
                        (opt.gadget->Activation & GACT_IMMEDIATE))
                        send_class = IDCMP_GADGETDOWN;
                    else
                        send_class = IDCMP_GADGETUP;
                    send_addr  = opt.gadget;
                    toggle     = is_toggle_gadget(opt.gadget);
                    break;
                case WK_OPT_STRING:
                    if (wk_input_problem(window) != NULL) {
                        wk_add(&wb, "%s Nothing was done.\r\n",
                               wk_input_problem(window));
                        break;
                    }
                    if (wk_text_begin(glob, &wb, opt.gadget)) {
                        done      = FALSE;
                        show_text = TRUE;
                    }
                    break;
                case WK_OPT_CLOSE:
                    send_class = IDCMP_CLOSEWINDOW;
                    break;
                case WK_OPT_DEPTH:
                    if ((window->WLayer != NULL) &&
                        (window->WLayer->front == NULL))
                        action = WK_ACT_BACK;
                    else
                        action = WK_ACT_FRONT;
                    break;
                case WK_OPT_ZOOM:
                    action = WK_ACT_ZOOM;
                    break;
            }
            break;
        }
        case WK_MENUS: {
            struct Menu *menu = wk_nth_menu(window->MenuStrip, idx);
            if ((idx >= WK_MAX_OPTS) ||
                (glob->wk_shown[idx].type == WK_OPT_NONE)) {
                bell = TRUE;
                break;
            }
            if (menu != glob->wk_shown[idx].ptr) {
                wk_add(&wb, "The menus have changed.\r\n");
                wk_show(glob, &wb);  // Show them as they are now
                break;
            }
            if ((menu->Flags & MENUENABLED) == 0) {
                bell = TRUE;
                break;
            }
            glob->wk_menu  = idx;
            glob->wk_level = WK_ITEMS;
            wk_show(glob, &wb);
            break;
        }
        case WK_ITEMS:
        case WK_SUBITEMS: {
            struct Menu     *menu = wk_nth_menu(window->MenuStrip,
                                                glob->wk_menu);
            struct MenuItem *first;
            struct MenuItem *item;
            struct MenuItem *parent    = NULL;
            int              item_real = 0;
            int              real;
            if ((idx >= WK_MAX_OPTS) ||
                (glob->wk_shown[idx].type == WK_OPT_NONE)) {
                bell = TRUE;
                break;
            }
            if (glob->wk_level == WK_SUBITEMS)
                parent = (menu == NULL) ? NULL :
                         wk_nth_item(menu->FirstItem, glob->wk_item,
                                     &item_real);
            first = (parent != NULL) ? parent->SubItem :
                    (menu != NULL) ? menu->FirstItem : NULL;
            item = wk_nth_item(first, idx, &real);
            if ((menu == NULL) || (menu != glob->wk_shown_menu) ||
                (parent != glob->wk_shown_parent) ||
                (item == NULL) || (item != glob->wk_shown[idx].ptr)) {
                wk_add(&wb, "The menu has changed. Nothing was done.\r\n");
                done = TRUE;
                break;
            }
            if ((item->Flags & ITEMENABLED) == 0) {
                bell = TRUE;
                break;
            }
            if ((parent == NULL) && (item->SubItem != NULL)) {
                glob->wk_item  = idx;
                glob->wk_level = WK_SUBITEMS;
                wk_show(glob, &wb);
                break;
            }
            done = TRUE;
            if ((window->IDCMPFlags & IDCMP_MENUPICK) == 0) {
                wk_add(&wb, "The program does not accept menu "
                       "selections.\r\n");
                break;
            }
            wk_menu_pick_prepare(first, item, real);
            wk_add(&wb, "Selected:    %c) ", wk_keys[idx]);
            wk_add_item(&wb, item);
            send_class = IDCMP_MENUPICK;
            if (parent == NULL)
                send_code = FULLMENUNUM(glob->wk_menu, real, NOSUB);
            else
                send_code = FULLMENUNUM(glob->wk_menu, item_real, real);
            break;
        }
    }

    if ((send_class != 0) || toggle) {
        /* Refuse input which the program could not receive from the user */
        const char *problem = wk_input_problem(window);
        if ((problem == NULL) && (send_class != 0) &&
            ((window->IDCMPFlags & send_class) == 0)) {
            if (toggle)
                send_class = 0;  // Change the state only; program reads it
            else
                problem = "The program does not accept this input.";
        }
        if (problem != NULL) {
            wk_add(&wb, "%s Nothing was done.\r\n", problem);
            send_class = 0;
            toggle     = FALSE;
            suspend    = FALSE;
        }
    }

unlock:
    UnlockIBase(ilock);
    if (bell)
        wk_add(&wb, "\a");
    wk_buf_emit(glob, &wb);
    if (show_text)
        xterm_console_emit_text(glob, (UBYTE *) glob->wk_text, glob->wk_tlen);
    if (done)
        wk_reset(glob);
    else if (show_page)
        wk_show_gadget_page(glob);

    if (window != NULL) {
        if (toggle && (wk_toggle_gadget(glob, window, send_addr) == FALSE))
            send_class = 0;  // State could not be changed
        if ((send_class != 0) &&
            (task_window_send(glob, window, send_class, send_code,
                              send_addr) == FALSE))
            suspend = FALSE;  // Software Failure requester was not answered
        switch (action) {
            case WK_ACT_FRONT:
                WindowToFront(window);
                break;
            case WK_ACT_BACK:
                WindowToBack(window);
                break;
            case WK_ACT_ZOOM:
                ZipWindow(window);
                break;
        }
    }
    if (suspend)
        replace_suspended_shell(glob, (struct Process *) task);
    return (TRUE);
}

static LONG
procbuf_space(glob_t *glob)
{
    LONG space = glob->proc_spos - glob->proc_epos - 1;
    if (space < 0)
        space += sizeof (glob->proc_buf);
    return (space);
}

/*
 * append_to_app_input() adds text to the buffer containing data to be
 *                       read by the application.
 */
static void
append_to_app_input(glob_t *glob, const UBYTE *buf, size_t len)
{
    LONG space = procbuf_space(glob);
    if (len > space) {
        warnx("BUG: Append %d bytes, but only space for %d", len, space);
        len = space;
    }
    while (len--) {
        glob->proc_buf[glob->proc_epos++] = *(buf++);
        if (glob->proc_epos == sizeof (glob->proc_buf))
            glob->proc_epos = 0;
    }
}

/*
 * translate_amiga_csi_to_xterm() handles Amiga CSI sequences
 * (sent by an Amiga app), converting them to appropriate xterm console
 * sequences.
 */
static void
translate_amiga_csi_to_xterm(glob_t *glob, char cmd, UBYTE *buf, int len)
{
    int    num;
    int    cur;
    UBYTE *orig_buf = buf;
    int    orig_len = len;

    switch (cmd) {
        case 'A':  /* CSI Pn A  - Cursor Up */
        case 'B':  /* CSI Pn B  - Cursor Down */
        case 'C':  /* CSI Pn C  - Cursor Right */
        case 'D':  /* CSI Pn D  - Cursor Left */
            if (glob->raw_mode)
                goto no_trans;
            return;
        case '@':  /* CSI Pn @  - Insert characters */
        case 'E':  /* CSI Pn E  - Cursor next line */
        case 'F':  /* CSI Pn F  - Cursor previous line */
        case 'H':  /* CSI Pr ; Pc H  - Cursor position (row ; column) */
        case 'I':  /* CSI Pn I  - Move forward to Pn tab position */
        case 'L':  /* CSI Pn L  - Insert lines */
        case 'M':  /* CSI Pn M  - Delete lines */
        case 'P':  /* CSI Pn P  - Delete characters */
        case 'S':  /* CSI Pn S  - Scroll up */
        case 'T':  /* CSI Pn T  - Scroll down */
        case 'Z':  /* CSI Pn Z  - Cursor backward tabulation */
        case 'f': { /* CSI Pr ; Pc H  - H/V position (row ; column) */
            /* No translation necessary, other than CSI */
            char tbuf[32];
no_trans:
            if (len > sizeof (tbuf) - 4)  // ESC [ len+1 \0
                len = sizeof (tbuf) - 4;
            snprintf(tbuf, sizeof (tbuf), STR_ESC "[%.*s", len + 1, buf);
            xterm_console_emit(glob, tbuf, strlen(tbuf));
            return;
        }
        case 'J':  /* CSI J  - Erase to end of display */
            /* Amiga console only supports a subset of this command */
            xterm_console_emit(glob, STR_ESC "[J", 3);
            return;
        case 'K':  /* CSI K  - Erase to end of line */
            /* Amiga console only supports a subset of this command */
            xterm_console_emit(glob, STR_ESC "[K", 3);
            return;
        case 'W':  /* CSI Pn W  - Cursor tab ctrl: 0=set, 2=clr, 5=clr all */
            cur = getnum(buf, &num);
            if (cur == 0)
                num = 0;
            switch (num) {
                case 0:  /* CSI W  or  CSI 0 W  - set tab */
                    xterm_console_emit(glob, STR_ESC "H", 2);  // AKA 0x88
                    break;
                case 2:  /* CSI 2 W  - clear tab */
                    xterm_console_emit(glob, STR_ESC "[g", 3);
                    break;
                case 5:  /* CSI 5 W  - clear all tabs */
                    xterm_console_emit(glob, STR_ESC "[3g", 4);
                    break;
            }
            return;
        case 'c':  /* ESC [ c - xterm identify */
            /*
             * This should not normally occur here (an App sending this to
             * an Amiga console). It will be ignored because reterm uses
             * this sequence to detect xterm.
             */
            return;
        case 'h':  /* CSI Pr h  - Set mode */
            if (buf[0] == '>') {
                /*
                 * CSI > ... h
                 *
                 * No xterm equivalent for these:
                 *   CSI > 1 h     - Enable scroll
                 *   CSI > ? 1 8 h - Do not follow the cursor by scrolling
                 *   CSI > ? 1 9 h - Scroll instead of word wrap at right border
                 *   CSI > ? 2 5 h - Enable ViNCEd auto paste mode
                 *   CSI > ? 3 0 h - Cursor doesn't move w/ scrollbar or blkmove
                 */
                if (buf[1] == '1')
                    return;
                if (buf[1] != '?')
                    break;  /* No match */

                /* CSI > ? ... h */
                cur = getnum(buf + 2, &num);
                if (cur == 0)
                    num = 0;
                switch (num) {
                    case 18: /* CSI > ? 1 8 h - Don't follow cursor by scroll */
                    case 19: /* CSI > ? 1 9 h - Wrap at right, not scroll */
                    case 25: /* CSI > ? 2 5 h - Enable ViNCEd auto paste mode */
                    case 30: /* CSI > ? 3 0 h - Don't move cursor w scrollbar */
                        return;
                    default:
                        break;
                }
                break;
            } else if (buf[0] == '?') {
                /* CSI ? ... */
                cur = getnum(buf + 1, &num);
                if (cur == 0)
                    num = 0;
                switch (num) {
                    case 7:
                        /* CSI ? 7 h  - Autowrap on */
                        xterm_console_emit(glob, STR_ESC "[?7h", 5);
                        return;
                    case 47:
                        /* CSI ? 4 7 h - Switch to alternate screen */
                        xterm_console_emit(glob, STR_ESC "[?47h", 6);
                        return;
                }
                break;
            } else if ((buf[0] == '2') && (buf[1] == '0')) {
                /* CSI 2 0 h  - Set Line Feed Mode */
                xterm_console_emit(glob, STR_ESC "[20h", 5);
                glob->nl_crlf = TRUE;
                return;
            }
            break;
        case 'l':  /* CSI Pr l  - Clear (unset) mode */
            if (buf[0] == '>') {
                /*
                 * CSI > ... l
                 *
                 * No xterm equivalent for these:
                 *   CSI > 1 l     - Disable scroll
                 *   CSI > ? 1 8 l - Follow the cursor (scroll the window)
                 *   CSI > ? 1 9 l - Scroll instead of word wrap at right border
                 *   CSI > ? 2 5 l - Disable ViNCEd auto paste mode
                 *   CSI > ? 3 0 l - Cursor moves w/ scrollbar or block move
                 */
                if (buf[1] == '1')
                    return;
                if (buf[1] != '?')
                    break;  /* No match */

                /* CSI > ? ... l */
                cur = getnum(buf + 2, &num);
                if (cur == 0)
                    num = 0;
                switch (num) {
                    case 18: /* CSI > ? 1 8 l - Follow cursor by scrolling */
                    case 19: /* CSI > ? 1 9 l - Scroll, not wrap at right */
                    case 25: /* CSI > ? 2 5 l - Disable ViNCEd auto paste */
                    case 30: /* CSI > ? 3 0 l - Move cursor w/ scrollbar */
                        return;
                    default:
                        break;
                }
                break;
            } else if (buf[0] == '?') {
                cur = getnum(buf + 1, &num);
                if (cur == 0)
                    num = 0;
                switch (num) {
                    case 7:
                        /* CSI ? 7 l  - Autowrap off */
                        xterm_console_emit(glob, STR_ESC "[?7l", 5);
                        return;
                    case 47:
                        /* CSI ? 4 7 l - Switch to primary screen */
                        xterm_console_emit(glob, STR_ESC "[?47l", 6);
                        return;
                }
                return;
            } else if ((buf[0] == '2') && (buf[1] == '0')) {
                /* CSI 2 0 l  - Reset newline mode */
                xterm_console_emit(glob, STR_ESC "[20l", 5);
                glob->nl_crlf = FALSE;
                return;
            }
            break;
        case 'm': {  /* CSI Pr ; Pr ... m  - Set graphic rendition */
            int rendition_mode = 0;  /* not started */

            if (len == 0) {
                /* CSI m  - normal text rendition */
                xterm_console_emit(glob, STR_ESC "[m", 3);
                return;
            }
            while (len > 0) {
                int add = 0;
                if (buf[0] == '>') {
                    buf++;
                    len--;
                    add = 140;
                }
                if ((cur = getnum(buf, &num)) == 0)
                    break;
                buf += cur;
                len -= cur;
                num += add;
                switch (num) {
                    case 140:  /* System background 0 (xterm Black) */
                    case 141:  /* System background 1 (xterm Red) */
                    case 142:  /* System background 2 (xterm Green) */
                    case 143:  /* System background 3 (xterm Yellow) */
                    case 144:  /* System background 4 (xterm Blue) */
                    case 145:  /* System background 5 (xterm Magenta) */
                    case 146:  /* System background 6 (xterm Cyan) */
                    case 147:  /* System background 7 (xterm White) */
                        num -= 100;
                        /* FALLTHROUGH */
                    case 0:  /* Plain text */
                    case 1:  /* Boldface */
                    case 2:  /* Faint (secondary color) */
                    case 3:  /* Italic */
                    case 4:  /* Underscore */
                    case 5:  /* Amiga slow Blink (xterm Blinking) */
                    case 6:  /* Amiga fast Blink */
                    case 7:  /* Reversed */
                    case 8:  /* Concealed (hidden / invisible) */
                    case 9:  /* Crossed-out */
                    case 21:  /* Double underline */
                    case 22:  /* Normal (not bold or faint) */
                    case 23:  /* Not italicized */
                    case 24:  /* Not underlined */
                    case 25:  /* Amiga slow Blink off (xterm Not blinking) */
                    case 26:  /* Amiga fast Blink off */
                    case 27:  /* Not Reversed */
                    case 28:  /* Not Concealed */
                    case 29:  /* Not crossed-out */
                    case 30:  /* System foreground 0 (xterm Black) */
                    case 31:  /* System foreground 1 (xterm Red) */
                    case 32:  /* System foreground 2 (xterm Green) */
                    case 33:  /* System foreground 3 (xterm Yellow) */
                    case 34:  /* System foreground 4 (xterm Blue) */
                    case 35:  /* System foreground 5 (xterm Magenta) */
                    case 36:  /* System foreground 6 (xterm Cyan) */
                    case 37:  /* System foreground 7 (xterm White) */
                    case 39:  /* System foreground default (xterm default) */
                    case 40:  /* Character cell color 0 (xterm Black) */
                    case 41:  /* Character cell color 1 (xterm Red) */
                    case 42:  /* Character cell color 2 (xterm Green) */
                    case 43:  /* Character cell color 3 (xterm Yellow) */
                    case 44:  /* Character cell color 4 (xterm Blue) */
                    case 45:  /* Character cell color 5 (xterm Magenta) */
                    case 46:  /* Character cell color 6 (xterm Cyan) */
                    case 47:  /* Character cell color 7 (xterm White) */
                    case 49:  /* Character cell default (xterm default) */
                    {
                        char tbuf[8];
                        const char *prefix = rendition_mode ? ";" : STR_ESC "[";
                        xterm_console_emit(glob, tbuf,
                                           sprintf(tbuf, "%s%d", prefix, num));
                        if (rendition_mode == 0)
                            rendition_mode = 1;
                        break;
                    }
                    default:
                        break;  /* Ignore and continue */
                }
                if (buf[0] == ';') {
                    buf++;
                    len--;
                }
            }
            if (rendition_mode == 1)
                xterm_console_emit(glob, "m", 1);
            return;
        }
        case 'n':  /* CSI 6 n  - Device status report */
            /*
             * Send the following to xterm (report cursor position):
             *    ESC [ 6 n
             * It will reply with
             *    ESC [ Pr ; Pc R
             * Amiga is expecting:
             *    CSI Pr ; Pc R
             */
            if ((len == 1) && (buf[0] == '6')) {
                if (glob->fake_xterm_reply) {
                    /* Do immediate reply with fake position */
                    char tbuf[32];
                    sprintf(tbuf, STR_CSI "%d;%dR",
                            glob->con_unit_ptr->cu_YCCP + 1,
                            glob->con_unit_ptr->cu_XCCP + 1);
                    append_to_app_input(glob, tbuf, strlen(tbuf));
                } else {
                    /* Ask remote xterm for cursor position */
                    xterm_console_emit(glob, STR_ESC "[6n", 4);
                    glob->xterm_request_pending = TRUE;
                }
            }
            return;
        case 'p':  /* CSI Pr p  - Show / hide cursor */
            if (((len == 1) && (buf[0] == ' ')) ||
                ((len == 2) && (buf[0] == '1') && buf[1] == ' ')) {
                /* CSI 1 SPACE p - Show cursor */
                xterm_console_emit(glob, STR_ESC "[?25h", 6);
                return;
            } else if ((len == 2) && (buf[0] == '0') && buf[1] == ' ') {
                /* CSI 0 SPACE p - Hide cursor */
                xterm_console_emit(glob, STR_ESC "[?25l", 6);
                return;
            }
            break;
        case 'q':
            if (((len == 1) && (buf[0] == ' ')) ||
                ((len == 2) && (buf[0] == '0') && (buf[1] == ' '))) {
                /*
                 * CSI 0 SPACE q  - Window status request (bounds report)
                 * CSI SPACE q    - Window status request (bounds report)
                 *
                 * Send the following to xterm (report text area in characters):
                 *    ESC [ 18 t
                 * It will reply with
                 *    ESC [ 8 ; Pr ; Pc t
                 * Amiga is expecting:
                 *    CSI 1 ; 1 ; Pr ; Pc SPACE r
                 */
                if (glob->fake_xterm_reply) {
                    /* Do immediate reply with fake screen size */
                    ULONG sec;
                    ULONG usec;
                    char tbuf[32];
                    sprintf(tbuf, STR_CSI "1;1;%d;%d r",
                            glob->con_unit_ptr->cu_YMax + 1,
                            glob->con_unit_ptr->cu_XMax + 1);
                    append_to_app_input(glob, tbuf, strlen(tbuf));

                    /* Request a screen size update at most once a second */
                    CurrentTime(&sec, &usec);
                    if (glob->last_ssize_time != sec) {
                        glob->last_ssize_time = sec;
                        xterm_console_emit(glob, STR_ESC "[18t", 5);
                    }
                } else {
                    xterm_console_emit(glob, STR_ESC "[18t", 5);
                    glob->xterm_request_pending = TRUE;
                }
                return;
            }
            break;
        case 's':  /* CSI Pn s - Set Default SGR Settings (rendition) */
            // XXX: This command should record the current SGR rendition to
            //      be restored whenever ESC [ m is issued.
            return;
        case 't':  /* CSI Pn t - Set Page Length */
        case 'u':  /* CSI Pn u - Set Line Length */
        case 'v':  /* CSI Pn v - Right Amiga-V pressed (paste from clipboard) */
            /*
             * Upon receipt of this sequence, your application should read
             * the contents of the clipboard device, make a copy of any text
             * found there and then release the clipboard so that it can be
             * used by other applications.
             */
            /* No xterm equivalent for these */
            return;
        case 'w':  /* CSI Pn w - 3.2? window sequences */
            if ((buf[0] == '>') && (buf[1] == '?')) {
                /*
                 * No xterm equivalent for these:
                 *   CSI > ? 1 8 w - Do not follow the cursor by scrolling
                 *   CSI > ? 1 9 w - Scroll instead of word wrap at right border
                 */
                if ((buf[1] == '?') && (buf[2] == '1') && (buf[3] == '8'))
                    return;
                else if ((buf[1] == '?') && (buf[2] == '1') && (buf[3] == '9'))
                    return;
                return;
            }
            printf("got buf w len=%d =%x %x %x\n", len, buf[0], buf[1], buf[2]);
            return;
        case 'x':  /* CSI Pn x - Set Left Offset */
        case 'y':  /* CSI Pn y - Set Top Offset */
            /* No equivalent for xterm */
            return;
        case '{': {  /* CSI Pn { - Set Raw Events */
            int tcur = 0;
            while ((cur = getnum(buf + tcur, &num)) != 0) {
                tcur += cur;
                if (buf[tcur] == ';')
                    tcur++;
                glob->amiga_console_eventmask |= (1 << num);
                if (num == 12) {
                    /* Request window dimensions (for vim) */
                    xterm_console_emit(glob, STR_ESC "[18t", 5);
                }
            }
            DPRINT2("set raw events %.*s = %x", len, buf,
                    glob->amiga_console_eventmask);
            return;
        }
        case '}': {  /* CSI Pn } - Reset Raw Events */
            int tcur = 0;
            while ((cur = getnum(buf + tcur, &num)) != 0) {
                tcur += cur;
                if (buf[tcur] == ';')
                    tcur++;
                glob->amiga_console_eventmask &= ~(1U << num);
            }
            DPRINT2("reset raw events %.*s = %x", len, buf,
                    glob->amiga_console_eventmask);
            return;
        }
    }
    debug_print_sequence("Unk CSI", orig_buf, orig_len + 1, TRUE);
}

/*
 * translate_amiga_esc_to_xterm() handles simple escape sequences
 * such as ESC c - Full Reset.
 */
static void
translate_amiga_esc_to_xterm(glob_t *glob, char cmd)
{
    switch (cmd) {
        case '7':  /* ESC 7 - Save cursor + rendition */
        case '8':  /* ESC 8 - Restore cursor + rendition */
            /*
             * Attempt to pass ESC 7 and ESC 8 through as they can't be
             * supported directly without knowing the actual cursor position.
             * The standard Amiga console doesn't support these, so we hope
             * the backing console is an xterm.
             */
        case 'D':  /* ESC D - Index (move down one line) */
        case 'E':  /* ESC E - Next Line */
        case 'H':  /* ESC H - Set Tab */
        case 'M':  /* ESC M - Reverse Index (move up one line) */
        {
            char tbuf[] = {KEY_ESC, cmd};
            xterm_console_emit(glob, tbuf, sizeof (tbuf));
            break;
        }
        case 'W':  /* ESC W - End of Guarded Area (ignore on Amiga) */
            break;
        case 'c':  /* ESC c  - Reset to initial state (soft reset) */
            xterm_console_emit(glob, STR_ESC "[!p", 4);
            glob->nl_crlf = TRUE;
            break;
        default:
            debug_print_sequence("Unk ESC", &cmd, 1, TRUE);
            break;
    }
}

/*
 * xterm_cons_text_write() sends regular text to the Xterm console.
 */
static void
xterm_cons_text_write(glob_t *glob, UBYTE *buf, size_t count)
{
    int pos;

    while (count > 0) {
        for (pos = 0; pos < (int) count; pos++) {
            if ((buf[pos] < ' ') || (buf[pos] >= 0x7f))
                break;  /* Non-printable characters get handled one-at-a-time */
        }
        if (pos == 0)
            pos = 1;  /* Emit at least one character at a time */
        if (pos == 1) {
            switch (buf[0]) {
                case KEY_CSI:  /* Amiga CSI -- should not see this */
                    /* Should not see this here -- if we do, it's a bug */
                    xterm_console_emit(glob, "Bug: Amiga CSI", 14);
                    goto go_next;
                case '\n':  /* Newline */
                    if (glob->nl_crlf && (glob->atx_last_ch != '\r')) {
                        xterm_console_emit(glob, "\r\n", 2);
                        goto go_next;
                    }
                    break;
                case '\f':  /* Form feed - clear the display */
                    xterm_console_emit(glob, STR_ESC "[2J" STR_ESC "[H", 7);
                    goto go_next;
                case '\v':  /* Amiga VT Vertical Tab is like cursor down */
                    xterm_console_emit(glob, STR_ESC "[B", 3);
                    goto go_next;
                case 0x0e:  /* SO Shift Out - Switch to G1 Handler */
                case 0x0f:  /* SI Shift In - Switch to G0 Handler */
                    /* Ignore these */
                    goto go_next;
                case 0x84:  /* Index - Move down one line */
                    xterm_console_emit(glob, STR_ESC "D", 2);
                    goto go_next;
                case 0x85:  /* Next line - Go to beginning of next line */
                    xterm_console_emit(glob, STR_ESC "E", 2);
                    goto go_next;
                case 0x88:  /* Horizontal tabulation - Set tab */
                    xterm_console_emit(glob, STR_ESC "H", 2);
                    goto go_next;
                case 0x8d:  /* Reverse index - Move up one line */
                    xterm_console_emit(glob, STR_ESC "M", 2);
                    goto go_next;
                case 0xa0 ... 0xff:
                    if (glob->support_utf8) {
                        xterm_console_emit_text(glob, buf, 1);
                        goto go_next;
                    }
                    break;
            }
        }
        xterm_console_emit(glob, buf, pos);

go_next:
        glob->atx_last_ch = buf[pos - 1];
        count -= pos;
        buf   += pos;
    }
}

/*
 * app_to_console() takes output written by an application and converts it
 *                  into output suitable for the console device. If the
 *                  console device is an xterm, then escape sequences are
 *                  translated, as appropriate.
 */
static void
app_to_console(glob_t *glob, UBYTE *buf, LONG count)
{
    LONG  pos;
    LONG  spos = 0;

    if ((glob->capture_AFH != 0) && glob->capture_output)
        Write(glob->capture_AFH, buf, count);

    if (glob->support_xterm == FALSE) {
        /* No emulate */
        xterm_console_emit(glob, buf, count);
        return;
    }

    for (pos = 0; pos < count; pos++) {
        UBYTE cmd = buf[pos];
        switch (glob->atc_mode) {
            case XT_MODE_NONE:
                if ((cmd != KEY_ESC) && (cmd != KEY_CSI))
                    continue;

                if (pos != spos)
                    xterm_cons_text_write(glob, buf + spos, pos - spos);

                if (cmd == KEY_ESC)
                    glob->atc_mode = XT_MODE_ESC;
                else
                    glob->atc_mode = XT_MODE_CSI;
                glob->atc_cmdbuf_pos = 0;
                spos = pos + 1;
                break;
            case XT_MODE_ESC:
                switch (cmd) {
                    case '[':  /* ESC [ Pn  - CSI mode start */
                        glob->atc_mode = XT_MODE_CSI;
                        glob->atc_cmdbuf_pos = 0;
                        break;
                    default:
                        translate_amiga_esc_to_xterm(glob, cmd);
                        glob->atc_mode = XT_MODE_NONE;
                        break;
                }
                spos = pos + 1;
                break;
            case XT_MODE_CSI:  /* ESC [  - CSI sequence */
                /* Data is buffered until the CSI sequence ends */
                if (glob->atc_cmdbuf_pos < sizeof (glob->atc_cmdbuf))
                    glob->atc_cmdbuf[glob->atc_cmdbuf_pos++] = cmd;
                if ((cmd >= '@' && cmd <= '}')) {
                    /* End of CSI sequence */
                    translate_amiga_csi_to_xterm(glob, cmd, glob->atc_cmdbuf,
                                                 glob->atc_cmdbuf_pos - 1);
                    glob->atc_mode = XT_MODE_NONE;
                    spos = pos + 1;
                }
                break;
        }
    }
    if ((glob->atc_mode == XT_MODE_NONE) && (pos != spos))
        xterm_cons_text_write(glob, buf + spos, pos - spos);
}

static struct DosPacket *
PktFromMsg(struct Message *Msg)
{
    return ((struct DosPacket *) Msg->mn_Node.ln_Name);
}

/* timer_cancel() cancels a pending timer */
static void
timer_cancel(struct timerequest *timer_req)
{
    struct IORequest *ioreq = &timer_req->tr_node;

    if (CheckIO(ioreq) == NULL)
        AbortIO(ioreq);
    WaitIO(ioreq);
    CloseDevice(ioreq);

    DeleteIORequest(timer_req);
}

static void
abort_read_queue(glob_t *glob, BOOL do_packet_reply)
{
    struct Message   *Msg;
    struct DosPacket *Pkt;

    if (glob->pending_reads.lh_Head->ln_Succ == NULL)
        return;

    Forbid();
    while (glob->pending_reads.lh_Head->ln_Succ != NULL) {
        Msg = (struct Message *) glob->pending_reads.lh_Head;
        Pkt = PktFromMsg(Msg);

        if (Pkt->dp_Type == ACTION_WAIT_CHAR) {
            Pkt->dp_Res1 = glob->stopping ? DOSTRUE : DOSFALSE;
            /* Cancel pending timer */
            struct timerequest *t_req = (struct timerequest *) Pkt->dp_Res2;
            if (t_req != NULL) {
                if (glob->reader_timer_pending == 0) {
                    warnx("BUG: t_req with no timer outstanding: %x",
                          Pkt->dp_Res2);
                } else {
                    /* Cancel pending timer */
                    timer_cancel(t_req);
                    glob->reader_timer_pending--;
                }
            }
            Pkt->dp_Res2 = 0;
        } else if (Pkt->dp_Type == ACTION_READ) {
            Pkt->dp_Res2 = 0;
        } else {
            /*
             * We should not get here, though could happen if the
             * child process exited without waiting for reads to
             * complete. It's best to not reply, as the message port
             * may have been deleted.
             */
            warnx("Unknown read queue pkt %d", Pkt->dp_Type);
            do_packet_reply = FALSE;
        }
        if (Pkt->dp_Type != ACTION_WAIT_CHAR)
            Pkt->dp_Res1 = DOSFALSE;

        /* Remove entry from read wait list */
        RemHead(&glob->pending_reads);

        if (do_packet_reply)
            PutMsg(Pkt->dp_Port, Pkt->dp_Link);   // Reply to packet
    }
    Permit();
}

#if 0
#include <clib/debug_protos.h>
static void
sp(const char *str)
{
    while (*str != '\0') {
        KPutChar(*str);
        str++;
    }
}
#endif

static struct Window *
fake_window(glob_t *glob)
{
    if (glob->fake_window == NULL) {
        /* Open a zero-size window on the Workbench backdrop */
        glob->fake_window = OpenWindowTags(NULL,
                                           WA_Width, 1,
                                           WA_Height, 1,
                                           WA_Borderless, DOSTRUE,
                                           WA_Backdrop, DOSTRUE,
                                           WA_NoCareRefresh, DOSTRUE,
                                           WA_Title, (ULONG) glob->fake_title,
                                           TAG_DONE);
    }
    return (glob->fake_window);
}

static void
handle_console_messages(glob_t *glob)
{
    struct MsgPort   *mp = glob->app_cons_msgport;
    struct Message   *Msg;
    struct DosPacket *Pkt;

    if (glob->pending_app_packet != NULL) {
        Pkt = glob->pending_app_packet;
        glob->pending_app_packet = NULL;
        goto process_pkt;
    }

    while ((Msg = GetMsg(mp)) != NULL) {
        LONG Res1;
        LONG Res2;
        LONG action;

        Pkt = PktFromMsg(Msg);

process_pkt:
        Res1 = DOSFALSE;
        Res2 = 0;
        action = Pkt->dp_Type;

        switch (action) {
            case ACTION_FINDINPUT:
            case ACTION_FINDOUTPUT:
            case ACTION_FINDUPDATE: {
                struct FileHandle *FH;
                DPRINT1("FIND%s",
                    (action == ACTION_FINDINPUT)  ? "INPUT" :
                    (action == ACTION_FINDOUTPUT) ? "OUTPUT" : "UPDATE");
                DPRINT2("Open(FH=%x, %s, \"%.80s\")", Pkt->dp_Arg1,
                    (action == ACTION_FINDINPUT)  ? "MODE_OLDFILE" :
                    (action == ACTION_FINDOUTPUT) ? "MODE_NEWFILE" :
                    "MODE_READWRITE",
                    (Pkt->dp_Arg3 != 0) ? (char *)BADDR(Pkt->dp_Arg3) : "");
                if (glob->stopping)
                    break;

                glob->open_count++;
                FH = (struct FileHandle *) BADDR((BPTR)Pkt->dp_Arg1);
                FH->fh_Pos  = -1;
                FH->fh_End  = -1;
                FH->fh_Type = mp;
                FH->fh_Args = glob->open_count;  /* (LONG) Info; */
                FH->fh_Port = (struct MsgPort *) DOSTRUE;
                Res1 = DOSTRUE;
                break;
            }
            case ACTION_WRITE:
                if ((glob->cmdline_len != 0) && (glob->stopping == FALSE)) {
                    /*
                     * Can not process packet at this time. Once stopping,
                     * the command line will never be completed, so the
                     * write must instead fail below (else the app hangs).
                     */
                    glob->pending_app_packet = Pkt;
                    return;
                }

                if (glob->requester_abort_active && (Pkt->dp_Arg3 > 0)) {
                    /* Program output ends the window control prompt */
                    if (glob->wk_level == WK_TEXT)
                        xterm_console_emit(glob, (UBYTE *) "\r\n", 2);
                    xterm_console_emit(glob, (UBYTE *)
                                       "Cancel (program output).\r\n", 26);
                    wk_reset(glob);
                }
                glob->child_wtask_mp = Pkt->dp_Port;
#ifdef DEBUG
                if (glob->debug_mode == 2) {
                    DPRINT("Write(ARG=%x, %x, %x, %x)",
                           Pkt->dp_Arg1, Pkt->dp_Arg2,
                           Pkt->dp_Arg3, Pkt->dp_Arg4);
                    debug_print_sequence(" ", (char *) Pkt->dp_Arg2,
                                         (int) Pkt->dp_Arg3, FALSE);
                }
                if (glob->debug_mode) {
                    UBYTE *buf = (char *) Pkt->dp_Arg2;
                    LONG   len = Pkt->dp_Arg3;
                    int    pos;
                    DPRINT("   WRITE");
                    for (pos = 0; pos < len; pos++)
                        DPRINT(" %02x", buf[pos]);
                    DPRINT("\n");
                }
#endif
                if (glob->stopping) {
                    Res1 = -1;
                    break;
                }

                /* Emit text */
                app_to_console(glob, (UBYTE *) Pkt->dp_Arg2, Pkt->dp_Arg3);

                Res1 = Pkt->dp_Arg3;  /* Bytes written */
                break;

            case ACTION_READ:
                DPRINT1("READ");
                glob->child_rtask_mp = Pkt->dp_Port;
                DPRINT2("Read(ARG=%x, buf=%x, num=%x)",
                        Pkt->dp_Arg1, Pkt->dp_Arg2, Pkt->dp_Arg3);
                if (glob->stopping) {
                    Res1 = -1;
                    break;
                }
                Forbid();
                AddTail(&glob->pending_reads, &Msg->mn_Node);
                Permit();
                continue;

            case ACTION_WAIT_CHAR: {
                LONG usecs = Pkt->dp_Arg1;

                DPRINT1("WAIT_CHAR %d", usecs);
                DPRINT2("WaitChar(ARG=%d)", usecs);
                if (glob->stopping) {
                    /*
                     * Report input "available" so that an application
                     * polling WaitForChar() will Read() and see the error,
                     * rather than poll forever.
                     */
                    Res1 = DOSTRUE;
                    Res2 = 1;
                    break;
                }

                if (reader_consume(glob, NULL, 0)) {  // NULL means just check
                    DPRINT("=Y\n");
                    Res1 = DOSTRUE;
                    Res2 = 1;  // Fake number of lines
                    break;
                }
                if (usecs == 0) {
                    /* Immediate poll with no data available */
                    DPRINT("=N\n");
                    Res1 = DOSFALSE;
                    Res2 = 0;
                    break;
                }
                /* Reader thread will deal with timeout */
                Pkt->dp_Res2 = 0;  // Required by reader_handle_app_reads()
                DPRINT("=W\n");

                Forbid();
                AddTail(&glob->pending_reads, &Msg->mn_Node);
                Permit();
                continue;  // No immediate PutMsg() in this case
            }
            case ACTION_CHANGE_SIGNAL: {
                ULONG prev_signal_mp = (ULONG) glob->child_stask_mp;

                DPRINT1("CHANGE_SIGNAL");
                DPRINT2("ChangeSignal(ARG=%x, MP=%x)",
                        Pkt->dp_Arg1, Pkt->dp_Arg2);
                if (glob->stopping)
                    break;

                if (Pkt->dp_Arg2 != 0)
                    glob->child_stask_mp = (struct MsgPort *) Pkt->dp_Arg2;

                Res1 = DOSTRUE;
                Res2 = prev_signal_mp;
                break;
            }
            case ACTION_DISK_INFO: {
                struct InfoData *idata = (struct InfoData *)BADDR(Pkt->dp_Arg1);
                DPRINT1("DISK_INFO");
                if (glob->stopping)
                    break;
                memset(idata, 0, sizeof (*idata));
                idata->id_DiskType   = glob->raw_mode ? ID_RAWCON : ID_CON;
                idata->id_VolumeNode = (LONG) fake_window(glob);
                idata->id_InUse = (LONG)&glob->id_inuse_req;  // Fake con_unit
                Res1 = DOSTRUE;
                break;
            }
            case ACTION_UNDISK_INFO:
                DPRINT1("UNDISK_INFO");
                Res1 = DOSTRUE;
                break;
            case ACTION_SCREEN_MODE:
                DPRINT1("SCREEN_MODE %d", Pkt->dp_Arg1);
                DPRINT2("ScreenMode(%s)", Pkt->dp_Arg1 ? "Raw" : "Cooked");
                if (glob->stopping)
                    break;
                if (glob->raw_mode != (BOOL)Pkt->dp_Arg1) {
                    Forbid();
                    glob->raw_mode = (BOOL)Pkt->dp_Arg1;
                    if (glob->raw_mode) {
                        /*
                         * If entering raw mode with pending input, send that
                         * input to the waiting process.
                         */
                        if (glob->cmdline_len != 0) {
                            append_to_app_input(glob, glob->cmdline,
                                                glob->cmdline_len);
                            glob->cmdline_len = 0;
                            glob->cmdline_pos = 0;
                        }
                    }
                    Permit();
                    /*
                     * In addition to changing the obvious input behavior
                     * (input editing, tab completion, command history),
                     * Cooked mode forces
                     *     Linefeed output as CRLF (Amiga CSI 2 0 h)
                     * Raw mode forces
                     *     Linefeed output as LF (Amiga CSI 2 0 l)
                     */
                }
                Res1 = DOSTRUE;
                Res2 = 1;
                break;

            case ACTION_DIE:  // Attempt to terminate application and shut down
                DPRINT2("Die(ARG=%x)", Pkt->dp_Arg1);
                glob->stopping = TRUE;
                warnx("**Aborting reterm due to ACTION_DIE**");
                Res1 = DOSTRUE;
                break;

            case ACTION_END:
                DPRINT1("END");
                DPRINT2("End(ARG=%x)", Pkt->dp_Arg1);
                if (glob->child_rtask_mp == Pkt->dp_Port)
                    glob->child_rtask_mp = NULL;
                if (glob->child_wtask_mp == Pkt->dp_Port)
                    glob->child_wtask_mp = NULL;
                if (glob->child_stask_mp == Pkt->dp_Port)
                    glob->child_stask_mp = NULL;

                if (glob->open_count > 0) {
                    glob->open_count--;
                    if (glob->open_count < glob->orphan_count)
                        glob->orphan_count = glob->open_count;
                    if (glob->open_count == glob->orphan_count) {
                        DPRINT2("ENDing");
                        if (glob->stopping == FALSE)
                            xterm_console_emit(glob, "\r\n", 2);
                        glob->stopping = TRUE;
                        glob->child_process_alive = FALSE;
                    }
                }
                Res1 = DOSTRUE;
                break;

            case ACTION_ABORT:
                DPRINT1("ACTION_ABORT");
                abort_read_queue(glob, TRUE);
                Res1 = DOSTRUE;
                break;

            case ACTION_SEEK:
                DPRINT1("SEEK");
                DPRINT2("Seek(ARG=%x, Pos=%x, %s)",
                        Pkt->dp_Arg1, Pkt->dp_Arg2,
                        (Pkt->dp_Arg3 == OFFSET_BEGINNING) ? "BEGIN" :
                        (Pkt->dp_Arg3 == OFFSET_END) ? "END" : "CURRENT");
                Res1 = -1;  /* Indicate error */
                Res2 = ERROR_OBJECT_WRONG_TYPE;
                break;

            case ACTION_QUEUE:  // REXX queue a line for paste
            case ACTION_STACK:  // REXX stack a line for paste
                Res1 = do_paste(glob, action, Pkt->dp_Arg2, Pkt->dp_Arg3);
                break;

            default:
                warnx("Unknown DOS Packet %d", action);
                /* FALLTHROUGH */
            case ACTION_EXAMINE_FH:
            case ACTION_IS_FILESYSTEM:
            case ACTION_LOCATE_OBJECT:
            case ACTION_PARENT_FH:
            case ACTION_SET_FILE_SIZE:
                /*
                 * Note that all the above are used by various apps to probe
                 * whether they are talking with a filesystem or a console
                 * handler.
                 */
                Res1 = DOSFALSE;
                Res2 = ERROR_ACTION_NOT_KNOWN;
                break;
        }

        /* Reply to request */
        Pkt->dp_Res1 = Res1;
        Pkt->dp_Res2 = Res2;
        Forbid();
        PutMsg(Pkt->dp_Port, Pkt->dp_Link);
        Permit();
    }
}

static void
xterm_console_emit_rep(glob_t *glob, UBYTE ch, int len)
{
    UBYTE buf[8];
    int emitlen = sizeof (buf);
    memset(buf, ch, sizeof (buf));
    while (len > 0) {
        if (emitlen > len)
            emitlen = len;
        xterm_console_emit(glob, buf, emitlen);
        len -= emitlen;
    }
}

typedef struct {
    BPTR next;
    BPTR lock;
} os_path_node_t;

static BPTR
tab_completion_pathlock(glob_t *glob, UBYTE *path, LONG pathlen)
{
    UBYTE *name = glob->cmdline + glob->tab_comp_spos;
    UBYTE  tmp;
    LONG   len  = glob->tab_comp_epos - glob->tab_comp_spos;
    LONG   pos;
    LONG   lastpos = 0;
    BOOL   found = FALSE;
    BPTR   lock = 0;
    LONG   pathcur = 0;
    int    nlen;
    struct FileInfoBlock *fib;
    struct Window *prev_windowptr = NULL;
    struct Process *myproc;

    if (pathlen == 0)
        return (0);

    fib = AllocDosObject(DOS_FIB, NULL);
    if (fib == NULL)
        return (0);

    path[0] = '\0';
    for (pos = 0; pos < len; pos++) {
        if ((name[pos] == ':') || (name[pos] == '/')) {
            if (found && (name[pos] == ':'))
                break;  // Invalid path

            tmp = name[pos + 1];
            name[pos + 1] = '\0';
            if (lock != 0)
                UnLock(lock);

            myproc = (struct Process *) glob->reader_task;
            if (myproc != NULL) {
                /* Prevent requesters for this access */
                prev_windowptr = myproc->pr_WindowPtr;
                myproc->pr_WindowPtr = (APTR) -1;
            }

            lock = Lock(name, ACCESS_READ);
            name[pos + 1] = tmp;  // Restore before any exit from the loop

            if (myproc != NULL) {
                /* Allow requesters again */
                myproc->pr_WindowPtr = prev_windowptr;
            }
            if (lock == 0)
                break;

            if (Examine(lock, fib) == DOSFALSE) {
                UnLock(lock);
                lock = 0;
                break;  // Examine failed
            }

            nlen = strlen(fib->fib_FileName);
            if (pathcur + nlen + 1 >= pathlen) {
                UnLock(lock);
                lock = 0;
                break;  // Not enough space
            }
            if (pathcur + nlen != pos) {
                /* Not the same string -- don't rewrite the name */
                strncpy(path + pathcur, name + lastpos, pos - lastpos + 1);
                pathcur += pos - lastpos + 1;
            } else {
                strcpy(path + pathcur, fib->fib_FileName);
                pathcur += nlen;
                path[pathcur++] = name[pos];
            }
            path[pathcur] = '\0';
            lastpos = pos + 1;
            found = TRUE;
        }
    }
    FreeDosObject(DOS_FIB, fib);

    if (lock == 0)
        return (0);

    /* Adjust spos as only the last component needs to be compared */
    glob->tab_comp_spos += lastpos;

    return (lock);
}

/* Remove all entries in the tab completion list */
static void
tab_completion_wipe(glob_t *glob)
{
    namelist_t *node;
    while (glob->completion_list.lh_Head->ln_Succ != NULL) {
        node = (namelist_t *) glob->completion_list.lh_Head;
        RemHead(&glob->completion_list);
        FreeVec(node->name);
        FreeVec(node);
    }
    glob->completion_cur = NULL;
}

/*
 * filename_needs_quotes() will return TRUE if the filename contains special
 *                         characters which require quotes in the shell.
 */
static BOOL
filename_needs_quotes(UBYTE *name)
{
    while (*name != '\0')
        if (strchr(" ><;&#?[]", *(name++)) != NULL)
            return (TRUE);
    return (FALSE);
}

/*
 * tab_completion_add() adds the specified filename to the tab completion list.
 */
static void
tab_completion_add(glob_t *glob, UBYTE *name, UBYTE *prepend, UBYTE append,
                   BYTE cursor_adjust)
{
    int         namelen  = strlen(name);
    int         preplen  = (prepend == NULL) ? 0 : strlen(prepend);
    int         applen   = (append == '\0') ? 0 : 1;
    int         quotes   = filename_needs_quotes(name) ? 1 : 0;
    int         cur      = 0;
    namelist_t *node     = AllocVec(sizeof (*node), MEMF_PUBLIC);
    ULONG       alloclen = preplen + 1 + namelen + applen + 1 + quotes * 2;
    /* node->name        = DIRPATH   /   FILENAME  /       \0   "" */

    if (node == NULL)
        return;
    if (alloclen == 0)
        warnx("tca Bug: Zero alloclen");
    node->name = AllocVec(alloclen, MEMF_PUBLIC);
    if (node->name == NULL) {
        FreeVec(node);
        return;
    }
    if (glob->tab_comp_maxlen < alloclen)
        glob->tab_comp_maxlen = alloclen;

    node->data = cursor_adjust;
    if (quotes)
        node->name[cur++] = '\"';
    if (preplen > 0) {
        memcpy(node->name + cur, prepend, preplen);
        cur += preplen;
        if ((node->name[cur - 1] != '/') && (node->name[cur - 1] != ':'))
            node->name[cur++] = '/';
    }
    memcpy(node->name + cur, name, namelen);
    cur += namelen;
    if (quotes)
        node->name[cur++] = '\"';
    if (append != '\0')
        node->name[cur++] = append;
    node->name[cur] = '\0';

    AddTail(&glob->completion_list, &node->node);
}

/*
 * tab_completion_show_names() displays all tab completion filenames on the
 *                             user's console.
 */
static void
tab_completion_show_names(glob_t *glob)
{
    namelist_t *node    = (namelist_t *) glob->completion_list.lh_Head;
    ULONG       linelen = glob->con_unit_ptr->cu_XMax;
    ULONG       pos     = linelen;
    ULONG       maxlen  = glob->tab_comp_maxlen;
    WORD        ccol    = 0;
    WORD        crow    = 0;

    if ((maxlen == 0) || (maxlen > 30))
        maxlen = 30;

    if (node->node.ln_Succ == NULL)
        return;  // No entries

    if (glob->no_cooked_esc_sequences == FALSE) {
        crow = glob->con_unit_ptr->cu_YCCP;
        ccol = glob->con_unit_ptr->cu_XCCP;
        if (crow == 0)
            crow = glob->con_unit_ptr->cu_YMax;
        xterm_console_emit(glob, STR_ESC "7", 2);  // Save cursor position
    }

    for (node = (namelist_t *) node->node.ln_Succ;
         node->node.ln_Succ != NULL;
         node = (namelist_t *) node->node.ln_Succ) {
        int namelen = strlen(node->name);
        int numspaces = maxlen - ((pos - 2) % maxlen);
        if (pos + maxlen + numspaces < linelen) {
            pos += namelen + numspaces;
        } else {
            numspaces = 2;
            pos = namelen + numspaces;
            if (glob->no_cooked_esc_sequences) {
                /* Go to next line */
                xterm_console_emit(glob, "\r\n", 2);
            } else if (glob->support_xterm == FALSE) {
                /* Scroll up, cursor up, insert blank line */
                UBYTE tbuf[16];
                sprintf(tbuf, STR_CSI "%dH" // Return to original row
                              STR_ESC "[S"  // Scroll up
                              STR_ESC "[A"  // Cursor up
                              STR_ESC "[L", // Insert line
                              crow + 1);
                xterm_console_emit(glob, tbuf, strlen(tbuf));
            } else {
                /* Original position, newline, cursor up, insert line */
                xterm_console_emit(glob, STR_ESC "8"   // Original position
                                         STR_ESC "D"   // Index (newline)
                                         STR_ESC "7"   // Record position
                                         STR_ESC "[A"  // Cursor up
                                         STR_ESC "[L", 12);  // Insert line
            }
        }
        xterm_console_emit_rep(glob, ' ', numspaces);
        xterm_console_emit_text(glob, node->name, namelen);
    }
    if (glob->no_cooked_esc_sequences) {
        xterm_console_emit(glob, "\r\n", 2);
    } else {
        if (glob->support_xterm == FALSE) {
            /* Go to previous cursor position (Amiga console) */
            UBYTE tbuf[16];
            sprintf(tbuf, STR_CSI "%d;%dH", crow + 1, ccol + 1);
            xterm_console_emit(glob, tbuf, strlen(tbuf));
        }

        xterm_console_emit(glob, STR_ESC "8", 2);  // Restore cursor position

        if (glob->support_xterm == FALSE) {
            /* Do nothing (special case for Amiga console) */
            xterm_console_emit(glob, STR_ESC "W", 2);
        }
    }
}

/*
 * tab_completion_curname() returns the current tab completion name.
 */
static UBYTE *
tab_completion_curname(glob_t *glob, int *cursor_adjust)
{
    *cursor_adjust = ((namelist_t *) glob->completion_cur)->data;
    return (((namelist_t *) glob->completion_cur)->name);
}

/*
 * tab_completion_nextname() returns the next name in the tab completion
 *                           list, wrapping around as necessary.
 */
static UBYTE *
tab_completion_nextname(glob_t *glob, int *cursor_adjust)
{
    if (glob->completion_cur->ln_Succ == NULL) {
        warnx("NULL completion_cur should not happen (empty list)");
        return (NULL);
    }

    /* Advance to next entry, or wrap around to start of list */
    glob->completion_cur = glob->completion_cur->ln_Succ;
    if (glob->completion_cur->ln_Succ == NULL)
        glob->completion_cur = glob->completion_list.lh_Head;

    return (tab_completion_curname(glob, cursor_adjust));
}

/*
 * tab_completion_prevname() returns the previous name in the tab completion
 *                           list, wrapping around as necessary.
 */
static UBYTE *
tab_completion_prevname(glob_t *glob, int *cursor_adjust)
{
    if (IsListEmpty(&glob->completion_list)) {
        warnx("NULL completion_cur should not happen (empty list)");
        return (NULL);
    }

    glob->completion_cur = glob->completion_cur->ln_Pred;
    if (glob->completion_cur->ln_Pred == NULL) {
        glob->completion_cur = glob->completion_list.lh_TailPred;
    }

    return (tab_completion_curname(glob, cursor_adjust));
}


/*
 * tab_completion_allmatch() will match the command line against directory
 *                           entries on the specified path (lock). Any
 *                           entries found will be added to the tab completion
 *                           list. Each entry will be added with the full path
 *                           (prepend) and trailing space or slash as expected
 *                           for file or directory.
 */
static void
tab_completion_allmatch(glob_t *glob, BPTR lock, BOOL exec_only, BOOL no_dir,
                        UBYTE *prepend)
{
    LONG   more;
    UBYTE *name_pre   = glob->cmdline + glob->tab_comp_spos;
    UBYTE *name_post  = glob->cmdline + glob->cmdline_pos;
    LONG   len_pre    = glob->cmdline_pos   - glob->tab_comp_spos;
    LONG   len_post   = glob->tab_comp_epos - glob->cmdline_pos;
    struct ExAllData *buf;
    struct ExAllData *ead;
    struct ExAllControl *control = AllocDosObject(DOS_EXALLCONTROL, NULL);
    ULONG  buflen = 512;

    buf = AllocVec(buflen, MEMF_PUBLIC);
    if (buf == NULL)
        return;

    control->eac_LastKey = 0;
    while (1) {
        int count = 0;
        memset(buf, 0xa5, buflen);
        more = ExAll(lock, buf, buflen, ED_PROTECTION, control);
        if ((more == 0) && (IoErr() != ERROR_NO_MORE_ENTRIES))
            break;  // Unexpected error

        for (ead = buf; ead != NULL; ead = ead->ed_Next) {
            char append;
            if (count++ == control->eac_Entries)
                break;  // No more directory entries

            if ((len_pre != 0) &&
                (strncasecmp(ead->ed_Name, name_pre, len_pre) != 0))
                continue;  // No match

            if ((len_post != 0) &&
                (strncasecmp(ead->ed_Name + strlen(ead->ed_Name) - len_post,
                             name_post, len_post) != 0))
                continue;  // No match

            if (exec_only &&
                (strncasecmp(ead->ed_Name + strlen(ead->ed_Name) - 5,
                             ".info", 5) == 0))
                continue;  // .info files should not be executable

            switch (ead->ed_Type) {
                case ST_ROOT:
                    append = ':';
                    break;
                case ST_USERDIR:
                case ST_LINKDIR:
                    if (no_dir)
                        continue;  // Exclude directories
                    append = '/';
                    break;
                default:
                    if (exec_only && (ead->ed_Prot & FIBF_EXECUTE))
                        continue;  // Exclude non-executable files
                    append = ' ';
                    break;
            }
            tab_completion_add(glob, ead->ed_Name, prepend, append, 0);
        }
        if (more == 0) {
            ExAllEnd(lock, buf, buflen, ED_PROTECTION, control);
            break;
        }
    };

    FreeVec(buf);
    FreeDosObject(DOS_EXALLCONTROL, control);
}

/*
 * my_assign_from_lock() will acquire the name of an assign, if it's
 *                       the same as the lock provided. This function
 *                       returns TRUE if a match is found.
 */
static BOOL
my_assign_from_lock(BPTR lock, UBYTE *buf, LONG *buflen)
{
    struct DosList *ent;
    BOOL            found = FALSE;

    /* Attempt to match lock with a system device */

    /* Attempt to match lock with one in the current system assign list */
    if ((ent = LockDosList(LDF_ASSIGNS | LDF_READ)) == NULL)
        return (FALSE);

    while ((ent = NextDosEntry(ent, LDF_ASSIGNS)) != NULL) {
        /* Late and non-binding assigns may not have a lock */
        if ((ent->dol_Lock != 0) &&
            (SameLock(ent->dol_Lock, lock) == LOCK_SAME)) {
            UBYTE *bcpl_name = (UBYTE *) BADDR(ent->dol_Name);
            UBYTE  len = *bcpl_name;
            if (len + 1 > *buflen)
                break;  // Not enough space
            buf[--(*buflen)] = ':';
            (*buflen) -= len;
            memcpy(buf + *buflen, bcpl_name + 1, len);
            found = TRUE;
            break;
        }
    }
    UnLockDosList(LDF_ASSIGNS | LDF_READ);
    return (found);
}

/*
 * my_name_from_lock() will return the full file path corresponding to the
 *                     specified lock. If the path may be shortened by an
 *                     active system assign, that assign will be used.
 * For example:
 *     Assign AmiTCP: sys:AmiTCP
 *     Path ADD sys:amitcp:bin
 *     ifconfig<TAB>
 * result:
 *     AmiTCP:bin/ifconfig
 *
 * This function returns a pointer to the buffer containing the file path
 * or NULL. Note the pointer to the buffer is likely not the same as buf,
 * as buf is filled from the end first.
 */
static UBYTE *
my_name_from_lock(BPTR lock, UBYTE *buf, LONG buflen)
{
    struct FileInfoBlock *fib;
    BPTR                  cur   = lock;
    BOOL                  owned = FALSE;  // cur was obtained by ParentDir()
    BOOL                  done  = FALSE;

    if (buflen == 0)
        return (NULL);
    buf[--buflen] = '\0';

    if (lock == 0) {
        strcpy(buf, "SYS:");
        return (buf);
    }

    fib = AllocDosObject(DOS_FIB, NULL);
    if (fib == NULL)
        return (NULL);

    while (cur != 0) {
        int len;
        BPTR plock = ParentDir(cur);

        if ((plock != 0) && my_assign_from_lock(cur, buf, &buflen)) {
            UnLock(plock);
            done = TRUE;  // Finished early and matched system assign
            break;
        }

        if ((Examine(cur, fib) == DOSFALSE) ||        // Examine failed
            ((len = strlen(fib->fib_FileName)) >= buflen)) {  // No space
            if (plock != 0)
                UnLock(plock);
            break;
        }

        buflen--;
        memcpy(buf + buflen - len, fib->fib_FileName, len);
        if (plock == 0)
            buf[buflen] = ':';
        else
            buf[buflen] = '/';
        buflen -= len;

        if (owned)
            UnLock(cur);
        cur   = plock;
        owned = TRUE;
        if (cur == 0)
            done = TRUE;  // Reached the root
    }
    if (owned && (cur != 0))
        UnLock(cur);
    FreeDosObject(DOS_FIB, fib);

    if (done == FALSE)
        return (NULL);

    return (buf + buflen);
}

/*
 * tab_completion_get_commands() will add to the tab completion list based on
 *                               the command path of the current child process.
 *
 * The function first searches the child process's current directory, followed
 * by entries in the CLI path, followed by the C: directory. If the CLI path
 * includes the current directory, it will be skipped (will always be searched
 * first). If the CLI path includes the C: directory, it will be searched
 * in the CLI path order, and not processed again.
 */
static void
tab_completion_get_commands(glob_t *glob)
{
    struct Process *child = get_recent_process(glob);
    struct CommandLineInterface *cli;
    os_path_node_t              *path_node;
    BPTR                         child_dir;
    BPTR                         c_dir;
    BOOL                         saw_c_dir = FALSE;

    if (child == NULL)
        return;

    /* First handle child process's current directory */
    Forbid();
    child_dir = child->pr_CurrentDir;
    if (child_dir != 0)
        child_dir = DupLock(child_dir);
    Permit();

    if (child_dir != 0)
        tab_completion_allmatch(glob, child_dir, TRUE, FALSE, NULL);

    /* Also lock C: for use below */
    c_dir = Lock("C:", ACCESS_READ);

    cli = (struct CommandLineInterface *) BADDR(child->pr_CLI);
    if (cli == NULL) {
        warnx("Could not get CLI pointer of task %d", child->pr_TaskNum);
        goto skip_path;
    }

    /* Walk process's path */
    for (path_node = (os_path_node_t *) BADDR(cli->cli_CommandDir);
         path_node != NULL;
         path_node = (os_path_node_t *) BADDR(path_node->next)) {
        UBYTE path[256];
        UBYTE *pathptr = path;

        if ((child_dir != 0) &&
            (SameLock(path_node->lock, child_dir) == LOCK_SAME))
            continue;  // Already handled current dir

        if ((c_dir != 0) && (SameLock(path_node->lock, c_dir) == LOCK_SAME)) {
            saw_c_dir = TRUE;  // Don't need to handle C: later
            strcpy(path, "C:");
        } else {
            pathptr = my_name_from_lock(path_node->lock, path, sizeof (path));
        }
        tab_completion_allmatch(glob, path_node->lock, TRUE, TRUE,
                                glob->tab_comp_no_exec_path ? NULL : pathptr);
    }

skip_path:
    /* Handle C: */
    if (c_dir != 0) {
        if (saw_c_dir == FALSE)
            tab_completion_allmatch(glob, c_dir, TRUE, TRUE,
                                    glob->tab_comp_no_exec_path ? NULL : "C:");
        UnLock(c_dir);
    }
    if (child_dir != 0)
        UnLock(child_dir);
}


/*
 * tab_completion_get_files() will add to the tab completion list based on
 *                            what is available in the child process's current
 *                            directory.
 */
static void
tab_completion_get_files(glob_t *glob)
{
    struct Process *child = get_recent_process(glob);
    BPTR            lock;

    if (child == NULL)
        return;

    Forbid();
    lock = child->pr_CurrentDir;
    if (lock != 0)
        lock = DupLock(lock);
    Permit();

    if (lock == 0) {
        warnx("Could not get current dir of process %d", child->pr_TaskNum);
        return;
    }

    tab_completion_allmatch(glob, lock, FALSE, FALSE, NULL);
    UnLock(lock);
}

/*
 * tab_completion_abs_path() will complete against an absolute path (one
 *                           which has a volume name embedded or starts
 *                           with a ":" indicating the root of the current
 *                           volume. It will also complete against paths
 *                           with an embedded slash "/" meaning the path
 *                           is relative to the current absolute directory.
 */
static BOOL
tab_completion_abs_path(glob_t *glob, BOOL is_command)
{
    UBYTE path[256];
    BPTR  lock = tab_completion_pathlock(glob, path, sizeof (path));

    if (lock == 0)
        return (FALSE);

    tab_completion_allmatch(glob, lock, is_command, FALSE, path);
    UnLock(lock);
    return (TRUE);
}

/*
 * tab_completion_initiate() will initiate or cycle to the next choice for
 *                           filename completion.
 *
 * The implemented filename completion context-sensitive. If the cursor
 * is in the first word on the line, then command path completion is
 * attempted. Otherwise, filename completion is attempted relative to the
 * current directory.
 */
static void
tab_completion_initiate(glob_t *glob, int direction)
{
    ULONG  epos;
    ULONG  spos;
    UBYTE *name;
    LONG   len_old;  // Old string length
    LONG   len_new;  // New (replacement) string length
    int    diff;
    int    cursor_adjust;

    if (glob->tab_comp_running) {
        spos = glob->tab_comp_spos;
        epos = glob->tab_comp_epos;
    } else {
        /* Fill the completion list with entries */
        struct Process *child;
        BOOL  is_command;
        UBYTE tmp;
        ULONG fpos;
        BPTR  child_dir = 0;
        BPTR  my_dir = 0;

        epos = glob->cmdline_pos;
        spos = glob->cmdline_pos;

        /* Wipe any active completion list and generate a new list */
        tab_completion_wipe(glob);

        /* First command line character (skip whitespace) */
        for (fpos = 0; fpos < glob->cmdline_len; fpos++)
            if (glob->cmdline[fpos] != ' ')
                break;

        /* Find first character of name to be completed */
        for (spos = glob->cmdline_pos; spos > fpos; spos--)
            if (glob->cmdline[spos - 1] == ' ')
                break;

        if (glob->tab_match_pre_only == FALSE) {
            /* Find the end position */
            for (; epos < glob->cmdline_len; epos++)
                if (glob->cmdline[epos] == ' ')
                    break;
        }
        if (epos > glob->cmdline_pos)
            glob->tab_have_post_chars = TRUE;
        else
            glob->tab_have_post_chars = FALSE;

        len_old = epos - spos;

        /* Always add the original entry first */
        name = glob->cmdline + spos;
        tmp = name[len_old];
        name[len_old] = '\0';
        tab_completion_add(glob, name, NULL, '\0', glob->cmdline_pos - epos);
        name[len_old] = tmp;

        /* If (spos == fpos), then we are completing a command */
        is_command = (spos == fpos) ? TRUE : FALSE;

        glob->tab_comp_spos = spos;
        glob->tab_comp_epos = epos;
        glob->tab_comp_maxlen = 0;

        /* Tab completion is relative to the child process current directory */
        child = get_recent_process(glob);
        if (child != NULL) {
            Forbid();
            child_dir = child->pr_CurrentDir;
            if (child_dir != 0)
                child_dir = DupLock(child_dir);
            Permit();

            if (child_dir != 0)
                my_dir = CurrentDir(child_dir);
        }

        /* If a non-relative path is specified, then use that path */
        if (tab_completion_abs_path(glob, is_command)) {
            glob->tab_comp_spos = spos;  // above call adjusted spos
        } else if (is_command) {
            tab_completion_get_commands(glob);
        } else {
            tab_completion_get_files(glob);
        }

        if (my_dir != 0)
            CurrentDir(my_dir);
        if (child_dir != 0)
            UnLock(child_dir);

        /*
         * Start completion_cur on original entry; tab or shift-tab will
         * initially take us to the first or last match in the list.
         */
        glob->completion_cur = glob->completion_list.lh_Head;
    }

    if (direction == 0) {
        /* Display list of possible completions */
        tab_completion_show_names(glob);
        goto finish_initiate;
    } else if (direction > 0) {
        /* Tab key pressed */
        name = tab_completion_nextname(glob, &cursor_adjust);
    } else {
        /* Shift-Tab key pressed */
        name = tab_completion_prevname(glob, &cursor_adjust);
    }

    if (name == NULL) {
        warnx("BUG: NULL tab_completion");
        return;
    }

    len_old = epos - spos;
    len_new = strlen(name);

    diff = len_new - len_old;
    if (glob->cmdline_len + diff > sizeof (glob->cmdline) - 1) {
        /*
         * Completion would not fit in the command line buffer (one byte
         * is reserved for the newline added on Enter). Leave the command
         * line as is; the next tab will move on to the next name.
         */
        xterm_console_emit(glob, "\a", 1);
        goto finish_initiate;
    }
    memmove(glob->cmdline + spos + len_new,
            glob->cmdline + spos + len_old,
            glob->cmdline_len - len_old - spos);
    glob->cmdline_len   += diff;
    glob->tab_comp_epos += diff;
    memcpy(glob->cmdline + spos, name, len_new);

    if (glob->no_cooked_esc_sequences) {
        /* Move cursor to spos */
        xterm_console_emit_rep(glob, '\b', glob->cmdline_pos - spos);
        /* Emit new cmdline */
        xterm_console_emit_text(glob, glob->cmdline + spos,
                                glob->cmdline_len - spos);

        if (diff < 0) {
            /* Overwrite the old end of line */
            xterm_console_emit_rep(glob, ' ', -diff);
            xterm_console_emit_rep(glob, '\b', -diff);
        }

        /* Adjust cursor position */
        glob->cmdline_pos = glob->tab_comp_epos + cursor_adjust;

        /* Move cursor back to new end position */
        xterm_console_emit_rep(glob, '\b',
                               glob->cmdline_len - glob->cmdline_pos);
    } else {
        UBYTE tbuf[16];
        int cursor_left = glob->cmdline_pos - spos;

        if (cursor_left == 0) {
            tbuf[0] = '\0';
        } else {
            /* Move cursor to spos */
            sprintf(tbuf, STR_ESC "[%dD", cursor_left);
        }

        if (diff < 0) {
            /* delete unwanted characters */
            sprintf(tbuf + strlen(tbuf), STR_ESC "[%dP", -diff);
        } else if (diff > 0) {
            /* insert new characters */
            sprintf(tbuf + strlen(tbuf), STR_ESC "[%d@", diff);
        }

        xterm_console_emit(glob, tbuf, strlen(tbuf));

        /* Output updated text */
        xterm_console_emit_text(glob, glob->cmdline + spos, len_new);

        /* Adjust cursor position */
        glob->cmdline_pos = glob->tab_comp_epos + cursor_adjust;

        if (glob->tab_comp_epos > glob->cmdline_pos) {
            /* Move back to cursor position */
            xterm_console_emit(glob, tbuf,
                    sprintf(tbuf, STR_ESC "[%uD",
                            glob->tab_comp_epos - glob->cmdline_pos));
        } else if (glob->tab_comp_epos < glob->cmdline_pos) {
            /* Move forward to cursor position */
            xterm_console_emit(glob, tbuf,
                    sprintf(tbuf, STR_ESC "[%uC",
                            glob->cmdline_pos - glob->tab_comp_epos));
        }
    }

finish_initiate:
    glob->tab_comp_staged = TRUE;   // Automatically canceled
    glob->tab_comp_running = TRUE;  // Automatically canceled
}

/*
 * tab_completion_handle() will disable the tab completion buffers if
 *                         the staged flag is not refreshed between calls.
 * This function is called for each character received from the xterm
 * console which is not part of an escape sequence. Thus, to keep a
 * tab completion active, the user must only be using the tab, shift tab,
 * or ^D input characters.
 */
static void
tab_completion_handle(glob_t *glob)
{
    if (glob->tab_comp_staged) {
        glob->tab_comp_staged = FALSE;
        return;
    }
    if (glob->tab_comp_running) {
        glob->tab_comp_running = FALSE;
        tab_completion_wipe(glob);
    }
}

/*
 * conv_int() converts a string decimal number to ULONG, similar in function
 *            to strtoul().
 */
static ULONG
conv_int(char *str, char **nstr)
{
    ULONG num = 0;
    int   pos = 0;
    sscanf(str, "%i%*[ ]%n", &num, &pos);
    if (nstr != NULL)
        *nstr = str + pos;

    return (num);
}

/*
 * create_fh() initializes a file handle pointing to the specified message port
 */
static struct FileHandle *
create_fh(glob_t *glob, struct MsgPort *mp)
{
    struct FileHandle *FH;

    FH = AllocDosObjectTags(DOS_FILEHANDLE,
                            ADO_FH_Mode, MODE_OLDFILE,
                            TAG_END);
    if (FH == NULL)
        err(EXIT_FAILURE, "Failed to Alloc DOS Object Tags");

    glob->open_count++;

    // FH->fh_Link  =
    // FH->fh_Buf   =
    // FH->fh_Funcs =
    // FH->fh_Func2 =
    // FH->fh_Func3 =
    // FH->fh_Arg2  =
    FH->fh_Pos  = -1;
    FH->fh_End  = -1;
    FH->fh_Type = mp;
    FH->fh_Args = glob->open_count;  /* (LONG)Info; */
    FH->fh_Port = (struct MsgPort *)DOSTRUE;

    return (FH);
}

/*
 * reader_handle_arrived_count() handles arrived data in the unprocessed
 *                               xterm/user input buffer.
 */
static void
reader_handle_arrived_count(glob_t *glob, LONG count)
{
    ULONG new_epos;
    if (count < 0) {
        warnx("Read failure caused stop");
        glob->stopping = TRUE;
        return;
    }

    if ((count == 0) && (glob->tcp_port != 0)) {
        /* recv() of 0 bytes on a TCP socket means the remote closed */
        DPRINT1("Remote closed connection");
        glob->stopping = TRUE;
        return;
    }

    if (count == 0) {
        /*
         * Device (e.g. TCP: handler) reported end of file. Propagate it
         * to the application, but track consecutive occurrences separately
         * from user-generated EOF (^\ or telnet EOF) so that an
         * application which consumes each EOF and reads again can not
         * prevent reterm from noticing that the device has closed.
         */
        glob->got_zero_read_count++;  // Propagate to ACTION_READ
        if (++glob->device_eof_count >= 3) {
            warnx("Too many zero-length reads -- exiting reterm");
            glob->stopping = TRUE;
        }
        return;
    }
    glob->device_eof_count = 0;

    if ((glob->capture_XFH != 0) && glob->capture_input) {
        Write(glob->capture_XFH, "{", 1);
        Write(glob->capture_XFH, glob->unproc_buf + glob->unproc_epos, count);
        Write(glob->capture_XFH, "}", 1);
    }

    /* Update end pointer so it will expose data to consumer */
    new_epos = glob->unproc_epos + count;
    if (new_epos >= sizeof (glob->unproc_buf))
        new_epos = 0;
    glob->unproc_epos = new_epos;
}

/*
 * send_Read() will queue an asynchronous read to the input device (console).
 *             It performs the equivalent of a Read(), but allows other code
 *             to run while the ACTION_READ remains blocked.
 * This function is called by the reader thread. The reply packet, when it
 * arrives, is handled by the reader thread.
 */
static void
send_Read(glob_t *glob)
{
    BPTR              fh;
    struct MsgPort   *input_mp;
    struct DosPacket *Pkt;
    ssize_t           space = (glob->unproc_spos) - (glob->unproc_epos) - 1;
    if (space < 0)
        space += sizeof (glob->unproc_buf);
    if (space == 0)
        return;  // No space

    /* Limit available space so we don't need to wrap buffer */
    if (space > sizeof (glob->unproc_buf) - glob->unproc_epos)
        space = sizeof (glob->unproc_buf) - glob->unproc_epos;

    if (glob->tcp_port != 0) {
        /* TCP socket */
        UBYTE *ptr = glob->unproc_buf + glob->unproc_epos;
        struct Library *SocketBase = glob->socketbase_reader;
        LONG sock = glob->tcp_socket_reader;
        ssize_t count;
        int     avail;

        /* Get number of bytes waiting to be read */
        if (IoctlSocket(sock, FIONREAD, &avail) < 0) {
            warnx("ioctl(FIONREAD) failed");
            glob->stopping = TRUE;
            return;
        }
        if (avail == 0) {
            /*
             * If WaitSelect() reported the socket as readable, but there
             * is no data, then the remote has closed the connection (or
             * the socket has an error). recv() will not block in that
             * case, and is required to observe the EOF (0) or error (-1).
             */
            if (glob->tcp_readable == FALSE)
                return;
            glob->tcp_readable = FALSE;
            avail = 1;
        }
        glob->tcp_readable = FALSE;
        if (space > avail) {
            space = avail;
        } else if (space < avail) {
            /* Set our own "data available" signal */
            SetSignal(glob->tcp_read_signal, glob->tcp_read_signal);
        }

        count = recv(sock, ptr, space, 0);
        if ((count < 0) &&
            ((Errno() == EWOULDBLOCK) || (Errno() == EINTR)))
            return;  // No data after all (socket is non-blocking)
        if (count > space) {
            count = space;
            warnx("reterm recv(%d) returned %d bytes", space, count);
        }
        reader_handle_arrived_count(glob, count);
        return;
    }

    /* Amiga device */
    fh           = glob->reader_IFH;
    Pkt          = glob->reader_dos_packet;
    Pkt->dp_Port = glob->reader_msgport;  // Reply message port
    Pkt->dp_Type = ACTION_READ;
    Pkt->dp_Arg1 = fh;
    Pkt->dp_Arg2 = (ULONG) (glob->unproc_buf + glob->unproc_epos);
    Pkt->dp_Arg3 = space;

    input_mp = ((struct FileHandle *) BADDR(fh))->fh_Type;
    PutMsg(input_mp, Pkt->dp_Link);

    glob->reader_read_pending = TRUE;
}

/*
 * send_Abort() sends an ACTION_ABORT command to the console handler,
 *              in an attempt to unblock a previously sent asynchronous
 *              ACTION_READ.
 * ViNCEd requires the message port to be the same as that of the
 * asynchronous read. This code will leak a DOS_STDPKT, which needs
 * to be later absorbed and deallocated by the caller by waiting on
 * the glob->reader_msgport.
 */
static struct DosPacket *
send_Abort(glob_t *glob, BPTR fh)
{
    struct DosPacket *Pkt;
    struct MsgPort   *input_mp = ((struct FileHandle *) BADDR(fh))->fh_Type;

    Pkt = AllocDosObject(DOS_STDPKT, TAG_END);
    if (Pkt == NULL) {
        warnx("Failed to allocate reader paste packet");
        return (NULL);
    }

    Pkt->dp_Port = glob->reader_msgport;
    Pkt->dp_Type = ACTION_ABORT;
    Pkt->dp_Arg1 = fh;

    PutMsg(input_mp, Pkt->dp_Link);
    return (Pkt);
}

/*
 * send_Paste() sends a paste character to the specified file handle
 *              to fake user input.
 * This function is used to unblock a pending read at program exit. It works
 * on Amiga console handler and apparently also AmiTCP's inet-handler. There
 * is no guarantee it will work with all console handlers.
 */
static void
send_Paste(BPTR fh, UBYTE *str, LONG len)
{
    struct DosPacket *Pkt;
    struct MsgPort   *input_mp = ((struct FileHandle *) BADDR(fh))->fh_Type;
    struct MsgPort   *reply_mp = CreateMsgPort();

    if (reply_mp == NULL) {
        warnx("CreateMsgPort failed");
        return;
    }

    Pkt = AllocDosObject(DOS_STDPKT, TAG_END);
    if (Pkt == NULL) {
        DeleteMsgPort(reply_mp);
        warnx("Failed to allocate reader paste packet");
        return;
    }

    Pkt->dp_Port = reply_mp;
    Pkt->dp_Type = ACTION_STACK;
    Pkt->dp_Arg1 = fh;
    Pkt->dp_Arg2 = (LONG)str;
    Pkt->dp_Arg3 = len;

    PutMsg(input_mp, Pkt->dp_Link);
    WaitPort(reply_mp);
    GetMsg(reply_mp);

    FreeDosObject(DOS_STDPKT, Pkt);
    DeleteMsgPort(reply_mp);
}

/*
 * history_char_next() retrieves the next character from the circular
 *                     history buffer, wrapping as necessary.
 */
static UBYTE *
history_char_next(glob_t *glob, UBYTE *ptr)
{
    if (++ptr >= glob->history_buf + sizeof (glob->history_buf))
        ptr = glob->history_buf;
    return (ptr);
}

/*
 * history_char_prev() retrieves the previous character from the circular
 *                     history buffer, wrapping as necessary.
 */
static UBYTE *
history_char_prev(glob_t *glob, UBYTE *ptr)
{
    if (ptr <= glob->history_buf)
        ptr = glob->history_buf + sizeof (glob->history_buf);
    return (--ptr);
}

/*
 * history_fetch() retrieves a line from the command history.
 */
static BOOL
history_fetch(glob_t *glob, UBYTE *cmd, int line_num)
{
    UBYTE *ptr = history_char_prev(glob, glob->history_cur);
    UBYTE *cmd_end;

    if (line_num == 0) {
        /* Blank input line */
        *cmd = '\0';
        return (TRUE);
    }

    while (ptr != glob->history_cur) {
        ptr = history_char_prev(glob, ptr);

        if (*ptr != '\0') {
            /* Not yet at the start of the previous line */
            continue;
        }

        if (--line_num > 0) {
            /* Not yet at the desired history line */
            ptr = history_char_prev(glob, ptr);  /* Skip '\0' */
            continue;
        }

        ptr = history_char_next(glob, ptr);
        if (*ptr == '\0')
            return (FALSE);  /* No previous history */

        /* All callers supply a buffer of sizeof (glob->cmdline) */
        cmd_end = cmd + sizeof (glob->cmdline) - 1;
        do {
            if (cmd < cmd_end)
                *(cmd++) = *ptr;
            ptr = history_char_next(glob, ptr);
        } while (*ptr != '\0');
        *cmd = '\0';

        return (TRUE);
    }
    /* Specified position was not located in history */
    return (FALSE);
}

/*
 * history_add() adds the current command line to the command history.
 *               It will discard the line if identical to the most recent
 *               line added to the command history.
 */
static BOOL
history_add(glob_t *glob, int prev_hist_line)
{
    UBYTE *ptr;
    UBYTE  prev[sizeof (glob->cmdline)];
    UBYTE *cmd = glob->cmdline;
    ULONG  len = glob->cmdline_len;

    if (prev_hist_line == 0)
        prev_hist_line = 1;

    if (glob->history_cur == NULL)
        glob->history_cur = glob->history_buf;

    /* Strip initial whitespace */
    while ((len > 0) && (*cmd == ' ' || *cmd == '\t')) {
        cmd++;
        len--;
    }
    cmd[len] = '\0';

    /* Don't add command line if it's blank */
    if (cmd[0] == '\0')
        return (FALSE);

    /* Don't add if it matches most recent history line */
    if ((history_fetch(glob, prev, prev_hist_line) == TRUE) &&
        (strcmp(prev, cmd) == 0))
        return (FALSE);

    /* Copy new string to history */
    while (*cmd != '\0') {
        *glob->history_cur = *(cmd++);
        glob->history_cur  = history_char_next(glob, glob->history_cur);
    }

    /* Terminate string and clear remaining part of old string */
    for (ptr = glob->history_cur; *ptr != '\0';
         ptr = history_char_next(glob, ptr))
        *ptr = '\0';

    glob->history_cur = history_char_next(glob, glob->history_cur);
    return (TRUE);
}

/*
 * history_show() displays the command history.
 */
void
history_show(glob_t *glob)
{
    int    cur_line = 0;
    UBYTE *ptr      = glob->history_cur;

    if (ptr == NULL)
        return;  // No history yet

    /* Display each line from history */
    do {
        if (*ptr != '\0') {
            char tbuf[8];
            if (!glob->no_cooked_esc_sequences) {
                /* Save cursor pos, scroll up, cursor up, insert blank line */
                xterm_console_emit(glob, STR_ESC "7" STR_ESC "[S"
                                         STR_ESC "[A" STR_ESC "[L", 11);
            }
            xterm_console_emit(glob, tbuf, sprintf(tbuf, "%4d: ", cur_line++));
            while (*ptr != '\0') {
                    xterm_console_emit_text(glob, ptr, 1);
                ptr = history_char_next(glob, ptr);
                if (ptr == glob->history_cur) {
                    xterm_console_emit(glob, "\r\n", 2);
                    return;
                }
            }
            if (glob->no_cooked_esc_sequences) {
                xterm_console_emit(glob, "\r\n", 2);
            } else {
                /* Restore cursor position */
                xterm_console_emit(glob, STR_ESC "8", 2);
            }
        }
        ptr = history_char_next(glob, ptr);
    } while (ptr != glob->history_cur);
}

/*
 * xterm_esc_raw_app_input() handles a two-character escape sequence as input
 *                           from the xterm to the Amiga app.
 */
static void
xterm_esc_raw_app_input(glob_t *glob, UBYTE cmd)
{
    /* Just stuff them both in the Amiga input stream for now */
    append_to_app_input(glob, STR_ESC, 1);
    append_to_app_input(glob, &cmd, 1);
}

/*
 * xterm_csi_raw_app_input() processes input CSI sequences (starting ESC [)
 *                           an xterm and processes it for raw input use by
 *                           an Amiga application.
 */
static void
xterm_csi_raw_app_input(glob_t *glob, UBYTE cmd, const UBYTE *buf, int len)
{
    int num;
    int mod;
    int cur;

    switch (cmd) {
        case 'A':  // ESC [ A  - Cursor up
            if (buf[0] == '1')
                cmd = 'T';
            append_to_app_input(glob, STR_CSI, 1);
            append_to_app_input(glob, &cmd, 1);
            return;
        case 'B':  // ESC [ B  - Cursor down
            if (buf[0] == '1')
                cmd = 'S';
            append_to_app_input(glob, STR_CSI, 1);
            append_to_app_input(glob, &cmd, 1);
            return;
        case 'C':  // ESC [ C  - Cursor right
            append_to_app_input(glob, STR_CSI, 1);
            if (buf[0] == '1') {
                append_to_app_input(glob, " ", 1);
                cmd = '@';
            }
            append_to_app_input(glob, &cmd, 1);
            return;
        case 'D':  // ESC [ D  - Cursor left
            append_to_app_input(glob, STR_CSI, 1);
            if (buf[0] == '1') {
                append_to_app_input(glob, " ", 1);
                cmd = 'A';
            }
            append_to_app_input(glob, &cmd, 1);
            return;
        case 'F':
            if (buf[0] == '1') {
                /* ESC [ 1 ; 2 F  - Shift End  (note 1 ; 5 F is Ctrl End */
                append_to_app_input(glob, STR_CSI "55~", 4);
            } else {
                /* ESC [ F  - End */
                append_to_app_input(glob, STR_CSI "45~", 4);
            }
            return;
        case 'H':
            if (buf[0] == '1') {
                /* ESC [ 1 ; 2 H  - Shift Home  (note 1 ; 5 F is Ctrl Home */
                append_to_app_input(glob, STR_CSI "54~", 4);
            } else {
                /* ESC [ H  - Home */
                append_to_app_input(glob, STR_CSI "44~", 4);
            }
            return;
        case 'P': // F1
        case 'Q': // F2
        case 'R': // F3
        case 'S': // F4
            if ((buf[0] == 'O') && (len == 1)) {
                /*
                 * xterm F1 (ESC [ P) -> Amiga F1 (CSI 0 ~)
                 * xterm F2 (ESC [ Q) -> Amiga F2 (CSI 1 ~)
                 * xterm F3 (ESC [ R) -> Amiga F3 (CSI 2 ~)
                 * xterm F4 (ESC [ S) -> Amiga F4 (CSI 3 ~)
                 */
                UBYTE tbuf[8];
                num = cmd - 'P';
                sprintf(tbuf, STR_CSI "%d~", num);
                append_to_app_input(glob, tbuf, strlen(tbuf));
                return;
            } else if ((buf[0] == '1') && (buf[1] == ';') && (buf[2] == '2')) {
                /*
                 * xterm Shift F1 (ESC [ 1 ; 2 P) -> Amiga Shift F1 (CSI 10 ~)
                 * xterm Shift F2 (ESC [ 1 ; 2 Q) -> Amiga Shift F2 (CSI 11 ~)
                 * xterm Shift F3 (ESC [ 1 ; 2 R) -> Amiga Shift F3 (CSI 12 ~)
                 * xterm Shift F4 (ESC [ 1 ; 2 S) -> Amiga Shift F4 (CSI 13 ~)
                 */
                UBYTE tbuf[8];
                if ((cmd == 'R') && glob->xterm_request_pending)
                    goto cursor_position;  // Shift-F3 same as cursor position
                num = cmd - 'P' + 10;
                sprintf(tbuf, STR_CSI "%d~", num);
                append_to_app_input(glob, tbuf, strlen(tbuf));
                return;
            } else if (cmd == 'R') {
                /* Got Cursor Position Report */
                char tbuf[32];
                int  row;
                int  col;
cursor_position:
                cur = getnum(buf, &row);
                if ((cur == 0) || (row == 0))
                    row = 1;
                if (buf[cur] == ';')
                    cur++;
                cur = getnum(buf + cur, &col);
                if ((cur == 0) || (col == 0))
                    col = 1;
                DPRINT("Got cursor pos row=%d col=%d\n", row, col);
                glob->con_unit.cu_XCP = glob->con_unit.cu_XCCP = col - 1;
                glob->con_unit.cu_YCP = glob->con_unit.cu_YCCP = row - 1;

                /* Only propagate this to app when a request was made */
                if (glob->xterm_request_pending) {
                    glob->xterm_request_pending = FALSE;
                    snprintf(tbuf, sizeof (tbuf), STR_CSI "%d;%dR", row, col);
                    append_to_app_input(glob, tbuf, strlen(tbuf));
                }
                return;
            }
            break;
        case 'Z': // ESC [ Z  - Reverse tab
            append_to_app_input(glob, STR_CSI "Z", 2);
            return;
        case 't':
            cur = getnum(buf, &num);
            if (cur == 0)
                num = 0;
            if (num == 8) {
                /* ESC [ 8 ; Pr ; Pc t  - Window bounds report */
                int tcur;
                int rows;
                int cols;
                char tbuf[32];
                BOOL updated = FALSE;
                if (buf[cur] == ';')
                    cur++;
                tcur = getnum(buf + cur, &rows);
                if ((tcur == 0) || (rows == 0))
                    rows = 1;
                cur += tcur;
                if (buf[cur] == ';')
                    cur++;
                tcur = getnum(buf + cur, &cols);
                if ((tcur == 0) || (cols == 0))
                    cols = 1;
                DPRINT("Got window size rows=%d cols=%d\n", rows, cols);
                if (glob->con_unit.cu_XMax != cols - 1) {
                    glob->con_unit.cu_XMax = cols - 1;
                    glob->con_unit.cu_XRExtant = glob->con_unit.cu_XRSize *
                                                 glob->con_unit.cu_XMax;
                    updated = TRUE;
                }
                if (glob->con_unit.cu_YMax != rows - 1) {
                    glob->con_unit.cu_YMax = rows - 1;
                    glob->con_unit.cu_YRExtant = glob->con_unit.cu_YRSize *
                                                 glob->con_unit.cu_YMax;
                    updated = TRUE;
                }
                /* Only propagate this to app when a request was made */
                if (glob->xterm_request_pending) {
                    glob->xterm_request_pending = FALSE;
                    sprintf(tbuf, STR_CSI "1;1;%d;%d r", rows, cols);
                    append_to_app_input(glob, tbuf, strlen(tbuf));
                }

                if (updated &&
                    (glob->amiga_console_eventmask & (1 << 12))) {
                    /* Console event window resized */
                    sprintf(tbuf, STR_CSI "12;0;0;0;0;0;1;0|");
                    /*
                     * All values are in decimal. These are (in order):
                     *    class (12 = Window resized)
                     *    subclass
                     *    keycode
                     *    qualifiers (32768 = 0100 = Numeric pad)
                     *    window_addr >> 16
                     *    window_addr & 0xffff
                     *    seconds
                     *    useconds
                     */
                    append_to_app_input(glob, tbuf, strlen(tbuf));
                }
                return;
            }
            break;
        case '~':
            cur = getnum(buf, &num);
            if (cur == 0)
                num = 0;
            if ((cur > 0) && (buf[cur - 1] == ';')) {
                /* getnum() consumed the ';' separator */
                if (getnum(buf + cur, &mod) == 0)
                    mod = 0;
            } else {
                mod = 0;
            }
            switch (num) {
                case 2:
                    if (mod == 2) {
                        /* ESC [ 2 ; 2 ~  - Shift Insert key */
                        append_to_app_input(glob, STR_CSI "50~", 4);
                    } else {
                        /* ESC [ 2 ~  - Insert key */
                        append_to_app_input(glob, STR_CSI "40~", 4);
                    }
                    return;
                case 3:  // ESC [ 3 ~  - Delete key
                    cmd = 127;
                    append_to_app_input(glob, &cmd, 1);
                    return;
                case 5:
                    if (mod == 2) {
                        /* ESC [ 5 ; 2 ~  - Shift Page Up */
                        append_to_app_input(glob, STR_CSI "51~", 4);
                    } else if (mod == 5) {
                        /* ESC [ 5 ; 5 ~  - Ctrl Page Up (map to Amiga Help) */
                        append_to_app_input(glob, STR_CSI "?~", 3);
                    } else {
                        /* ESC [ 5 ~  - Page Up */
                        append_to_app_input(glob, STR_CSI "41~", 4);
                    }
                    return;
                case 6:
                    if (mod == 2) {
                        /* ESC [ 6 ; 2 ~  - Shift Page Down */
                        append_to_app_input(glob, STR_CSI "52~", 4);
                    } else if (mod == 5) {
                        /* ESC [ 6 ; 5 ~   Ctrl Page Down (map to Amiga Help) */
                        append_to_app_input(glob, STR_CSI "?~", 3);
                    } else {
                        /* ESC [ 6 ~  - Page Down */
                        append_to_app_input(glob, STR_CSI "42~", 4);
                    }
                    return;
                case 15:   // F5  -> Amiga CSI 4 ~
                    num++;
                    /* FALLTHROUGH */
                case 17:   // F6  -> Amiga CSI 5 ~
                case 18:   // F7  -> Amiga CSI 6 ~
                case 19:   // F8  -> Amiga CSI 7 ~
                case 20:   // F9  -> Amiga CSI 8 ~
                case 21: { // F10 -> Amiga CSI 9 ~
                    UBYTE tbuf[8];
                    num -= 12;
                    if (mod == 2)
                        num += 10;
                    sprintf(tbuf, STR_CSI "%d~", num);
                    append_to_app_input(glob, tbuf, strlen(tbuf));
                    return;
                }
            }
            break;
    }
    debug_print_sequence("UNK ESC [", buf, len + 1, TRUE);
}

/*
 * xterm_cook_app_input() takes raw input from an xterm and processes it
 *                        to provide a suitable command line handler,
 *                        complete with command editing, tab completion,
 *                        and command history. Only when enter is pressed
 *                        is the input presented to the Amiga application.
 */
static void
xterm_cook_app_input(glob_t *glob, UBYTE cmd)
{
    int num;

    switch (cmd) {
        case 0x00:  // ^@
            break;
        case 0x01:  // ^A - Go to the beginning of the input line
            if (glob->no_cooked_esc_sequences ||
                (glob->cmdline_pos < 3)) {
                /* Use backspace */
                xterm_console_emit_rep(glob, '\b', glob->cmdline_pos);
            } else {
                /* Use cursor left */
                UBYTE tbuf[8];
                xterm_console_emit(glob, tbuf,
                        sprintf(tbuf, STR_ESC "[%uD", glob->cmdline_pos));
            }
            glob->cmdline_pos = 0;
            break;
        case 0x02:  // ^B - Cursor left
            if (glob->cmdline_pos > 0) {
                glob->cmdline_pos--;
                xterm_console_emit(glob, "\b", 1);
            }
            break;
        case 0x03:  // ^C
            if ((glob->cmdline_len > 0) ||
                (glob->proc_epos != glob->proc_spos)) {
                glob->proc_epos = glob->proc_spos;  // Empty app input buffer
                glob->cmdline_len = 0;
                xterm_console_emit(glob, "^C", 2);
                goto send_input_to_app;             // Send newline to app
            }
            break;
        case 0x04:  // ^D - Delete
            /* Delete one character to the right or show tab completions */
            if (glob->tab_comp_running ||
                (glob->cmdline_pos == glob->cmdline_len)) {
                tab_completion_initiate(glob, 0);
                break;
            }
            /* Just move one to the right and execute backspace */
            glob->cmdline_pos++;
            xterm_console_emit(glob, " ", 1);
            xterm_cook_app_input(glob, '\b');
            break;
        case 0x05:  // ^E - Go to the end of the input line
            num = glob->cmdline_len - glob->cmdline_pos;
            if (glob->no_cooked_esc_sequences || (num < 3)) {
                /* Emit command line text to go forward */
                xterm_console_emit_text(glob, glob->cmdline + glob->cmdline_pos,
                                        num);
            } else {
                /* Use cursor right */
                UBYTE tbuf[8];
                xterm_console_emit(glob, tbuf,
                        sprintf(tbuf, STR_ESC "[%dC", num));
            }
            glob->cmdline_pos = glob->cmdline_len;
            break;
        case 0x06:  // ^F - Cursor right
            if (glob->cmdline_pos < glob->cmdline_len) {
                xterm_console_emit_text(glob,
                                        glob->cmdline + glob->cmdline_pos, 1);
                glob->cmdline_pos++;
            }
            return;
        case 0x07:  // ^G
            break;
        case 0x08:  // ^H Backspace ('\b')
            if (glob->cmdline_pos == 0)
                break;
            memmove(glob->cmdline + glob->cmdline_pos - 1,
                    glob->cmdline + glob->cmdline_pos,
                    glob->cmdline_len - glob->cmdline_pos);
            glob->cmdline_pos--;
            glob->cmdline_len--;
            if (glob->no_cooked_esc_sequences) {
                xterm_console_emit_text(glob, &cmd, 1);
                xterm_console_emit_text(glob, glob->cmdline + glob->cmdline_pos,
                                        glob->cmdline_len - glob->cmdline_pos);
                xterm_console_emit(glob, " ", 1);
                xterm_console_emit_rep(glob, '\b',
                                       glob->cmdline_len -
                                       glob->cmdline_pos + 1);
            } else {
                /* Use backspace followed by delete character */
                xterm_console_emit(glob, "\b" STR_ESC "[P", 4);
            }
            break;
        case 0x09:  // ^I - Tab
            tab_completion_initiate(glob, 1);
            break;
        case 0x0a:  // ^J Linefeed ('\n')
        case 0x0d:  // ^M Carriage Return ('\r')
send_input_to_app:
            xterm_console_emit(glob, "\r\n", 2);
            (void) history_add(glob, 0);
            glob->history_cur_line = 0;
            glob->cmdline[glob->cmdline_len++] = '\n';
            append_to_app_input(glob, glob->cmdline, glob->cmdline_len);
            glob->cmdline_len = 0;
            glob->cmdline_pos = 0;
            break;
        case 0x0b:  // ^K - Clear to end of line
            num = glob->cmdline_len - glob->cmdline_pos;
            xterm_console_emit_rep(glob, ' ', num);
            xterm_console_emit_rep(glob, '\b', num);
            glob->cmdline_len = glob->cmdline_pos;
            break;
        case 0x0c:  // ^L - Form feed
            break;
        case 0x0e:  // ^N - Next line in history
            if ((history_add(glob, glob->history_cur_line) == TRUE) &&
                (glob->history_cur_line != 0)) {
                glob->history_cur_line++;  // Line was modified and is now saved
            }
            if (glob->history_cur_line == 0) {
                glob->cmdline[0] = '\0';
                goto update_input_line;
            }
            glob->history_cur_line--;
            if (history_fetch(glob, glob->cmdline,
                              glob->history_cur_line) == FALSE) {
                glob->history_cur_line++;
                return;
            }

update_input_line:
            num = strlen(glob->cmdline);

            if (glob->no_cooked_esc_sequences || (glob->cmdline_pos < 3)) {
                /* Backspace to start of line */
                xterm_console_emit_rep(glob, '\b', glob->cmdline_pos);
            } else {
                /* Use cursor left to get to start of line */
                UBYTE tbuf[8];
                xterm_console_emit(glob, tbuf,
                        sprintf(tbuf, STR_ESC "[%uD", glob->cmdline_pos));
            }

            xterm_console_emit_text(glob, glob->cmdline, num);  // Emit new line
            if (glob->no_cooked_esc_sequences) {
                /* Space to end of old line and then backspace */
                if (glob->cmdline_len > num) {
                    xterm_console_emit_rep(glob, ' ', glob->cmdline_len - num);
                    xterm_console_emit_rep(glob, '\b', glob->cmdline_len - num);
                }
            } else {
                /* Erase to end of line */
                xterm_console_emit(glob, STR_ESC "[K", 3);
            }

            glob->cmdline_pos = num;
            glob->cmdline_len = num;
            break;
        case 0x0f:  // ^O
            break;
        case 0x10:  // ^P - Previous line in history
            if (history_add(glob, glob->history_cur_line) == TRUE)
                glob->history_cur_line++;  // Line was modified and is now saved

            glob->history_cur_line++;
            if (history_fetch(glob, glob->cmdline,
                              glob->history_cur_line) == FALSE) {
                glob->history_cur_line--;
                return;
            }
            goto update_input_line;
        case 0x11:  // ^Q
            break;
        case 0x12:  // ^R - Redraw command line
            if (glob->no_cooked_esc_sequences) {
                xterm_console_emit_rep(glob, '\b', glob->cmdline_pos);
                xterm_console_emit_text(glob, glob->cmdline, glob->cmdline_len);
                xterm_console_emit(glob, " ", 1);
                xterm_console_emit_rep(glob, '\b', glob->cmdline_len -
                                                   glob->cmdline_pos + 1);
            } else {
                /* Use cursor left */
                UBYTE tbuf[16];
                int left;
                if (glob->cmdline_pos > 0)
                    xterm_console_emit(glob, tbuf,
                            sprintf(tbuf, STR_ESC "[%uD", glob->cmdline_pos));
                xterm_console_emit_text(glob, glob->cmdline, glob->cmdline_len);

                left = glob->cmdline_len - glob->cmdline_pos;
                if (left < 4) {
                    /* Erase to end of line and then backspace */
                    xterm_console_emit(glob, STR_ESC "[K", 3);
                    xterm_console_emit_rep(glob, '\b', left);
                } else {
                    /* Erase to end of line and then cursor left */
                    xterm_console_emit(glob, tbuf,
                            sprintf(tbuf, STR_ESC "[K" STR_ESC "[%uD",
                                    glob->cmdline_len - glob->cmdline_pos));
                }
            }
            break;
        case 0x13:  // ^S
        case 0x14:  // ^T
            break;
        case 0x15:  // ^U - Clear to start of line
            /* Go to start of line, print remaining text, blank end of line */
            num = glob->cmdline_len - glob->cmdline_pos;
            memmove(glob->cmdline, glob->cmdline + glob->cmdline_pos, num);
            xterm_console_emit_rep(glob, '\b', glob->cmdline_pos);
            xterm_console_emit_text(glob, glob->cmdline, num);
            xterm_console_emit_rep(glob, ' ', glob->cmdline_len - num);
            xterm_console_emit_rep(glob, '\b', glob->cmdline_len);
            glob->cmdline_pos = 0;
            glob->cmdline_len = num;
            break;
        case 0x16:  // ^V
            break;
        case 0x17: {  // ^W - Delete word
            int tailen;
            int newpos;
            int remlen;

            /* Delete word */
            if (glob->cmdline_pos == 0)
                break;

            /* Skip whitespace */
            for (newpos = glob->cmdline_pos; newpos > 0; newpos--)
                if ((glob->cmdline[newpos - 1] != ' ') &&
                    (glob->cmdline[newpos - 1] != '\t'))
                    break;

            /* Find the start of the word */
            for (; newpos > 0; newpos--)
                if ((glob->cmdline[newpos - 1] == ' ') ||
                    (glob->cmdline[newpos - 1] == '\t'))
                    break;

            remlen = glob->cmdline_pos - newpos;
            tailen = glob->cmdline_len - glob->cmdline_pos;
            if (glob->no_cooked_esc_sequences) {
                /* Use backspace, partial cmdline, space, backspace */
                xterm_console_emit_rep(glob, '\b', remlen);
                xterm_console_emit_text(glob, glob->cmdline + glob->cmdline_pos,
                                        tailen);
                xterm_console_emit_rep(glob, ' ', remlen);
                xterm_console_emit_rep(glob, '\b', remlen + tailen);
            } else {
                /* Use cursor left and delete characters */
                UBYTE tbuf[16];
                xterm_console_emit(glob, tbuf,
                        sprintf(tbuf, STR_ESC "[%dD" STR_ESC "[%dP",
                                remlen, remlen));
            }
            memmove(glob->cmdline + newpos,
                    glob->cmdline + glob->cmdline_pos, tailen + 1);
            glob->cmdline_len -= remlen;
            glob->cmdline_pos = newpos;
            break;
        }
        case 0x18:  // ^X - Clear line (delete all text)
            if (glob->no_cooked_esc_sequences) {
                xterm_console_emit_rep(glob, '\b', glob->cmdline_pos);
                xterm_console_emit_rep(glob, ' ', glob->cmdline_len);
                xterm_console_emit_rep(glob, '\b', glob->cmdline_len);
            } else {
                /* Use cursor left and erase to end of line */
                UBYTE tbuf[16];
                if (glob->cmdline_pos == 0) {
                    /* ESC [ 0 D would move the cursor left one */
                    xterm_console_emit(glob, STR_ESC "[K", 3);
                } else {
                    xterm_console_emit(glob, tbuf,
                            sprintf(tbuf, STR_ESC "[%uD" STR_ESC "[K",
                                    glob->cmdline_pos));
                }
            }
            glob->cmdline_len = 0;
            glob->cmdline_pos = 0;
            break;
        case 0x19:  // ^Y - Show history
            if (glob->no_cooked_esc_sequences) {
                xterm_console_emit(glob, "\r\n", 2);
                history_show(glob);
                xterm_console_emit_text(glob, glob->cmdline, glob->cmdline_len);
                num = glob->cmdline_len - glob->cmdline_pos;
                xterm_console_emit_rep(glob, '\b', num);
            } else {
                /* Fully handled in the history_show() function */
                history_show(glob);
            }
            break;
        case 0x1a:  // ^Z
        case 0x1b:  // ESC -- Should not see that here
        case 0x1c:  // FS - File separator
        case 0x1d:  // GS - Group separator
            break;
        case 0x1e: { // RS - Record separator
            /* xterm_csi_cook_app_input() requests word left */
            int newpos;
            int diff;

            if (glob->cmdline_pos == 0)
                break;  // Already at start of line

            /* Skip whitespace */
            for (newpos = glob->cmdline_pos; newpos > 0; newpos--)
                if ((glob->cmdline[newpos - 1] != ' ') &&
                    (glob->cmdline[newpos - 1] != '\t'))
                    break;

            /* Find the start of the word */
            for (; newpos > 0; newpos--)
                if ((glob->cmdline[newpos - 1] == ' ') ||
                    (glob->cmdline[newpos - 1] == '\t'))
                    break;

            diff = glob->cmdline_pos - newpos;
            if (glob->no_cooked_esc_sequences || (diff < 5)) {
                /* Use backspace */
                xterm_console_emit_rep(glob, '\b', diff);
            } else {
                /* Use cursor left */
                UBYTE tbuf[8];
                xterm_console_emit(glob, tbuf,
                        sprintf(tbuf, STR_ESC "[%dD", diff));
            }
            glob->cmdline_pos = newpos;
            break;
        }
        case 0x1f: { // US - Unit separator
            /* xterm_csi_cook_app_input() requests word right */
            int newpos;
            int diff;

            if (glob->cmdline_pos == glob->cmdline_len)
                break;  // Already at end of line

            /* Find the end of the word */
            for (newpos = glob->cmdline_pos;
                 newpos < glob->cmdline_len; newpos++)
                if ((glob->cmdline[newpos] == ' ') ||
                    (glob->cmdline[newpos] == '\t'))
                    break;

            /* Skip whitespace */
            for (; newpos < glob->cmdline_len; newpos++)
                if ((glob->cmdline[newpos] != ' ') &&
                    (glob->cmdline[newpos] != '\t'))
                    break;

            diff = newpos - glob->cmdline_pos;
            if (glob->no_cooked_esc_sequences || (diff < 5)) {
                /* Emit cmdline text */
                xterm_console_emit_text(glob, glob->cmdline + glob->cmdline_pos,
                                        diff);
            } else {
                /* Use cursor right */
                UBYTE tbuf[8];
                xterm_console_emit(glob, tbuf,
                        sprintf(tbuf, STR_ESC "[%dC", diff));
            }
            glob->cmdline_pos = newpos;
            break;
        }
        default:
            /* Regular command line input */
            if (glob->cmdline_len >= sizeof (glob->cmdline) - 1)
                break;  // No space left

            /* Insert at cursor position */
            if (glob->cmdline_pos < glob->cmdline_len)
                memmove(glob->cmdline + glob->cmdline_pos + 1,
                        glob->cmdline + glob->cmdline_pos,
                        glob->cmdline_len - glob->cmdline_pos);

            glob->cmdline[glob->cmdline_pos] = cmd;
            glob->cmdline_len++;
            if (glob->no_cooked_esc_sequences) {
                xterm_console_emit_text(glob, glob->cmdline + glob->cmdline_pos,
                                        glob->cmdline_len - glob->cmdline_pos);
                glob->cmdline_pos++;
                if (glob->cmdline_len > glob->cmdline_pos) {
                    xterm_console_emit_rep(glob, '\b',
                                           glob->cmdline_len -
                                           glob->cmdline_pos);
                }
            } else {
                glob->cmdline_pos++;
                if (glob->cmdline_pos == glob->cmdline_len) {
                    xterm_console_emit_text(glob, &cmd, 1);
                } else {
                    /* Insert space before emitting character */
                    xterm_console_emit(glob, STR_ESC "[@", 3);
                    xterm_console_emit_text(glob, &cmd, 1);
                }
            }
            break;
    }
}

/*
 * xterm_csi_cook_app_input() takes a CSI sequence from the user or xterm and
 *                            uses it to manipulate the "cooked" command line.
 */
static void
xterm_csi_cook_app_input(glob_t *glob, UBYTE cmd, const UBYTE *buf, int len)
{
    int    num;
    int    mod;
    int    cur;
    switch (cmd) {
        case 'A':  // ESC [ A  - Cursor up
            xterm_cook_app_input(glob, 0x10);  // ^P Previous line in history
            return;
        case 'B':  // ESC [ B  - Cursor down
            xterm_cook_app_input(glob, 0x0e);  // ^N Next line in history
            return;
        case 'C':  // ESC [ C  - Cursor right
            if ((buf[0] == '1') && (buf[1] == ';') && (buf[2] == '2'))
                xterm_cook_app_input(glob, 0x05);  // ^E - End of line
            else if ((buf[0] == '1') && (buf[1] == ';') && (buf[2] == '5'))
                xterm_cook_app_input(glob, 0x1f);  // RS - Forward one word
            else
                xterm_cook_app_input(glob, 0x06);  // ^F - Forward one char
            return;
        case 'D':  // ESC [ D  - Cursor left
            if ((buf[0] == '1') && (buf[1] == ';') && (buf[2] == '2'))
                xterm_cook_app_input(glob, 0x01);  // ^A - Start of line
            else if ((buf[0] == '1') && (buf[1] == ';') && (buf[2] == '5'))
                xterm_cook_app_input(glob, 0x1e);  // US - Back one word
            else
                xterm_cook_app_input(glob, 0x02);  // ^B - Back one character
            return;
        case 'F':
            if (buf[0] == '1') {
                /* ESC [ 1 ; 2 F  - Shift End  (note 1 ; 5 F is Ctrl End */
            } else {
                /* ESC [ F  - End */
            }
            return;
        case 'H':
            if (buf[0] == '1') {
                /* ESC [ 1 ; 2 H  - Shift Home  (note 1 ; 5 F is Ctrl Home */
            } else {
                /* ESC [ H  - Home */
            }
            return;
        case 'R':  // ESC [ Pr ; Pc R - Cursor position report
        case 't':  // ESC [ 8 ; Pr ; Pc t  - Window bounds report
            xterm_csi_raw_app_input(glob, cmd, buf, len);
            return;
        case 'Z':  // ESC [ Z - Shift-tab (backward tab)
            tab_completion_initiate(glob, -1);
            return;
        case 'c':  // ESC [ ? ; Pr ; Pc c  - Identify response
            if (buf[0] == '?') {
                /*
                 * A survey of different terminal emulator responses:
                 * st              ESC [ ? 6 c
                 * screen          ESC [ ? 1 ; 2 c
                 * rxvt            ESC [ ? 1 ; 2 c
                 * mrxvt           ESC [ ? 1 ; 2 c
                 * konsole         ESC [ ? 1 ; 2 c
                 * qterminal       ESC [ ? 1 ; 2 c
                 * roxterm         ESC [ ? 6 2 ; c
                 * sakura          ESC [ ? 6 2 ; c
                 * tilix           ESC [ ? 6 2 ; c
                 * Mate terminal   ESC [ ? 6 2 ; c
                 * Gnome terminal  ESC [ ? 6 2 ; c
                 * xfce4-terminal  ESC [ ? 6 2 ; c
                 * termit          ESC [ ? 6 2 ; 9 ; c
                 * qodem           ESC [ ? 6 2 ; 1 ; 6 ; c ^@
                 * xterm (F28)     ESC [ ? 6 4 ; 1 ; 2 ; 6 ; 9 ; 1 5 ; 1 8 ;
                 *                 2 1 ; 2 2 c
                 */
                buf++;
                len--;
                if ((buf[0] == '1') || (buf[0] == '6')) {
                    if (glob->term_type == TERM_TYPE_UNKNOWN) {
                        glob->term_type = TERM_TYPE_XTERM;
                        glob->support_xterm = TRUE;
                        DPRINT1("xterm terminal type");
                    }
                }
            }
            return;
        case 'r':  // CSI 1 ; 1 ; Pr ; Pc SPACE r - Amiga Window Bounds Report
            /*
             * This should not normally occur here (an xterm answering back
             * with an Amiga Window Bounds Report. It will be used to detect
             * an Amiga console as present.
             */
            if (((strncmp(buf, "1;1;", 4) == 0) ||
                 (strncmp(buf, "?601;1;", 7) == 0)) &&
                (buf[len - 1] == ' ')) {
                if (glob->term_type == TERM_TYPE_UNKNOWN) {
                    glob->term_type = TERM_TYPE_AMIGA;
                    glob->support_xterm = FALSE;
                    DPRINT1("Amiga terminal type");
                }
                return;
            }
            break;
        case '~':
            cur = getnum(buf, &num);
            if (cur == 0)
                num = 0;
            if ((cur > 0) && (buf[cur - 1] == ';')) {
                /* getnum() consumed the ';' separator */
                if (getnum(buf + cur, &mod) == 0)
                    mod = 0;
            } else {
                mod = 0;
            }
            switch (num) {
                case 3:  // ESC [ 3 ~  - Delete key
                    xterm_cook_app_input(glob, 0x04);  // ^D
                    break;
                default:
                    break;
            }
            return;
    }
    debug_print_sequence("unk ESC [", buf, len + 1, TRUE);
}

/*
 * xterm_esc_timer_start() starts a timer to terminate an escape sequence
 *                         should the sequence not be received within an
 *                         acceptable time limit. This allows reterm to
 *                         differentiate a user ESC press and have that
 *                         sent to the application vs an ESC sequence which
 *                         is to be interpreted.
 */
static void
xterm_esc_timer_start(glob_t *glob)
{
    struct timerequest *t_req;
    struct MsgPort     *timer_mp = glob->xterm_timer_msgport;
    if (glob->xterm_timer_request != NULL) {
        warnx("BUG: xterm timer request already outstanding");
        return;
    }
    SetSignal(0, glob->xterm_timer_signal);  // Clear previous signal
    t_req = CreateIORequest(timer_mp, sizeof (struct timerequest));
    if (t_req == NULL) {
        warnx("CreateIORequest failed");
        return;
    }
    if (OpenDevice(TIMERNAME, UNIT_MICROHZ, &t_req->tr_node, 0) != 0) {
        warnx("timer.device MICROHZ failed");
        DeleteIORequest(t_req);
        return;
    }
    t_req->tr_node.io_Command = TR_ADDREQUEST;
    t_req->tr_time.tv_secs  = 0;
    t_req->tr_time.tv_micro = 400000;  // 400ms
    SendIO(&t_req->tr_node);
    glob->xterm_timer_request = t_req;
}

static void
xterm_timer_cancel(glob_t *glob)
{
    if (glob->xterm_timer_request != NULL) {
        timer_cancel(glob->xterm_timer_request);
        glob->xterm_timer_request = NULL;
    }
}

static BOOL
xterm_timer_occurred(glob_t *glob)
{
    struct timerequest *t_req;

    t_req = (struct timerequest *) GetMsg(glob->xterm_timer_msgport);
    if (t_req != NULL) {
        CloseDevice(&t_req->tr_node);
        DeleteIORequest(t_req);
        glob->xterm_timer_request = NULL;
        return (TRUE);
    }
    return (FALSE);
}

/*
 * This function will process xterm or user input to look like Amiga console
 * output. This processed output will eventually be read by the Amiga app.
 * The function is called by the reader thread. Note that this code also
 * executes when connected to an Amiga console.
 */
static void
reader_process_xterm_to_amiga(glob_t *glob)
{
    UBYTE cmd;

    if (xterm_timer_occurred(glob)) {
        if (wk_esc_timeout(glob)) {
            /* Lone ESC key press canceled the window control prompt */
        } else if (glob->xta_mode == XT_MODE_ESC) {
            /* Lone ESC key press (the cooked line editor ignores ESC) */
            if (glob->raw_mode)
                append_to_app_input(glob, STR_ESC, 1);
            glob->xta_mode = XT_MODE_NONE;
        }
    }

    while (glob->unproc_epos != glob->unproc_spos) {  // No more read data
        /* Data is available */
        LONG space = procbuf_space(glob);

        /*
         * We could have command line entry or a Windows Bounds Report +
         * Window Resize Event as the longest input.Need to be sure
         * there will be enough space for either in the processed buffer
         * before proceeding to handle further input.
         */
        if ((space < 32) || (space <= glob->cmdline_len))
            break;

        cmd = glob->unproc_buf[glob->unproc_spos++];
        if (glob->unproc_spos == sizeof (glob->unproc_buf))
            glob->unproc_spos = 0;

        switch (glob->xta_mode) {
            case XT_MODE_NONE: {
                BOOL utf8_decoded = FALSE;

                tab_completion_handle(glob);
                if (glob->utf8_lead != 0) {
                    /* Second byte of a UTF-8 sequence U+0080 - U+00FF */
                    UBYTE lead = glob->utf8_lead;
                    glob->utf8_lead = 0;
                    if ((cmd & 0xc0) == 0x80) {
                        cmd = (UBYTE) (((lead & 0x03) << 6) | (cmd & 0x3f));
                        utf8_decoded = TRUE;
                    }
                    /* else invalid sequence: lead is dropped */
                }
                if (glob->wk_eat_nl) {
                    glob->wk_eat_nl = FALSE;
                    if ((cmd == '\n') || (cmd == '\0'))
                        break;  // End of line which entered gadget text
                }
                if (glob->requester_abort_active &&
                    task_window_kill(glob, cmd)) {
                    break;  // Input was absorbed
                }
                if ((cmd == glob->requester_abort_key) &&
                    task_window_kill(glob, cmd)) {
                    break;  // Input was absorbed
                }
                if (utf8_decoded) {
                    /*
                     * Decoded character is literal ISO 8859-1 text. It must
                     * not be interpreted below (e.g. 0xff as telnet IAC,
                     * 0x9b as CSI, or 0xc2 as another UTF-8 lead byte).
                     */
                    goto pass_through;
                }

                switch (cmd) {
                    case 0:
                        if (glob->support_telnet) {
                            /* Discard NIL (happens following CR) */
                            continue;
                        }
                        break;
                    case 3:  // ^C
                    case 4:  // ^D
                    case 5:  // ^E
                        /* Cooked mode handles these differently */
                        signal_child(glob, SIGBREAKF_CTRL_C << (cmd - 3));
                        break;
                    case KEY_ESC:
                        glob->xta_mode = XT_MODE_ESC;
                        xterm_esc_timer_start(glob);
                        continue;
                    case KEY_CSI:
                        /* Should not get this unless it's an Amiga console */
                        glob->xta_mode = XT_MODE_CSI;
                        glob->xta_cmdbuf_pos = 0;
                        continue;
#if 0
                    case 0x0d:
                        if (glob->support_telnet) {
                            /* Convert CR to LF */
                            cmd = 0xa;
                        }
                        break;
#endif
                    case 0x1c:  // xterm Ctrl-Backslash (file separator)
                        glob->got_zero_read_count++;
                        continue;
                    case 0x7f:  // xterm Backspace
                        cmd = '\b';
                        break;
                    case 0xc2:  // UTF-8 lead for U+0080 - U+00BF
                    case 0xc3:  // UTF-8 lead for U+00C0 - U+00FF
                        if (glob->support_utf8) {
                            /* Combine with next byte to form ISO 8859-1 */
                            glob->utf8_lead = cmd;
                            continue;
                        }
                        break;
                    case TELNET_IAC:
                        if (glob->support_telnet) {
                            glob->xta_mode = XT_MODE_IAC;
                            continue;
                        }
                        break;
                    default:
                        break;
                }
pass_through:
                if (glob->raw_mode)
                    append_to_app_input(glob, &cmd, 1);
                else
                    xterm_cook_app_input(glob, cmd);
                break;
            }
            case XT_MODE_ESC:
                xterm_timer_cancel(glob);
                switch (cmd) {
                    case '[':  /* ESC [ Pn  - CSI mode start */
                        glob->xta_mode = XT_MODE_CSI;
                        glob->xta_cmdbuf_pos = 0;
                        break;
                    case KEY_ESC:
                        /* Pass the first ESC through and re-start ESC mode */
                        xterm_esc_timer_start(glob);
                        goto pass_through;
                    case 'O':
                        /*
                         * ESC O x (SS3) is sent by xterm for F1-F4, and for
                         * cursor / Home / End keys in application cursor
                         * mode. Handle it as a CSI sequence beginning with
                         * 'O', which the CSI input handlers recognize.
                         */
                        glob->xta_mode = XT_MODE_CSI;
                        glob->xta_cmdbuf[0] = 'O';
                        glob->xta_cmdbuf_pos = 1;
                        break;
                    default:
                        /* ESC x (such as Alt-x): only meaningful in raw mode */
                        if (glob->raw_mode)
                            xterm_esc_raw_app_input(glob, cmd);
                        glob->xta_mode = XT_MODE_NONE;
                        break;
                }
                break;
            case XT_MODE_CSI:
                /* Data is buffered until the CSI sequence ends */
                if (glob->xta_cmdbuf_pos < sizeof (glob->xta_cmdbuf))
                    glob->xta_cmdbuf[glob->xta_cmdbuf_pos++] = cmd;

                if (cmd == KEY_ESC) {
                    /* ESC in the middle of an ESC sequence */
                    debug_print_sequence("UNk ESC [", glob->xta_cmdbuf,
                                         glob->xta_cmdbuf_pos, TRUE);
                    glob->xta_mode = XT_MODE_ESC;
                    xterm_esc_timer_start(glob);
                    break;
                }
                if (cmd == KEY_CSI) {
                    debug_print_sequence("UNk ESC [", glob->xta_cmdbuf,
                                         glob->xta_cmdbuf_pos, TRUE);
                    glob->xta_cmdbuf_pos = 0;
                    break;
                }
                if ((cmd >= '@' && cmd <= '~')) {
                    /* End of CSI sequence */
                    UBYTE  len = glob->xta_cmdbuf_pos - 1;
                    UBYTE *buf = glob->xta_cmdbuf;
                    if (glob->raw_mode) {
                        if (glob->support_xterm) {
                            xterm_csi_raw_app_input(glob, cmd, buf, len);
                        } else {
                            /* Pass through to Amiga application */
                            append_to_app_input(glob, STR_CSI, 1);
                            append_to_app_input(glob, buf, len + 1);
                        }
                    } else {
                        xterm_csi_cook_app_input(glob, cmd, buf, len);
                    }
                    glob->xta_mode = XT_MODE_NONE;
                }
                break;
            case XT_MODE_IAC:
                /*
                 * Most telnet commands are a single byte following IAC.
                 * Those which take an option byte set a new mode below.
                 */
                glob->xta_mode = XT_MODE_NONE;
                switch (cmd) {
                    case TELNET_EOF:    // 0xec - Enf of file (EOF)
                        glob->got_zero_read_count++;
                        break;
                    case TELNET_NOP:    // 0xf1 - No operation (NOP)
                        warnx("Telnet NOP");
                        break;
                    case TELNET_BRK:    // 0xf3 - Break interrupt (BRK)
                        warnx("Telnet BRK");
                        signal_child(glob, SIGBREAKF_CTRL_C);
                        break;
                    case TELNET_IP:     // 0xf4 - Interrupt process (IP)
                        warnx("Telnet IP");
                        signal_child(glob, SIGBREAKF_CTRL_C);
                        break;
                    case TELNET_AO:     // 0xf5 - Abort output (AO)
                        warnx("Telnet AO");
                        signal_child(glob, SIGBREAKF_CTRL_E);
                        break;
                    case TELNET_WILL:   // 0xfb - Will Do
                    case TELNET_WONT:   // 0xfc - Will Not Do
                    case TELNET_DO:     // 0xfd - Must Will Do
                    case TELNET_DONT:   // 0xfe - Must Not Do
                    case TELNET_SB:     // 0xfa - Sub-Negotiation Begin
                        glob->xta_mode = cmd;
                        break;
                    case TELNET_IAC:    // 0xff - Next byte is code
                        goto pass_through;
                    default:
                        warnx("Unknown Telnet IAC %02x", cmd);
                        glob->xta_mode = XT_MODE_NONE;
                        break;
                }
                break;
            case TELNET_WILL:
                DPRINT("WILL %02x\n", cmd);
                if (cmd == TELNET_OP_LINEMODE) {
                    UBYTE tbuf[] = {TELNET_IAC, TELNET_DO, cmd};
                    telnet_emit(glob, tbuf, sizeof (tbuf));
                    DPRINT(" DO   %02x\n", cmd);
                    glob->did_telnet_do_linemode = TRUE;
                } else if (cmd == TELNET_OP_NO_GO_AHEAD) {
                    if (glob->did_telnet_no_go_ahead == FALSE) {
                        glob->did_telnet_no_go_ahead = TRUE;
                        UBYTE tbuf[] = {TELNET_IAC, TELNET_DO, cmd};
                        telnet_emit(glob, tbuf, sizeof (tbuf));
                        DPRINT(" DO   %02x\n", cmd);
                    }
                } else {
                    UBYTE tbuf[] = {TELNET_IAC, TELNET_DONT, cmd};
                    telnet_emit(glob, tbuf, sizeof (tbuf));
                    DPRINT(" DONT %02x\n", cmd);
                }
                glob->xta_mode = XT_MODE_NONE;
                break;
            case TELNET_WONT:
                DPRINT("WONT %02x\n", cmd);
                if (cmd == TELNET_OP_ECHO) {
                    UBYTE tbuf[] = {TELNET_IAC, TELNET_WILL, cmd};
                    telnet_emit(glob, tbuf, sizeof (tbuf));
                    DPRINT(" WILL %02x\n", cmd);
                }
                glob->xta_mode = XT_MODE_NONE;
                break;
            case TELNET_DO: {
                UBYTE tbuf[] = {TELNET_IAC, TELNET_WONT, cmd};
                if ((cmd == TELNET_OP_NO_GO_AHEAD) || (cmd == TELNET_OP_ECHO))
                    tbuf[1] = TELNET_WILL;
                if (cmd == TELNET_OP_ECHO)
                    glob->did_telnet_will_echo = TRUE;

                telnet_emit(glob, tbuf, sizeof (tbuf));

                DPRINT("DO %02x\n", cmd);
                DPRINT(" %s %02x\n",
                       (tbuf[1] == TELNET_WILL) ? "WILL" : "WONT", cmd);
                if (cmd == TELNET_OP_NO_GO_AHEAD) {
                    tbuf[1] = TELNET_WILL;
                    tbuf[2] = TELNET_OP_ECHO;
                    telnet_emit(glob, tbuf, sizeof (tbuf));
                    DPRINT(" WILL %02x\n", TELNET_OP_ECHO);
                }
                glob->xta_mode = XT_MODE_NONE;
                break;
            }
            case TELNET_DONT: {
                UBYTE tbuf[] = {TELNET_IAC, TELNET_WONT, cmd};
                DPRINT("DONT %02x\n", cmd);
                if (((cmd == TELNET_OP_ECHO) &&
                     (glob->did_telnet_wont_echo++)) ||
                    ((cmd == TELNET_OP_EXT_LIST) &&
                     (glob->did_telnet_wont_extlist++)) ||
                    ((cmd == TELNET_OP_OUTMRK) &&
                     (glob->did_telnet_wont_outmark++))) {
                    /* The above have already been sent -- don't send again */
                    glob->xta_mode = XT_MODE_NONE;
                    break;
                }
                telnet_emit(glob, tbuf, sizeof (tbuf));
                DPRINT(" WONT %02x\n", cmd);
                glob->xta_mode = XT_MODE_NONE;
                break;
            }
            case TELNET_SB:
                if (cmd == TELNET_IAC)  // Wait for TELNET_SE (seq end)
                    glob->xta_mode = TELNET_SE;
                break;
            case TELNET_SE:
                if (cmd != TELNET_SE)
                    glob->xta_mode = TELNET_SB;  // Go back and try again
                else
                    glob->xta_mode = XT_MODE_NONE; // Got TELNET_SE -- seq end
                break;
            default:
                warnx("BUG: Unknown reader mode %d", glob->xta_mode);
                glob->xta_mode = XT_MODE_NONE;
                break;
        }
    }
}

static void
reader_handle_arrived_read(glob_t *glob, struct MsgPort *reply_mp)
{
    struct Message *rMsg;

    /*
     * Only one message at a time will ever arrive, since the
     * glob->reader_read_pending flag prevents multiple reads
     * from being issued.
     */
    WaitPort(reply_mp);
    rMsg = GetMsg(reply_mp);
    if (rMsg == NULL) {
        warnx("Reader got NULL from GetMsg of arrived reads");
        return;  // Should not happen
    }

    struct DosPacket *rPkt = PktFromMsg(rMsg);
    if (rPkt != glob->reader_dos_packet) {
        warnx("BUG: Sent %p to console but got %p",
              glob->reader_dos_packet, rPkt);
        return;
    }

    glob->reader_read_pending = FALSE;
    reader_handle_arrived_count(glob, rPkt->dp_Res1);
}

/*
 * reader_schedule_timer_request() will schedule a timer request based on
 *     the amount of time requested. It will store a pointer to this request
 *     (for later cancellation) in the pkt_res2 pointer. On failure, this
 *     function returns TRUE (non-zero) and sets pkt_res2 to a failure code.
 */
static BOOL
reader_schedule_timer_request(glob_t *glob, struct Message *Msg,
                              struct DosPacket *Pkt)
{
    struct timerequest *t_req;
    struct MsgPort     *timer_mp = glob->reader_timer_msgport;
    LONG                usecs    = Pkt->dp_Arg1;

    SetSignal(0, glob->reader_timer_signal);  // Clear previous signal, if set

    DPRINT2("SchedWait %d (outstanding=%d)",
            usecs, glob->reader_timer_pending);
    t_req = CreateIORequest(timer_mp, sizeof (struct timerequest));
    if (t_req == NULL) {
        warnx("CreateIORequest failed");
        Pkt->dp_Res2 = ERROR_NO_FREE_STORE;
        return (TRUE);
    }
    if (OpenDevice(TIMERNAME, UNIT_MICROHZ, &t_req->tr_node, 0) != 0) {
        warnx("timer.device MICROHZ failed");
        DeleteIORequest(t_req);
        Pkt->dp_Res2 = ERROR_NO_FREE_STORE;
        return (TRUE);
    }
    t_req->tr_node.io_Command = TR_ADDREQUEST;
    if (glob->xterm_request_pending) {
        /* Add 100ms to allow for remote response */
        usecs += 100000;
    }
    if (usecs < 1000000) {
        t_req->tr_time.tv_secs = 0;
        t_req->tr_time.tv_micro = (ULONG) usecs;
    } else {
        t_req->tr_time.tv_secs = (ULONG) usecs / 1000000;
        t_req->tr_time.tv_micro = (ULONG) usecs % 1000000;
    }
    t_req->tr_node.io_Message.mn_Node.ln_Name = (char *) Msg;
    glob->reader_timer_pending++;

    Pkt->dp_Res2 = (LONG) t_req;
    SendIO(&t_req->tr_node);
    return (FALSE);
}

/*
 * reader_handle_app_reads() handles ACTION_READ and ACTION_WAIT_CHAR packets
 *                           from the child application.
 */
static void
reader_handle_app_reads(glob_t *glob)
{
    if (glob->pending_reads.lh_Head->ln_Succ == NULL)
        return;

    Forbid();
    while (glob->pending_reads.lh_Head->ln_Succ != NULL) {
        struct Message   *Msg = (struct Message *) glob->pending_reads.lh_Head;
        struct DosPacket *Pkt = PktFromMsg(Msg);

        if (Pkt->dp_Type == ACTION_WAIT_CHAR) {
            struct timerequest *t_req = (struct timerequest *) Pkt->dp_Res2;

            if (reader_consume(glob, NULL, 0) == 0) {
                if (t_req == NULL) {
                    if (reader_schedule_timer_request(glob, Msg, Pkt)) {
                        /* Failed to schedule timer */
                        Pkt->dp_Res1 = DOSFALSE;
                        goto reply_message;
                    }
                }
                /* Nothing more to do at this point -- wait for timer */
                Permit();
                return;
            }

            if (t_req != NULL) {
                if (glob->reader_timer_pending == 0) {
                    warnx("BUG: t_req with no timer outstanding: %x",
                          Pkt->dp_Res2);
                } else {
                    timer_cancel(t_req);
                    glob->reader_timer_pending--;
                }
            }
            Pkt->dp_Res1 = DOSTRUE;
            Pkt->dp_Res2 = 1;  // Fake number of lines

reply_message:
            RemHead(&glob->pending_reads);       // Remove top of read wait list
            PutMsg(Pkt->dp_Port, Pkt->dp_Link);  // Reply to packet

        } else if (Pkt->dp_Type == ACTION_READ) {
            LONG len;
            if (glob->got_zero_read_count) {
                /* Propagate zero read count (file closed) to reader */
                glob->got_zero_read_count--;
                Pkt->dp_Res1 = 0;
                Pkt->dp_Res2 = 0;
                DPRINT(" Done_READ(len=%d)=0\n", Pkt->dp_Arg3);
                goto reply_message;
            }
            len = reader_consume(glob, (UBYTE *) Pkt->dp_Arg2, Pkt->dp_Arg3);
            if (len == 0)
                break;  // Nothing currently available

            Pkt->dp_Res1 = len;
            Pkt->dp_Res2 = 0;
            DPRINT(" Done_READ(len=%d)=%d\n", Pkt->dp_Arg3, len);
            goto reply_message;
        } else {
            warnx("BUG: Unknown read pkt %d", Pkt->dp_Type);
            Pkt->dp_Res1 = DOSFALSE;
            Pkt->dp_Res2 = ERROR_ACTION_NOT_KNOWN;
            goto reply_message;
        }
    }
    Permit();
}

static void
reader_handle_timeouts(glob_t *glob)
{
    struct Message     *Msg;
    struct DosPacket   *Pkt;
    struct timerequest *t_req;
    struct MsgPort     *timer_mp = glob->reader_timer_msgport;

    /*
     * Do not do WaitPort(timer_mp) here because the timer might have
     * been already terminated by a WAIT_FOR_CHAR which just completed.
     */
    while ((t_req = (struct timerequest *) GetMsg(timer_mp)) != NULL) {
        Msg = (struct Message *) t_req->tr_node.io_Message.mn_Node.ln_Name;
        Pkt = PktFromMsg(Msg);
        CloseDevice(&t_req->tr_node);
        DeleteIORequest(t_req);
        Pkt->dp_Res1 = DOSFALSE;
        Pkt->dp_Res2 = 0;
        glob->reader_timer_pending--;
        Forbid();
        Remove(&Msg->mn_Node);              // Remove it from the read wait list
        PutMsg(Pkt->dp_Port, Pkt->dp_Link); // Reply to packet
        Permit();
    }
}

static ULONG
do_WaitSelect(glob_t *glob, ULONG all_sigmask)
{
    struct Library *SocketBase = glob->socketbase_reader;
    ULONG signals;

    /* TCP Socket */
    fd_set rdset;
    LONG sock = glob->tcp_socket_reader;
    LONG nfds = sock + 1;
    LONG space = (LONG) glob->unproc_spos - (LONG) glob->unproc_epos - 1;
    FD_ZERO(&rdset);
    if (space < 0)
        space += sizeof (glob->unproc_buf);
    if (space > 0) {
        FD_SET(sock, &rdset);
    } else {
        /*
         * No room to receive data, so don't wait for the socket to become
         * readable (it already is, so that would just spin). Processing
         * resumes when the application consumes input (signal) or on the
         * timeout below.
         */
        nfds = 0;
    }
    signals = all_sigmask;
    /*
     * We need a timeout (must poll) because FS-UAE doesn't yet
     * implement the TCP data "ready" signal.
     */
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 100000;
    LONG rc = WaitSelect(nfds, &rdset, NULL, NULL, &tv, &signals);
    if (rc < 0) {
        LONG error = Errno();
        if (error != EINTR) {
            warnx("WaitSelect failed: %d", error);
            glob->stopping = TRUE;
        }
    } else if ((rc > 0) && FD_ISSET(sock, &rdset)) {
        glob->tcp_readable = TRUE;
    }
    return (signals);
}

static void
query_terminal_type(glob_t *glob)
{
    /*
     * Send ESC [ c - Query terminal type -- this code is recognized by
     *                most terminal types (VT100, VT200, etc), but not by
     *                the Amiga console.
     *     xterm will respond back with something like:
     *          ESC [ ? 6 2 c
     *     or
     *          ESC [ ? 6 4 ; .... c
     *     or
     *          ESC [ ? 1 ; 2 c
     *     We will only key off the initial 1 or 6 and ending c.
     *
     * Send Amiga CSI 0 SPACE q - Window Status Request -- this code is
     *                recognized by the Amiga console, but not by the
     *                terminal types that I tried.
     *     Amiga will respond back with:
     *          CSI 1 ; 1 ; XX XX ; XX XX SPACE r
     */
    /* Try both xterm ID seq and Amiga Window Status Request seq */
    xterm_console_emit(glob, STR_CSI "0 q"   // Amiga Window Status Request
                             STR_ESC "[c"    // xterm identify sequence
                             "\r"                // Carriage return
                             STR_ESC "[K", 11);  // Erase to end of line
}

static int __regargs
#ifdef FBASEREL
__saveds
#endif
reader_thread(register char *arg, register long len)
{
    LONG  wake_sigbit;
    int   stop_count = 0;
    struct DateStamp stop_ds;
    BOOL             sent_break = FALSE;  // Break sent to application at stop
    LONG  tcp_read_sigbit = -1;
    ULONG reader_sigmask;
    ULONG app_cons_sigmask;
    ULONG timer_sigmask;
    ULONG xterm_timer_sigmask;
    ULONG all_sigmask;
    struct MsgPort *reply_mp;
    struct MsgPort *timer_mp;
    struct MsgPort *xterm_timer_mp;
    struct Library *SocketBase = NULL;
    struct Task    *task;
    glob_t         *glob;

    if (DOSBase == NULL)
        return (0);

    task = FindTask(NULL);
    if (task == NULL)
        return (0);

    glob = (glob_t *) ((struct Process *) task)->pr_ExitData;
    if (glob == NULL)
        return (0);

    glob->reader_task = task;
    glob->reader_thread_alive = TRUE;

#if 0
    if (IsInteractive(IFH))
        Write(OFH, "Interactive\n", 12);
#endif

    /*
     * Verify formula using all position combinations for three cell buffer:
     *    a = s - e + 1
     *    if (a < 0) a += bufsize
     *
     *  e follows s         s follows e         e and s in same cell
     *  _ _ _               _ _ _               __ _ _
     * |s|e| | a=-1-1+3=1  |e|s| | a=1-1=0     |es| | | a=-1+3=2
     *  _ _ _               _ _ _               _ __ _
     * | |s|e| a=-1-1+3=1  | |e|s| a=1-1=0     | |es| | a=-1+3=2
     *  _ _ _               _ _ _               _ _ __
     * |s| |e| a=-2-1+3=0  |e| |s| a=2-1=1     | | |es| a=-1+3=2
     *  0 1 2               0 1 2               0 1 2
     */
    wake_sigbit = AllocSignal(-1L);
    glob->reader_wake_signal   = 1 << wake_sigbit;

    if (glob->adopt_port != NULL) {
        /* Take over the abandoned console port claimed by main() */
        struct MsgPort *port = glob->adopt_port;
        LONG            bit  = AllocSignal(-1L);
        if (bit >= 0) {
            Forbid();
            port->mp_SigBit        = bit;
            port->mp_SigTask       = task;
            port->mp_Flags         = PA_SIGNAL;
            glob->app_cons_msgport = port;
            glob->adopted          = TRUE;
            glob->open_count       = glob->adopt_handles;
            glob->raw_mode = (port->mp_Node.ln_Pri == PORT_PRI_RAW_MODE);
            {
                glob_t *kept = (glob_t *) port->mp_Node.ln_Name;
                if ((kept != NULL) && (TypeOfMem(kept) != 0) &&
                    (kept->magic == GLOB_MAGIC))
                    glob->kept_prev = (void *) kept;
                port->mp_Node.ln_Name = NULL;
            }
            if (!IsMsgPortEmpty(port))
                Signal(task, 1 << bit);  // Handle packets already queued
            Permit();
        }
    } else {
        glob->app_cons_msgport = CreateMsgPort();
    }
    glob->reader_msgport       = reply_mp       = CreateMsgPort();
    glob->reader_timer_msgport = timer_mp       = CreateMsgPort();
    glob->xterm_timer_msgport  = xterm_timer_mp = CreateMsgPort();

    if ((reply_mp == NULL) ||
        (timer_mp == NULL) ||
        (xterm_timer_mp == NULL) ||
        (glob->app_cons_msgport == NULL)) {
        warnx("Failed to create Message Port");
        goto fail_exit;
    }

    if (glob->tcp_port != 0) {
        /* Obtain previously-opened TCP socket */
        SocketBase = OpenLibrary("bsdsocket.library", 3);
        if (SocketBase == NULL)
            goto fail_exit;
        glob->socketbase_reader = SocketBase;
        glob->tcp_socket_reader = ObtainSocket(glob->tcp_socket_id, AF_INET,
                                               SOCK_STREAM, 0);
        if (glob->tcp_socket_reader < 0) {
            warnx("Failed to obtain reader socket");
            goto fail_exit;
        }
        {
            /*
             * Keepalive allows a dead peer (no FIN/RST) to eventually be
             * detected. Non-blocking I/O allows a stalled send() to be
             * interrupted when reterm is stopping.
             */
            LONG one = 1;
            if (setsockopt(glob->tcp_socket_reader, SOL_SOCKET, SO_KEEPALIVE,
                           &one, sizeof (one)) < 0)
                warnx("setsockopt(SO_KEEPALIVE) failed: %d", Errno());
            if (IoctlSocket(glob->tcp_socket_reader, FIONBIO, &one) < 0)
                warnx("ioctl(FIONBIO) failed: %d", Errno());
        }
        tcp_read_sigbit = AllocSignal(-1);
        if (tcp_read_sigbit < 0)
            goto fail_exit;
        glob->tcp_read_signal = 1 << tcp_read_sigbit;

        /*
         * Configure socket to send signal when packets are available
         * to be read.
         */
        struct TagItem tags[] = {
            { SBTM_SETVAL(SBTC_SIGIOMASK), glob->tcp_read_signal },
            { TAG_END, 0 }
        };
        SocketBaseTagList(tags);
    } else {
        /* Raw mode for input file handle */
        if (glob->reader_IFH != 0)
            SetMode(glob->reader_IFH, TRUE);
    }

    glob->reader_dos_packet = AllocDosObject(DOS_STDPKT, TAG_END);
    if (glob->reader_dos_packet == NULL) {
        warnx("Failed to allocate Reader request packet");
        goto fail_exit;
    }

    reply_mp->mp_Node.ln_Name = "reterm-reader";
    reader_sigmask            = (1 << reply_mp->mp_SigBit);
    timer_sigmask             = (1 << timer_mp->mp_SigBit);
    xterm_timer_sigmask       = (1 << xterm_timer_mp->mp_SigBit);
    app_cons_sigmask          = (1 << glob->app_cons_msgport->mp_SigBit);
    glob->reader_timer_signal = timer_sigmask;
    glob->xterm_timer_signal  = xterm_timer_sigmask;

    all_sigmask = reader_sigmask | timer_sigmask | xterm_timer_sigmask |
                  glob->reader_wake_signal | glob->tcp_read_signal |
                  app_cons_sigmask |
                  SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F;
    /* Kick off telnet negotiations */
    if (glob->support_telnet && !glob->did_telnet_linemode) {
        const UBYTE tbuf[] = {TELNET_IAC, TELNET_DO, TELNET_OP_LINEMODE};
        DPRINT(" DO %02x\n", tbuf[2]);
        telnet_emit(glob, tbuf, sizeof (tbuf));
        glob->did_telnet_linemode = TRUE;
    }
#if 0
// DEBUG
warnx("DEBUG: Reader exiting early 3");
if (glob->reader_read_pending == 0) {
    if (glob->reader_dos_packet != NULL)
        FreeDosObject(DOS_STDPKT, glob->reader_dos_packet);
}
if (glob->tcp_socket_reader >= 0)
    CloseSocket(glob->tcp_socket_reader);
FreeSignal(wake_sigbit);
return (0);
// DEBUG
#endif
    if (glob->support_utf8) {
        /* Put terminal in UTF-8 mode */
        xterm_console_emit(glob, STR_ESC "%G", 3);
    }
    get_con_unit(glob);

    int qtt_count = 20;
    if (glob->support_telnet == FALSE)
        qtt_count = 6;

    while (glob->stopping == FALSE) {
        /*
         * 1. Check for stop
         * 2. Re-queue read
         * 3. Wait for signal(s)
         * 4. Handle arrived read packet
         * 5. Process any new arrived data into xterm buffer
         * 6. Handle arrived console messages from application
         * 7. Handle pending ACTION_READ or ACTION_WAIT_CHAR
         * 8. Handle timer messages (ACTION_READ or ACTION_WAIT_CHAR timeouts)
         */
        ULONG signals;
#if 0
// DEBUG
warnx("DEBUG: Reader exiting early 4");
break;
// DEBUG
#endif

        /* 2. Re-queue read */
        if (glob->reader_read_pending == FALSE)
            send_Read(glob);  // Send read to console

        /* 3. Wait for signal(s) */
        if (glob->tcp_port != 0)
            signals = do_WaitSelect(glob, all_sigmask);
        else
            signals = Wait(all_sigmask);

        /* 4. Handle arrived read packet */
        if (signals & reader_sigmask)
            reader_handle_arrived_read(glob, reply_mp);

        /* 5. Process arrived data in read buffer to proc buffer */
        reader_process_xterm_to_amiga(glob);
        (void) task_window_collect(glob, 0);  // Replied gadget/menu messages

        /* 6. Handle arrived console messages from application */
        if (qtt_count == 0) {
            handle_console_messages(glob);
        } else {
            /* Wait for telnet negotiation and terminal type to settle */
            if (((--qtt_count == 5)    || glob->did_telnet_will_echo) &&
                ((glob->tcp_port != 0) || IsInteractive(glob->reader_IFH)) &&
                ((glob->term_type == TERM_TYPE_UNKNOWN) &&
                (glob->support_xterm == FALSE) &&
                (glob->did_query_term_type == FALSE))) {
                glob->did_query_term_type = TRUE;
                query_terminal_type(glob);
            }
            if (glob->term_type != TERM_TYPE_UNKNOWN)
                qtt_count = 0;
            Delay(1);

            /* Re-set signal if application message is waiting */
            if (!IsMsgPortEmpty(glob->app_cons_msgport))
                Signal(glob->reader_task, app_cons_sigmask);
        }

        /* 7. Handle pending application ACTION_READ or ACTION_WAIT_CHAR */
        reader_handle_app_reads(glob);

        /* 8. Handle timer messages: ACTION_READ or ACTION_WAIT_CHAR timeouts */
        if (signals & timer_sigmask)
            reader_handle_timeouts(glob);
    }

    /*
     * The application may still hold file handles which reference
     * glob->app_cons_msgport. For a grace period, that port is serviced
     * (failing all I/O) so that the application sees EOF and exits, as an
     * idle shell will. Send break signals so that applications which are
     * not doing console I/O will also notice and exit. If the application
     * is still using the console after the grace period, the session
     * detaches from it (see below).
     */
    if (glob->child_process_alive && session_app_active(glob)) {
        /* Not already closing its console (where ACTION_END stops) */
        signal_child(glob, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D);
        sent_break = TRUE;
    }
    DateStamp(&stop_ds);
    while (session_app_active(glob) || glob->runner_thread_alive) {
        /* Abort and fail any pending reads/waits (and pending WAIT timers) */
        abort_read_queue(glob, TRUE);
        handle_console_messages(glob);
        if ((session_app_active(glob) == FALSE) &&
            (glob->runner_thread_alive == FALSE))
            break;  // Application closed its console
        if (reterm_exiting)
            break;  // Leak the console port (below) so that reterm can exit
        stop_count++;
        if (ticks_since(&stop_ds) < 10 * TICKS_PER_SECOND) {
            Delay(1);  // Application should close the console soon
            continue;
        }
        if (glob->runner_thread_alive) {
            Delay(50);  // Runner (code in this program) should finish soon
            continue;
        }
        /*
         * The application is busy elsewhere (such as waiting on a requester
         * or a long-running command), or is an application such as an
         * editor which does not exit on EOF. Detach from it: the port is
         * left abandoned (below), so the application blocks at its next
         * console I/O rather than spinning on failed I/O, and it may later
         * be reattached with "reterm -A". This also frees the session.
         * The port can not be deleted, as the application still uses it.
         */
        DPRINT1("reader stop: detaching from app");
        break;
    }
    if (sent_break && session_app_active(glob)) {
        /* Detaching: the application did not act on the break; withdraw it */
        unsignal_child(glob, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D);
    }
    DPRINT1("reader stop: open_count=%d runner=%d waited=%d",
            glob->open_count, glob->runner_thread_alive, stop_count);
    glob->child_process_alive = FALSE;

    /*
     * Clean up so the reader thread may exit.
     */
    if (glob->reader_timer_pending) {
        warnx("Should not see read timer pending on reader thread exit!");
    }

    if (glob->reader_read_pending) {
        struct DosPacket *Pkt = NULL;
        int count;

        for (count = 20; count > 0; count--) {
            if (count == 15) {
                /*
                 * Sending a Paste into the handler to clear a pending read
                 * works with the AmigaOS 3.1 CON: and with AmiTCP 3.x TCP:
                 * handlers. It might not work with other handlers.
                 */
                send_Paste(glob->reader_IFH, "\n", 1);

                /* AmigaOS 3.1 "CON:" sometimes gets stuck; the below helps */
                xterm_console_emit(glob, "", 0);
            } else if (count == 20) {
                /*
                 * ViNCEd documentation suggests ACTION_ABORT may be used to
                 * unblock an asynchronous read, so this is attempted first.
                 */
                Pkt = send_Abort(glob, glob->reader_IFH);
            }
            struct Message *rMsg = GetMsg(reply_mp);
            if (rMsg != NULL) {
                struct DosPacket *rPkt = PktFromMsg(rMsg);
                if (rPkt == Pkt) {
                    /* Got reply from ACTION_ABORT packet */
                    FreeDosObject(DOS_STDPKT, Pkt);
                    Pkt = NULL;
                } else if (rPkt != glob->reader_dos_packet) {
                    /* Leave this packet dangling, as it's probably not ours */
                    warnx("BUG: Sent %p to console but got %p",
                          glob->reader_dos_packet, rPkt);
                } else {
                    /*
                     * Asynchronous read was successfully aborted.
                     * Packet is deallocated later in this function.
                     */
                    glob->reader_read_pending = FALSE;
                }
            }
            if ((glob->reader_read_pending == FALSE) && (Pkt == NULL))
                break;
            Delay(1);  // Let other tasks run
        }
    }

    xterm_timer_cancel(glob);

    DPRINT2("reader stopping");

fail_exit:
    if (glob->reader_IFH != 0)
        SetMode(glob->reader_IFH, FALSE);  // Input back to cooked mode
//  xterm_console_emit(glob, "\r\n", 2);

    if (SocketBase != NULL) {
        if (glob->tcp_socket_reader >= 0)
            CloseSocket(glob->tcp_socket_reader);
        CloseLibrary(SocketBase);
        glob->tcp_socket_reader = -1;
        glob->socketbase_reader = NULL;
    }
    glob->reader_task = NULL;
    if (glob->reader_read_pending) {
        warnx("Failed to abort an asynchronous read");
        /*
         * Set the read length (Arg3) of the outstanding packet to 0 so that
         * if data does arrive, there is less chance of random corruption.
         */
        if (glob->reader_dos_packet != NULL)
            glob->reader_dos_packet->dp_Arg3 = 0;

        /* Don't signal any task if a message arrives */
        if (reply_mp != NULL) {
            reply_mp->mp_Flags = PA_IGNORE;
            reply_mp->mp_SigTask = 0;
        }
    } else {
        /* Deallocate these only if there is no read outstanding */
        if (glob->reader_dos_packet != NULL)
            FreeDosObject(DOS_STDPKT, glob->reader_dos_packet);
        if (reply_mp != NULL)
            DeleteMsgPort(reply_mp);
    }
    if ((glob->reader_timer_pending == 0) && (timer_mp != NULL))
        DeleteMsgPort(timer_mp);
    if (xterm_timer_mp != NULL)
        DeleteMsgPort(xterm_timer_mp);
    if (glob->wk_reply_mp != NULL) {
        if (task_window_collect(glob, 2 * TICKS_PER_SECOND) == 0) {
            DeleteMsgPort(glob->wk_reply_mp);
        } else {
            /* Application never replied: leak the port and messages */
            glob->wk_reply_mp->mp_Flags   = PA_IGNORE;
            glob->wk_reply_mp->mp_SigTask = NULL;
        }
        glob->wk_reply_mp = NULL;
    }
    if (glob->adopted) {
        /*
         * An adopted port is never deleted, as file handles which are not
         * visible from the processes using it may still reference it.
         * Return it to the abandoned state, so it may be attached again.
         */
        struct MsgPort *port   = glob->app_cons_msgport;
        BOOL            in_use = port_in_use(port);
        Forbid();
        port->mp_Node.ln_Pri = glob->raw_mode ? PORT_PRI_RAW_MODE : 0;
        port->mp_Flags       = PA_IGNORE;
        port->mp_SigTask     = NULL;
        Permit();
        FreeSignal(port->mp_SigBit);
        if (in_use) {
            report_detach(glob);
            glob->keep_for_app = TRUE;
            port->mp_Node.ln_Name = (char *) glob;  // Kept state chain
        } else {
            /* Application exited: release state kept for it earlier */
            free_kept_globs((glob_t *) glob->kept_prev);
            glob->kept_prev = NULL;
        }
    } else if (glob->app_cons_msgport != NULL) {
        if ((glob->open_count > 0) || glob->runner_thread_alive) {
            /*
             * The application still has file handles referencing this
             * port. Deleting it would cause a crash or hang the next time
             * the application performs console I/O, so it is leaked.
             * Packets sent to it will no longer signal this (exiting) task.
             */
            if (glob->open_count > glob->orphan_count) {
                report_detach(glob);
                glob->keep_for_app = TRUE;
            }
            Forbid();
            if (glob->keep_for_app)
                glob->app_cons_msgport->mp_Node.ln_Name = (char *) glob;
            glob->app_cons_msgport->mp_Node.ln_Pri =
                    glob->raw_mode ? PORT_PRI_RAW_MODE : 0;
            glob->app_cons_msgport->mp_Flags   = PA_IGNORE;
            glob->app_cons_msgport->mp_SigTask = NULL;
            Permit();
        } else {
            DeleteMsgPort(glob->app_cons_msgport);
        }
    }

    FreeSignal(wake_sigbit);
    if (tcp_read_sigbit != -1)
        FreeSignal(tcp_read_sigbit);

    tab_completion_wipe(glob);
    /*
     * ACTION_DISK_INFO gave the application pointers to the fake window
     * (id_VolumeNode) and to the console unit in this glob (id_InUse). If
     * the application is still running, it may use them at any time (an
     * editor may restore the window title when it exits), so the window
     * is left open and the glob is not freed.
     */
    if ((glob->fake_window != NULL) && (glob->keep_for_app == FALSE))
        CloseWindow(glob->fake_window);

    if (glob->reader_close_FHs) {
        Close(glob->reader_IFH);
        Close(glob->reader_OFH);
    }

    Forbid();
    glob->reader_thread_alive = FALSE;
    return (0);
}

static int __regargs
#ifdef FBASEREL
__saveds
#endif
runner_thread(register char *arg, register long len)
{
    BPTR IFH;
    BPTR OFH;
    BPTR old_IFH;
    BPTR old_OFH;
    char *cmd;
    glob_t *glob;
    int rc;
    struct Process *proc;

    if (DOSBase == NULL)
        return (0);

    proc = (struct Process *) FindTask(NULL);
    if (proc == NULL)
        return (0);

    glob = (glob_t *) proc->pr_ExitData;
    if (glob == NULL)
        return (0);

    glob->runner_thread_alive = TRUE;
    IFH = MKBADDR(create_fh(glob, glob->app_cons_msgport));
    OFH = MKBADDR(create_fh(glob, glob->app_cons_msgport));

    old_IFH = SelectInput(IFH);
    old_OFH = SelectOutput(OFH);

    cmd = glob->runner_cmd;
    if (cmd[0] == '\0') {
        warnx("No command specified");
        rc = -1;
        goto skip;
    }

//  warnx("\rRunning: %s", cmd);

    rc = SystemTags(cmd,
                    SYS_Input, IFH,   // IFH and OFH point to our fake console
                    SYS_Output, OFH,
                    SYS_Asynch, TRUE, // Automatically close IFH and OFH on exit
                    NP_Cli, TRUE,     // Create CLI structure
                    NP_ConsoleTask, (ULONG) glob->app_cons_msgport,
                    NP_CopyVars, TRUE,
                    NP_StackSize, glob->stack_size,
                    NP_WindowPtr, (LONG)-1,  // No requesters XXX: Doesn't work?
#if 0
                    NP_Path, (ULONG)path,
                    NP_Input, IFH,
                    NP_Output, OFH,
                    NP_Output, Open("CONSOLE:", MODE_OLDFILE),
                    NP_Error, IFH,
                    NP_WindowPtr, 0,  // Workbench window
                    NP_Arguments, BADDR(cmd),
                    NP_Seglist, (LONG) progseg,  // Not sure
                    NP_Seglist, (LONG) NULL,     // Not sure
                    NP_FreeSeglist, (LONG) FALSE,
                    NP_HomeDir, NULL,
                    NP_CloseInput, FALSE,
                    NP_CloseOutput, FALSE,
                    NP_CurrentDir, NULL,
                    NP_Input, NULL,
                    NP_Output, NULL,
                    NP_CopyVars, TRUE,
                    NP_Name, (LONG) "reterm process",
#endif
                    TAG_END);

skip:
    SelectInput(old_IFH);
    SelectOutput(old_OFH);

    if (rc < 0) {
        /* Failed */
        Close(IFH);
        Close(OFH);
    } else {
        glob->child_process_alive = TRUE;
    }

    Forbid();
    glob->runner_thread_alive = FALSE;
    return (rc);
}

static BPTR
open_console_dev(const char *filename, LONG mode)
{
    struct FileInfoBlock fib;
    BPTR                 FH;

    if (strchr(filename, ':') == NULL)
        return (0);

    FH = Open(filename, mode);
    if (FH == 0)
        return (0);

    if (ExamineFH(FH, &fib) == DOSTRUE) {
        Close(FH);
        return (0);  // Should not be able to examine a console FH
    }
    return (FH);
}

static LONG
get_stack_size(void)
{
    struct Task *task = FindTask(NULL);
    return (task->tc_SPUpper - task->tc_SPLower);
}

/*
 * glob_init() allocates and initializes space for the global values
 *             shared among threads.
 */
static void
glob_init(glob_t **glob_p, glob_t *glob_proto)
{
    glob_t *glob = AllocVec(sizeof (*glob), MEMF_PUBLIC);
    if (glob == NULL)
        err(EXIT_FAILURE, "Failed to allocate memory");
    *glob_p = glob;

    if (glob_proto != NULL) {
        memcpy(glob, glob_proto, sizeof (*glob));

        /* Insert this node after glob_proto in the list */
        if (glob_proto->node.mln_Succ != NULL)
            glob_proto->node.mln_Succ->mln_Pred = &glob->node;
        glob->node.mln_Pred = &glob_proto->node;
        glob->node.mln_Succ = glob_proto->node.mln_Succ;
        glob_proto->node.mln_Succ = &glob->node;

        goto finish_init;
    }

    /* Initialize fields in the glob structure */
    memset(glob, 0, sizeof (*glob));
    /*
     * memset() above makes the below unnecessary.
     *
     * glob->con_unit.cu_XCP      = 0;
     * glob->con_unit.cu_YCP      = 0;
     * glob->con_unit.cu_XCCP     = 0;
     * glob->con_unit.cu_YCCP     = 0;
     */
    glob->con_unit.cu_XMax     = 79;  // 80 columns
    glob->con_unit.cu_YMax     = 23;  // 24 rows
    glob->con_unit.cu_XRSize   = 8;
    glob->con_unit.cu_YRSize   = 8;
    glob->con_unit.cu_XRExtant = (WORD) (glob->con_unit.cu_XRSize *
                                         glob->con_unit.cu_XMax);
    glob->con_unit.cu_YRExtant = (WORD) (glob->con_unit.cu_YRSize *
                                         glob->con_unit.cu_YMax);
    glob->nl_crlf              = TRUE;
    glob->reader_IFH           = Input();
    glob->reader_OFH           = Output();
    glob->stack_size           = get_stack_size();
    glob->tcp_socket_reader    = -1;
    glob->tcp_socket_master    = -1;
    glob->requester_abort_key  = 0x03;  // ^C
    glob->node.mln_Succ        = NULL;
    glob->node.mln_Pred        = NULL;

finish_init:
    strcpy(glob->fake_title, "Reterm");
    glob->magic        = GLOB_MAGIC;
    glob->wk_reply_mp    = NULL;
    glob->wk_outstanding = 0;
    glob->kept_unlinked = FALSE;
    glob->kept_released = FALSE;
    glob->kept_prev    = NULL;
    glob->keep_for_app = FALSE;
    glob->fake_window  = NULL;
    glob->con_unit_ptr = &glob->con_unit;
    glob->id_inuse_req.io_Unit = (struct Unit *) &glob->con_unit;
    NewList(&glob->pending_reads);
    NewList(&glob->pending_pastes);
    NewList(&glob->completion_list);
}

static void
glob_free(glob_t *glob)
{
    if (glob != NULL)
        FreeVec(glob);
}

static BOOL
handle_connection(glob_t *glob_p, char *runner_cmd)
{
    glob_t         *glob;
    char            reader_name[64];
    char            runner_name[64];

    glob_init(&glob, glob_p);

    if (glob->disable_telnet)
        glob->support_telnet = FALSE;

    if (runner_cmd[0] == '\0')
        strcpy(runner_cmd, "newshell CONSOLE:");
// OR   strcpy(runner_cmd, "newshell CONSOLE: from S:Remote-Startup");

    glob->runner_cmd = runner_cmd;
    sprintf(reader_name, "reterm-reader-%d", glob->client_number);
    sprintf(runner_name, "reterm-runner-%d", glob->client_number);

    /* Start the reader thread first so it can begin waiting for input */
    CreateNewProcTags(NP_Entry, (ULONG) reader_thread,
                      NP_Name, (ULONG) reader_name,
                      NP_StackSize, 8192,  // ^C prompt runs here (vsnprintf)
                      NP_ExitData, (ULONG) glob,
                      TAG_END);

    if (glob->adopt_port != NULL) {
        /* Attaching to an existing program: there is nothing to run */
        glob->child_process_alive = TRUE;
        return (FALSE);
    }

    /*
     * Start the runner thread to execute the requested program.
     * runner_thread_alive is set before the runner starts so that the
     * reader thread will not tear down the console message port while
     * the runner is still starting the application.
     */
    glob->runner_thread_alive = TRUE;
    if (CreateNewProcTags(NP_Entry, (ULONG) runner_thread,
                          NP_Cli, TRUE,  // Create CLI struct (propagate path)
                          NP_Name, (ULONG) runner_name,
                          NP_StackSize, 2000,
                          NP_ExitData, (ULONG) glob,
                          TAG_END) == NULL) {
        warnx("Failed to start runner");
        glob->runner_thread_alive = FALSE;
    }

    return (FALSE);
}

/*
 * handle_task_end() cleans up tasks and returns TRUE when no more
 *                   tasks are running.
 */
static int
handle_task_end(glob_t *glob_p, BOOL do_warn, BOOL quiet)
{
    int count = 0;
    struct MinNode *node = &glob_p->node;
    for (node = node->mln_Succ; node != NULL; node = node->mln_Succ) {
        glob_t *glob = (glob_t *) node;
        BOOL    done = TRUE;
        if (glob->reader_thread_alive) {
            done = FALSE;
            if (do_warn) {
                warnx("Reader thread %d failed to terminate",
                      glob->client_number);
            }
        }
        if (glob->runner_thread_alive) {
            done = FALSE;
            if (do_warn) {
                warnx("Runner thread %d failed to terminate",
                      glob->client_number);
            }
        }
        if (glob->child_process_alive) {
            struct Process *child = get_recent_process(glob);
            if (is_valid_task(child)) {
                done = FALSE;
                if (do_warn) {
                    warnx("Child process %d failed to terminate",
                          glob->client_number);
                }
            }
        }
        if (done == TRUE) {
            if (!quiet)
                warnx("disconnect %d", glob->client_number);

            node->mln_Pred->mln_Succ = node->mln_Succ;
            if (node->mln_Succ != NULL)
                node->mln_Succ->mln_Pred = node->mln_Pred;
            node = node->mln_Pred;
            if (glob->keep_for_app) {
                /* State kept for a still-running application */
                BOOL can_free;
                Forbid();
                can_free = glob->kept_released;
                if (can_free == FALSE)
                    glob->kept_unlinked = TRUE;  // Freed when app is done
                Permit();
                if (can_free)
                    free_kept_glob(glob);
            } else {
                glob_free(glob);
            }
        } else {
            /* Task still running */
            count++;
        }
    }
    return (count);
}

/*
 * report_busy_sessions() lists sessions whose application has not yet
 *                        closed its console, preventing reterm from exiting.
 */
static void
report_busy_sessions(glob_t *glob_p)
{
    struct MinNode *node;
    for (node = glob_p->node.mln_Succ; node != NULL; node = node->mln_Succ) {
        glob_t         *glob = (glob_t *) node;
        struct Process *proc;
        char            name[40];

        if (glob->reader_thread_alive == FALSE)
            continue;
        strcpy(name, "unknown");
        Forbid();
        proc = get_recent_process(glob);
        if (is_valid_task(proc)) {
            struct CommandLineInterface *cli = BADDR(proc->pr_CLI);
            UBYTE *bstr = (cli != NULL) ? BADDR(cli->cli_CommandName) : NULL;
            if ((bstr != NULL) && (bstr[0] != 0)) {
                int len = (bstr[0] < sizeof (name)) ? bstr[0] :
                                                      sizeof (name) - 1;
                memcpy(name, bstr + 1, len);
                name[len] = '\0';
            } else if (proc->pr_Task.tc_Node.ln_Name != NULL) {
                strncpy(name, proc->pr_Task.tc_Node.ln_Name, sizeof (name));
                name[sizeof (name) - 1] = '\0';
            }
        }
        Permit();
        warnx("Client %d: waiting for \"%s\" to close its console",
              glob->client_number, name);
    }
}

/* readers_alive() returns TRUE if any session reader thread is running */
static BOOL
readers_alive(glob_t *glob_p)
{
    struct MinNode *node;
    for (node = glob_p->node.mln_Succ; node != NULL; node = node->mln_Succ)
        if (((glob_t *) node)->reader_thread_alive)
            return (TRUE);
    return (FALSE);
}

static void
handle_signals(glob_t *glob)
{
    ULONG brk_sigmask = SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D |
                        SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F;
    ULONG signals = SetSignal(0, brk_sigmask);

    if ((signals & SIGBREAKF_CTRL_C) &&
        ((glob->tcp_port != 0) || (glob->reader_IFH != Input()))) {
        if (glob->stopping == FALSE) {
            warnx("**Aborting reterm due to ^C Break**");
            stop_readers(glob);
            signal_readers(glob, 0);
        } else if ((reterm_exiting == FALSE) && readers_alive(glob)) {
            /* Second break: give up on applications which are still busy */
            warnx("**Forcing reterm exit: programs still using a reterm "
                  "console will hang**");
            reterm_exiting = TRUE;
            signal_readers(glob, 0);
        }
    }

    if (signals & SIGBREAKF_CTRL_F) {
        printf("Send ^F\n");
        signal_readers(glob, SIGBREAKF_CTRL_F);
    }
}

// main() requires about 3200 bytes of stack
// reader_thread() requires about 1400 bytes of stack
//      (about 1000 bytes if warnx() is not called)
// runner_thread() requires about 700 bytes of stack
int
main(int argc, char *argv[])
{
    char            runner_cmdbuf[1000];
    char           *term;
    char           *first_cmd_arg = NULL;
    char           *runner_cmd    = runner_cmdbuf;
    glob_t         *glob          = NULL;
    struct Library *SocketBase    = NULL;
    BOOL            got_cmd       = FALSE;
    BOOL            quiet         = FALSE;
    int             daemon_count  = 0;
    int             current_count = 0;
    int             accept_fail_count = 0;
    LONG            attach_cli    = 0;
    int             arg;

// XXX: (argc == 0) means this program was started by WorkBench

    if (IntuitionBase == NULL) {
        IntuitionBase = OpenLibrary("intuition.library", 0);
        if (IntuitionBase == NULL) {
            err(EXIT_FAILURE, "Failed to open %s", "intuition.library");
        }
    }
    /* Optional: used only to recognize gadget labels drawn as pixels */
    if (GfxBase == NULL)
        GfxBase = (struct GfxBase *) OpenLibrary("graphics.library", 36);
    if (LayersBase == NULL)
        LayersBase = OpenLibrary("layers.library", 36);

    /* Initialize the global data */
    glob_init(&glob, NULL);

// AmiTCP seems to use NP_ExitCode and NP_ExitData to pass arguments
// to servers (pr_ExitCode and pr_ExitData).

#if 0
struct DaemonMessage {
    struct Message  dm_Msg;     // Message name is FreeVec()'ed by inetd
    struct Process *dm_Pid;     // Set by the launcher
    struct Segment *dm_Seg;     // Used only if resident segment
    LONG            dm_Id;      // Socket id
    LONG            dm_Retval;  // Non-zero errorcode
    UBYTE           dm_Family;  // Address/protocol family
    UBYTE           dm_Type;
};
#endif

    term = getenv("TERM");
    if (term != NULL) {
        if (strcmp(term, "xterm") == 0)
            glob->support_xterm = TRUE;
        else if (strcmp(term, "amiga") == 0)
            glob->support_xterm = FALSE;
    }

    /* File handle will be passed to child process */
    runner_cmd[0] = '\0';

    /* Construct cmdline args for the subprocess */
    for (arg = 1; arg < argc; arg++) {
        char *ptr = argv[arg];
        if (*ptr == '-') {
            BPTR *FHp;
            while (*(++ptr) != '\0') {
                char ch = *ptr;
                switch (ch) {
                    case 'a':  // List abandoned console ports
                        list_abandoned_ports();
                        goto fail_exit;
                    case 'A': {  // Attach to abandoned console port
                        char  *endptr;
                        if (++arg >= argc) {
                            warnx("-%c requires a CLI number", ch);
                            goto fail_exit;
                        }
                        attach_cli = conv_int(argv[arg], &endptr);
                        if ((*endptr != '\0') || (attach_cli <= 0)) {
                            warnx("Invalid CLI number %s", argv[arg]);
                            goto fail_exit;
                        }
                        break;
                    }
                    case 'C':  // Capture xterm {input}/output
                        if (++arg >= argc) {
                            warnx("-%c requires a filename", ch);
                            goto fail_exit;
                        }
                        FHp = &glob->capture_XFH;
                        goto handle_capture;
                    case 'c':  // Capture application {input}/output
                        if (++arg >= argc) {
                            warnx("-%c requires a filename", ch);
                            goto fail_exit;
                        }
                        FHp = &glob->capture_AFH;
handle_capture:
                        *FHp = Open(argv[arg], MODE_NEWFILE);
                        if (*FHp == 0) {
                            DeleteFile(argv[arg]);
                            *FHp = Open(argv[arg], MODE_NEWFILE);
                        }
                        if (*FHp == 0) {
                            warnx("Could not open %s for write", argv[arg]);
                            goto fail_exit;
                        }
                        FHp = &glob->capture_AFH;
                        break;
                    case 'd': {  // Daemon mode
                        char  *endptr;
                        if (++arg >= argc) {
                            warnx("-%c requires a value", ch);
                            goto fail_exit;
                        }
                        daemon_count = conv_int(argv[arg], &endptr);
                        if (*endptr != '\0') {
                            warnx("Invalid count %s", argv[arg]);
                            goto fail_exit;
                        }
                        break;
                    }
                    case 'D':  // Debug mode
                        glob->debug_mode++;
                        break;
                    case 'E':  // Disable most escape mode sequences
                        glob->no_cooked_esc_sequences = TRUE;
                        break;
                    case 'F':  // Fake cursor position
                        glob->fake_xterm_reply = TRUE;
                        break;
                    case 'i':  // Only capture {input}
                        glob->capture_input = TRUE;
                        break;
                    case 'M':  // Tab complete just beginning of filename
                        glob->tab_match_pre_only = TRUE;
                        break;
                    case 'o':  // Only capture output
                        glob->capture_output = TRUE;
                        break;
                    case 'p': {  // TCP Port (use TCP socket)
                        ULONG  port;
                        char  *endptr;
                        if (++arg >= argc) {
                            warnx("-%c requires a value", ch);
                            goto fail_exit;
                        }
                        port = conv_int(argv[arg], &endptr);
                        if ((*endptr != '\0') || (port >= 65536)) {
                            warnx("Invalid port %s", argv[arg]);
                            goto fail_exit;
                        }
                        glob->tcp_port = (UWORD) port;
                        glob->support_telnet = TRUE;
                        break;
                    }
                    case 'P':  // Do not include path in tab completion result
                        glob->tab_comp_no_exec_path = TRUE;
                        break;
                    case 'q':  // Quiet
                        quiet = TRUE;
                        break;
                    case 'R':  // Do not allow requester abort
                        glob->requester_abort_key = 256;  // disabled
                        break;
                    case 'r': {  // Requester abort key
                        ULONG key;
                        char  *endptr;
                        if (++arg >= argc) {
                            warnx("-%c requires a value", ch);
                            goto fail_exit;
                        }
                        key = conv_int(argv[arg], &endptr);
                        if ((*endptr != '\0') || (key >= 256)) {
                            warnx("Invalid key %s", argv[arg]);
                            goto fail_exit;
                        }
                        glob->requester_abort_key = key;
                        break;
                    }
                    case 's': {  // Stack size
                        ULONG  newsize;
                        char  *endptr;
                        if (++arg >= argc) {
                            warnx("-%c requires a value", ch);
                            goto fail_exit;
                        }
                        newsize = conv_int(argv[arg], &endptr);
                        if ((*endptr != '\0') || (newsize < 256) ||
                            (newsize > (64 << 20))) { // 64 MB
                            warnx("Invalid stack size %s", argv[arg]);
                            goto fail_exit;
                        }
                        glob->stack_size = newsize;
                        break;
                    }
                    case 't':  // Enable telnet protocol
                        glob->support_telnet = TRUE;
                        glob->disable_telnet = FALSE;
                        break;
                    case 'T':  // Disable telnet protocol
                        glob->support_telnet = FALSE;
                        glob->disable_telnet = TRUE;
                        break;
                    case 'u':  // Enable xterm UTF-8 translation
                        glob->support_utf8 = TRUE;
                        break;
                    case 'v':  // Display program version
                        warnx("%s", version + 7);
                        goto fail_exit;
                    case 'x':
                        glob->support_xterm = TRUE;
                        break;
                    case 'X':  // Reserved for force disable xterm support
                    default:
                        warnx("Unknown option -%c", ch);
                        /* FALLTHROUGH */
                    case '?':
                    case 'h':  // Display help
                        warnx(usage);
                        goto fail_exit;
                }
            }
            continue;
        }

        if (got_cmd == FALSE) {
            got_cmd = TRUE;
            first_cmd_arg = ptr;
        }
        runner_cmd += sprintf(runner_cmd, " %s", ptr);
    }
    runner_cmd = runner_cmdbuf;

    if ((glob->capture_input == FALSE) && (glob->capture_output == FALSE)) {
        /* Default to capture both input and output */
        glob->capture_input  = TRUE;
        glob->capture_output = TRUE;
    }

    if (attach_cli != 0) {
        if (daemon_count > 0) {
            warnx("-A can not be used with -d");
            goto fail_exit;
        }
        if (claim_abandoned_port(glob, attach_cli) == FALSE)
            goto fail_exit;
        glob->child_rtask_mp = &glob->adopt_proc->pr_MsgPort;
        if (glob->tcp_port == 0)
            printf("Attached to CLI %ld\n", (long) attach_cli);
    }

    LONG master_sock = -1;
    if (glob->tcp_port != 0) {
        struct sockaddr_in addr;
        int    listen_count = daemon_count;
        int    reuse = 1;
        if (SocketBase == NULL) {
            SocketBase = OpenLibrary("bsdsocket.library", 3);
            if (SocketBase == NULL) {
                warnx("Failed to open %s", "bsdsocket.library");
                goto fail_exit;
            }
        }
        master_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (master_sock < 0) {
            warnx("socket create failed");
            goto fail_exit;
        }
        glob->tcp_socket_master = master_sock;
        if (setsockopt(master_sock, SOL_SOCKET, SO_REUSEADDR,
                      &reuse, sizeof (int)) < 0) {
            printf("setsockopt(reuse) failed\n");
        }

        addr.sin_port        = glob->tcp_port;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_family      = AF_INET;
        addr.sin_len         = sizeof (addr);

        if (bind(master_sock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
            warnx("bind to port %d failed: %d", glob->tcp_port, Errno());
            goto fail_exit;
        }
        if (listen(master_sock, listen_count) < 0) {
            warnx("listen on port %d failed: %d", glob->tcp_port, Errno());
            goto fail_exit;
        }
    }

    if (daemon_count == 0)
        quiet = TRUE;

    do {
        if ((daemon_count > 0) && (daemon_count <= current_count)) {
            /* All daemons in service */
            Delay(5);
            goto no_task_to_run;
        } else if (glob->tcp_port != 0) {
            struct sockaddr_in addr;
            socklen_t len = sizeof (addr);
            LONG sock = accept(master_sock, (struct sockaddr *) &addr, &len);
            if (sock < 0) {
                LONG error = Errno();
                warnx("socket accept failed: %d", error);
                /*
                 * A break (EINTR) or repeated failure stops reterm. Other
                 * failures (such as a client which reset the connection
                 * before it was accepted) are transient.
                 */
                if ((error == EINTR) || (++accept_fail_count >= 10))
                    break;
                Delay(25);
                goto no_task_to_run;
            }
            accept_fail_count = 0;
            glob->client_number++;
            if (!quiet) {
                char *hostname = Inet_NtoA(addr.sin_addr.s_addr);
                printf("connect %d %d %s %d\n", glob->client_number,
                       glob->tcp_port, hostname, ntohs(addr.sin_port));
            }
            glob->tcp_socket_id = ReleaseSocket(sock, UNIQUE_ID);
        } else if (first_cmd_arg != NULL) {
            BPTR IFH = open_console_dev(first_cmd_arg, MODE_OLDFILE);
            if (IFH != 0) {
                struct MsgPort *new_ct =
                        (APTR)((struct FileHandle *) BADDR(IFH))->fh_Type;
                struct MsgPort *old_ct = SetConsoleTask(new_ct);
                BPTR   OFH = Open("CONSOLE:", MODE_NEWFILE);

                SetConsoleTask(old_ct);
                if (OFH == 0) {
                    warnx("Failed to open CONSOLE: on %s", first_cmd_arg);
                    Close(IFH);
                    break;
                }
                glob->reader_IFH = IFH;
                glob->reader_OFH = OFH;
                glob->reader_close_FHs = TRUE;
                glob->client_number++;
                if (strncasecmp(first_cmd_arg, "tcp:", 4) == 0)
                    glob->support_telnet = TRUE;
                if (!quiet)
                    printf("connect %d %s\n",
                           glob->client_number, first_cmd_arg);

                runner_cmd = runner_cmdbuf + strlen(first_cmd_arg) + 1;
            }
        }
        if (handle_connection(glob, runner_cmd))
            break;
no_task_to_run:
        current_count = handle_task_end(glob, FALSE, quiet);
        handle_signals(glob);
        if (glob->stopping)
            break;
    } while (daemon_count > 0);

    int              stop_count = 0;
    BOOL             reported   = FALSE;
    BOOL             forced     = FALSE;
    struct DateStamp stop_ds;
    while (handle_task_end(glob, FALSE, quiet) > 0) {
        handle_signals(glob);
        /*
         * Reader threads run code in this program, so they must be gone
         * before reterm exits. A reader thread does not exit until its
         * application has closed the console, because the application
         * would otherwise hang at its next console I/O. That may take a
         * long time (for example, a requester which nobody has answered),
         * so the user may force an exit with a second break.
         */
        if (glob->stopping && (stop_count == 0))
            DateStamp(&stop_ds);
        if (reterm_exiting && (forced == FALSE)) {
            DateStamp(&stop_ds);  // Restart the clock for forced exit
            forced = TRUE;
        }
        if (glob->stopping && (stop_count++ > 20)) {
            if (readers_alive(glob) == FALSE)
                break;
            if (forced) {
                if (ticks_since(&stop_ds) > 15 * TICKS_PER_SECOND)
                    break;
            } else if ((reported == FALSE) &&
                       (ticks_since(&stop_ds) > 5 * TICKS_PER_SECOND)) {
                reported = TRUE;
                if (glob->tcp_socket_master >= 0) {
                    /* Refuse new connections while waiting */
                    shutdown(glob->tcp_socket_master, 2);  // SHUT_RDWR
                    CloseSocket(glob->tcp_socket_master);
                    glob->tcp_socket_master = -1;
                }
                report_busy_sessions(glob);
                warnx("Waiting for these programs to exit; "
                      "break again to force reterm exit");
            }
        }
        Delay(1);
    }

    /* Complain about any task which did not stop */
    handle_task_end(glob, TRUE, quiet);


    /* De-init is done in reverse order from above init */
fail_exit:

    if (glob->tcp_socket_master >= 0) {
        shutdown(glob->tcp_socket_master, 2);  // SHUT_RDWR
        Delay(10);  // Allow time to shut down
        CloseSocket(glob->tcp_socket_master);
    }
    if (glob->capture_AFH != 0)
        Close(glob->capture_AFH);
    if (glob->capture_XFH != 0)
        Close(glob->capture_XFH);
    unclaim_abandoned_port(glob);
    glob_free(glob);
    if (IntuitionBase != NULL) {
        CloseLibrary(IntuitionBase);
        IntuitionBase = NULL;
    }
    if (LayersBase != NULL) {
        CloseLibrary(LayersBase);
        LayersBase = NULL;
    }
    if (GfxBase != NULL) {
        CloseLibrary((struct Library *) GfxBase);
        GfxBase = NULL;
    }
    if (SocketBase != NULL) {
        CloseLibrary(SocketBase);
        SocketBase = NULL;
    }

    warnx("Exit reterm\r");
    return (0);
}
