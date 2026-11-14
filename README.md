# reterm

reterm is a remote terminal server for AmigaOS. It lets you telnet to an
Amiga and get a shell (or run any console program) from a modern terminal
compatible with xterm. reterm acts as the Amiga console handler for the
programs it runs, translating between xterm and Amiga console escape
sequences, so shells, editors and other console programs work over the
network as they would in an Amiga Shell window.

## Features

- Built-in TCP server (`-p`), with a daemon mode for several simultaneous
  sessions (`-d`), or use of an existing device such as `TCP:`
- Telnet protocol support, xterm terminal detection, and automatic window size
  reporting to Amiga programs
- Translation between xterm and Amiga console escape sequences, including
  cursor and function keys, colors, and raw console events
- Command line editing, command history and tab completion for commands and
  file names in cooked mode shells (such as AmigaShell)
- Optional UTF-8 conversion to and from Amiga ISO 8859-1 (`-u`)
- Remote control of requesters and program windows with ^C: press buttons,
  edit string gadgets, toggle checkboxes, select menu items, even when the
  window draws its button labels as graphics
- Recovery from "Software Failure" requesters: choosing Suspend starts a
  replacement shell
- Programs left running when a connection drops are detached rather than
  hung, and can be reattached later (`-a`, `-A`)
- Capture of session input and output to files, and debug tracing
- Can interpose on SER: to provide the same protocol translation as over TCP.

## Example session

On the Amiga:

```
1.SYS:> run >nil: reterm -p 23 -d 5
```

From another computer:

```
$ telnet amiga
Trying 192.168.1.55...
Connected to amiga.
Escape character is '^]'.
10.OS321:> cd ram:
10.RAM Disk:> list
Disk.info                       352 ----rwed Yesterday 23:43:53
> ENVARC:Sys/def_RAM.info
Clipboards                      Dir ----rwed Yesterday 23:43:51
T                               Dir ----rwed Yesterday 23:43:51
ENV                             Dir ----rwed Yesterday 23:43:51
1 file - 352 bytes - 3 directories - 8 blocks used
10.RAM Disk:> status
Process  1: Loaded as command: TCP/IP Superserver
Process  2: Loaded as command: Workbench
Process  3: Loaded as command: reterm
Process  4: Loaded as command: NetLogViewer
Process  5: No command loaded
Process  6: No command loaded
Process  9: No command loaded
Process 10: Loaded as command: status
10.RAM Disk:> endcli
Process 10 ending
Connection closed by foreign host.
$
```

## Contents

- [Requirements](#requirements)
- [Building](#building)
- [Usage](#usage)
- [Starting reterm](#starting-reterm)
- [Connecting from another computer](#connecting-from-another-computer)
- [Running a program other than the shell](#running-a-program-other-than-the-shell)
- [Command line editing](#command-line-editing)
- [Tab completion](#tab-completion)
- [Raw mode programs and terminal handling](#raw-mode-programs-and-terminal-handling)
- [Editors](#editors)
- [Requesters and program windows (^C)](#requesters-and-program-windows-c)
- [Software Failure requesters](#software-failure-requesters)
- [Disconnects, detaching and reattaching](#disconnects-detaching-and-reattaching)
- [Stopping reterm](#stopping-reterm)
- [Capture and debugging](#capture-and-debugging)
- [How reterm works](#how-reterm-works)
- [Known limitations](#known-limitations)
- [License](#license)

## Requirements

- AmigaOS 2.04 or later (developed and tested on AmigaOS 3.2)
- A TCP/IP stack providing `bsdsocket.library` (such as Roadshow or AmiTCP)
  for the built-in TCP server, or a `TCP:` device for device mode
- A terminal which understands xterm (or VT100) escape sequences on the
  remote computer

## Building

reterm is cross-compiled with the m68k-amigaos gcc toolchain:

```
PATH=$PATH:/opt/amiga/bin make reterm
```

Copy the resulting `reterm` binary to the Amiga, for example to `SYS:Util/`.
`reterm -v` shows the version and build date.

## Usage

```
reterm [options] [<device>] [<command> [<arguments>]]
```

| Option | Description |
|---|---|
| `-a` | List abandoned console ports (programs left by a reterm session) |
| `-A <cli>` | Attach to the abandoned console of CLI process `<cli>` |
| `-c <file>` | Capture program input and output to `<file>` |
| `-C <file>` | Capture terminal (xterm) input and output to `<file>` |
| `-d <count>` | Daemon mode: serve up to `<count>` sessions at the same time |
| `-D[D[D]]` | Debug output (more `D`s give more detail) |
| `-E` | Avoid xterm escape sequences where possible |
| `-F` | Fake xterm cursor position and window size replies |
| `-h` | Show help |
| `-i` | Capture only input |
| `-M` | Tab completion matches only characters to the left of the cursor |
| `-o` | Capture only output |
| `-p <port>` | Listen for connections on TCP `<port>` (enables telnet protocol) |
| `-P` | Don't show the program path when tab completing commands |
| `-q` | Quiet: don't announce connects and disconnects |
| `-r <ascii>` | Requester abort key (default 3, which is ^C) |
| `-R` | Disable the ^C requester abort |
| `-s <size>` | Stack size for the program which reterm runs |
| `-t` | Enable the telnet protocol |
| `-T` | Disable the telnet protocol |
| `-u` | Convert between xterm UTF-8 and Amiga ISO 8859-1 |
| `-v` | Show the program version |
| `-x` | Force the terminal type to xterm (usually not needed) |

If no command is given, reterm runs `newshell CONSOLE:`.

## Starting reterm

### Built-in TCP server

The simplest way to run reterm is with its own TCP server:

```
run >nil: reterm -p 23 -d 5
```

`-p 23` listens on the standard telnet port, and `-d 5` allows up to five
sessions at the same time. Each connection gets its own shell. Without
`-d`, reterm serves a single session and then exits. Port 23 must not be in
use by another telnet server; choose another port (such as `-p 2323`) if it
is. To start reterm at boot, add the `run` line to `S:User-Startup` (or to
your network startup script, after the TCP/IP stack is running).

While running, reterm reports each session on its console:

```
connect 1 23 192.168.1.30 52308
disconnect 1
```

Use `-q` to turn these messages off.

### Device mode

reterm can instead run a session on any device which behaves like a
console, such as the `TCP:` device:

```
reterm TCP:2000
reterm TCP:2000 NewShell CONSOLE: from S:Remote-Startup
```

The first argument is taken as the device when its name (the part before
the colon) is not a filesystem. If the device can't be opened (for example,
if it is busy), reterm reports `Failed to open <device>` instead of running
the name as a command. In daemon mode it retries every second.

### From an existing remote session

If you already have a telnet or ssh session to the Amiga (from another
server), you can start reterm inside it to get reterm's terminal handling:

```
5.DH0:> reterm
New Shell process 6
6.DH0:>
```

## Connecting from another computer

The easiest way to connect is with telnet:

```
telnet amiga 23
```

reterm handles the telnet option negotiation and echoes your input itself,
so keys are sent as you type them. reterm identifies the terminal as an xterm by its reply to
a terminal identification query, and asks it for its size.

You may also use `nc`, but then you must exit the Amiga program to end the
connection:

```
stty raw -echo onlcr && nc amiga 2000 ; stty sane
```

### Character sets

The Amiga uses ISO 8859-1 (Latin 1). With `-u`, reterm converts UTF-8 typed
at the terminal to ISO 8859-1, and Amiga output back to UTF-8. Characters
which have no ISO 8859-1 equivalent arrive at the Amiga as `?`.

Without `-u`, you can use `luit` to convert at the terminal instead:

```
luit -encoding ISO-8859-1 telnet amiga 2000 ; stty sane
```

## Running a program other than the shell

Anything after the options (and device, if any) is the command which reterm
runs for each session. For example, to edit a file directly:

```
reterm -p 2000 Util:Vim SYS:reterm/reterm.c
```

When the program exits, the session ends. Use `-s` if the program needs a
larger stack than reterm's own.

## Command line editing

Shells which leave the console in cooked mode (such as AmigaShell) rely on
the console handler for line editing and command history. reterm provides
these, with the following keys:

| Key | Action |
|---|---|
| ^A, Shift-Cursor Left | Go to the beginning of the input line |
| ^B, Cursor Left | Move the cursor left |
| ^D | Delete to the right, or show tab completions |
| ^E, Shift-Cursor Right | Go to the end of the input line |
| ^F, Cursor Right | Move the cursor right |
| ^H, Backspace | Delete to the left of the cursor |
| ^I, Tab | Cycle to the next tab completion |
| Shift-Tab | Cycle to the previous tab completion |
| ^J, ^M, Return | Submit the input line to the program |
| ^K | Clear to the end of the line |
| ^N, Cursor Down | Next line in command history |
| ^P, Cursor Up | Previous line in command history |
| ^R | Redisplay the input line |
| ^U | Clear to the start of the line |
| ^W | Delete word |
| ^X | Clear the entire input line |
| ^Y | Show command history |
| Control-Cursor Left | Go to the previous word |
| Control-Cursor Right | Go to the next word |
| ^\ | End of file: terminate the current read with zero bytes |
| ^C, ^D, ^E | Also send the matching break signal to the program; ^C discards the typed line (and may first offer requester control; see below) |

While you have a partly typed command line, program output is held until
you press Return, so that it doesn't break into the line you are typing.

## Tab completion

In cooked mode, Tab completes commands and file names. Pressing Tab on the
first word of a command line searches the command path; on later words it
searches the current directory, or the directory named in the word. Press
Tab again for the next match, or Shift-Tab for the previous one. After the
last match, the line returns to what you typed.

```
10.DH0:> list sys:tools/commodities/auto       <Tab>
10.DH0:> list sys:Tools/Commodities/AutoPoint  <Tab>
10.DH0:> list sys:Tools/Commodities/AutoPoint.info  <Tab>
10.DH0:> list sys:tools/commodities/auto
```

When completing a command, the result includes the path where it was found,
shortened through an assign when one matches (`-P` hides the path):

```
10.DH0:> vim  <Tab>
10.DH0:> util:vim-5.3
```

Characters on both sides of the cursor are matched: with the cursor on the
`.` of `list t.info`, Tab offers `Tools.info`, then `Trashcan.info`. Use
`-M` to match only the characters to the left of the cursor.

Hints:

- To descend into a directory, press ^E once the completion has reached
  it, then Tab again to see the entries within.
- After pressing Tab, ^D lists all matches. With the cursor at the end of the
  line, ^D also lists matches for what you have typed; on an empty argument it
  is a quick way to list the current directory:

```
5.DH0:> Type ^D
  DPat              DW.config          History            PCD
  SPat              SetFont            SetKeyboard        Shell-Startup
  Startup-Sequence  bg                 fg                 fork
5.DH0:> Type
```

## Raw mode programs and terminal handling

Programs which put the console in raw mode (such as editors, or shells like
csh) do their own line editing. reterm passes their input through, converting
xterm key sequences (cursor keys, function keys, Home/End, Page Up/Down, and
their Shift and Control variants) to the Amiga equivalents, and converting
Amiga console output sequences to xterm sequences. Telnet commands and
terminal replies are handled by reterm and not passed to the program.

reterm emulates the console features programs ask for:

- **Window size**: programs get the terminal's real size, both through
  `ACTION_DISK_INFO` (the console unit) and through the Window Status
  Request (`CSI 0 SPACE q`). When a raw mode program asks for the size, reterm
  queries the terminal so the answer is current even if the terminal was
  resized.
- **Cursor position reports** (`CSI 6 n`)
- **Raw console events** (`CSI n {`), including window resize events
- **Screen modes**: cooked, raw, and the `ID_CON` / `ID_RAWCON` disk types

If your terminal doesn't answer size or cursor position queries, use `-F`
to have reterm reply immediately with its own values. `-E` makes reterm
avoid xterm sequences where it can, for limited terminals, and `-x` forces
xterm mode when the terminal doesn't identify itself.

## Editors

AmigaDOS `ed` needs to be told to use the console:

```
ed WINDOW CONSOLE: my_file
```

In `ed`, ^A moves to the next line, and ^\ aborts it.

Vim works well, including picking up the terminal's rows and columns:

- http://aminet.net/package/text/edit/vim53bin
- http://aminet.net/package/text/edit/vim53rt

## Requesters and program windows (^C)

Amiga programs sometimes open a window you can't see from a remote terminal,
such as a requester asking you to insert a volume or retry an operation, and
then wait for it. Pressing ^C in reterm finds the window belonging to the
session's program (or a related requester, such as AssignWedge's "Volume
Request") and lists what you can do with it:

```
Program has "Volume Request" window open.
    A) [Depth: send window to back]
    B) ID=1 _Retry
    C) ID=2 _Assign
    D) ID=3 _Deny
    E) ID=0 _Cancel
Select a letter for a gadget or edit its text ( ESC=cancel).
```

Press a letter to choose. reterm then sends the program exactly the message
the Amiga would on a mouse click. If no window is found, ^C is passed to the
program as a break, as usual.

The list contains:

- **Title bar gadgets** first: Close (if the program accepts it), Depth, and
  Zoom.
- **Buttons**, labeled with their text. When a program draws its labels as
  graphics, reterm reads the label from the window's pixels using the
  window's fonts, as each line is listed. Disabled (ghosted) buttons are
  recognized too.
- **String and integer gadgets**, with their contents:
  `ID=8 Name = "hello"`. Choosing one opens a line editor with the current
  text: Backspace deletes, ^U clears, Return sets the new text, and ESC or ^C
  cancels. Integer gadgets accept only numbers.
- **Checkboxes**, shown as `[x]` or `[ ]`, which toggle when chosen.
- **Radio buttons** (MX gadgets), shown as `(*)` or `( )`, selected when
  chosen.
- **[Menu]** at Z, when the window has a menu. Menus list their items and
  sub-items, with checkmarks and keyboard shortcuts; disabled entries are
  marked.

Keys in the prompt:

| Key | Action |
|---|---|
| A-Z | Choose an option (Z is always [Menu], when there is one) |
| Space | Show the next page of options, when there are more than fit |
| Backspace | Previous page, or back one menu level |
| ESC | Cancel |

Each letter stays tied to the gadget or menu item it was shown for. If that
gadget has gone (or the menu changed) by the time you choose, reterm says so
rather than act on something else. reterm also refuses to send input to a
window which is blocked by a requester or which isn't accepting input, as
the Amiga itself would. If the program prints output while the prompt is
shown, the prompt is canceled with `Cancel (program output).`

Use `-r <ascii>` to choose a different key, or `-R` to turn this off.

## Software Failure requesters

When a program crashes, AmigaOS shows a "Software Failure" requester with
Suspend and Reboot buttons. Suspend leaves the crashed process frozen, and
since shell commands run in the shell's own process, that would leave your
session without a shell. If you choose Suspend through the ^C prompt, reterm
starts a replacement shell (in the same directory and with the same command
path) so that you can continue working.

## Disconnects, detaching and reattaching

When a connection closes while a program is running, reterm sends the
program ^C and ^D, and gives it 10 seconds to exit. A shell or a program
which notices the break exits normally.

A program which is still using the console after that (for example, an
editor, or a program waiting on a requester) is **detached** rather than left
hung. reterm reports it:

```
Client 1: CLI 12 (vi) still using console; detached (reattach with "reterm -A 12")
```

The detached program waits at its next console input or output. The break
signals which it didn't act on are withdrawn, so it isn't killed by a stale
^C when you reattach.

List detached programs with `-a`:

```
1.SYS:> reterm -a
CLI  Port        State      Queued  Command
 12  0833b598    waiting         0  vi
Use "reterm -A <cli>" to attach to a waiting program.
```

Reattach with `-A`, giving the CLI number and a way to connect:

```
run >nil: reterm -p 2326 -A 12
```

Then connect to port 2326; the program continues where it left off, in the
same raw or cooked mode. A program can be detached and reattached as many
times as needed. Programs whose process has crashed (suspended) can't be
reattached.

## Stopping reterm

Send reterm a break (for example, `break <cli>` from another shell, or ^C in
its console). reterm stops accepting connections, and waits for its sessions'
programs to close their consoles, telling you which ones it is waiting for:

```
**Aborting reterm due to ^C Break**
Client 3: waiting for "vi" to close its console
Waiting for these programs to exit; break again to force reterm exit
```

A second break forces reterm to exit. Programs still using a reterm console
are then left waiting, and can be found with `reterm -a`.

## Capture and debugging

`-c <file>` captures what the program reads and writes; `-C <file>` captures
what passes to and from the terminal. Input is enclosed in `{` and `}` in the
capture file. Use `-i` or `-o` to capture only input or only output.

`-D` turns on debug output, and each additional `D` adds detail: `-D`
shows the data the program reads and the terminal's replies, `-DD` adds the
console packets the program sends, and `-DDD` adds the packets' arguments. Debug output goes to reterm's
standard output, so start reterm without redirecting it to `NIL:` when using
`-D`.

## How reterm works

reterm runs each session with three kinds of thread:

- The **main** thread accepts connections, starts sessions, and cleans them up
  when they end.
- A **reader** thread for each session is the console handler for that
  session's program. It services the program's console packets
  (`ACTION_READ`, `ACTION_WRITE`, `ACTION_WAIT_CHAR`, `ACTION_SCREEN_MODE`,
  `ACTION_DISK_INFO` and others), reads the terminal's input, and translates
  between the terminal and the program.
- A **runner** thread starts the program on the reader's console port, and
  then exits.

Because Amiga console programs expect a console handler, reterm implements
the full set of console handler packets. When the program issues
`ACTION_READ` (a `Read()` call), the packet is queued, and the reader thread
answers it when processed input is available.

## Known limitations

- Labels drawn as graphics are recognized only in the window's own fonts,
  without styles (such as bold), and only where the window isn't covered.
- Gadgets of custom gadget classes (such as MUI or ReAction string gadgets)
  aren't listed by the ^C prompt, and sliders, scrollers, list views and
  cycle gadgets can't be set.
- A window which is busy without a requester (for example, showing only a
  busy pointer) still accepts input from the ^C prompt.
- `ed` may hang when run on a serial port.
- Vim 1.14 crashes when resized while running; resizing the terminal while
  it runs, and then having it ask for the size, can crash the Amiga.

## License

reterm is copyright (c) 2024 Chris Hooper, and is distributed under the BSD
2-Clause License. See [LICENSE](LICENSE).
