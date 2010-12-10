/* System-wide notify-send wrapper
 * (c) 2010 Michał Górny
 * Released under the terms of 3-clause BSD license
 * (link with -lproc)
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <unistd.h>

#include <proc/readproc.h>

#ifdef HAVE_SYSEXITS_H
#	include <sysexits.h>
#else
#	define EX_OK EXIT_SUCCESS
#	define EX_OSERR EXIT_FAILURE
#	define EX_UNAVAILABLE (EXIT_FAILURE + 1)
#endif

/* Check whether supplied process data matches session-wide dbus
 * instance. */
int validateproc(proc_t* const p) {
	const char *procname;
	char* const *ap;
	if (!p->cmdline)
		return 0;

	/* Check whether the binary name matches. */
	procname = basename(p->cmdline[0]);
	if (strcmp(procname, "dbus-daemon"))
		return 0;

	/* Lookup supplied command-line argument list for '--session'.
	 * We don't have to worry about additional '--system' arguments as
	 * dbus refuses to run with multiple configuration files supplied.
	 */
	for (ap = &(p->cmdline[1]); *ap; ap++)
		if (!strcmp(*ap, "--session"))
			return 1;

	return 0;
}

/* Lookup the process environment for specified keystr (a key name with
 * terminating "=" and return the corresponding key=value suitable for
 * passing to putenv(). If no key matches, return NULL. */
char *_findenv(const proc_t* const p, const char* const keystr) {
	char* const *ap;
	const int matchlen = strlen(keystr);

	if (!p->environ)
		return NULL;

	for (ap = p->environ; *ap; ap++) {
		if (!strncmp(*ap, keystr, matchlen))
			return *ap;
	}

	return NULL;
}

/* Get the /proc/<pid>/root path suitable for chroot() call or return
 * NULL if chroot not possible/necessary. */
const char* getroot(int pid) {
#ifdef HAVE_CHROOT
	static char fnbuf[11 + sizeof(pid) * 3];
	char rlbuf[2];
	snprintf(fnbuf, sizeof(fnbuf), "/proc/%d/root", pid);
	if (readlink(fnbuf, rlbuf, sizeof(rlbuf)) != 1 || rlbuf[0] != '/')
		return fnbuf;
	else
#endif
		return NULL;
}

#define FINDENV(p, key) _findenv(p, key "=")
#define CANFAIL(expr) if (expr) perror(#expr " failed (ignoring)")
#define CANTFAIL(expr) if (expr) { perror(#expr " failed (aborting)"); exit(1); }

/* Fork and call notify-send for particular dbus session. */
int send_notify(char* const display, char* const xauth,
		uid_t uid, const char* const root, char* const argv[]) {

	switch (fork()) {
		case 0:
#ifdef HAVE_CHROOT
			if (root)
				CANFAIL(chroot(root));
#endif
			CANFAIL(setuid(uid));
			CANTFAIL(putenv(display));
			CANTFAIL(putenv(xauth));

			execvp("notify-send", argv);
			perror("execvp() returned");
			exit(1);
			return EX_OSERR;
			break;
		case -1:
			perror("fork() failed (aborting)");
			return EX_OSERR;
			break;
		default:
			wait(NULL);
			return EX_OK;
	}
}

int main(int argc, char* const argv[]) {
	/* We need the command line and environment. Username would be nice
	 * too but readproc() shortens it and we need to getpwuid() anyway. */
	PROCTAB *proc = openproc(PROC_FILLCOM | PROC_FILLENV);
	proc_t *p = NULL;
	int ret = EX_UNAVAILABLE;

	if (!proc) {
		fputs("FATAL: openproc() failed", stderr);
		return EX_OSERR;
	}

	while (((p = readproc(proc, p)))) {
		if (validateproc(p)) {
			char* const display = FINDENV(p, "DISPLAY");
			char* xauth = FINDENV(p, "XAUTHORITY");
			const struct passwd* const pw = getpwuid(p->euid);
			char *xauthbuf = NULL;

			if (!display || !pw || !(pw->pw_dir)) /* obligatory */
				continue;
			if (!xauth) { /* default to ~/.Xauthority */
				const int bufsize = strlen(pw->pw_dir) + 25;
				xauthbuf = calloc(bufsize, sizeof(*xauthbuf));
				if (!xauthbuf) {
					fprintf(stderr, "calloc() failed to allocate %dx%lud"
							"bytes of memory for xauthbuf", bufsize, sizeof(*xauthbuf));
					continue;
				}
				snprintf(xauthbuf, bufsize, "XAUTHORITY=%s/.Xauthority", pw->pw_dir);
				xauth = xauthbuf;
			}

			ret = send_notify(display, xauth, p->euid, getroot(p->tgid), argv);

			if (xauthbuf)
				free(xauthbuf);
		}
	}

	closeproc(proc);
	return ret;
}
