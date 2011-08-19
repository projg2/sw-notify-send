/* System-wide notify-send wrapper
 * (c) 2010 Michał Górny
 * Released under the terms of 3-clause BSD license
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

#include <tinynotify.h>
#include <tinynotify-cli.h>

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
		uid_t uid, const char* const root, NotifySession s, Notification n) {
	int ret = 0;
	uid_t old_uid = geteuid();

#ifdef HAVE_CHROOT
	if (root)
		CANFAIL(chroot(root));
#endif
	CANFAIL(setresuid(uid, uid, old_uid));

	CANTFAIL(putenv(display));
	CANTFAIL(putenv(xauth));

	notify_session_disconnect(s); /* ensure to get new connection */
	if (!notification_send(n, s))
		ret = 1;

	CANTFAIL(setuid(old_uid));
#ifdef HAVE_CHROOT
	if (root)
		CANTFAIL(chroot(".")); /* escape the chroot */
#endif

	return ret;
}

int main(int argc, char* argv[]) {
	/* We need the command line and environment. Username would be nice
	 * too but readproc() shortens it and we need to getpwuid() anyway. */
	PROCTAB *proc;
	proc_t *p = NULL;
	int ret = EX_UNAVAILABLE;

	NotifySession s;
	Notification n;

	CANTFAIL(chdir("/"));

	n = notification_new_from_cmdline(argc, argv, PACKAGE " " VERSION);
	if (!n)
		return EX_USAGE;

	proc = openproc(PROC_FILLCOM | PROC_FILLENV);
	if (!proc) {
		fputs("FATAL: openproc() failed", stderr);
		notification_free(n);
		return EX_OSERR;
	}

	s = notify_session_new(PACKAGE, NULL);
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

			if (send_notify(display, xauth, p->euid, getroot(p->tgid), s, n))
				ret = EX_OK;

			if (xauthbuf)
				free(xauthbuf);
		}
	}

	notify_session_free(s);
	closeproc(proc);
	notification_free(n);
	return ret;
}
