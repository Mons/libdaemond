#include "libdaemond.h"

#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <stdarg.h>

#include <time.h>
#include <sys/time.h>
#include <signal.h>

#include <sys/wait.h>

#include <syslog.h>

#define debug(f, ...) fprintf(stderr, "[%d] " f " at %s line %d.\n", getpid(), ##__VA_ARGS__, __FILE__, __LINE__)
#define warn(f, ...) fprintf(stderr, f " at %s line %d.\n", ##__VA_ARGS__, __FILE__, __LINE__)
#define ewarn(f, ...) fprintf(stderr, f ": %s at %s line %d.\n", ##__VA_ARGS__, strerror(errno), __FILE__, __LINE__)
#define ERR strerror(errno)

static void die (const char * f, ...) {
	va_list va_args;
	va_start(va_args,f);
	vfprintf(stderr, f, va_args);
	va_end(va_args);
	fprintf(stderr,"\n");
	exit(255);
}


// verbosity + colors

typedef struct {
	char *n;
	char *seq;
} daemond_term_color_t;


static daemond_term_color_t colors[] = {
	{ "/", "0" },
	{ "b", "1" },

	{ "r", "31" },
	{ "g", "32" },
	{ "y", "33" },
	{ "n", "34" },
	{ "w", "37" },
	{ NULL,NULL }
};


static void vcolorprintf(const char * fmt, va_list va_args) {
	char buf[4096];
	bzero(buf,4096);
	char *p, *b, *end, *be;
	p = (char *)fmt;
	b = be = buf;
	*b = 0;
	be += 4095;
	daemond_term_color_t * col;
	while (*p) {
		switch(*p) {
			case '<':
				if (end = strchr(p,'>')) {
					p++;
					//debug("matched color: %-.*s", end-p,p );
					for (col = colors; col->n > 0; col++) {
						if ( strncmp( col->n, p, strlen( col->n ) ) == 0 ) {
							//debug("is: %s",col->n);
							//debug("buffer:  +%d: '%s'",b-buf,buf);
							strncat(b,"\033[",  be-b ); b+= 2;
							//debug("buffer:  +%d: '%s'",b-buf,buf);
							strncat(b,col->seq, be-b);  b+= strlen(col->seq);
							//debug("buffer:  +%d: '%s'",b-buf,buf);
							strncat(b,"m",      be-b);  b+= 1;
							//debug("buffer:  +%d: '%s'",b-buf,buf);
							break;
						}
					}
					if (col->n == NULL) {
						p--;
						strncat(b, p, end-p+1 ); b+= end-p+1;
						//debug("buffer:  +%d: '%s'",b-buf,buf);
						p = end+1;
						break;
					} else {
						//debug("last color: %s",col->n);
					}
					p = end+1;
					break;
				} else {
					*b++ = *p++;
					break;
				}
			default:
				//debug("copy %c -> +%d",*p,b-buf);
				*b++ = *p++;
		}
	}
	*b++ = 0;
	//debug("composed buffer: '%s'",buf);
	
	vfprintf(stdout, buf, va_args);
	fprintf(stdout,"\033[0m");
	return;
	
}

static void colorprintf(const char * fmt, ...) {
	va_list va_args;
	va_start(va_args,fmt);
	vcolorprintf(fmt, va_args);
	va_end(va_args);
}

// <r><sample>test</>
int daemond_say(daemond * d, const char * fmt, ...) {
	va_list va_args;
	char * p = (char *)fmt;
	p += strlen(fmt)-1;
	
	if (d) {
		colorprintf("<g>%s</> - ", d->name);
	}
	
	va_start(va_args,fmt);
	vcolorprintf(fmt, va_args);
	va_end(va_args);
	
	colorprintf("</>%s", *p == '\n' ? "" : "\n");
}

/*
 * Pid functions
 */

static int file_exists (const char * file) {
	struct stat sb;
	if( stat(file, &sb) == -1 ) {
		return errno == ENOENT ? 0 : -1;
	} else {
		return 1;
	}
}

int daemond_pid_lock(daemond_pid * pid) {
	struct stat sb;
	int r,err;
	pid_t oldpid;
	FILE *f;
	daemond_say(pid->d, "lock %s", pid->pidfile);
	if( stat(pid->pidfile, &sb) == -1 ) {
		err = errno;
		ewarn("no pid");
		switch(err) {
			case ENOENT:
				r = daemond_pid_openlocked( pid, 0 );
				break;
			default:
				warn("shit!");
		}
	} else {
		//debug("have pid");
		f = fopen(pid->pidfile,"r");
		if (!f) {
			die("Can't open old pidfile `%s' for reading: %s",pid->pidfile, ERR);
		}
		if( fscanf(f,"%d",&oldpid) > 0 ) {
			//debug("got old pid: %d",oldpid);
			if( kill(oldpid,0) == 0 ) {
				//warn("old process %d still alive",oldpid);
				pid->oldpid = oldpid;
				return 0;
			}
		}
		r = daemond_pid_openlocked( pid, 0 );
	}
	if (pid->locked) {
		if (pid->verbose)
			//debug( "pidfile `%s' was locked", pid->pidfile );
		if( flock(pid->fd, LOCK_EX|LOCK_NB) == -1) {
			die("Relock pidfile `%s' failed: %s",pid->pidfile, strerror(errno));
		}
		daemond_pid_write(pid);
		return 1;
	}
	return 0;
}

void daemond_pid_forget(daemond_pid * pid) {
	pid->owner = 0;
}

void daemond_pid_close(daemond_pid * pid) {
	if (pid->handle) {
		fclose(pid->handle);
	}
	close(pid->fd);
	bzero(pid,sizeof(daemond_pid));
}

void daemond_pid_write(daemond_pid * pid) {
	if (! pid->handle )
		die("Can't write to unopened pidfile");
	if (! pid->locked)
		die("Mustn't write to not locked pidfile");
	if ( pid->owner != getpid() )
		die("Write to pidfile allowed only to owner(%d), tried by %d", pid->owner, getpid());
	if( fseek(pid->handle,0,SEEK_SET) == -1 )
		die("Can't seek handle: %s",strerror(errno));
	if( fprintf( pid->handle, "%u\n", getpid() ) == -1)
		die("Failed to write pidfile: %s",strerror(errno));
	if( fflush(pid->handle) == 1 )
		die("Failed to flush pidfile: %s",ERR);
	if ( fsync( pid->fd ) == -1 )
		die("Failed to sync pid after write: %s",ERR);
}

static int daemond_pid_openlocked( daemond_pid * pid, int recurse ) {
	int r,err;
	int created;
	int fd;
	int failures;
	int ready = 0;
	char * file = pid->pidfile;
	struct stat sh,sf;
	//debug("locking file %s", file);

	if (recurse > 5) {
		die("Fall into recursion during lock tries");
	}
	
	while(!ready) {
		if (file_exists( file )) {
			//debug("file `%s' exists", file);
			fd = open(file, O_RDWR);
			if (fd == -1) {
				switch(errno) {
					case ENOENT:
						if ( ++failures < 5 ) {
							warn("failed open, try again");
							break;
						} else {
							warn ("failed open in 5 times");
							return -1;
						}
					default:
						ewarn("error too bad");
						ready = 1;
				}
			} else {
				//debug("file opened r/w");
				ready = 1;
			}
		} else {
			warn("file not exists");
			fd = open(file, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IROTH);
			if (fd == -1) {
				switch(errno) {
					case EEXIST:
						if ( ++failures < 5 ) {
							warn("failed create, try again");
							break;
						} else {
							warn ("failed create in 5 times");
							return -1;
						}
					default:
						ewarn("error too bad");
						ready = 1;
				}
			} else {
				debug("file created r/w; fd=%d", fd);
				ready = 1;
				created = 1;
			}
		}
	}
	
	//debug("call flock on %d",fd);
	r = flock(fd, LOCK_EX|LOCK_NB);
	
	if (r == 0) {
		//debug("flock successful");
		if ( fstat(fd, &sh) == -1) {
			die("Can't get stat on locked filehandle: %s", strerror(errno));
		}
		if ( stat( file, &sf ) == -1) {
			switch(errno) {
				case ENOENT:
					break;
				default:
					die("Can't stat on file `%s': %s",file,strerror(errno));
			}
			close(fd);
			return daemond_pid_openlocked(pid, recurse + 1);
		}
		if ( sh.st_dev != sf.st_dev || sh.st_ino != sf.st_ino ) {
			warn("dev/ino on file `%s' mismatch with opened filehandle. reopen", file);
			close(fd);
			return daemond_pid_openlocked(pid, recurse + 1);
		}
		pid->locked = 1;
		pid->owner = getpid();
		pid->fd = fd;
		pid->handle = fdopen(fd,"w+");
		if (!pid->handle)
			die("failed fdopen: %s",ERR);
		
	} else {
		err = errno;
		warn("%d: lock failed: %s", getpid(), strerror(err));
		close(fd);
	}
	return r;
}

void daemond_pid_relock(daemond_pid * pid) {
	if (pid->locked) {
		if( flock(pid->fd,LOCK_EX|LOCK_NB) == -1)
			die("Relock pid from %d to %d failed: %s",pid->owner, getpid(), ERR);
		pid->owner = getpid();
		daemond_pid_write(pid);
	}
}

/*
 * Cli functions
 */

static int kill_ext(int pidgrp, int sig) {
	pid_t pid;
	pid_t grp;
	if (pid < 0) {
		pid = -pidgrp;
		grp = getpgid(pid);
		if (grp != -1) {
			return -1; // also have good errno
		}
		debug("detected grp %d for pid %d",grp,pid);
		return killpg(grp,sig);
	} else {
		pid = pidgrp;
		return kill(pid,sig);
	}
}

static int daemond_kill_wait( pid_t inpid, int sig, double interval ) {
	double at = htime();
	//debug("kill_wait(%d,%d,%0.2f)",inpid,sig,interval);
	pid_t pid = (inpid < 0) ? -inpid : inpid;
	//debug("kill pid %d and wait for %0.2f...",pid,interval);
	if( kill_ext(inpid,sig) == 0 ) {
		//debug("kill_ext successful (process exists)");
		while (1) {
			usleep(100000);
			if(kill(pid,0) == -1) {
				//debug("kill failed: %s",ERR);
				return errno == ESRCH ? 1 : -1;
			}
			if (htime() - at > interval) {
				//debug("interval overflow");
				return 0;
			}
		}
	} else {
		//debug("kill_ext failed: %s", ERR);
		switch(errno) {
			case ESRCH:
				return 1;
			default:
				ewarn("kill %d",pid);
				return -1;
		}
	}
	//debug("fallback");
	return 0;
}

pid_t daemond_cli_kill(daemond_cli * cli, pid_t pid) {
	//debug("killing %d...",pid);
	float t;
	if (kill(pid,0) == 0) {
		daemond_say(cli->d,"<y>killing %d with <b><w>INT</>", pid);
		if ( daemond_kill_wait(pid, SIGINT, 1 ) ) {
			//debug("Gone after SIGINT");
		} else {
			daemond_say(cli->d,"<y>killing %d with <b><w>TERM</>", pid);
			if( daemond_kill_wait(pid, SIGTERM, cli->d->force_quit ? cli->d->force_quit * 2 : 1 ) ) {
				//debug("Gone after SIGTERM");
			} else {
				daemond_say(cli->d,"<y>killing %d group with <r><b>KILL</>", pid);
				//debug("Not gone after TERM, send KILL to group");
				if( daemond_kill_wait(-pid, SIGKILL, cli->d->force_quit ? cli->d->force_quit * 2 : 1 ) ) {
					//debug("Gone after SIGKILL");
				} else {
					warn("WTF? Not gone after KILL!");
					daemond_say(cli->d,"<r>Process not gone after KILL. Giving up");
					return 0;
				}
			}
		}
		daemond_say(cli->d,"<g>process %d is gone</>",pid);
		
	} else {
		return errno == ESRCH ? pid : 0;
	}
}

void daemond_cli_usage(daemond_cli * cli) {
	
}

void daemond_cli_run(daemond_cli * cli, int argc, char *argv[]) {
	//debug("name = %s",cli->d->name);
	//if (!cli->d->pid)
	//	die("Pid required for CLI");
	daemond_pid * pid = &cli->d->pid;
	pid_t oldpid, killed;
	char * command;
	daemond_cli_com com;
	
	//daemond_cli_kill(cli,96202);exit(0);
	
	if (argc > 0) {
		command = argv[0];
		//debug("got command '%s'",command);
	} else {
		daemond_say(cli->d, "<r>Need command");
		exit(255);
	}
	
	
	if ( strcmp(command, "start") == 0 ) {
		com = START;
	} else
	if ( strcmp(command, "stop") == 0 ) {
		com = STOP;
	} else
	if ( strcmp(command, "restart") == 0 ) {
		com = RESTART;
	} else
	if ( strcmp(command, "check") == 0 ) {
		com = CHECK;
	} else
		com = EXTENDED;
	
	if( daemond_pid_lock(pid) ) {
		//debug("pid locked by cli");
	} else {
		//debug("pid not locked");
		if (oldpid = pid->oldpid) {
			//debug("have old pid: %d",pid->oldpid);
			switch(com) {
				case STOP:
				case RESTART:
					killed = daemond_cli_kill(cli,oldpid);
					if (com == STOP)
						exit(255);
					daemond_pid_lock(pid);
					break;
				case CHECK:
					if (kill(oldpid,0) == 0) {
						daemond_say(cli->d, "<g>running</> - pid <r>%d</>", oldpid);
						exit(0);
					} else {
						daemond_say(cli->d, "<g>not running</> - stalled pidfile <r>%d</>", oldpid);
						exit(255);
					}
					break;
				case START:
					daemond_say(cli->d, "is <b><red>already running</> (pid <red>%d</>)",oldpid);
					exit(255);
				/*
				default:
					die("Unknown command: %s",command);
				*/
			}
		} else {
			daemond_say(cli->d, "<r>pid neither locked nor have old value</>");
			exit(255);
		}
	}
	
	if ( ( com == STOP || com == CHECK ) || ( com == RESTART && !killed ) )
		daemond_say(cli->d, "<y><b>no instance running</>");
	
	if ( com == STOP || com == CHECK )
		exit(0);
	
	if ( com != START && com != RESTART) {
		daemond_say(cli->d, "<b><y>unknown command: <r>%s</>", command);
		daemond_cli_usage( cli );
		exit(0);
	}
	
}

/*
 * SIG functions
 */

/*
sig_atomic_t daemond_sig_received;
sig_atomic_t daemond_sig_int;
sig_atomic_t daemond_sig_term;
*/

static void daemond_sig_handler(int sig) {
	//debug("Signal %d received", sig);
	daemond_sig_received = 1;
	switch(sig) {
		case SIGQUIT:
		case SIGINT:
			//debug("Handle sigint");
			daemond_sig_int = 1;
			return;
		case SIGTERM:
			//debug("Handle sigterm");
			daemond_sig_term = 1;
			return;
		default:
			debug("Signal %d received", sig);
			break;
	}
	exit(255);
}

typedef struct {
	int     signo;
	char   *signame;
	char   *name;
	void  (*handler)(int);
} daemond_sig_t;

daemond_sig_t signals[] = {
    { SIGTERM, "SIGTERM", "", daemond_sig_handler },
    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },
    { 0, NULL, "", NULL }
};


void daemond_sig_init(daemond * d) {
/*
	if( signal(SIGINT,daemond_sig_handler) == -1 ){
		die("signal watcher SIGINT failed: %s",ERR);
	}
	if( signal(SIGTERM,daemond_sig_handler) == -1 ){
		die("signal watcher SIGTERM failed: %s",ERR);
	}
	if( signal(SIGCHLD,daemond_sig_handler) == -1 ){
		die("signal watcher SIGCHLD failed: %s",ERR);
	}
*/
	
	daemond_sig_t     *sig;
	struct sigaction   sa;
	
	for (sig = signals; sig->signo != 0; sig++) {
		bzero(&sa, sizeof(struct sigaction));
		sa.sa_handler = daemond_sig_handler;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGINT, &sa, NULL) == -1) {
			die("signal watcher sigaction(%s) failed: %s", sig->signame, ERR);
		}
	}
}

/*
 * Daemonization functions
 */

void daemond_daemonize(daemond * d) {
	int fd, pidf, status;
	pid_t pid, gone;
	double t;
	
	if(!d->detach)
		return;
	if (d->detached) {
		warn("Process already detached");
		return;
	}
	
	switch (pid = fork()) {
		case -1:
			return die("fork1 failed: %s", ERR);
		case 0: // forked child
			break;
		default: // parent, controlling terminal
			//daemond_say("")
			daemond_say(d, "<y>waiting for %d to gone</>...", pid);
			daemond_pid_forget(&d->pid);
			t = htime();
			while(1) {
				gone = waitpid(pid, &status, WNOHANG);
				//debug("gone = %d (%s)",gone, ERR);
				if (gone > 0) {
					break;
				}
				if (htime() - t > 10) {
					daemond_say(d, "<r>tired of waiting");
					break;
				}
				usleep(100000);
				fprintf(stdout,".");
			}
			//if (d->pid)
			exit(0);
	}
	
	//warn("i'm an intermediate process %d, fork again", getpid());
	
	switch (pid = fork()) {
		case -1:
			return die("fork2 failed: %s", ERR);
		case 0: // forked child
			break;
		default:
			//warn("forked child: %d", pid);
			exit(0);
	}
	
	d->detached = 1;
	daemond_pid_relock(&d->pid); // if?
	
	//warn("i'm forked master process %d", getpid());
	
	if( setsid() == -1 ) {
		return die("setsid failed");
	}
	
	fd = open("/dev/null", O_RDWR);
	
	if (fd < 0) {
		return die("open /dev/null failed: %s", ERR);
	}
	
	if (dup2(fd, STDIN_FILENO) == -1) {
		die("dup2(stdin) failed: %s",ERR);
	}
	
	if (dup2(fd, STDOUT_FILENO) == -1) {
		die("dup2(stdout) failed: %s",ERR);
	}
	
	if (fd > STDERR_FILENO) {
		if (close(fd) == -1) {
			warn("close() failed: %s", ERR);
		}
	}
}

/*
 * STDIN/ERR functions
 */

static void nonblock(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1){
		die("fcntl get failed: %s",ERR);
	}
	if( fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		die("fcntl set failed: %s",ERR);
	}
	return;
}

void daemond_log_std_intercept(daemond * d) {
	int fds[2];
	int outf,errf;
	if( pipe(fds) == -1 ) die("Can't create pipe for STDOUT interception: %s",ERR);
	d->stdout_fd = fds[0];outf = fds[1];
	if( pipe(fds) == -1 ) die("Can't create pipe for STDOUT interception: %s",ERR);
	d->stderr_fd = fds[0];errf = fds[1];
	if (dup2( outf, STDOUT_FILENO ) == -1)
		die("Can't dup2 piped stdout: %s", ERR);
	//if (dup2(errf, STDERR_FILENO ) == -1)
	//	die("Can't dup2 piped stderr: %s", ERR);
	nonblock(d->stdout_fd);
	//nonblock(d->stderr_fd);
}

#define DAEMOND_LOG_BUF 4096

void daemond_log_std_read(daemond * d) {
	char buf[DAEMOND_LOG_BUF];
	bzero(buf,DAEMOND_LOG_BUF);
	char *p,*end, *nl;
	ssize_t got, cut;
	p = end = buf; end += DAEMOND_LOG_BUF-1;

	fflush(stdout);
	fflush(stderr);
	
	while(1) {
		got = read(d->stdout_fd, p, end - p);
		if (got > 0) {
			//debug("read %d bytes: '%s'",got, buf);
			p += got;
			while(p > buf) {
				if (nl = strchr(buf, '\n')) {
					cut = nl-buf+1;
					debug("got single string: '%-.*s'", cut,buf);
					memmove(buf, buf + cut, p - buf + 1);
					p -= cut;
				} else {
					if (p > buf) {
						debug("left string: '%s'",buf);
					}
					break;
				}
			}
		}
		else if (got == 0) {
			debug("no more bytes");
			break;
		}
		else {
			switch(errno) {
				case EAGAIN: // no more data;
					return;
				case EINTR: // try again now
					break;
				default:
					die("read failed: %s",ERR);
			}
		}
	}
	return;
}

/*
 * Main init functions
 */

void daemond_init(daemond * d) {
	daemond_sig_received =
	daemond_sig_int =
	daemond_sig_term = 0;
	
	bzero(d,sizeof(*d));
	d->cli.d = d;
	d->pid.d = d;
}
