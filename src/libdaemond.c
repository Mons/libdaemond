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
//#include <sys/signal.h>
#include <sys/wait.h>

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

int daemond_printf(daemond * d, const char * fmt, ...) {
	va_list va_args;
	char * p = (char *)fmt;
	p += strlen(fmt)-1;
	
	if (d) {
		colorprintf("<g>%s</> - ", d->name);
	}
	
	va_start(va_args,fmt);
	vcolorprintf(fmt, va_args);
	va_end(va_args);
	
	colorprintf("</>");
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
			} else {
				//daemond_say(pid->d, "<y>stalled pidfile old pid %d is invalid", oldpid);
			}
		} else {
			daemond_say(pid->d, "<r>can't read pidfile contents");
		}
		r = daemond_pid_openlocked( pid, 0 );
	}
	if (pid->locked) {
		//if (pid->verbose)
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

pid_t daemond_pid_read(daemond_pid * pid) {
	pid_t new;
	if (! pid->handle )
		die("Can't read unopened pidfile");
	
	if ( fsync( pid->fd ) == -1 )
		die("Failed to sync pid before read: %s",ERR);
	
	if( fseek(pid->handle,0,SEEK_SET) == -1 )
		die("Can't seek handle: %s",strerror(errno));
	
	if ( fscanf( pid->handle, "%d", &new ) != 1 )
		die("Can't read pidfile: %s", strerror(errno));
	
	if( fseek(pid->handle,0,SEEK_SET) == -1 )
		die("Can't rewind handle: %s",strerror(errno));
	
	return new;
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

static double htime() {
	struct timeval tp;
	gettimeofday(&tp,NULL);
	return ((double)tp.tv_usec / 1000000) + ((double)tp.tv_sec);
}


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
	if (!cli->d->use_pid) {
		daemond_say(cli->d,"<r>use_pid required for CLI");
		exit(255);
	}
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
		//debug("pid not locked (old=%d)", pid->oldpid);
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
volatile sig_atomic_t daemond_sig_was_received;
volatile sig_atomic_t daemond_sig_received[NSIG];
*/

static void daemond_sig_handler(int sig) {
	//debug("Signal %d received", sig);
	if (sig < NSIG) {
		daemond_sig_was_received = 1;
		daemond_sig_received[sig]++;
	} else {
		debug("Received signal %d (%s), ignoring", sig, sys_signame[sig]);
	}
	return;
	/*
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
	*/
}

//#include <sys/ucontext.h>

typedef struct {
	int     signo;
	char   *signame;
	int     flags;
	char   *name;
	void  (*handler)(int);
	//void  (*sihandler)(int, struct __siginfo *, ucontext_t *);
	void  (*sihandler)(int, struct __siginfo *, void *);
} daemond_sig_t;

daemond_sig_t signals[] = {
	{ SIGINT,  "SIGINT",  0, "", daemond_sig_handler, 0 },
	{ SIGTERM, "SIGTERM", 0, "", daemond_sig_handler, 0 },
	{ SIGQUIT, "SIGQUIT", 0, "", daemond_sig_handler, 0 },
	{ SIGCHLD, "SIGCHLD", 0, "", daemond_sig_handler, 0 },
	{ SIGPIPE, "SIGPIPE, SIG_IGN", 0, "", SIG_IGN, 0 },
	{ 0,       NULL,      0, "", NULL,             NULL }
};

void daemond_sig_set(daemond * d, daemond_sig_t * sig) {
	struct sigaction   sa;
	
		bzero(&sa, sizeof(struct sigaction));
		sa.sa_flags = sig->flags;
		if ( sig->sihandler ) {
			sa.sa_sigaction = sig->sihandler;
			sa.sa_flags  |= SA_SIGINFO;
		}
		else
		if( sig->handler ) {
			sa.sa_handler = sig->handler;
			sa.sa_flags  &= ~((unsigned int)SA_SIGINFO);
		}
		else {
			sa.sa_handler = SIG_DFL;
			sa.sa_flags  &= ~((unsigned int)SA_SIGINFO);
		}
		
		sigemptyset(&sa.sa_mask);
		if (sigaction(sig->signo, &sa, NULL) == -1) {
			die("signal watcher sigaction(%s) failed: %s", sig->signame, ERR);
		} else {
			//debug("installed signal %s flags: %08x", sig->signame, sa.sa_flags);
		}
}

void daemond_sig_init(daemond * d) {
	
	daemond_sig_was_received = 0;
	memset( (void *) daemond_sig_received,0,NSIG );
	
	daemond_sig_t     *sig;
	struct sigaction   sa;
	
	for (sig = signals; sig->signo != 0; sig++) {
		daemond_sig_set(d, sig);
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
			daemond_printf(d, "<y>waiting for %d to gone</>...", pid);
			daemond_pid_forget(&d->pid);
			t = htime();
			while(1) {
				gone = waitpid(pid, &status, WNOHANG);
				//debug("gone = %d (%s)",gone, ERR);
				if (gone > 0) {
					colorprintf("<g>done</>\n");
					break;
				}
				if (htime() - t > 10) {
					colorprintf("<r>tired of waiting</>\n");
					exit(255);
				}
				usleep(100000);
				fprintf(stdout,".");
			}
			
			if (d->use_pid) {
				daemond_printf(d, "<y>Reading new pid</>...");
				t = htime();
				while (1) {
					pid = daemond_pid_read(&d->pid);
					if (gone == pid) {
						if (!file_exists( d->pid.pidfile )) {
							colorprintf( "<r>Pidfile disappeared. Possible daemon died. Look at logs</>\n" );
							exit(255);
						}
						if (htime() - t > 10) {
							colorprintf("<r>tired of waiting</>\n");
							exit(255);
						}
						
						fprintf(stdout,".");
						usleep(100000);
					} else {
						colorprintf(" <g>%d</>\n", pid);
						break;
					}
				}
				daemond_printf(d, "<y>checking it's live</>...");
				usleep(300000);
				
				if( kill(pid,0) == 0 ) {
					colorprintf(" <g>looks ok</>\n");
				} else {
					colorprintf(" <r>no process with pid %d. Look at logs\n", pid);
					exit(255);
				}
			}
			
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
	if (d->use_pid)
		daemond_pid_relock(&d->pid);
	
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
	
	if (dup2(fd, STDERR_FILENO) == -1) {
		die("dup2(stderr) failed: %s",ERR);
	}
	
	if (fd > STDERR_FILENO) {
		if (close(fd) == -1) {
			warn("close(%d) failed: %s", fd, ERR);
		}
	}
	
	/*
	fclose(stdout);
	stdout = fdopen( STDOUT_FILENO, "w" );
	fclose(stderr);
	stderr = fdopen( STDERR_FILENO, "w" );
	fclose(stdin);
	stdin = fdopen( STDIN_FILENO, "r" );
	*/
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
 * Main functions
 */

void daemond_init(daemond * d) {
	
	
	bzero(d,sizeof(*d));
	
	d->use_pid          = 1;
	d->children_count   = 1;
	d->max_die          = 3;   // max die before raising restart interval
	d->min_restart_interval =  // double seconds
	d->restart_interval = 0.1; // double seconds
	d->max_restart_interval = 30; // double seconds
	
	d->cli.d = d;
	d->pid.d = d;
}

void daemond_sig_child_sihandler(int sig, struct __siginfo *info, void *uap) {
	//debug("Signal %d received", sig);
	debug("Received signal %d (%s), ignoring", sig, sys_signame[sig]);
	return;
}

void daemond_sig_child_handler(int sig) {
	//debug("Signal %d received", sig);
	debug("Received signal %d (%s), ignoring", sig, sys_signame[sig]);
	return;
}


int daemond_spawned(daemond * d) {

/*
	
	daemond_sig_t child_signals[] = {
		{ SIGINT,  "SIGINT",           0,            "", NULL, daemond_sig_child_sihandler },
		{ SIGTERM, "SIGTERM",          0,            "", NULL, daemond_sig_child_sihandler },
		{ SIGQUIT, "SIGQUIT",          0,            "", NULL, daemond_sig_child_sihandler },
		{ SIGCHLD, "SIGCHLD",          SA_NOCLDSTOP, "", NULL, daemond_sig_child_sihandler },
		{ SIGPIPE, "SIGPIPE, SIG_IGN", 0,            "", SIG_IGN, NULL },
		{ 0,        NULL,              0,            "", NULL, NULL }
	};
	
	daemond_sig_t child_signals[] = {
		{ SIGINT,  "SIGINT",           0,            "", daemond_sig_child_handler, NULL },
		{ SIGTERM, "SIGTERM",          0,            "", daemond_sig_child_handler, NULL },
		{ SIGQUIT, "SIGQUIT",          0,            "", daemond_sig_child_handler, NULL },
		{ SIGCHLD, "SIGCHLD",          SA_NOCLDSTOP, "", daemond_sig_child_handler, NULL },
		{ SIGPIPE, "SIGPIPE, SIG_IGN", 0,            "", SIG_IGN, NULL },
		{ 0,        NULL,              0,            "", NULL, NULL }
	};
*/
	daemond_sig_t child_signals[] = {
		{ SIGINT,  "SIGINT",           0,            "", SIG_IGN, NULL },
		{ SIGTERM, "SIGTERM",          0,            "", SIG_DFL, NULL },
		{ SIGQUIT, "SIGQUIT",          0,            "", SIG_DFL, NULL },
		{ SIGCHLD, "SIGCHLD",          SA_NOCLDSTOP, "", SIG_DFL, NULL },
		{ SIGPIPE, "SIGPIPE, SIG_IGN", 0,            "", SIG_IGN, NULL },
		{ 0,        NULL,              0,            "", NULL, NULL }
	};
	
	daemond_sig_t     *sig;
	
	for (sig = child_signals; sig->signo != 0; sig++) {
		daemond_sig_set(d, sig);
	}

/*
	{ SIGINT,  "SIGINT",  "", SIG_IGN },
	{ SIGQUIT, "SIGQUIT", "", SIG_DFL },
	{ SIGCHLD, "SIGCHLD", "", SIG_DFL },
*/
	//{ SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },
}

// should return 1 on master, 0 on child
int daemond_fork(daemond * d, int slot) {
	pid_t pid;
	//char *argv[] = { "echo", "echo", "ok", 0 };
	
	switch (pid = fork()) {
		case -1:
			die("fork failed: %s", ERR);
			return 1;
		case 0:  // forked child
			daemond_spawned(d);
			return 0;
		default: // master process
			d->children[slot] = pid;
			d->children_running++;
			return 1;
	}
}

// should return 1 on master, 0 on child
int daemond_check_children(daemond * d) {
	int i, do_fork = 0, running = 0;
	pid_t pid;
	for ( i=0; i < d->children_count; i++ ) {
		if ( pid = d->children[i] ) {
			if ( kill(pid,0) == 0 ) {
				// ok
				daemond_say(d,"<g>pid %d (slot %d) is alive",pid, i);
				running++;
			} else {
				daemond_say(d,"<r>no more child for slot %d with pid %d (%s)",i,pid, ERR);
				d->children[i] = 0;
				do_fork = 1;
			}
		} else {
			do_fork = 1;
		}
		if (do_fork) {
			if (htime() > d->fork_at) {
				if( !daemond_fork(d,i) ) {
					return 0;
				}
			}
		}
	}
	d->children_running = running;
	return 1;
}


static void daemond_reaper(daemond * d) {
	pid_t pid;
	int status, exitcode, signal, core, died = 0;
			while( ( pid = waitpid(-1,&status,WNOHANG) )  > 0) {
				d->children_running--;
				exitcode = status >> 8;
				signal =  status & 127;
				core = status & 128;
				//debug("Reaping %d (status=%d, exit=%d, sig='%s', core=%d)", pid, status, exitcode, sys_signame[ signal ], core );
				if (exitcode != 0) {
					debug("Child %d died with exitcode %d (%s); signal=%s, core=%d", pid, exitcode, strerror(exitcode), sys_signame[ signal ], core );
					died = 1;
				} else
				if (signal || core) {
					if (signal == SIGTERM || signal == SIGQUIT || signal == SIGINT) {
						debug("Child %d correctly exited with signal=%s, core=%d", pid, sys_signame[ signal ], core );
					} else {
						debug("Child %d died with signal=%s, core=%d", pid, sys_signame[ signal ], core );
						died = 1;
					}
				}
				else {
					debug("Child %d normally gone",pid);
					/*
					if ( kill( pid, 0 ) == 0 ) {
						debug("Pid is alive");
					} else {
						debug("Pid is dead: %s", ERR);
					}
					*/
				}
			}
			if (died) {
				d->die_count++;
				d->last_die_count++;
				if (d->max_die > 0 && ( d->last_die_count + 1 > d->max_die * d->children_count )) {
					d->restart_interval *= 2;
					if (d->restart_interval > d->max_restart_interval)
						d->restart_interval = d->max_restart_interval;
					debug( "Children repeatedly died %d times, restart interval=%0.2fs", d->die_count, d->restart_interval );
					d->fork_at = htime() + ( d->restart_interval *= 2 );
					d->last_die_count = 0;
					//d->terminate = 1;
				} else {
					d->fork_at = htime() + d->restart_interval;
				}
			} else {
				d->last_die_count = d->die_count = 0;
				d->fork_at = htime();
			}
	
}


static void daemond_sig_safe_handler(daemond * d, int sig) {
	switch(sig) {
		case SIGQUIT:
		case SIGINT:
			debug("Handle sigint/sigquit");
			d->terminate = 1;
			return;
		case SIGTERM:
			debug("Handle sigterm");
			d->terminate = 2;
			return;
		case SIGCHLD:
			debug("Handle sigchld");
			daemond_reaper(d);
			return;
		default:
			debug("Signal %d received", sig);
			break;
	}
	
}

void daemond_sig_check(daemond * d) {
	pid_t pid;
	int sig;
		if(daemond_sig_was_received) {
			for (sig=0; sig < NSIG; sig++) {
				if (daemond_sig_received[sig]) {
					daemond_sig_received[sig] = 0;
					daemond_sig_safe_handler(d, sig);
				}
			}
			daemond_sig_was_received = 0;
		}
	
}

void daemond_master(daemond * d) {
	pid_t pid, children[ 10 ];
	int i, sig;
	
	bzero( children, sizeof(children) );
	d->children = children;
	d->children_running = 0;
	d->fork_at  = htime();
	
	d->force_quit       = 1;
	
	daemond_sig_init(d);
	
	while(1) {
		daemond_say(d,"xxx");
		daemond_sig_check(d);
		if (d->terminate)
			break;
		
		/*
			check_children will do forks. so if it's a master, it should leave within this loop.
			otherwise it should go out
			so, 0 is a child, 1 is a master
		*/
		
		if ( ! daemond_check_children(d) ) {
			return;
		}
		//usleep(100000);
		usleep(1000000);
	}
	if (d->children_running) {
		debug("Terminating %d children",d->children_running);
		for ( i=0; i < d->children_count; i++ ) {
			if ( pid = d->children[i] ) {
				if(kill(pid, SIGTERM) == -1) {
					debug("kill TERM %d failed: %s", pid,ERR);
				} else {
					debug("kill TERM %d successful", pid);
				}
			}
		}
		for (i=0;i<100;i++) {
			daemond_sig_check(d);
			if (d->children_running == 0)
				break;
			usleep( 50000 );
		}
		if (d->children_running) {
			for ( i=0; i < d->children_count; i++ ) {
				if ( pid = d->children[i] ) {
					if(kill(pid, SIGKILL) == -1) {
						debug("kill KILL %d failed: %s", pid,ERR);
					} else {
						debug("kill KILL %d successful", pid);
					}
				}
			}
		}
	}
	/*
	for ( i=0; i < d->children_count; i++ ) {
		if ( pid = d->children[i] ) {
		}
	}
	*/
	
	daemond_say(d,"<y>terminating master");
	exit(0);
}

void daemond_stop(daemond * d) {
	
}
