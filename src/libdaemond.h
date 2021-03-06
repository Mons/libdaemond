#include <sys/types.h>
#include <stdio.h>
#include <signal.h>

struct _daemond; // global container

typedef struct {
	struct _daemond * d;
	char            * pidfile;
	int               locked;
	pid_t             owner;
	pid_t             oldpid;
	int               fd;
	FILE            * handle;
	int               verbose;
} daemond_pid;

typedef struct {
	struct _daemond * d;
	
} daemond_cli;

struct _daemond {
	char            * name;
	int               use_pid;
	int               force_quit;
	int               detach;
	int               detached;
	
	int               die_count;
	int               last_die_count;
	int               max_die;
	double            fork_at;
	double            min_restart_interval;
	double            restart_interval;
	double            max_restart_interval;
	
	daemond_pid       pid;
	daemond_cli       cli;
	
	int               stdout_fd;
	int               stderr_fd;
	
	int               children_count;
	int               children_running;
	pid_t           * children;
	
	int               terminate;
};

typedef struct _daemond daemond;

typedef enum { START,CHECK,STOP,RESTART,EXTENDED } daemond_cli_com;


/*
 * Speech functions
 */

int   daemond_say(daemond * d, const char * fmt, ...);

/*
 * Pid functions
 */

int   daemond_pid_lock(daemond_pid * pid);
void  daemond_pid_write(daemond_pid * pid);
void  daemond_pid_relock(daemond_pid * pid);
void  daemond_pid_forget(daemond_pid * pid);
void  daemond_pid_close(daemond_pid * pid);

/*
 * CLI functions
 */

pid_t daemond_cli_kill(daemond_cli * cli, pid_t pid);
void  daemond_cli_usage(daemond_cli * cli); // TODO
void  daemond_cli_run(daemond_cli * cli, int argc, char *argv[]);

/*
 * SIG functions
 */

#ifndef NSIG
#define NSIG 128
#endif

volatile sig_atomic_t daemond_sig_was_received;
volatile sig_atomic_t daemond_sig_received[NSIG];

void daemond_sig_init(daemond * d);

/*
 * Daemonization functions
 */

void daemond_daemonize(daemond * d);

/*
 * STDIN/ERR functions
 */

void daemond_log_std_intercept(daemond * d);
void daemond_log_std_read(daemond * d);

/*
 * Main init functions
 */

void daemond_init(daemond * d);
void daemond_master(daemond * d);
