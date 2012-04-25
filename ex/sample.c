#include "libdaemond.h"
#include <stdlib.h>

#define debug(f, ...) fprintf(stderr, "[%d] " f " at %s line %d.\n", getpid(), ##__VA_ARGS__, __FILE__, __LINE__)

int main (int argc, char *argv[]) {
	
	int i;
	daemond d;
	
	daemond_init(&d);
	
	d.name = "sample";
	
	d.use_pid = 1;
	d.detach = 1;
	
	d.pid.pidfile = "/tmp/sample.pid";
	d.pid.verbose = 1;
	
	//daemond_run(&d);
	
	daemond_cli_run(&d.cli, argc-1, argv+1);
	daemond_say(&d, "<g>starting up</>... (pidfile = %s, pid = <y>%d</>)", d.pid.pidfile, getpid());
	daemond_daemonize(&d);
	
	daemond_master(&d);
	
	daemond_say(&d, "followed child: %d",getpid());
	
	for (i=0;i<50;i++) {
		debug("child...");
		usleep(1000000);
	}
	
	/*
	while(1) {
		if( usleep(1000000) == -1 ) daemond_say(&d,"sleep");
		if (daemond_sig_received) {
			daemond_say(&d, "Handling signal in loop");
			if (daemond_sig_int)
				break;
			
		}
		//debug("loop");
	}
	*/

	return rand() > 1000 ? 0 : 10;
}
