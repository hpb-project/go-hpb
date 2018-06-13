
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <iperf_api.h>

int iperf_server(int port)
{

    struct iperf_test *test;
    int consecutive_errors;

    test = iperf_new_test();
    if ( test == NULL ) {
	fprintf( stderr, " failed to create test\n" );
	exit( EXIT_FAILURE );
    }

    iperf_defaults( test );
    iperf_set_verbose( test, 1 );
    iperf_set_test_role( test, 's' );
    iperf_set_test_server_port( test, port );

    consecutive_errors = 0;
    for (;;) {
	if ( iperf_run_server( test ) < 0 ) {
	    fprintf( stderr, " error - %s\n\n", iperf_strerror( i_errno ) );
	    ++consecutive_errors;
	    if (consecutive_errors >= 5) {
	        fprintf(stderr, "too many errors, exiting\n");
		break;
	    }
	} else
	    consecutive_errors = 0;
	iperf_reset_test( test );
    }

    iperf_free_test( test );
    return 0;
}


int
main( int argc, char** argv )
{
    return iperf_server(5201);
}
