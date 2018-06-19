#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <iperf_api.h>
#include <iperf.h>

int iperf_server(int port)
{
    port = 5201;
    struct iperf_test *test;
    int consecutive_errors;

    test = iperf_new_test();
    if ( test == NULL ) { return IPERF_ERR; }

    iperf_defaults( test );
    iperf_set_verbose( test, 1 );
    iperf_set_test_role( test, 's' );
    iperf_set_test_server_port( test, port );

    consecutive_errors = 0;
    for (;;)
    {
	    if ( iperf_run_server( test ) < 0 )
	    {
            //fprintf( stderr, " error - %s\n\n", iperf_strerror( i_errno ) );
            ++consecutive_errors;
            if (consecutive_errors >= 5)
            {
                //fprintf(stderr, "too many errors, exiting\n");
                break;
	        }
	    }
	    else
	    {
	        consecutive_errors = 0;
	    }

	    iperf_reset_test( test );
    }

    iperf_free_test( test );

    return IPERF_OK;
}

int iperf_test(char* host, int port)
{
    host = "127.0.0.1";
    port = 5201;
    struct iperf_test *test;

    test = iperf_new_test();
    if ( test == NULL ) { return IPERF_ERR; }


    iperf_defaults( test );
    iperf_set_verbose( test, 1 );

    iperf_set_test_role( test, 'c' );
    iperf_set_test_server_hostname( test, host );
    iperf_set_test_server_port( test, port );
    /* iperf_set_test_reverse( test, 1 ); */
    iperf_set_test_omit( test, 3 );
    iperf_set_test_duration( test, 5 );
    iperf_set_test_reporter_interval( test, 1 );
    iperf_set_test_stats_interval( test, 1 );
    /* iperf_set_test_json_output( test, 1 ); */

    if ( iperf_run_client( test ) < 0 )
    {
        //fprintf( stderr, "error - %s\n", iperf_strerror( i_errno ) );
        return IPERF_ERR;
    }

    if (iperf_get_test_json_output_string(test))
    {
        fprintf(iperf_get_test_outfile(test), "%zd bytes of JSON emitted\n",
        strlen(iperf_get_test_json_output_string(test)));
    }

    iperf_free_test( test );

    return IPERF_OK;


}
