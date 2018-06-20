#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <iperf_api.h>
#include <iperf.h>

struct iperf_test *SERVER   = NULL;
int    iperf_server_running = IPERF_FALSE;

int iperf_server_init(int port)
{
    if (iperf_server_running)
    {
        return IPERF_ERR_RUNNING;
    }

    if (SERVER != NULL)
    {
        iperf_free_test( SERVER );
        SERVER = NULL;
    }

    SERVER = iperf_new_test();
    if ( SERVER == NULL )
    {
        return IPERF_ERR_NEWTEST;
    }

    iperf_defaults( SERVER );
    iperf_set_verbose( SERVER, 1 );
    iperf_set_test_role( SERVER, 's' );
    iperf_set_test_server_port( SERVER, port );
    iperf_set_test_json_output( SERVER, 1 );

    return IPERF_OK;
}

int iperf_server_stop()
{
    iperf_server_running = IPERF_FALSE;
    return IPERF_OK;
}

int iperf_server_kill()
{
    iperf_server_running = IPERF_FALSE;
    iperf_reset_test( SERVER );
    iperf_free_test( SERVER );
    SERVER = NULL;
    return IPERF_OK;
}

int iperf_server_start()
{
    int result = IPERF_OK;
    int count_errors = 0;

    iperf_server_running = IPERF_TRUE;
    for (;;)
    {
        if(!iperf_server_running)
    	{
    	    break;
    	}

	    if ( iperf_run_server( SERVER ) < 0 )
	    {
            ++count_errors;
            if (count_errors >= 15)
            {
                break;
	        }
	    }
	    else
	    {
	        count_errors = 0;
	    }

	    iperf_reset_test( SERVER );
    }


    iperf_server_running = IPERF_FALSE;
    iperf_free_test( SERVER );
    SERVER = NULL;

    if (count_errors > 0) result = IPERF_ERR;

    return result;
}

///////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////
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
