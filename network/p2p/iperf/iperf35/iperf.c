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
    /*iperf_set_test_one_off( SERVER, 1 );*/

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
char* iperf_test(char* host, int port, int duration)
{
    struct iperf_test *client;
    char   *result = NULL;

    client = iperf_new_test();
    if ( client == NULL )
    {
        return result;
    }

    iperf_defaults( client );

    iperf_set_test_role( client, 'c' );
    iperf_set_test_server_hostname( client, host );
    iperf_set_test_server_port( client, port );
    iperf_set_test_duration( client, duration);

    iperf_set_verbose( client, 1 );
    /* iperf_set_test_reverse( client, 1 ); */
    iperf_set_test_omit( client, 1 );
    //iperf_set_test_reporter_interval( client, 1 );
    iperf_set_test_stats_interval( client, 1 );
    iperf_set_test_json_output( client, 1 );


    if ( iperf_run_client( client ) < 0 )
    {
        return result;
    }

    result = iperf_get_test_json_output_string(client);
    iperf_free_test( client );

    return result;
}
