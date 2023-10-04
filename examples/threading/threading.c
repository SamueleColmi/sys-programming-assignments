#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    struct thread_data *thread_func_args = (struct thread_data *) thread_param;
    thread_func_args->thread_complete_success = false;

    usleep((thread_func_args->wait_to_obtain) * 1000);

    if (!pthread_mutex_lock(thread_func_args->mutex)) {
        usleep((thread_func_args->wait_to_release) * 1000);
        if (!pthread_mutex_unlock(thread_func_args->mutex))
            thread_func_args->thread_complete_success = true;
    }

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    struct thread_data *thr_data;

    thr_data = (struct thread_data*) malloc(sizeof(struct thread_data));
    thr_data->wait_to_release = wait_to_release_ms;
    thr_data->wait_to_obtain = wait_to_obtain_ms;
    thr_data->mutex = mutex;

    if (!pthread_create(thread, NULL, threadfunc, thr_data))
        return true;

    return false;
}

