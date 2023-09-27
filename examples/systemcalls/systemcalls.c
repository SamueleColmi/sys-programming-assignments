#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "systemcalls.h"

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    int status;

    status = system(cmd);
    if (WIFEXITED(status))
        if (!WEXITSTATUS(status))
            return true;

    return false;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    bool ret = false;
    int status;
    pid_t pid;

    pid = fork();
    if (pid == -1)
        goto exit;

    if (pid == 0) {
        /* child */
        execv(command[0], command);
        exit(errno);
    } else {
        /* parent */
        if (waitpid(pid, &status, 0) != -1)
            if (WIFEXITED(status))
                if (!WEXITSTATUS(status))
                    ret = true;
    }

exit:
    va_end(args);
    return ret;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;


    bool ret = false;
    int status;
    pid_t pid;
    int fd;

    fd = open(outputfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (fd < 0)
        goto exit;

    pid = fork();
    if (pid == -1)
        goto exit;

    if (pid == 0) {
        /* child */
        if (dup2(fd, 1) < 0)
            goto exit;

        close(fd);
        execv(command[0], command);
        exit(errno);
    } else {
        /* parent */
        close(fd);
        if (waitpid(pid, &status, 0) != -1)
            if (WIFEXITED(status))
                if (!WEXITSTATUS(status))
                    ret = true;
    }

exit:
    va_end(args);
    return ret;
}
