#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

static void close_file(FILE *fp)
{
	if (fclose(fp))
		syslog(LOG_ERR, "Error closing file\n");
}

static int write_string_to_file(char const *string, char const *path, FILE *fp)
{
	if (!fprintf(fp, "%s\n", string)) {
		syslog(LOG_ERR, "Error writing '%s'' to file %s: %d\n", string, path, errno);
		return -1;
	}

	syslog(LOG_DEBUG, "Writing %s to %s\n", string, path);

	return 0;
}

static int open_file(FILE **fp, char const *path)
{
	*fp = fopen(path, "w");
	if (!fp) {
		syslog(LOG_ERR, "Error opening file %s: %d\n", path, errno);
		return -1;
	}

	return 0;
}

static int write_to_file(char const *path, char const *string)
{
	FILE *fp = NULL;
	int r = 0;

	if (open_file(&fp, path))
		return -1;

	if (write_string_to_file(string, path, fp))
		r = -1;

	close_file(fp);

	return r;
}

static int check_input_args(int argc, char const *argv[])
{
	if (argc != 3) {
		syslog(LOG_ERR, "Invalid number of arguments: %d", argc);
		return -1;
	}

	return 0;
}

int main(int argc, char const *argv[])
{
	int ret = 0;
	openlog(NULL, 0, LOG_USER);

	if (check_input_args(argc, argv)) {
		ret = 1;
		goto exit;
	}

	if (write_to_file(argv[1], argv[2])) {
		ret = 1;
		goto exit;
	}

exit:
	closelog();
	return ret;
}
