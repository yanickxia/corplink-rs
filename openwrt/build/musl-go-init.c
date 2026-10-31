/* Build-only adapter for Go's Linux/amd64 c-archive constructor on musl.
 * Go expects argc/argv in its .init_array entry; musl invokes entries without
 * arguments. Capture the original process arguments before libc initialization,
 * then start Go from a normal constructor after musl has initialized TLS/env.
 * Link with --wrap=__libc_start_main and remove only Go's original init_array.
 */
typedef int (*main_function)(int, char **, char **);
typedef void (*init_function)(void);

extern int __real___libc_start_main(main_function, int, char **,
                                    init_function, init_function, init_function,
                                    void *);
extern void _rt0_amd64_linux_lib(int, char **);

static int process_argc;
static char **process_argv;

int __wrap___libc_start_main(main_function main, int argc, char **argv,
                            init_function init, init_function fini,
                            init_function rtld_fini, void *stack_end)
{
    process_argc = argc;
    process_argv = argv;
    return __real___libc_start_main(main, argc, argv, init, fini,
                                   rtld_fini, stack_end);
}

__attribute__((constructor))
static void initialize_go_with_process_arguments(void)
{
    _rt0_amd64_linux_lib(process_argc, process_argv);
}
