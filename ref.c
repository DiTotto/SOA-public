#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/spinlock.h> // for spin_lock, spin_unlock
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/workqueue.h>
#include <crypto/hash.h> // Required for cryptographic hash functions
#include <linux/signal.h>
#include "utils/hash.h"
#include "utils/func_aux.h"

#define PATH 512
#define PASS_LEN 32
#define SHA256_LENGTH 32
#define SALT_LENGTH 16

#define DEVICE_NAME "ref_monitor"

// // Define the size of the log buffer
// #define LOG_BUFFER_SIZE 1024

// char log_buffer[LOG_BUFFER_SIZE];
// int log_index = 0;

static char *the_file = NULL; //in the makefile will be setted the path of the file
module_param(the_file, charp, 0660);
MODULE_PARM_DESC(the_file, "Path of the file in the singleFS");

static int Major;
static struct class *device_class = NULL;
static struct device *device = NULL;

// Define the path_node structure
struct path_node
{
    char *path;             // path to be protected
    struct path_node *next; // pointer to the next node
};

// Define the monitor structure
struct reference_monitor
{
    struct path_node *head; // head of the list of protected paths
    int mode;               // 0 = OFF; 1 = ON; 2 = REC_OFF; 3 = REC_ON;
    char password[PASS_LEN];
    spinlock_t lock;
};

// Initialize the monitor structure with the head of the list set to NULL and the mode set to OFF
struct reference_monitor monitor = {
    .head = NULL,
    .mode = 0,
};


// Define the open_flags structure, which contains the flags used to open a file
struct open_flags
{
    int open_flag; // open flag (O_RDONLY, O_WRONLY, O_RDW, O_CREAT, O_APPEND), passed to the open or openat syscall
    umode_t mode;  // file permissions, passed to the open or openat syscall
    int acc_mode;  // access mode (FMODE_READ, FMODE_WRITE, FMODE_READ|FMODE_WRITE), used to check if the file is opened for reading, writing, or both
    int intent;    // intent (FMODE_OPENED, FMODE_CREATED, FMODE_EXCL), used to specify the intent of the open operation
};
// the structure is used to determine why a process is trying to open a file anf for what purpose. With this we can block the access if the file is protected


// Workqueue for deferred logging so it doesn't block the monitor
static struct workqueue_struct *log_wq;
typedef struct
{
    struct work_struct work; // Structure for deferred work, contains the work to be done in the workqueue
    char log_entry[512];     // log entry to be written to the log file
} log_work_t;

// Define the kprobe structures
static struct kprobe kp_filp_open;
static struct kprobe kp_rmdir;
static struct kprobe kp_mkdir_at;
static struct kprobe kp_unlinkat;


static ssize_t ref_write(struct file *, const char *, size_t, loff_t *); // function to write to the device, used to interpret the commands sent by the user (ON, OFF, REC_ON, REC_OFF)
static int ref_open(struct inode *, struct file *);                      // function to open the device

// management functions
void setMonitorON(void);
void setMonitorOFF(void);
void setMonitorREC_ON(void);
void setMonitorREC_OFF(void);
int comparePassw(char *password);
int changePassword(char *new_password);
int add_protected_path(const char *path);
int delete_protected_path(const char *path);



// function to check if the current user is root
static inline bool is_root_uid(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
#include "linux/uidgid.h"
    return uid_eq(current_uid(), GLOBAL_ROOT_UID);
#else
    return 0 == current_uid();
#endif
}



/* ---------------------------------------------- */
// Function for deffered work

// Function to get the TGID, thread ID, UID, EUID
void get_process_info(char *info, size_t len)
{
    struct task_struct *task = current;
    snprintf(info, len, " %d,  %d,  %d,  %d", task->tgid, task->pid, __kuid_val(task_uid(task)), __kuid_val(task_euid(task)));
}

// Function to compute the SHA-256 hash of a file
int compute_file_hash(const char *filename, unsigned char *hash)
{
    struct file *filp;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    char *buf;
    int bytes_read;
    int ret = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf)
    {
        kfree(desc);
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    if (crypto_shash_init(desc))
    {
        ret = -EINVAL;
        goto out_free;
    }

    filp = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(filp))
    {
        ret = PTR_ERR(filp);
        goto out_free;
    }

    // Read blocks of size PAGE_SIZE and update the hash
    while ((bytes_read = kernel_read(filp, buf, PAGE_SIZE, &filp->f_pos)) > 0)
    {
        if (crypto_shash_update(desc, buf, bytes_read))
        {
            ret = -EINVAL;
            goto close_filp;
        }
    }

    if (bytes_read < 0)
    {
        ret = bytes_read;
    }
    else if (crypto_shash_final(desc, hash))
    {
        ret = -EINVAL;
    }

close_filp:
    filp_close(filp, NULL);
out_free:
    kfree(buf);
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

// Function to compute the SHA-256 hash of a directory
int compute_directory_hash(const char *path, unsigned char *hash)
{
    struct path p;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    //char *buf;
    int ret = 0;

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        return PTR_ERR(tfm);
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }

    desc->tfm = tfm;

    if (crypto_shash_init(desc))
    {
        ret = -EINVAL;
        goto out_free;
    }

    // Get path (kern_path) and stats (vfs_getattr)
    ret = kern_path(path, LOOKUP_FOLLOW, &p);
    if (ret)
    {
        goto out_free;
    }

    ret = crypto_shash_update(desc, path, strlen(path));
    if (ret)
    {
        ret = -EINVAL;
        goto out_free;
    }

    ret = crypto_shash_final(desc, hash);

out_free:
    //kfree(buf);
    kfree(desc);
    crypto_free_shash(tfm);
    return ret;
}

// Function to write the log entry to the log file
void log_to_file(struct work_struct *work)
{
    struct file *filp;
    loff_t pos = 0;
    // Pointer to the log_work_t structure: contains the log data (obtained with container_of).
    log_work_t *log_work = container_of(work, log_work_t, work);
    ssize_t ret;

    filp = filp_open(the_file, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(filp))
    {
        printk(KERN_ERR "Failed to open log file\n");
    }
    else
    {
        ret = kernel_write(filp, log_work->log_entry, strlen(log_work->log_entry), &pos);
        if (ret < 0)
        {
            printk(KERN_ERR "Failed to write to log file\n");
        }
        filp_close(filp, NULL);
    }

    kfree(log_work);
}

// Function to schedule the logging work
void schedule_logging(const char *program_path)
{
    unsigned char hash[SHA256_LENGTH];
    char hash_str[SHA256_LENGTH * 2 + 1];
    char info[128];
    log_work_t *log_work;
    int i;
    int hash_result;
    struct path p;
    struct kstat stat;

    printk(KERN_INFO "Starting schedule_logging for path: %s\n", program_path);

    // Get path and stats
    if (kern_path(program_path, LOOKUP_FOLLOW, &p) == 0) //kern_path resolve a file_path to a struct_path
    {
        // Getting file/directory statistics
        if (vfs_getattr(&p, &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT) == 0)
        {
            // If the path is a directory, calculate the hash of the directory
            if (S_ISDIR(stat.mode))
            {
                printk(KERN_INFO "Computing hash for directory: %s\n", program_path);
                hash_result = compute_directory_hash(program_path, hash);
            }
            else
            {
                // If the path is a file, calculate the hash of the file
                printk(KERN_INFO "Computing hash for file: %s\n", program_path);
                hash_result = compute_file_hash(program_path, hash);
            }

            if (hash_result != 0)
            {
                printk(KERN_ERR "Failed to compute hash for path: %s, error code: %d\n", program_path, hash_result);
                return;
            }

            // Convert the hash to a string
            for (i = 0; i < SHA256_LENGTH; i++)
            {
                sprintf(&hash_str[i * 2], "%02x", hash[i]);
            }
            hash_str[SHA256_LENGTH * 2] = '\0';

            // Getting the current process
            get_process_info(info, sizeof(info));

            log_work = kmalloc(sizeof(*log_work), GFP_KERNEL);
            if (!log_work)
            {
                printk(KERN_ERR "Failed to allocate memory for log work\n");
                return;
            }

            snprintf(log_work->log_entry, sizeof(log_work->log_entry), "%s, %s, %s\n", info, program_path, hash_str);
            printk(KERN_INFO "Log entry created: %s\n", log_work->log_entry);

            // Macro that initialize a work struct that will be done in deferred work. The work struct point to the function "log_to_file" 
            INIT_WORK(&log_work->work, log_to_file); 
            // insert the deferred job into the workqueue
            queue_work(log_wq, &log_work->work);
        }
        else
        {
            printk(KERN_ERR "Failed to get stats for path: %s\n", program_path);
        }
    }
    else
    {
        printk(KERN_ERR "Failed to get path: %s\n", program_path);
    }
}

/* ---------------------------------------------- */

// Function to check if a route is protected
bool is_protected_path(const char *dir_path)
{
    struct path_node *node_ptr;
    bool is_protected = false;

    //acquire the spinlock to protect the list of protected paths
    spin_lock(&monitor.lock);

    node_ptr = monitor.head; // set the current node to the head of the list of protected paths
    while (node_ptr)
    {
        size_t path_len = strlen(node_ptr->path);
        
        // check if the path is in the list of protected paths
        if (strncmp(node_ptr->path, dir_path, path_len) == 0)
        { 
            // check if the path is an exact match or a subdirectory
            if (dir_path[path_len] == '\0' || dir_path[path_len] == '/')
            { 
                is_protected = true;
                break;
            }
        }

        node_ptr = node_ptr->next;
    }

    //release the spinlock
    spin_unlock(&monitor.lock);

    return is_protected;
}


// function to send a signal to the process that tried to access a protected path without permission
static void send_terminate_signal(void)
{
    struct kernel_siginfo info;
    memset(&info, 0, sizeof(struct kernel_siginfo));
    info.si_signo = SIGTERM;
    info.si_code = SI_KERNEL;
    info.si_errno = -EACCES;

    send_sig_info(SIGTERM, &info, current);
}

// Function to handle the open syscall
static int monitor_filp_open(struct kprobe *p, struct pt_regs *registers)
{

    int fd = (int)registers->di;                                               // in the DI register there is the file descriptor of the file to be opened
    struct open_flags *flags = (struct open_flags *)(registers->dx);              // in the DX register there are the open flags
    const __user char *user_path = ((struct filename *)(registers->si))->uptr; // in the SI register there is the path of the file to be opened, in uptr there is the user space pointer to the path
    const char *kernel_path = ((struct filename *)(registers->si))->name;      // in the SI register there is the path of the file to be opened, in name there is the kernel space pointer to the path
    char *path = NULL;
    char *dir = NULL;
    bool file_exist = false;


    if (!registers){
        printk(KERN_ERR "Invalid register state\n");
        return 0;
    }

    if (strncmp(kernel_path, "/run", 4) == 0){ // check if the path is /run
        return 0;
    }

    if (!(flags->open_flag & O_RDWR) && !(flags->open_flag & O_WRONLY) && !(flags->open_flag & (O_CREAT | __O_TMPFILE | O_EXCL)))
    { // check if the file is opened for reading
        return 0;
    }

    if (!user_path)
    {
        path = kstrdup(kernel_path, GFP_KERNEL); // copy the path
        if (!path)
        {
            printk(KERN_ERR "Memory allocation for full_path failed\n\n");
            registers->ax = -ENOMEM;
            return 0;
        }
    }
    else
    {
        path = full_path(fd, user_path); // get the full path of the file
        if (!path)
        {
            path = kstrdup(kernel_path, GFP_KERNEL);
            if (!path)
            {
                printk(KERN_ERR "Memory allocation for full_path failed\n\n");
                registers->ax = -ENOMEM;
                return 0;
            }
            file_exist = true;
        }
    }

    dir = find_directory(path); // find the directory of the file
    if (!dir)
    {
        dir = get_pwd(); // get the current working directory of the process if the directory is not found
    }

    if (!dir)
    {
        printk(KERN_ERR "Failed to determine directory\n");
        kfree(path);
        registers->ax = -EACCES;
        return 0;
    }

    // check if the path of the file to be opened is protected
    if ((!(flags->open_flag & O_CREAT) || flags->mode) && file_exist)
    { // check if you are not trying to create a file or the mode is 1 and the file already exists
        if (is_protected_path(dir))
        {
            printk(KERN_INFO "Access to secured path blocked: %s\n", dir);
            schedule_logging(dir);
            kfree(dir);
            kfree(path);
            registers->ax = -EACCES;
            registers->di = (unsigned long)NULL;
            send_terminate_signal();
            return 0;
        }
    }
    else if (is_protected_path(path))
    {
        printk(KERN_INFO "Access to protected path blocked: %s\n", path);
        schedule_logging(path);
        kfree(dir);
        kfree(path);
        registers->ax = -EACCES;
        registers->di = (unsigned long)NULL;
        send_terminate_signal();
        return 0;
    }

    kfree(dir);
    kfree(path);

    return 0;
}

// Function to handle the rmdir syscall
static int monitor_rmdir(struct kprobe *p, struct pt_regs *registers)
{

    int fd = (int)registers->di;
    const __user char *user_path = ((struct filename *)(registers->si))->uptr;
    const char *kernel_path = ((struct filename *)(registers->si))->name;

    char *ret_pointer = NULL;

    if (!registers)
    {
        printk(KERN_ERR "Invalid registers state\n");
        return 0;
    }

    if (!user_path)
    {
        ret_pointer = kstrdup(kernel_path, GFP_KERNEL);
        if (!ret_pointer)
        {
            printk(KERN_ERR "Memory allocation failed\n");
            registers->ax = -ENOMEM;
            return 0;
        }
    }
    else
    {
        ret_pointer = full_path(fd, user_path);
        if (!ret_pointer)
        {
            ret_pointer = kstrdup(kernel_path, GFP_KERNEL);
            if (!ret_pointer)
            {
                printk(KERN_ERR "Memory allocation failed\n");
                registers->ax = -ENOMEM;
                return 0;
            }
        }
    }

    if (is_protected_path(ret_pointer))
    {
        printk(KERN_INFO "Access to secured path blocked: %s\n", ret_pointer);
        schedule_logging(ret_pointer);
        kfree(ret_pointer);
        registers->di = (unsigned long)NULL;
        registers->ax = -EACCES;
        send_terminate_signal();
        return 0;
    }

    kfree(ret_pointer);
    return 0;
}

// Function to handle the mkdirat syscall
static int monitor_mkdirat(struct kprobe *p, struct pt_regs *registers)
{

    int fd = (int)registers->di;
    const __user char *user_path = ((struct filename *)(registers->si))->uptr;
    const char *kernel_path = ((struct filename *)(registers->si))->name;

    char *ret_pointer = NULL;
    char *dir = NULL;

    if (!registers)
    {
        printk(KERN_ERR "Invalid registers\n");
        return 0;
    }

    if (!user_path)
    {
        ret_pointer = kstrdup(kernel_path, GFP_KERNEL);
        if (!ret_pointer)
        {
            printk(KERN_ERR "Memory allocation failed\n");
            registers->ax = -ENOMEM;
            return 0;
        }
    }
    else
    {
        ret_pointer = full_path(fd, user_path);
        if (!ret_pointer)
        {
            ret_pointer = kstrdup(kernel_path, GFP_KERNEL);
            if (!ret_pointer)
            {
                printk(KERN_ERR "Memory allocation failed\n");
                registers->ax = -ENOMEM;
                return 0;
            }
        }
    }

    dir = find_directory(ret_pointer);
    if (!dir)
    {
        dir = get_pwd();
    }

    if (!dir)
    {
        printk(KERN_ERR "Failed to determine directory\n");
        kfree(ret_pointer);
        registers->ax = -EACCES;
        return 0;
    }

    if (is_protected_path(dir))
    {
        printk(KERN_INFO "Access to secured path blocked: %s\n", dir);
        schedule_logging(dir);
        kfree(dir);
        kfree(ret_pointer);
        registers->di = (unsigned long)NULL;
        registers->ax = -EACCES;
        send_terminate_signal();
        return 0;
    }

    kfree(dir);
    kfree(ret_pointer);
    return 0;
}

// Function to handle the unlinkat syscall
static int monitor_unlinkat(struct kprobe *p, struct pt_regs *registers)
{

    int fd = (int)registers->di;
    const __user char *user_path = ((struct filename *)(registers->si))->uptr;
    const char *kernel_path = ((struct filename *)(registers->si))->name;

    char *ret_pointer = NULL;

    if (!registers)
    {
        printk(KERN_ERR "Invalid registers\n");
        return 0;
    }

    if (!user_path)
    {
        ret_pointer = kstrdup(kernel_path, GFP_KERNEL);
        if (!ret_pointer)
        {
            printk(KERN_ERR "Memory allocation failed\n");
            registers->ax = -ENOMEM;
            return 0;
        }
    }
    else
    {
        ret_pointer = full_path(fd, user_path);
        if (!ret_pointer)
        {
            ret_pointer = kstrdup(kernel_path, GFP_KERNEL);
            if (!ret_pointer)
            {
                printk(KERN_ERR "Memory allocation failed\n");
                registers->ax = -ENOMEM;
                return 0;
            }
        }
    }

    if (is_protected_path(ret_pointer))
    {
        printk(KERN_INFO "Access to secured path blocked: %s\n", ret_pointer);
        schedule_logging(ret_pointer);
        kfree(ret_pointer);
        registers->di = (unsigned long)NULL;
        registers->ax = -EACCES;
        send_terminate_signal();
        return 0;
    }

    kfree(ret_pointer);
    return 0;
}

void print_hash(const unsigned char *hash, size_t length)
{
    int i;
    char hash_str[SHA256_LENGTH * 2 + 1];

    for (i = 0; i < length; i++)
    {
        sprintf(&hash_str[i * 2], "%02x", hash[i]);
    }

    hash_str[length * 2] = '\0';
    printk(KERN_INFO "Hash: %s\n", hash_str);
}

void setMonitorON()
{

    void enable_all_kprobes(void){
        enable_kprobe(&kp_filp_open);
        enable_kprobe(&kp_rmdir);
        enable_kprobe(&kp_mkdir_at);
        enable_kprobe(&kp_unlinkat);
    }

    void update_monitor_mode(int new_mode) {
        spin_lock(&monitor.lock);
        monitor.mode = new_mode;
        spin_unlock(&monitor.lock);
    }

    switch (monitor.mode)

    {
    case 0:
        // change the monitor mode to ON in an atomic way
        update_monitor_mode(1);

        // enable the kprobes
        enable_all_kprobes();


        printk(KERN_INFO "Monitor is now ON\n");
        break;
    case 1:
        printk(KERN_INFO "Monitor is already ON\n");
        break;
    case 2:
        update_monitor_mode(1);
        enable_all_kprobes();

        printk(KERN_INFO "Monitor is now ON\n");
        break;
    case 3:
        update_monitor_mode(1);

        printk(KERN_INFO "Monitor is now ON\n");
        break;
    default:
        printk(KERN_ERR "Error: invalid mode\n");
    }
}

void setMonitorOFF()
{

    void disable_all_kprobes(void){
        disable_kprobe(&kp_filp_open);
        disable_kprobe(&kp_rmdir);
        disable_kprobe(&kp_mkdir_at);
        disable_kprobe(&kp_unlinkat);
    }

    void update_monitor_mode(int new_mode) {
        spin_lock(&monitor.lock);
        monitor.mode = new_mode;
        spin_unlock(&monitor.lock);
    }

    switch (monitor.mode)
    {
    case 0:
        printk(KERN_INFO "Monitor is already OFF\n");
        break;
    case 1:
        update_monitor_mode(0);
        disable_all_kprobes();

        printk(KERN_INFO "Monitor is now OFF\n");
        break;
    case 2:
        update_monitor_mode(0);

        printk(KERN_INFO "Monitor is now OFF\n");
        break;
    case 3:
        update_monitor_mode(0);

        disable_all_kprobes();

        printk(KERN_INFO "Monitor is now OFF\n");
        break;
    default:
        printk(KERN_ERR "Error: invalid mode\n");
    }
}

void setMonitorREC_ON()
{

    void enable_all_kprobes (void){
        enable_kprobe(&kp_filp_open);
        enable_kprobe(&kp_rmdir);
        enable_kprobe(&kp_mkdir_at);
        enable_kprobe(&kp_unlinkat);
    }

    void update_monitor_mode(int new_mode) {
        spin_lock(&monitor.lock);
        monitor.mode = new_mode;
        spin_unlock(&monitor.lock);
    }

    switch (monitor.mode)
    {

    case 0:
        update_monitor_mode(3);

        enable_all_kprobes();

        printk(KERN_INFO "Monitor is now REC_ON\n");
        break;

    case 1:
        update_monitor_mode(3);
        printk(KERN_INFO "Monitor is now REC_ON\n");
        break;

    case 2:
        update_monitor_mode(3);

        enable_all_kprobes();

        printk(KERN_INFO "Monitor is now REC_ON\n");
        break;

    case 3:
        printk(KERN_INFO "Monitor is already REC_ON\n");
        break;
    default:
        printk(KERN_ERR "Error: invalid mode\n");
    }
}

void setMonitorREC_OFF()
{

    void disable_all_kprobes(void){
        disable_kprobe(&kp_filp_open);
        disable_kprobe(&kp_rmdir);
        disable_kprobe(&kp_mkdir_at);
        disable_kprobe(&kp_unlinkat);
    }

    void update_monitor_mode(int new_mode) {
        spin_lock(&monitor.lock);
        monitor.mode = new_mode;
        spin_unlock(&monitor.lock);
    }

    switch (monitor.mode)
    {
    case 0:
        update_monitor_mode(2);

        printk(KERN_INFO "Monitor is now REC_OFF\n");
        break;
    case 1:
        update_monitor_mode(2);
        disable_all_kprobes();

        printk(KERN_INFO "Monitor is now REC_OFF\n");
        break;
    case 2:
        printk(KERN_INFO "Monitor is already REC_OFF\n");
        break;
    case 3:
        update_monitor_mode(2);
        disable_all_kprobes();

        printk(KERN_INFO "Monitor is now REC_OFF\n");
        break;
    default:
        printk(KERN_ERR "Error: invalid mode\n");
    }
}

int add_protected_path(const char *path)
{
    struct path_node *new_node, *current_node;
    char *resolved_path;

    // Check if the monitor is in REC_ON or REC_OFF mode
    if (monitor.mode != 2 && monitor.mode != 3)
    {
        printk(KERN_ERR "Error: Monitor must be in RECORDING_ON or RECORDING_OFF mode\n");
        return -1;
    }

    // Convert the given path to an absolute path
    resolved_path = get_absolute_path(path);
    if (!resolved_path)
    {
        printk(KERN_ERR "Error: Unable to resolve absolute path\n");
        return -EINVAL;
    }

    // Check if the absolute path is the same as the log file
    if (the_file && strncmp(resolved_path, the_file, strlen(the_file)) == 0)
    {
        printk(KERN_ERR "Error: Cannot protect the log file path\n");
        kfree(resolved_path); // Libera la memoria allocata per absolute_path
        return -EINVAL;
    }

    spin_lock(&monitor.lock);

    // Check if the path is already present in the list
    current_node = monitor.head;
    while (current_node)
    {
        if (strcmp(current_node->path, resolved_path) == 0)
        {
            printk(KERN_INFO "Path already exists: %s\n", resolved_path);
            spin_unlock(&monitor.lock);
            kfree(resolved_path);
            return -EEXIST;
        }
        current_node = current_node->next;
    }

    // Creation of the new node
    new_node = kmalloc(sizeof(struct path_node), GFP_ATOMIC); // Alloc memory for the new node
    if (!new_node)
    {
        printk(KERN_ERR "Memory allocation failed for new node\n");
        spin_unlock(&monitor.lock);
        kfree(resolved_path);
        return -ENOMEM;
    }
    new_node->path = resolved_path;
    new_node->next = monitor.head;
    monitor.head = new_node;

    spin_unlock(&monitor.lock);

    printk(KERN_INFO "Path added: %s\n", resolved_path);
    
    return 0;
}

int delete_protected_path(const char *path)
{
    struct path_node *current_node, *prev_node = NULL;
    int status = -1;
    char *resolved_path;

    if (monitor.mode != 2 && monitor.mode != 3)
    {
        printk(KERN_ERR "Error: Monitor must be in RECORDING_ON or RECORDING_OFF mode\n");
        return -1;
    }

    // Convert the given path to an absolute path
    resolved_path = get_absolute_path(path);
    if (!resolved_path)
    {
        printk(KERN_ERR "Error: Unable to resolve absolute path\n");
        return -EINVAL;
    }

    spin_lock(&monitor.lock);

    current_node = monitor.head;
    while (current_node)
    {
        if (strcmp(current_node->path, resolved_path) == 0)
        {
            if (prev_node)
            {
                prev_node->next = current_node->next;
            }
            else
            {
                monitor.head = current_node->next;
            }
            kfree(current_node->path);
            kfree(current_node);
            status = 0;
            break;
        }
        prev_node = current_node;
        current_node = current_node->next;
    }

    spin_unlock(&monitor.lock);

    if (status == 0)
    {
        printk(KERN_INFO "Protected path successfully removed: %s\n", resolved_path);
    }
    else
    {
        printk(KERN_ERR "Failed to find and remove path: %s\n", resolved_path);
    }

    kfree(resolved_path);
    return status;
}

int changePassword(char *new_password)
{
    int ret;
    char hash[PASS_LEN + 1];
    unsigned char salt[SALT_LENGTH];

    if (strlen(new_password) < 6)
    {
        printk(KERN_ERR "Error: Password must be at least 6 characters long\n");
        return -1;
    }

    if (monitor.mode != 2 && monitor.mode != 3)
    {
        printk(KERN_ERR "Error: REC_ON or REC_OFF required\n");
        return -1;
    }

    // Hash of the given password
    ret = hash_password(new_password, salt, hash);
    if (ret != 0)
    {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    printk(KERN_INFO "Password changed\n");
    //printk("new password without hash %s\n", new_password);

    spin_lock(&monitor.lock);
    strncpy(monitor.password, hash, PASS_LEN);
    spin_unlock(&monitor.lock);

    return 0;
}

int verifyPassword(const char *password, const char *stored_hash, const unsigned char *salt)
{
    unsigned char hash[SHA256_LENGTH];
    int ret;

    ret = hash_password(password, salt, hash);
    if (ret != 0)
    {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    if (constant_time_compare(hash, stored_hash, SHA256_LENGTH) == 0)
    {
        printk(KERN_INFO "Password correct\n");
        return 0;
    }
    else
    {
        printk(KERN_INFO "Password incorrect\n");
        return -1;
    }
}

static int ref_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "Open\n");
    return 0;
}

static int verify_user_password(const char *parameter)
{
    unsigned char salt[SALT_LENGTH];
    int ret = verifyPassword(parameter, monitor.password, salt);
    if (ret != 0)
    {
        printk(KERN_ERR "Error verifying password\n");
    }
    return ret;
}


// Funzione per eseguire il comando del monitor
static int execute_monitor_command(const char *command, const char *parameter, const char *additional_param)
{
    int ret = -1;

    if (strncmp(command, "ON", 2) == 0)
    {
        printk(KERN_INFO "Setting monitor ON\n");
        setMonitorON();
        ret = 1;
    }
    else if (strncmp(command, "OFF", 3) == 0)
    {
        printk(KERN_INFO "Setting monitor OFF\n");
        setMonitorOFF();
        ret = 1;
    }
    else if (strncmp(command, "REC_ON", 6) == 0)
    {
        printk(KERN_INFO "Setting monitor REC_ON\n");
        setMonitorREC_ON();
        ret = 1;
    }
    else if (strncmp(command, "REC_OFF", 7) == 0)
    {
        printk(KERN_INFO "Setting monitor REC_OFF\n");
        setMonitorREC_OFF();
        ret = 1;
    }
    else if (strncmp(command, "CHGPASS", 7) == 0)
    {
        if (additional_param)
        {
            ret = changePassword((char *)additional_param);
            if (ret != 0)
            {
                printk(KERN_ERR "Error changing password\n");
                return ret;
            }
            ret = 1;
        }
        else
        {
            printk(KERN_ERR "Missing new password\n");
            ret = -EINVAL;
        }
    }
    else if (strncmp(command, "INSERT", 6) == 0)
    {
        ret = add_protected_path(additional_param);
        if (ret != 0)
        {
            printk(KERN_ERR "Error inserting path\n");
            return ret;
        }
        ret = 1;
    }
    else if (strncmp(command, "REMOVE", 6) == 0)
    {
        ret = delete_protected_path(additional_param);
        if (ret != 0)
        {
            printk(KERN_ERR "Error removing path\n");
            return ret;
        }
        ret = 1;
    }
    else
    {
        printk(KERN_ERR "Unknown command\n");
        ret = -EINVAL;
    }

    return ret;
}

// Function to write to the device and change the monitor mode
static ssize_t ref_write(struct file *f, const char __user *buff, size_t len, loff_t *off)
{
    char *buffer;
    char *command;
    char *parameter;
    char *additional_param = NULL;
    //int ret = -1;
    ssize_t ret = -1;
    //unsigned char salt[SALT_LENGTH];

    if (is_root_uid() != 1)
    {
        printk(KERN_ERR "Error: ROOT user required\n");
        return -EPERM;
    }

    buffer = kmalloc(len + 1, GFP_KERNEL);
    if (!buffer)
    {
        printk(KERN_ERR "Failed to allocate memory\n");
        return -ENOMEM;
    }

    if (copy_from_user(buffer, buff, len))
    {
        kfree(buffer);
        return -EFAULT;
    }
    buffer[len] = '\0';

    command = strsep(&buffer, ":");
    parameter = strsep(&buffer, ":");
    if (buffer)
    {
        additional_param = strsep(&buffer, ":");
    }

    //printk(KERN_INFO "Command: %s\n", command);

    if (command && parameter)
    {
        ret = verify_user_password(parameter);
        if (ret != 0)
        {
            kfree(buffer);
            return ret;
        }

        ret = execute_monitor_command(command, parameter, additional_param);


    //     if (strncmp(command, "ON", 2) == 0)
    //     {
    //         ret = verifyPassword(parameter, monitor.password, salt);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error verifying password\n");
    //             kfree(buffer);
    //             //printk("ret: %zd\n", ret);
    //             return ret;
    //         }
    //         printk(KERN_INFO "Setting monitor ON\n");
    //         setMonitorON();
    //         ret = 1;
    //     }
    //     else if (strncmp(command, "OFF", 3) == 0)
    //     {
    //         ret = verifyPassword(parameter, monitor.password, salt);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error verifying password\n");
    //             kfree(buffer);
    //             return ret;
    //         }
    //         printk(KERN_INFO "Setting monitor OFF\n");
    //         setMonitorOFF();
    //         ret = 1;
    //     }
    //     else if (strncmp(command, "REC_ON", 6) == 0)
    //     {
    //         ret = verifyPassword(parameter, monitor.password, salt);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error verifying password\n");
    //             kfree(buffer);
    //             return ret;
    //         }
    //         printk(KERN_INFO "Setting monitor REC_ON\n");
    //         setMonitorREC_ON();
    //         ret = 1;
    //     }
    //     else if (strncmp(command, "REC_OFF", 7) == 0)
    //     {
    //         ret = verifyPassword(parameter, monitor.password, salt);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error verifying password\n");
    //             kfree(buffer);
    //             return ret;
    //         }
    //         printk(KERN_INFO "Setting monitor REC_OFF\n");
    //         setMonitorREC_OFF();
    //         ret = 1;
    //     }
    //     else if (strncmp(command, "CHGPASS", 7) == 0)
    //     {
    //         ret = verifyPassword(parameter, monitor.password, salt);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error verifying password\n");
    //             kfree(buffer);
    //             return ret;
    //         }
    //         if (additional_param)
    //         {
    //             ret = changePassword(additional_param);
    //             if (ret != 0)
    //             {
    //                 printk(KERN_ERR "Error changing password\n");
    //                 kfree(buffer);
    //                 return ret;
    //             }
    //         }
    //         else
    //         {
    //             printk(KERN_ERR "Missing new password\n");
    //             ret = -EINVAL;
    //         }
    //         ret = 1;
    //     }
    //     else if (strncmp(command, "INSERT", 6) == 0)
    //     {
    //         ret = verifyPassword(parameter, monitor.password, salt);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error verifying password\n");
    //             kfree(buffer);
    //             return ret;
    //         }
    //         ret = add_protected_path(additional_param);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error inserting path\n");
    //             kfree(buffer);
    //             return ret;
    //         }
    //         ret = 1;
    //     }
    //     else if (strncmp(command, "REMOVE", 6) == 0)
    //     {
    //         ret = verifyPassword(parameter, monitor.password, salt);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error verifying password\n");
    //             kfree(buffer);
    //             return ret;
    //         }
    //         ret = delete_protected_path(additional_param);
    //         if (ret != 0)
    //         {
    //             printk(KERN_ERR "Error removing path\n");
    //             kfree(buffer);
    //             return ret;
    //         }
    //         ret = 1;
    //     }
    //     else
    //     {
    //         printk(KERN_ERR "Unknown command\n");
    //         ret = -EINVAL;
    //     }
    }
    else
    {
        printk(KERN_ERR "Invalid input format\n");
        ret = -EINVAL;
    }

    kfree(buffer);
    return ret;
}

// File operations for the device
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .write = ref_write,
    .open = ref_open,
};

static int __init monitor_init(void)
{

    int ret;
    char hash[PASS_LEN + 1];
    unsigned char salt[SALT_LENGTH];

    printk(KERN_INFO "Monitor module loaded\n");

    // Registering the device in the kernel. the call return the major number assigned to the device
    // we do not pass the minor number because the kernel doesn't care about it. It's only the driver that use it
    // if we pass "0" as the first parameter, the kernel will assign a major number dynamically and return it
    Major = register_chrdev(0, DEVICE_NAME, &fops);
    if (Major < 0)
    {
        printk(KERN_ALERT "Registering char device failed with %d\n", Major);
        return Major;
    }

    // Creating the device class
    device_class = class_create(THIS_MODULE, DEVICE_NAME);
    if (IS_ERR(device_class))
    {
        unregister_chrdev(Major, DEVICE_NAME);
        printk(KERN_INFO "Class creation failed\n");
        return PTR_ERR(device_class);
    }

    // Creating the device
    device = device_create(device_class, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(device))
    {
        class_destroy(device_class);
        unregister_chrdev(Major, DEVICE_NAME);
        printk(KERN_INFO "Device creation failed\n");
        return PTR_ERR(device);
    }

    // printk(KERN_INFO "Major number %d\n", Major);

    // Initializing the monitor
    ret = hash_password("default", salt, hash);
    if (ret != 0)
    {
        printk(KERN_ERR "Error hashing password\n");
        return -1;
    }

    spin_lock(&monitor.lock);
    monitor.mode = 0;
    strncpy(monitor.password, hash, PASS_LEN);
    spin_unlock(&monitor.lock);

    // Initialize the kprobe structures
    // we define the pre_handler function that will be called before the original function
    // we define the symbol_name that is the name of the function we want to monitor
    kp_filp_open.pre_handler = monitor_filp_open;
    kp_filp_open.symbol_name = "do_filp_open";

    kp_rmdir.pre_handler = monitor_rmdir;
    kp_rmdir.symbol_name = "do_rmdir";

    kp_mkdir_at.pre_handler = monitor_mkdirat;
    kp_mkdir_at.symbol_name = "do_mkdirat";

    kp_unlinkat.pre_handler = monitor_unlinkat;
    kp_unlinkat.symbol_name = "do_unlinkat";

    if (register_kprobe(&kp_filp_open) < 0)
    {
        printk(KERN_INFO "Failed to register kprobe filp_open\n");
        return -1;
    }
    if (register_kprobe(&kp_rmdir) < 0)
    {
        printk(KERN_INFO "Failed to register kprobe rmdir\n");
        return -1;
    }
    if (register_kprobe(&kp_mkdir_at) < 0)
    {
        printk(KERN_INFO "Failed to register kprobe mkdirat\n");
        return -1;
    }
    if (register_kprobe(&kp_unlinkat) < 0)
    {
        printk(KERN_INFO "Failed to register kprobe unlinkat\n");
        return -1;
    }

    // Disable the kprobes at the beginning, them will be enabled when the monitor mode change
    disable_kprobe(&kp_filp_open);
    disable_kprobe(&kp_rmdir);
    disable_kprobe(&kp_mkdir_at);
    disable_kprobe(&kp_unlinkat);

    printk(KERN_INFO "Kprobe filp_open registered and disabled successfully\n");
    printk(KERN_INFO "Kprobe rmdir registered and disabled successfully\n");
    printk(KERN_INFO "Kprobe mkdirat registered and disabled successfully\n");
    printk(KERN_INFO "Kprobe unlinkat registered and disabled successfully\n");

    // Initialize workqueue
    log_wq = create_workqueue("log_wq");
    if (!log_wq)
    {
        printk(KERN_ERR "Failed to create workqueue\n");
        return -ENOMEM;
    }

    return 0;
}

static void __exit monitor_exit(void)
{

    // Flush and destroy the workqueue
    flush_workqueue(log_wq);
    destroy_workqueue(log_wq);

    printk(KERN_INFO "Monitor module unloaded\n");

    // Removing the device
    device_destroy(device_class, MKDEV(Major, 0));
    class_unregister(device_class);
    class_destroy(device_class);
    unregister_chrdev(Major, DEVICE_NAME);

    unregister_kprobe(&kp_filp_open);
    unregister_kprobe(&kp_rmdir);
    unregister_kprobe(&kp_mkdir_at);
    unregister_kprobe(&kp_unlinkat);

    printk(KERN_INFO "Kprobe filp_open unregistered\n");
    printk(KERN_INFO "Kprobe rmdir unregistered\n");
    printk(KERN_INFO "Kprobe mkdirat unregistered\n");
    printk(KERN_INFO "Kprobe unlinkat unregistered\n");
}

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Di Totto");
MODULE_DESCRIPTION("Reference Monitor");