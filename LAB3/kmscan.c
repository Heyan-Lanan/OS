#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/err.h>

#include <linux/types.h>
#include <linux/freezer.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/signal.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/rmap.h>
typedef typeof(follow_page)* my_follow_page;
typedef typeof(page_referenced)* my_page_referenced;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OS2021");
MODULE_DESCRIPTION("SYSFS_TEST!");
MODULE_VERSION("1.0");



//sysfs
#define SYSFS_TEST_RUN_STOP 0
#define SYSFS_TEST_RUN_START 1

// /sys/kerbel/mm/sysfs_test/pid
static unsigned int pid = 0;
// /sys/kerbel/mm/sysfs_test/func
static unsigned int sysfs_test_func = 0;
//  /sys/kernel/mm/sysfs_test/sysfs_test_run
static unsigned int sysfs_test_run = SYSFS_TEST_RUN_STOP;
//  /sys/kernel/mm/sysfs_test/sleep_millisecs
static unsigned int sysfs_test_thread_sleep_millisecs = 5000;

struct proc_ops test_ops;
static struct proc_dir_entry* proc_test=NULL;
static int count; 
static int count1; 
static int count2; 
static int count3; 
static int count4; 
static struct vm_area_struct* vma=NULL;
static struct vm_area_struct* firstvma=NULL;
static struct task_struct* sysfs_test_thread=NULL;
static struct task_struct* task=NULL;
static DECLARE_WAIT_QUEUE_HEAD(sysfs_test_thread_wait);

static DEFINE_MUTEX(sysfs_test_thread_mutex);


static int sysfs_testd_should_run(void)
{
    return (sysfs_test_run & SYSFS_TEST_RUN_START);
}

static void func_1(void)
{
    count=0;
    task = pid_task(find_vpid(pid),PIDTYPE_PID);
    if(!task)
	return;
    vma = task->mm->mmap;
    count++;
    vma = vma->vm_next;
    while(vma!=task->mm->mmap){
	count++;
	vma = vma->vm_next;
        if(!vma)
           break;
    }
}

static void func_2(void)
{
	my_follow_page mfollow_page;
	my_page_referenced mpage_referenced;
	mfollow_page = (my_follow_page)0xffffffffb2e73af0  ;
	mpage_referenced = (my_page_referenced)0xffffffffb2e8e030 ;
        count1=count2=count3=count4=0;
        task = pid_task(find_vpid(pid),PIDTYPE_PID);
        if(!task)
	    return;
        vma = task->mm->mmap;
        //unsigned int foll_flags=0x04;
        unsigned long addr;
        while(vma){
	addr=vma->vm_start;
        if(!addr)
	    break;
        //printk("addr=%ld\n",addr);
	struct page* page=NULL;
	while(addr!=vma->vm_end){
	     page=mfollow_page(vma,addr,FOLL_GET);
	     if(!page){
                  addr+=PAGE_SIZE;
                  continue;
             }
             //printk("page: %p\n",page);
	     count1++;
	     if(mpage_referenced(page, 0, page->mem_cgroup, &vma->vm_flags))
		  count2++;
	     if(PageAnon(page)){
		  count3++;
		  if(mpage_referenced(page, 0, page->mem_cgroup, &vma->vm_flags))
		  	count4++; 
	     }
	     addr+=PAGE_SIZE;
             //printk("addr=%ld\n",addr);
	}
	vma = vma->vm_next;
        //printk("next vma\n\n");
    }

}

static void timer_func1(void){
    func_1();
    printk(KERN_ALERT"Test:func1 VMA count = %d\n", count);
    
    
    return;
}
static void timer_func2(void){
    func_2();
    printk(KERN_ALERT"Test func 2\n");
    printk(KERN_ALERT"file count= %d\n", count1);
    printk(KERN_ALERT"active_file count = %d\n", count2);
    printk(KERN_ALERT"anon count =  %d\n", count3);
    printk(KERN_ALERT"active_anon count = %d\n", count4);
    
    
    return;
}

static int test_show(struct seq_file* m, void* v)
{
    pid_t* pid_n = (pid_t*)m->private;
    if (pid_n != NULL)
    {
        seq_printf(m, "%d\n", *pid_n);
    }
    return 0;
}

static int test_open(struct inode* inode, struct file* file)
{
    return single_open(file, test_show, PDE_DATA(inode));
}

struct proc_ops test_ops = {
    .proc_open = test_open,
    .proc_read = seq_read,
    .proc_release = single_release,
};

static void int2string(int x, char* c) {
    int temp = x, len=0;
    int i;
    
    while (temp >= 10) {
        len++;
        temp = temp / 10;
        
    }
    temp = x;
    for (i = len; i >= 0; i--) {
        c[i] = 48 + temp % 10;
        temp = temp / 10;
    }
    c[len+1] = '\0';
    for(i=len+4;i>=4;i--)
        c[i]=c[i-4];
    c[0]='p';
    c[1]='i';
    c[2]='d';
    c[3]='_';
    return;
}

static void sysfs_test_to_do(void)
{
    char s[20];
    int2string(pid,s);
    printk("s=%s\n",s);
    if(proc_test != NULL)
    {
        proc_remove(proc_test);
        // printk(KERN_ALERT"remove proc_pid successfully\n");
    }
    proc_test = proc_mkdir(s, NULL);
    if (proc_test == NULL) {
        printk("%d proc create %d failed\n",sysfs_test_func , pid);
        return -EINVAL;
    }
    
    if (sysfs_test_func == 1){
        timer_func1();
        proc_create_data("vma_count", 0664, proc_test, &test_ops, &count);
        return;
    }
    
    else if (sysfs_test_func == 2){
        timer_func2();
        proc_create_data("file", 0664, proc_test, &test_ops, &count1);
    proc_create_data("active_file", 0664, proc_test, &test_ops, &count2);
    proc_create_data("anon", 0664, proc_test, &test_ops, &count3);
    proc_create_data("active_anon", 0664, proc_test, &test_ops, &count4);
        return;
    } 
}

static int sysfs_testd_thread(void* nothing)
{
    set_freezable();
    set_user_nice(current, 5);
    while (!kthread_should_stop())
    {
        mutex_lock(&sysfs_test_thread_mutex);
        if (sysfs_testd_should_run())
            sysfs_test_to_do();
        mutex_unlock(&sysfs_test_thread_mutex);
        try_to_freeze();
        if (sysfs_testd_should_run())
        {
            schedule_timeout_interruptible(
                msecs_to_jiffies(sysfs_test_thread_sleep_millisecs));
        }
        else
        {
            wait_event_freezable(sysfs_test_thread_wait,
                sysfs_testd_should_run() || kthread_should_stop());
        }
    }
    return 0;
}


#ifdef CONFIG_SYSFS

/*
 * This all compiles without CONFIG_SYSFS, but is a waste of space.
 */

#define SYSFS_TEST_ATTR_RO(_name) \
        static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

#define SYSFS_TEST_ATTR(_name)                         \
        static struct kobj_attribute _name##_attr = \
                __ATTR(_name, 0644, _name##_show, _name##_store)

static ssize_t sleep_millisecs_show(struct kobject* kobj,
    struct kobj_attribute* attr, char* buf)
{
    return sprintf(buf, "%u\n", sysfs_test_thread_sleep_millisecs);
}

static ssize_t sleep_millisecs_store(struct kobject* kobj,
    struct kobj_attribute* attr,
    const char* buf, size_t count)
{
    unsigned long msecs;
    int err;

    err = kstrtoul(buf, 10, &msecs);
    if (err || msecs > UINT_MAX)
        return -EINVAL;

    sysfs_test_thread_sleep_millisecs = msecs;

    return count;
}
SYSFS_TEST_ATTR(sleep_millisecs);

static ssize_t pid_show(struct kobject* kobj,
    struct kobj_attribute* attr, char* buf)
{
    return sprintf(buf, "%u\n", pid);
}

static ssize_t pid_store(struct kobject* kobj,
    struct kobj_attribute* attr,
    const char* buf, size_t count)
{
    unsigned long tmp;
    int err;

    err = kstrtoul(buf, 10, &tmp);
    if (err || tmp > UINT_MAX)
        return -EINVAL;

    pid = tmp;

    return count;
}
SYSFS_TEST_ATTR(pid);


static ssize_t func_show(struct kobject* kobj,
    struct kobj_attribute* attr, char* buf)
{
    return sprintf(buf, "%u\n", sysfs_test_func);
}

static ssize_t func_store(struct kobject* kobj,
    struct kobj_attribute* attr,
    const char* buf, size_t count)
{
    unsigned long tmp;
    int err;

    err = kstrtoul(buf, 10, &tmp);
    if (err || tmp > UINT_MAX)
        return -EINVAL;

    sysfs_test_func = tmp;

    return count;
}
SYSFS_TEST_ATTR(func);

static ssize_t run_show(struct kobject* kobj, struct kobj_attribute* attr,
    char* buf)
{
    return sprintf(buf, "%u\n", sysfs_test_run);
}

static ssize_t run_store(struct kobject* kobj, struct kobj_attribute* attr,
    const char* buf, size_t count)
{
    int err;
    unsigned long flags;
    err = kstrtoul(buf, 10, &flags);
    if (err || flags > UINT_MAX)
        return -EINVAL;
    if (flags > SYSFS_TEST_RUN_START)
        return -EINVAL;
    mutex_lock(&sysfs_test_thread_mutex);
    if (sysfs_test_run != flags)
    {
        sysfs_test_run = flags;
    }
    mutex_unlock(&sysfs_test_thread_mutex);

    if (flags & SYSFS_TEST_RUN_START)
        wake_up_interruptible(&sysfs_test_thread_wait);
    return count;
}
SYSFS_TEST_ATTR(run);



static struct attribute* sysfs_test_attrs[] = {
    // 扫描进程的扫描间隔 默认为20秒 
    &sleep_millisecs_attr.attr,
    &pid_attr.attr,
    &func_attr.attr,
    &run_attr.attr,
    NULL,
};


static struct attribute_group sysfs_test_attr_group = {
    .attrs = sysfs_test_attrs,
    .name = "sysfs_test",
};
#endif /* CONFIG_SYSFS */


static int sysfs_test_init(void)
{
    int err;
    sysfs_test_thread = kthread_run(sysfs_testd_thread, NULL, "sysfs_test");
    if (IS_ERR(sysfs_test_thread))
    {
        pr_err("sysfs_test: creating kthread failed\n");
        err = PTR_ERR(sysfs_test_thread);
        goto out;
    }

#ifdef CONFIG_SYSFS
    err = sysfs_create_group(mm_kobj, &sysfs_test_attr_group);
    if (err)
    {
        pr_err("sysfs_test: register sysfs failed\n");
        kthread_stop(sysfs_test_thread);
        goto out;
    }
#else
    sysfs_test_run = KSCAN_RUN_STOP;
#endif  /* CONFIG_SYSFS */

out:
    return err;
}

static void sysfs_test_exit(void)
{
    proc_remove(proc_test);
    if (sysfs_test_thread)
    {
        kthread_stop(sysfs_test_thread);
        sysfs_test_thread = NULL;
    }

#ifdef CONFIG_SYSFS

    sysfs_remove_group(mm_kobj, &sysfs_test_attr_group);

#endif
    
    printk("sysfs_test exit success!\n");
}

/* --- 随内核启动  ---  */
// subsys_initcall(kscan_init);
module_init(sysfs_test_init);
module_exit(sysfs_test_exit);

