// 必备头函数
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/time.h>

// 该模块的LICENSE
MODULE_LICENSE("GPL");
// 该模块的作者
MODULE_AUTHOR("ZSH");
// 该模块的说明
MODULE_DESCRIPTION("This is ZSH's lab3!/n");

// 该模块需要传递的参数
static int func = -1;
static int pid = -1;
static struct timer_list zsh_timer;
module_param(func, int, 0644);
module_param(pid, int, 0644);

void timer_function(struct timer_list* t){
    int counter = 0;
    struct task_struct *temp;
    for_each_process(temp){
        if(temp->mm==NULL)counter++;
    }
    printk(KERN_ALERT"The number of kernel process is %d",counter);
    mod_timer(t, jiffies + 5*HZ);
    return;
}

// 初始化入口
// 模块安装时执行
// 这里的__init 同样是宏定义，主要的目的在于
// 告诉内核，加载该模块之后，可以回收init.text的区间
static int __init zsh_init(void)
{	
    int pid1;
    int state;
    char comm[16];
    struct task_struct * task;
    printk(KERN_ALERT" module zsh init!\n");
    if(func==1){
        printk(KERN_ALERT"func=1\nPID     STATE   COMMAND");
        for_each_process(task){
            if(task->mm==NULL){
                 pid1 = task->pid;
                 state = task->state;
                 strcpy(comm,task->comm);
                 printk(KERN_ALERT"%-8d%-8d[%s]\n",pid1,state,comm);
            }
        }
    }
    else if(func==2){//Every 5s get the total number of processes
        printk(KERN_ALERT"func=2\n");
        timer_setup(&zsh_timer, timer_function, 0);
        zsh_timer.expires = jiffies + (HZ*5);//5s
        add_timer(&zsh_timer);
    }
    else if(func==3){//process information
        printk(KERN_ALERT"func=3\n");
        printk(KERN_ALERT"pid receive successfully: %d\n",pid);
	struct pid* kpid = find_get_pid(pid);
	
        task = pid_task(kpid,PIDTYPE_PID);
	        printk(KERN_ALERT"He is: pid=%d,state=%ld,comm=%s\n",pid,task->state,task->comm);
	        printk(KERN_ALERT"His father is: pid=%d,state=%ld,comm=%s\n",task->parent->pid,task->parent->state,task->parent->comm);
	struct task_struct *child,*sibling,*thread;
        struct list_head *list;
	list_for_each(list,&task->children){
		child=list_entry(list,struct task_struct,sibling);
        	printk(KERN_ALERT"His child is: pid=%d,state=%ld,comm=%s\n",child->pid,child->state,child->comm);
        }
	list_for_each(list,&task->parent->children){
		sibling=list_entry(list,struct task_struct,sibling);
        	printk(KERN_ALERT"His sibling is: pid=%d,state=%ld,comm=%s\n",sibling->pid,sibling->state,sibling->comm);
        }
	thread=task->group_leader;
	while_each_thread(task->group_leader,thread){
		
		printk(KERN_ALERT"His thread is: pid=%d,state=%ld,comm=%s\n",thread->pid,thread->state,thread->comm);
	}
        
       
    }
    else{
        printk(KERN_ALERT"No more functions!\n");
    }
}

// 模块卸载时执行
// 同上
static void __exit zsh_exit(void)
{   
    del_timer_sync(&zsh_timer);
    printk(KERN_ALERT" module zsh exit!\n");
}

// 模块初始化宏，用于加载该模块
module_init(zsh_init);
// 模块卸载宏，用于卸载该模块
module_exit(zsh_exit);

