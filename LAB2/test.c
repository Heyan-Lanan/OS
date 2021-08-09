#include<linux/unistd.h>
#include<sys/syscall.h> 
#include<stdio.h>
int main(void) { 
	int result,i; 
	int pid[100];
	char comm[100][16];
	syscall(333, &result,pid,comm); 
	printf("pid   command\n");
	for(i=0;i<result;i++){	
		printf("%d   %s\n",pid[i],comm[i]);  
	}
	printf("process number is %d\n",result);
	return 0;
}
