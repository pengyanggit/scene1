/************************************************************************
	> File Name: strcpy.c
	> Author: zeng123456
	> Mail: zeng2010203921@163.com 
	> Created Time: 2016年04月28日 星期四 09时46分24秒
 ************************************************************************/

#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

char *str_cpy(char *dest,char *source)
{
	assert(dest!=source);
	assert(dest!=NULL && source!= NULL);
	char *head_dest=dest;
	while((*dest++=*source++)!='\0');
	return head_dest;
}

int main(void)
{
	char str_source[]="This is good";
	char *p1=str_source;
	char *p2=(char *)malloc(sizeof(char)*strlen(str_source));
	p2=str_cpy(p2,p1);
	printf("%s\n",p2);
	return 0;
}
