/*************************************************************************
	> File Name: stdcmp.c
	> Author: zeng123456
	> Mail: zeng2010203921@163.com 
	> Created Time: 2016年04月28日 星期四 10时35分24秒
 ************************************************************************/

#include<stdio.h>
#include<stdlib.h>
int str_cmp(char *str1,char *str2)
{
	int i=0;
	while(*(str1+i)==*(str2+i))
	{
		if(*(str1+i)=='\0')			//if(*(str1+i++)=='\0')包含i自加1,首先参与运算，再完成自加１
			return 0;
		else
			i++;
	}
	return (*(str1+i)-*(str2+i));
}
int main(void)
{
	char s1[20]="shis is hit";
	char s2[20]="this is hello";
	char *p1,*p2;
	p1=s1;
	p2=s2;
	int m=str_cmp(p1,p2);
	printf("比较值是:%d\n",m);
	return 0;
}
