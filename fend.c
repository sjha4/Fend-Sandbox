#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include<sys/reg.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <glob.h>
#include<limits.h>
int insys = 0;
FILE * config;
int PermRefused = -1;
void CreateFiles()
{
int fdFile = creat("temp.txt",0066);
int fdDir = mkdir("adir",0066);
//printf("%d and %d\n",fdFile,fdDir);
}
void removeFiles()
{
chmod("temp.txt",0777);
unlink("temp.txt");
chmod("adir",0777);
rmdir("adir");
}

/* This structure is defined in the getPermssions header to store separate lines of perm and glob in config file
struct perm{
char* permFlag;
char * matchingFileNames;
};
*/
const int long_size = sizeof(long);
void getdata(pid_t child, long addr,char *str)
		{   
		    int len = 255;	
		    char *laddr;
		    int i, j;
		    union u {
			    long val;
			    char chars[long_size];
		    }data;
		    i = 0;
		    j = len / long_size;
		    laddr = str;
		    while(i <= j) {
			data.val = ptrace(PTRACE_PEEKDATA,
				          child, addr + i * 8,
				          NULL);
			memcpy(laddr, data.chars, long_size);
			++i;
			laddr += long_size;
		    }
		    j = len % long_size;
		    if(j != 0) {
			data.val = ptrace(PTRACE_PEEKDATA,
				          child, addr + i * 8,
				          NULL);
			memcpy(laddr, data.chars, j);
		    }
		    str[len] = '\0';
		    //puts("In Get Data");
		    //puts(str);
		    //puts("Leaving get Data");
		}

		void putdata(pid_t child, long addr, char *str)
		{   
						
			//puts(str);			
			PermRefused =1;			
			//puts("In Put Data");
			int len = strlen(str);
			char* laddr;
			
			int i, j;
			union u 
			{
			    long unsigned val;
			    char chars1[long_size];
			}data1;
			i = 0;
			j = len/sizeof(long);j++;
			laddr = str;
			int itr =0;
			//puts(laddr);
			while(i<j) {
			memcpy(data1.chars1, laddr, sizeof(long));
			ptrace(PTRACE_POKEDATA, child,
			       addr + i * 8, data1.val);
			i++;
			laddr += long_size;
			}
			j = len % long_size;
			if(j != 0) {
			memcpy(data1.chars1, laddr, j);
			ptrace(PTRACE_POKEDATA, child,addr + i * 8, data1.val);
			}
			//puts("In putdata");			
			//puts(str);
			
}


struct perm{
char* permFlag;
char * matchingFileNames;
};

void trim(char *str)
{
    char *ptr = str;
    while(*ptr == ' ' || *ptr == '\t') ++ptr;

    char *end = ptr;
    while(*end) ++end;
    
    if(end > ptr)
    {	end--;
        for(; end >= ptr && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n');--end);
    }

    memmove(str, ptr, end-ptr+1);
    str[end-ptr+1] = 0;
} 
struct perm* permissionMatrix;
struct perm* getConfigPermissions(FILE* fp1)
{	
	permissionMatrix = (struct perm *)malloc(255*1000*sizeof(char));	
	FILE *fp = fp1;	
	glob_t returnedGlob;	
	char str[255][255];	
	globfree(&returnedGlob);
	int i=0,j=0;
	char lines[255][255];
	int lineNo=0;
	//if((fgets(lines[lineNo],1000,fp)==NULL)) printf("Null returned for fgets from Config File");
	//if you use **lines allocate size for all lines with the loop or else you can allocate size inside loop and then read.
		while((fgets(lines[lineNo],1000,fp)!=NULL) && (lineNo<1000))
		{
			//printf("[getConfigPermissions]: %d line of file gives %s\n",lineNo,lines[lineNo]);				
			sprintf(str[lineNo],"%s\n",lines[lineNo]);
			lineNo++;
		}
		while(i<lineNo)
		{	
			//printf("[get_Perm]:Inside 2nd while for %s\n",pathname);
			char *perm = malloc(3*sizeof(char));
			char *pathGlob = malloc(1000*sizeof(char));
			memcpy(perm,str[i],3);
			memcpy(pathGlob,str[i]+4,1000);
			trim(pathGlob);
			permissionMatrix[i].permFlag = malloc(3 * sizeof(char));
			permissionMatrix[i].matchingFileNames = malloc(1000 * sizeof(char));
			memcpy(permissionMatrix[i].permFlag,perm,3);
			memcpy(permissionMatrix[i].matchingFileNames,pathGlob,1000);
			//printf("[getConfigPermissions 2]Perm:%s and Path:%s from 1st loop string %s\n",perm,pathGlob,str[i]);
			i++;
			free(perm);
			free(pathGlob);
			
		}

	//int glob_Result = glob(pathname,GLOB_TILDE,NULL,&returnedGlob);
	
return permissionMatrix;





}

struct sandbox
{
	pid_t child;
	const char *progname;
	struct perm * configMatrix;
	int lenPerm;
};

//char *restrictedFilePath;



	/*

		Check Permissions function: 
		Parameters: 
		1) Permission Glob from Config File
		2) Requested Permission:
		0: READ 1: WRITE 2: READ/WRITE 3: EXECUTE 4: (Write and execute) MKDIR

		Return Value:
		0 : Not Allowed!
		1: Allowed!
		
		No reference from anywhere!

	*/
	int checkPermissions(char *permConfig, int permReq)
	{
		//printf("permConfig: Read: %c Write: %c Execute: %c and permission requested: %d\n",permConfig[0],permConfig[1],permConfig[2],permReq);
		if(!strcmp(permConfig,"111")) return 1; //All permissions
		else if(!strcmp(permConfig,"000")) return 0; // No permissions
		else if(permConfig[0]=='1' && permReq ==0) return 1; // Read Permission
		else if(permConfig[1]=='1' && permReq ==1) return 1; //Write Permission
		else if(permConfig[0]=='1' && permConfig[1]=='1' && permReq ==2) return 1; // Read & Write permissions
		else if(permConfig[2]=='1' && permReq ==3) return 1; // Execute Permission
		else if(permConfig[2]=='1' && permConfig[1]=='1' && permReq == 4) return 1; //Write and execute permission
		else if(permConfig[2]=='1' && permConfig[0]=='1' && permReq == 5) return 1; //Read and Execute permission
		else return 0;
	}

	char* getParent(char* path)
	{
		char* path1 = malloc(1000* sizeof(char));
		int i=strlen(path)-1;
		while(i>0)
		{
			if(path[i]=='/')
			{
				memcpy(path1, path, i);
				path1[i+1]='\0';
				break;
			}
			else i--;
			//
			
		}
		//printf("\nGetting parent path for %s : %s \n",path,path1);		
		return path1;



	}


	void sandb_kill(struct sandbox *sandb)
	{ 
		kill(sandb->child, SIGKILL);
		wait(NULL);
		if(PermRefused==1) fopen("temp.txt", "r+");
		exit;
	}

	void sandb_handle_syscall(struct sandbox *sandb)
	{	

		int i;
		struct user_regs_struct regs;
		int ins;
		char *PathNameOpen;
		char *AbPathNameOpen;

		if(ptrace(PTRACE_GETREGS, sandb->child, NULL,&regs) < 0)
			err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");

		if(regs.orig_rax == -1) 
		{
			//printf("[SANDBOX] Segfault ?! KILLING !!!\n");
		} 
/* 


THIS SECTION IS FOR SYS_OPEN


*/
		else if(regs.orig_rax == __NR_open) 
		{
			if(insys==0)
			{	
				insys=1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				
			
				int PermValue = (int)ptrace(PTRACE_PEEKUSER,sandb->child,8 * RSI,NULL);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//puts(AbPathNameOpen);
				int i = 0;
				int lastMatch = -1;

				//puts(AbPathNameOpen);				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match Open: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{

					int openPermissionRequested;
					if((PermValue & O_RDWR) == O_RDWR)
					{	
						openPermissionRequested = 2;
					}
					else if(((PermValue & O_WRONLY) == O_WRONLY)||((PermValue & O_CREAT) == O_CREAT))
					{
						openPermissionRequested = 1;
					}
					else // Read by default since WR and RDWR are not set.
					{
						openPermissionRequested = 0;
					}
					//printf("\nPermission %d requested for Path : %s:\n",openPermissionRequested,PathNameOpen);
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
					if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{	
						//puts("Not allowed!");
						int sizeOfPath = strlen(PathNameOpen);
						if((PermValue&O_DIRECTORY)==O_DIRECTORY) 
						{
							//puts("dir");
							
							putdata(sandb->child,Pathvalue,"adir");
						}						
						else 
						{
							//puts("File");	
							//CreateFiles();						
							putdata(sandb->child,(ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL)),"temp.txt");
						}
						//puts("1");
						//getdata(sandb->child,Pathvalue,PathNameOpen);						
						//putdata(sandb->child,Pathvalue,DirName,long_size);
						//puts(strerror(13));
						//kill(sandb->child,SIGKILL);
						//exit(13); 	
					}
				
				} //free(PathNameOpen);//free(AbPathNameOpen);

			} //end of if insys=0
			else
			{
				insys = 0; 
				//puts("File Exit");
				//Returning from Open System Call;
				////printf("End of insys exit for read\n");

			}
			////printf("End of OPEN");
		}//end of regs.orig_rax == __NR_open

		else if(regs.orig_rax == __NR_openat) 
		{
			if(insys==0)
			{	
				insys=1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);
				
			
				int PermValue = (int)ptrace(PTRACE_PEEKUSER,sandb->child,8 * RDX,NULL);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				/*if(!strcmp(PathNameOpen,"."))
				{
					char cwd[1024];
					if (getcwd(cwd, sizeof(cwd)) != NULL)
					PathNameOpen = cwd;
				}
				*/
				
				////printf("PathNameOpen: %s and length = %lu\n", PathNameOpen,strlen(PathNameOpen));
				////printf("\nGet Parent:%s\n",getParent(PathNameOpen));
				
				////printf("Permission Mask passed: %d\n\n",PermValue);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						////printf("\nLast Match Open: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{

					int openPermissionRequested;
					if((PermValue & O_RDWR) == O_RDWR)
					{	
						openPermissionRequested = 2;
					}
					else if(((PermValue & O_WRONLY) == O_WRONLY)||((PermValue & O_CREAT) == O_CREAT))
					{
						openPermissionRequested = 1;
					}
					else // Read by default since WR and RDWR are not set.
					{
						openPermissionRequested = 0;
					}
			
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
					if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						int sizeOfPath = strlen(PathNameOpen);
						if((PermValue&O_DIRECTORY)==O_DIRECTORY) 
						{
							//puts("dir");
							putdata(sandb->child,Pathvalue,"adir");
						}						
						else 
						{
							//puts("File");							
							putdata(sandb->child,Pathvalue,"temp.txt");
						}	
					}
				
				} free(PathNameOpen);free(AbPathNameOpen);////printf("End of insys entry for read\n");

			} //end of if insys=0
			else
			{
				insys = 0; 
				//Returning from Open System Call;
				////printf("End of insys exit for read\n");

			}
			////printf("End of OPEN");
		}//end of regs.orig_rax == __NR_open

/* 


THIS SECTION IS FOR SYS_EXECVE


*/
		else if(regs.orig_rax == __NR_execve) 
		{
			////printf("Inside execve:execve No: %d and insys:%d",__NR_execve,insys); 
			if(insys==0)//entering Execve call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside execve: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				
				//printf("PathNameOpen: %s\n", PathNameOpen);
				
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=3;					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						puts(strerror(13));kill(sandb->child,SIGKILL);
						exit(13); 		
					}
				}

			}free(PathNameOpen);free(AbPathNameOpen);//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for read\n");
			}
		}//end of execute
		
/* 


THIS SECTION IS FOR SYS_MKDIR 
Doubt: Do we handle permission at parent directory?


*/


		else if(regs.orig_rax == __NR_mkdir)
		{
			////printf("Inside mkdir:mkdir No: %d and insys:%d",__NR_mkdir,insys); 
			if(insys==0)//entering __NR_mkdir call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside mkdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				//PathNameOpen=getParent(PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=4;					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a");
					}
				}
			free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}

			






		}
/* 


THIS SECTION IS FOR SYS_MKDIRAT 
Doubt: Do we handle permission at parent directory?


*/


		else if(regs.orig_rax == __NR_mkdirat)
		{
			////printf("Inside mkdir:mkdir No: %d and insys:%d",__NR_mkdir,insys); 
			if(insys==0)//entering __NR_mkdir call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);
				//printf("Inside mkdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				//PathNameOpen=getParent(PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=4;					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a");	
					}
				}
			free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}

			






		}

/* 


THIS SECTION IS FOR rmdir


*/
		else if(regs.orig_rax == __NR_rmdir)
		{
			////printf("Inside mkdir:mkdir No: %d and insys:%d",__NR_mkdir,insys); 
			if(insys==0)//entering __NR_mkdir call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside mkdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				//PathNameOpen=getParent(PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=4;					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a");	
					}
				}
				free(PathNameOpen);free(AbPathNameOpen);
			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}
		}

/* 


THIS SECTION IS FOR SYS_stat 
Permission defined at parent directory?




		else if(regs.orig_rax == __NR_stat || regs.orig_rax == __NR_lstat)
		{
			////printf("Inside stat:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside stat: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));					
				getdata(sandb->child,Pathvalue,PathNameOpen);PathNameOpen=realpath(PathNameOpen,PathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				//PathNameOpen = getParent(PathNameOpen);
					
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,PathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=3;					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						puts(strerror(13));kill(sandb->child,SIGKILL);
						exit(13); 	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}*/
/*
to implement: link,

*/
/* 


THIS SECTION IS FOR SYS_link() 
Permission defined at parent directory for new path.
Also, doesnt matter if oldfile has 000 permission. Link is still created.


*/

		else if(regs.orig_rax == __NR_link  || regs.orig_rax == __NR_linkat)
		{
			////printf("Inside stat:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering link call
			{
				char *PathNameNew = (char *)malloc(255* sizeof(char));	
				char *AbPathNameNew = (char *)malloc(255* sizeof(char));				
				insys = 1;
				long unsigned Pathvalue;
				if(regs.orig_rax == __NR_link)
				Pathvalue= ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				else if(regs.orig_rax == __NR_linkat)
				Pathvalue= ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);
				//printf("Inside stat: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				//PathNameOpen = getParent(PathNameOpen);
				long unsigned NewPathvalue;//= ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);
				if(regs.orig_rax == __NR_link)
				NewPathvalue= ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);
				else if(regs.orig_rax == __NR_linkat)
				NewPathvalue= ptrace(PTRACE_PEEKUSER, sandb->child,8*RCX,NULL);	
							
				getdata(sandb->child,NewPathvalue,PathNameNew);
				realpath(PathNameNew,AbPathNameNew);
				//printf("New PathNameOpen: %s\n", PathNameNew);	
				int i = 0;
				int lastMatch = -1;				
				/*

				This part to check permissions at the Old Path.	No permissions are required at Old path other than Search at parent directory.

								
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=0; 					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						int sizeOfPath = strlen(PathNameOpen);
						putdata(sandb->child,Pathvalue,"temp.txt",sizeOfPath);
						//puts(strerror(13));kill(sandb->child,SIGKILL);
						//exit(13); 
							
					}
				}*/
			
			/*

				This part to check permissions at the New Path.	Write permissions are required at New path directory and also write permission needed.

			*/
				i =0; lastMatch = -1;
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameNew,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else //Matched hence pass Directory write permissions??
				{
					int openPermissionRequested_new=1; // Write permission required on file.					
					int allow_new = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested_new);
				
				if(allow_new)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						int sizeOfPath = strlen(PathNameNew);
						putdata(sandb->child,NewPathvalue,"adir/a");
						//puts(strerror(13));kill(sandb->child,SIGKILL);
						//exit(13); 	
					}
				}
			free(PathNameOpen);free(AbPathNameOpen);free(PathNameNew);free(AbPathNameNew);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}

/*


This part is for truncate


*/

		else if(regs.orig_rax == __NR_truncate)
		{
			////printf("Inside stat:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside Truncate: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=1;					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						int sizeOfPath = strlen(PathNameOpen);
						putdata(sandb->child,Pathvalue,"temp.txt");	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}
/* 

To implement: unlink,creat

*/

		else if(regs.orig_rax == __NR_unlink || regs.orig_rax == __NR_unlinkat)
		{
			////printf("Inside stat:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue;// = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				if(regs.orig_rax == __NR_unlink)
				{	Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);	}
				else if(regs.orig_rax == __NR_unlinkat)
				{	Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);	}
				
				//printf("Inside Truncate: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=4;					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						int sizeOfPath = strlen(PathNameOpen);
						putdata(sandb->child,Pathvalue,"adir/a");	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}


		

/*

This method is for Creat

*/
		else if(regs.orig_rax == __NR_creat)
		{
			////printf("Inside stat:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside Truncate: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=1;					
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						putdata(sandb->child,Pathvalue,"temp.txt");
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}

/* 

This is for chdir --> needs execute at file path.

*/
		else if(regs.orig_rax == __NR_chdir)
		{
			////printf("Inside __NR_chdir:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				//puts("HERE");
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside __NR_chdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=3;	//execute permission on dir				
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a");	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}

/*

This part is for chmod

*/

		else if(regs.orig_rax == __NR_chmod)
		{
			////printf("Inside __NR_chdir:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside __NR_chdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=3;	//execute permission on dir				
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a");	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}


/*

This part is for fchmod

*/

		else if(regs.orig_rax == __NR_fchmodat || regs.orig_rax == __NR_fchownat)
		{
			////printf("Inside __NR_chdir:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);
				//printf("Inside __NR_chdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=3;	//execute permission on dir				
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a");
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}

/* 

This is for chdir --> needs execute at file path.

*/
		else if(regs.orig_rax == __NR_chown || regs.orig_rax == __NR_fchownat)
		{
			////printf("Inside __NR_chdir:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue;
				if (regs.orig_rax == __NR_chown)			
				{Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);}
				else if (regs.orig_rax == __NR_fchownat)
				{Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);}
				//printf("Inside __NR_chdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=3;	//execute permission on dir				
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a");
						//exit(13); 	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}

/*
This part is for mknod -> Write permission needed.
*/
	else if(regs.orig_rax == __NR_mknod)
		{
			////printf("Inside __NR_chdir:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside __NR_chdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=1;	//write permission on dir				
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a"); 	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}

/*
This part is for mknodat -> Write permission needed.
*/
	else if(regs.orig_rax == __NR_mknodat)
		{
			////printf("Inside __NR_chdir:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RSI,NULL);
				//printf("Inside __NR_chdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=1;	//write permission on dir				
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a"); 	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}

else if(regs.orig_rax == __NR_chroot)
		{
			////printf("Inside __NR_chdir:stat No: %d and insys:%d",stat,insys); 
			if(insys==0)//entering stat call
			{
				insys = 1;
				long unsigned Pathvalue = ptrace(PTRACE_PEEKUSER, sandb->child,8*RDI,NULL);
				//printf("Inside __NR_chdir: RDI value: %lu",Pathvalue);
				PathNameOpen = (char *)malloc(255* sizeof(char));
				AbPathNameOpen	= (char *)malloc(255* sizeof(char));				
				getdata(sandb->child,Pathvalue,PathNameOpen);
				realpath(PathNameOpen,AbPathNameOpen);
				//printf("PathNameOpen: %s\n", PathNameOpen);
				int i = 0;
				int lastMatch = -1;				
				for(;i<sandb->lenPerm;i++)
				{						
					if(!(fnmatch(sandb->configMatrix[i].matchingFileNames,AbPathNameOpen,FNM_PATHNAME)))
					{
						lastMatch = i;
						//printf("\nLast Match: %s\n", sandb->configMatrix[i].matchingFileNames);
					
					}
					

				}
				if(lastMatch==-1)
				{
					//No match : Continue
				}
				else
				{
					int openPermissionRequested=3;	//execute permission on dir				
					int allow = checkPermissions(sandb->configMatrix[lastMatch].permFlag,openPermissionRequested);
				
				if(allow)
					{
						//printf("Requested permission allowed!\n");
					}  
					else
					{
						//printf("Requested permission is not allowed!\n");
						
						putdata(sandb->child,Pathvalue,"adir/a");
						//exit(13); 	
					}
				}free(PathNameOpen);free(AbPathNameOpen);

			}//end of insys
			if(insys==1)
			{
				insys = 0;
				////printf("End of insys exit for mkdir\n");
			}








		}

	////printf("End of sys-Handle_Call\n");
	}//end of sandb_handle_syscall

	void sandb_init(struct sandbox *sandb, int argc, char **argv,struct perm * configMatrix1)
	{
		pid_t pid;

		pid = fork();

		if(pid == -1)
			err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

		if(pid == 0)
		{
			
			if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
				err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");

			if(execvp(argv[0], argv) < 0)
				err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");

		}
		else
		{
			sandb->child = pid;
			sandb->progname = argv[0];
			sandb->configMatrix = configMatrix1;
			{
				int i=0;				
				while(i<1000 && sandb->configMatrix[i].permFlag!=NULL)
				{
					////printf("Inside Sandbox Init No: %d Permission : %s and Pattern : %s\n",i,sandb->configMatrix[i].permFlag,sandb->configMatrix[i].matchingFileNames);
					i++;
				}
				sandb->lenPerm = i;
				i=0;
				/*while(i<1000 && configMatrix1[i].permFlag!=NULL)
				{
					////printf("Inside original Init No: %d Permission : %s and Pattern : %s\n",i,configMatrix1[i].permFlag,configMatrix1[i].matchingFileNames);
					i++;
				}*/					
			}
			wait(NULL);
		}
	}

	void sandb_run(struct sandbox *sandb) 
	{
  		int status;

  		if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0)
		{
			if(errno == ESRCH) 
		  	{
				//puts("EACCESS");				
				waitpid(sandb->child, &status, __WALL | WNOHANG);
				sandb_kill(sandb);
			} 
			else
			{
				err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
			}
		}

		wait(&status);
		

		if(WIFEXITED(status))
		{	
			if(PermRefused==1) //puts("Permission Denied");
			removeFiles();			
			exit(EXIT_FAILURE);
		}
		if(WIFSTOPPED(status))
		{
			sandb_handle_syscall(sandb);
			////printf("\nGetting outside sanb_run method\n");
		}
	}


int main(int argc, char **argv)
 {       
	CreateFiles();
	struct perm* Perm;
	struct sandbox sandb;
        char * configFilename = malloc(100*sizeof(char));
	char str[255][255];
	//printf("\nO_RDWR: %d and O_WRONLY: %d and 2113|O_RDWR: %d\n",O_RDWR,O_WRONLY,2113&O_RDWR);
	/*Create a global non accessible file and global non accessible directory */
	
	
	
        if(argc < 2)
        {
                errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
        }
         if(!strcmp(argv[1],"-c"))
        {
                configFilename = argv[2];
                ////printf("Config File Passed is: %s\n", configFilename);

        }
        else
        {
                configFilename = ".fendrc";
        }

        config = fopen(configFilename,"r+");
        if (config  == NULL)
        {
                configFilename = "~/.fendrc";
                config = fopen(configFilename,"r+");

        }
         if(config!=NULL)
        {
                Perm = (struct perm*)malloc(1000*255*sizeof(char)); 
		Perm = getConfigPermissions(config);
		
		/*while(1)
		{
			while(i<255 && Perm[i].permFlag!='\0' )
				{
					//printf("%s permission for %s path glob\n",Perm[i].permFlag,Perm[i].matchingFileNames);
				i++;}	
			break;

		}*/
		if(!strcmp(argv[1],"-c"))
                        sandb_init(&sandb, argc-1, argv+3,Perm);
                else
                        sandb_init(&sandb, argc-1,argv +1,Perm);
			
        }
        else
        {
                printf("No config File found. Please create a .fendrc in the current working directory./n");
                exit(0);
        } 

        for(;;) 
        {
                sandb_run(&sandb);
        }
	if(PermRefused==1) puts("Permission Denied");
	removeFiles();
	//perror("Error:");
	free(Perm);free(configFilename);
	
        
}
