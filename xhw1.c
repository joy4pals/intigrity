#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "hw1_header.h"

#define __NR_xintegrity	349	/* our private syscall number */

void write_to_file(int fd){
    char *buf = "HELLO WORLD";
    int bts = -1;
    bts = write(fd, buf, strlen(buf));
    printf("%d bytes written", bts);
    close(fd);
}

int main(int argc, char *argv[])
{
	int rc, c, index,ii=0;
	int fflag=-1, mode = -1;
    //	void *dummy = (void *) atoi(argv[1]);
    
    unsigned char flag = 0; //the mode to open file in. Accepted values {1, 2, 3}
	char *filename = NULL;
	char *pass = NULL;
    char *hash = NULL;
	//Args args;
    mode1_args argsm1;
	mode2_args argsm2;
	mode3_args argsm3;
	
	void *args;
	//arguments that are to be returned
	unsigned int ilen = 1024;
	unsigned char ibuf[ilen];
    
    while ((c = getopt (argc, argv, "h:")) != -1)
        switch (c)
    {
        case 'h':
            hash = optarg;
            break;
        case '?':
            if (optopt == 'h')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
        default:
            abort ();
    }
    if(hash)
        printf ("hash = %s\n", hash);
    index = optind;
    if (argc-index < 2){
		printf("This takes two(2) or three(3) arguments:\n"
               "-h <checksum type to use> (Unnecessary for mode 1 and 3. defaults to md5 for mode 2)\n"
               "1: the mode(1 or 2 or 3)[REQUIRED]\n"
               "2: the filename[REQUIRED]\n"
               "3: user credential(Optional for mode 1)\n. The system will now exit\n"
               "A possible argument type could be\n"
               "-h md5 2 abc.txt password");
		exit(-1);
	}
    flag = atoi(argv[index++]);
    filename = argv[index++];
    if(index < argc)
        pass = argv[index++];
    
	if (flag<1 || flag>3){
		printf("The value of flag entered is: %d\n"
               "The accepted values of flag are : 1 or 2 or 3.\n"
               "Sys will now exit\n", flag);
		exit(-1);
	}
    if((flag == 2 || flag == 3) && pass==NULL){
        printf("For mode 2 and 3 the third argument(credential) is a required field\n");
        exit(-1);
    }
    
    printf("argc: %d, index: %d\n", argc,index);
    if(flag == 3 && argc < 6){
	printf("With mode 3, you need to pass flag and mode to open the file in.\n");
	exit(-1);
    }
    if(flag == 3){
     	fflag = atoi(argv[index++]);
	mode = atoi(argv[index]);
    }
	//The nexy few lines wraps up the arguments into the struct args to pass
	//it to our system call
	// args.flag = flag;
	// args.filename = filename;
    
	switch(flag){
        case 1: //Mode 1: return existing integrity
			argsm1.flag = 1;
			argsm1.filename = filename;
            argsm1.ibuf = ibuf;
            argsm1.ilen = ilen;
			args = &argsm1;
            rc = syscall(__NR_xintegrity, args);
            if(!rc){
                printf("\nReturned from sys call for mode 1 successfully. sizeof ibuf: %d\n",strlen((char *)ibuf));
            for(ii=0; ii< strlen((char *)ibuf);ii++)
                printf("%02x",*(ibuf+ii));
            printf("\n");
	    }
            else
                perror("Error in calling syscall");
            break;
        case 2: //Mode 2: update integrity
			argsm2.flag = 2;
			argsm2.filename = filename;
            argsm2.ibuf = ibuf;
            argsm2.ilen = ilen;
            argsm2.credbuf = (unsigned char*)pass;
            argsm2.clen = strlen(pass);
#ifdef EXTRA_CREDIT
            argsm2.hash_type = hash;
            printf("This is the extra stuff\n.");
#endif
			args = &argsm2;
            rc = syscall(__NR_xintegrity, args);
            if(!rc)
                printf("The integrity of the file updated successfully.\n");
            else
                perror("Error in calling syscall");
            break;
        case 3: //Mode 3: open with integrity check
			argsm3.flag = 3;
			argsm3.filename = filename;
            argsm3.oflag = fflag;
            argsm3.mode = mode;
			args = &argsm3;
            rc = syscall(__NR_xintegrity, args);
            if(rc > 0){
                printf("The file descriptor received is: %d\n",rc);
//                write_to_file(rc);
                close(rc);
            }
            else
                perror("Error in calling syscall");
            break;
	}
    
    
    //  	rc = syscall(__NR_xintegrity, args);
    //	if (rc == 0)
    //		printf("syscall returned %d\n", rc);
    //	else{
    //		perror("error in syscall");
    //		printf("syscall returned %d (errno=%d)\n", rc, errno);
    //	}
	exit(rc);
}
