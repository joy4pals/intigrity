#ifndef MYHEAD_H_
#define MYHEAD_H_

//define the header that can e passed to the system call that takes
//only one argument
typedef struct my_args{
	//General used by all modes
	unsigned char flag; //This specifies the mode. valid-> 1,2,3
	const char *filename; //The file entity whose checksum is to be calculated
	
    //used by mode 1 nd 2
    unsigned char *ibuf; //The checksum value
	unsigned int ilen; //the length of ibuf
    
	//Used in mode 2
	unsigned char *credbuf; //buff containing the password.Used in mode 2
	unsigned int clen; //Length of the password buffer
    
	//Used by mode 3
	int oflag; //flags same as in open(2)
	int mode; //mode to open a file in. same as in open(2)
}Args;
typedef struct {
	unsigned char flag;
	const char *filename;
	unsigned char *ibuf; //The checksum value
	unsigned int ilen; //the length of ibuf
}mode1_args;
typedef struct {
	unsigned char flag;
	const char *filename;
	unsigned char *ibuf; //The checksum value
	unsigned int ilen; //the length of ibuf
	unsigned char *credbuf; //buff containing the password.Used in mode 2
	unsigned int clen; //Length of the password buffer
#ifdef EXTRA_CREDIT
    const char *hash_type;
#endif
}mode2_args;
typedef struct {
	unsigned char flag;
	const char *filename;
	int oflag; //flags same as in open(2)
	int mode; //mode to open a file in. same as in open(2)
}mode3_args;
#endif
