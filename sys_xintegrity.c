#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include "hw1_header.h"

asmlinkage extern long (*sysptr)(void *arg);

#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/fdtable.h>
#include <linux/xattr.h>
#include <asm/uaccess.h>
#include <asm/fcntl.h>

#include <linux/crypto.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/file.h>

#include <linux/scatterlist.h>

static const char *key="helloworld"; //The hard coded key
static const char *I_ATTR = "user.integrity";
static const char *H_ATTR = "user.hash_type";
///////////////////////////////////////////////////////////////////////////////
static DEFINE_PER_CPU(struct fdtable_defer, fdtable_defer_list);
struct kmem_cache *files_cachep;
int sysctl_nr_open __read_mostly = 1024*1024;
struct fdtable_defer {
	spinlock_t lock;
	struct work_struct wq;
	struct fdtable *next;
};
void free_fdtable_rcu(struct rcu_head *rcu)
{
	struct fdtable *fdt = container_of(rcu, struct fdtable, rcu);
	struct fdtable_defer *fddef;
    
	BUG_ON(!fdt);
    
	if (fdt->max_fds <= NR_OPEN_DEFAULT) {
		/*
		 * This fdtable is embedded in the files structure and that
		 * structure itself is getting destroyed.
		 */
		kmem_cache_free(files_cachep,
                        container_of(fdt, struct files_struct, fdtab));
		return;
	}
	if (!is_vmalloc_addr(fdt->fd) && !is_vmalloc_addr(fdt->open_fds)) {
		kfree(fdt->fd);
		kfree(fdt->open_fds);
		kfree(fdt);
	} else {
		fddef = &get_cpu_var(fdtable_defer_list);
		spin_lock(&fddef->lock);
		fdt->next = fddef->next;
		fddef->next = fdt;
		/* vmallocs are handled from the workqueue context */
		schedule_work(&fddef->wq);
		spin_unlock(&fddef->lock);
		put_cpu_var(fdtable_defer_list);
	}
}
static void copy_fdtable(struct fdtable *nfdt, struct fdtable *ofdt)
{
	unsigned int cpy, set;
    
	BUG_ON(nfdt->max_fds < ofdt->max_fds);
    
	cpy = ofdt->max_fds * sizeof(struct file *);
	set = (nfdt->max_fds - ofdt->max_fds) * sizeof(struct file *);
	memcpy(nfdt->fd, ofdt->fd, cpy);
	memset((char *)(nfdt->fd) + cpy, 0, set);
    
	cpy = ofdt->max_fds / BITS_PER_BYTE;
	set = (nfdt->max_fds - ofdt->max_fds) / BITS_PER_BYTE;
	memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
	memset((char *)(nfdt->open_fds) + cpy, 0, set);
	memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
	memset((char *)(nfdt->close_on_exec) + cpy, 0, set);
}
static void *alloc_fdmem(unsigned int size)
{
	/*
	 * Very large allocations can stress page reclaim, so fall back to
	 * vmalloc() if the allocation size will be considered "large" by the VM.
	 */
	if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)) {
		void *data = kmalloc(size, GFP_KERNEL|__GFP_NOWARN);
		if (data != NULL)
			return data;
	}
	return vmalloc(size);
}
static void free_fdmem(void *ptr)
{
	is_vmalloc_addr(ptr) ? vfree(ptr) : kfree(ptr);
}

static void __free_fdtable(struct fdtable *fdt)
{
	free_fdmem(fdt->fd);
	free_fdmem(fdt->open_fds);
	kfree(fdt);
}
static struct fdtable * alloc_fdtable(unsigned int nr)
{
	struct fdtable *fdt;
	char *data;
    
	/*
	 * Figure out how many fds we actually want to support in this fdtable.
	 * Allocation steps are keyed to the size of the fdarray, since it
	 * grows far faster than any of the other dynamic data. We try to fit
	 * the fdarray into comfortable page-tuned chunks: starting at 1024B
	 * and growing in powers of two from there on.
	 */
	nr /= (1024 / sizeof(struct file *));
	nr = roundup_pow_of_two(nr + 1);
	nr *= (1024 / sizeof(struct file *));
	/*
	 * Note that this can drive nr *below* what we had passed if sysctl_nr_open
	 * had been set lower between the check in expand_files() and here.  Deal
	 * with that in caller, it's cheaper that way.
	 *
	 * We make sure that nr remains a multiple of BITS_PER_LONG - otherwise
	 * bitmaps handling below becomes unpleasant, to put it mildly...
	 */
	if (unlikely(nr > sysctl_nr_open))
		nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;
    
	fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL);
	if (!fdt)
		goto out;
	fdt->max_fds = nr;
	data = alloc_fdmem(nr * sizeof(struct file *));
	if (!data)
		goto out_fdt;
	fdt->fd = (struct file **)data;
	data = alloc_fdmem(max_t(unsigned int,
                             2 * nr / BITS_PER_BYTE, L1_CACHE_BYTES));
	if (!data)
		goto out_arr;
	fdt->open_fds = (fd_set *)data;
	data += nr / BITS_PER_BYTE;
	fdt->close_on_exec = (fd_set *)data;
	fdt->next = NULL;
    
	return fdt;
    
out_arr:
	free_fdmem(fdt->fd);
out_fdt:
	kfree(fdt);
out:
	return NULL;
}
static int expand_fdtable(struct files_struct *files, int nr)
__releases(files->file_lock)
__acquires(files->file_lock)
{
	struct fdtable *new_fdt, *cur_fdt;
    
	spin_unlock(&files->file_lock);
	new_fdt = alloc_fdtable(nr);
	spin_lock(&files->file_lock);
	if (!new_fdt)
		return -ENOMEM;
	/*
	 * extremely unlikely race - sysctl_nr_open decreased between the check in
	 * caller and alloc_fdtable().  Cheaper to catch it here...
	 */
	if (unlikely(new_fdt->max_fds <= nr)) {
		__free_fdtable(new_fdt);
		return -EMFILE;
	}
	/*
	 * Check again since another task may have expanded the fd table while
	 * we dropped the lock
	 */
	cur_fdt = files_fdtable(files);
	if (nr >= cur_fdt->max_fds) {
		/* Continue as planned */
		copy_fdtable(new_fdt, cur_fdt);
		rcu_assign_pointer(files->fdt, new_fdt);
		if (cur_fdt->max_fds > NR_OPEN_DEFAULT)
			free_fdtable(cur_fdt);
	} else {
		/* Somebody else expanded, so undo our attempt */
		__free_fdtable(new_fdt);
	}
	return 1;
}
int expand_files(struct files_struct *files, int nr)
{
	struct fdtable *fdt;
    
	fdt = files_fdtable(files);
    
	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	if (nr >= rlimit(RLIMIT_NOFILE))
		return -EMFILE;
    
	/* Do we need to expand? */
	if (nr < fdt->max_fds)
		return 0;
    
	/* Can we expand? */
	if (nr >= sysctl_nr_open)
		return -EMFILE;
    
	/* All good, so we try */
	return expand_fdtable(files, nr);
}
int alloc_fd(unsigned start, unsigned flags)
{
	struct files_struct *files = current->files;
	unsigned int fd;
	int error;
	struct fdtable *fdt;
    
	spin_lock(&files->file_lock);
repeat:
	fdt = files_fdtable(files);
	fd = start;
	if (fd < files->next_fd)
		fd = files->next_fd;
    
	if (fd < fdt->max_fds)
		fd = find_next_zero_bit(fdt->open_fds->fds_bits,
                                fdt->max_fds, fd);
    
	error = expand_files(files, fd);
	if (error < 0)
		goto out;
    
	/*
	 * If we needed to expand the fs array we
	 * might have blocked - try again.
	 */
	if (error)
		goto repeat;
    
	if (start <= files->next_fd)
		files->next_fd = fd + 1;
    
	FD_SET(fd, fdt->open_fds);
	if (flags & O_CLOEXEC)
		FD_SET(fd, fdt->close_on_exec);
	else
		FD_CLR(fd, fdt->close_on_exec);
	error = fd;
#if 1
	/* Sanity check */
	if (rcu_dereference_raw(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif
    
out:
	spin_unlock(&files->file_lock);
	return error;
}
///////////////////////////////////////////////////////////////////////////////
/*This function initialized with all nulls
 *@param
 *buf : the buffer to be written
 *buflen: the size of the buffer
 */
 
static void __initialize_with_null(char *buf, long buflen){
    long i=0;
    for(i=0; i<buflen; i++)
        *(buf+i) = '\0';
}

/*
 This function extracts the xattr value for user.integrity xattr and returns it in the
 ibuf. The user.iintegrity is chosen as a convention to store the checksum value.
 @param:
 filename: the file whose checksum needs to be retrieved
 ibuf: the user provided buffer address where the checksum is to be written
 ilen: the length of the integrity buffer
 attr: this specifies the attribute value that is to be retrieved.
 
 @return:
 success: 0
 failure: corresponding error to show if file is in accesssable to read or the
        xattr does not exist
 */
static int get_integrity_val(const char *filename,
                             char *ibuf,
                             int ilen,
                             const char *attr){
    int retval=-EINVAL;
    struct file *filp=filp_open(filename, O_RDONLY, 0);
    
    __initialize_with_null(ibuf, ilen);
    
    if(!filp || IS_ERR(filp)){
		printk(KERN_INFO "Could not allocate file pointer\n");
		return -EIO;
	}
    if (!(filp->f_op)) {
        pr_err("%s(): File has no file operations registered!\n",
               __func__);
        filp_close(filp, NULL);
        return -EIO;
    }
    if (!filp->f_op->read) {
        pr_err("%s(): File has no READ operations registered!\n",
               __func__);
        filp_close(filp, NULL);
        return -EIO;
    }
    retval = vfs_getxattr(filp->f_dentry, attr, ibuf, ilen);
    
    if (retval > 0) {
        retval = 0;
    }
    filp_close(filp, NULL);
    return retval;
}
/*
 This function updates the checksum of a file in the user.integrity xattr by convention
 @param
 dtry: the file dentry
 ibuf: the buffer containing the checksum to be updated
 ilen: the length of the buffer
 
 @return
 SUCCESS: 0
 FAILURE: -ve number
 */
static int __update_file_integrity(struct dentry *dtry, char *ibuf, int ilen, const char *algo)
{
    int r;
    struct iattr newattrs;
    if(ibuf == NULL || algo==NULL){
        printk(KERN_ERR "either ibuf or algo is null");
        return -EINVAL;
    }
    r=vfs_setxattr(dtry, I_ATTR, ibuf, ilen,0);
	if(r<0){
		printk(KERN_ERR "error occured while setting integrity: %d",r);
		return r;
	}
    r=vfs_setxattr(dtry, H_ATTR, algo, strlen(algo),0);
    if(r<0){
		printk(KERN_ERR "error occured while setting hash type: %d",r);
		return r;
	}
    printk(KERN_INFO "The hash type updated to %s\n", algo);
    
    newattrs.ia_valid = ATTR_FORCE;
    r = notify_change(dtry, &newattrs);
    if(r<0)
        return r;
    return 0;
}
/*
 This function calculates the integrity of the file by reading it page by page and then calls then in order to update the xattr of the file it consults the update argument.
 @param:
    filename: the file for which the checksum needs to be calculated
    ibuf: the buffer to be written with the checksum value
    ilen: the length of the buffer
    upadte: should be 1: if the integrity calculated need to be written as in the xattr 
     or 0 otherwise.
    algo: the hash calculation algorith to be used to calculate the hash. In normal mode it is md5 but can be myraid algorithms in case of the extra credit.
 @return:
 SUCCESS: 0
 FAILURE: anything else.
 */
static int calculate_integrity(const char *filename,
                               char *ibuf,
                               int ilen,
                               int update,
                               const char *algo)
{
    int r=-1 , ret=-1;
    ssize_t vfs_read_retval = 0;
    loff_t file_offset = 0;
    
    struct file *filp=filp_open(filename, O_RDONLY, 0);
	mm_segment_t oldfs=get_fs();
//	char *algo = "md5";
    
//	long len=PAGE_SIZE;
    char *buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    
    //initializations for crypto
	struct scatterlist sg;
	struct crypto_hash *tfm=NULL;
	struct hash_desc desc;
    
    if(!buf)
        goto out;
    __initialize_with_null(ibuf, ilen);
    
    if(!filp || IS_ERR(filp)){
		printk(KERN_INFO "Could not open file\n");
        return -EIO;
	}
	if(!filp->f_op->read){
        printk(KERN_ERR "Could not read file.\n");
        r=-2;
		goto out;
	}
	filp->f_pos=0;
    //	oldfs = get_fs();
	set_fs(KERNEL_DS);
    
	tfm = crypto_alloc_hash(algo, 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm)){
		printk(KERN_ERR "failed to load transform for %s: %ld.\n", algo, PTR_ERR(tfm));
        r = -EINVAL;
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;
    
	if(crypto_hash_digestsize(tfm) > ilen){
		printk(KERN_ERR "digest size(%u) > outputbuffer(%zu)\n",
               crypto_hash_digestsize(tfm), ilen);
        r = -EINVAL;
		goto out;
	}
	crypto_hash_setkey(tfm, key, strlen(key));
	ret = crypto_hash_init(&desc);
	if(ret){
        r = ret;
		goto out;
    }
    sg_init_table(&sg, 1);
    ////	while(filp->f_op->read(filp, buf, len, &filp->f_pos)){
    //    r = filp->f_op->read(filp, buf, len, &filp->f_pos);
    //		sg_init_one(sg, buf, len);
    //        printk(KERN_INFO "r:%d\n",r);
    //        printk(KERN_INFO "DAAAAAATA:%s\n",buf);
    //        printk(KERN_INFO "f_pos: %lld",filp->f_pos);
    //    filp->f_pos = PAGE_SIZE;
    //    r = filp->f_op->read(filp, buf, len, &filp->f_pos);
    //        printk(KERN_INFO "r:%d\n",r);
    //        printk(KERN_INFO "DAAAAAATA:%s\n",buf);
    //        printk(KERN_INFO "f_pos: %lld",filp->f_pos);
    file_offset = 0;
    do {
        vfs_read_retval = vfs_read(filp, buf, ksize(buf), &file_offset);
        sg_set_buf(&sg, (u8 *)buf, vfs_read_retval);
        ret = crypto_hash_update(&desc, &sg, sg.length);
        
        if(ret){
            r = ret;
            goto out;
        }
        if(vfs_read_retval < ksize(buf)){
            printk(KERN_INFO "read the entire file\n");
            break;
        }
    }while(1);
    ret=crypto_hash_final(&desc, ibuf);
    if(ret){
        r = ret;
        goto out;
    }
    //		ret = crypto_hash_update(&desc, sg, len);
    //		if(ret)
    //			return ret;
    //	}
    //	ret=crypto_hash_final(&desc, ibuf);
    //	if(ret)
    //		return ret;
    
    if(update)
        r = __update_file_integrity(filp->f_dentry, ibuf, ilen, algo);
out:
    if(buf)
        kfree(buf);
    if(!IS_ERR(tfm))
        crypto_free_hash(tfm);
	set_fs(oldfs);
    filp_close(filp, NULL);
	return r;
}
/*
 This function is the starting point for mode 3. This function checks if a file requested to be open is a new file. If it is then it bypasses the integrity matching step and tries to open the file with the given mode and flags. In case the file is an existing file it checks if the calculated integrity matches the stored integrity and if it does not it throws an error or a valid file descriptor otherwise.
@param:
    filename: the file to be opened.
    flags: the flags to be open with, same as sys_open
    mode: the mode in which the file needs to be opened if created. same as sys_open
 @return
    SUCCESS: valid file descriptor. >0
    FAILURE: a numeber < 0
 */
static long secure_open(const char *filename,
                        int flags,
                        int mode)
{
    int size_arr = 1024;
    char algo[10];
    char *integrity_buf= NULL;
    char *ibuf = NULL;
    struct file *f = NULL;
    int fd = -1;
    struct file *filp=NULL;
    
    __initialize_with_null(algo, sizeof(algo));
    
    //check if a file exists with this name
    filp=filp_open(filename, O_RDONLY, 0);
    //This file cannot be opened in readonly mode then probably we need to
    //create a new file
    if(!filp || IS_ERR(filp))
        goto newfd;
    filp_close(filp, NULL);
    
    integrity_buf= kmalloc(size_arr, GFP_KERNEL);
    ibuf = kmalloc(size_arr, GFP_KERNEL);
    
    if(!integrity_buf || !ibuf){
        printk(KERN_INFO "Could not allocate memory");
        goto out;
    }
    
    if(flags & O_TRUNC)//File needs to be truncated. Bypasss the checksum check
        goto newfd;
    
    __initialize_with_null(ibuf, ksize(ibuf));
    __initialize_with_null(integrity_buf, ksize(integrity_buf));
    
    get_integrity_val(filename, algo, sizeof(algo), H_ATTR);
    calculate_integrity(filename, ibuf, ksize(ibuf), 0, algo);
    get_integrity_val(filename, integrity_buf, ksize(integrity_buf), I_ATTR);
    
    
    if(strcmp(ibuf, integrity_buf) != 0){
        printk(KERN_INFO "File corrupted.\n");
        fd = -EPERM;
        goto out;
    }
    printk(KERN_INFO "File Safe\n");
newfd:
    if (force_o_largefile())
        flags |= O_LARGEFILE;
    
    fd=alloc_fd(0, flags);
    if (fd < 0){
        printk(KERN_ERR "Could not get valid FD\n");
        goto out;
    }
    f=filp_open(filename, flags, mode);
    if (IS_ERR(f)) {
        put_unused_fd(fd);
        fd = PTR_ERR(f);
        printk(KERN_ERR "Could not open file with given flags.\n");
        goto out;
    }
    fsnotify_open(f);
    fd_install(fd, f);
    
    /* avoid REGPARM breakage on x86: */
    asmlinkage_protect(3, fd, filename, flags, mode);
out:
    if(ibuf)
        kfree(ibuf);
    if(integrity_buf)
        kfree(integrity_buf);
    return fd;
}

asmlinkage long xintegrity(void *arg)
{
    long retval = -EINVAL;
	unsigned char *flag = NULL;
	mode1_args *arg1_struct=NULL;
	mode2_args *arg2_struct=NULL;
	mode3_args *arg3_struct=NULL;
    
	char *filename = NULL;
    char *hash_type = NULL;
	char *ibuf = NULL;
	char *credbuf = NULL;
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
    //	if (arg == NULL)
    //		return -EINVAL;
    //	else
    //		return 0;
    
    //Args *rgs = NULL;
    
    //int file_name_len = -1;
    if(arg != NULL && access_ok(VERIFY_READ, arg, sizeof(unsigned char))){
		flag = kmalloc(sizeof(unsigned char), GFP_KERNEL);
        
        if(copy_from_user(flag, arg, sizeof(unsigned char))){
            printk(KERN_ERR "copy_from_user unsuccessful while copying flag\n");
            goto out;
        }
        switch (*flag) {
            case 1://return integrity value
                if(!access_ok(VERIFY_WRITE, arg, sizeof(mode1_args)))
                    goto out;
                arg1_struct = kmalloc(sizeof(mode1_args), GFP_KERNEL);
                if(!arg1_struct)
                    goto out;
                if(copy_from_user(arg1_struct, arg, sizeof(mode1_args))){
                    printk(KERN_ERR "copy_from_user unsuccessful while copying structure 1\n");
                    goto out;
                }
                if(arg1_struct->ilen == 0){
                    printk(KERN_ERR "Too less bytes to writeto. intigrity buffer length is 0");
                    retval = -EINVAL;
                    goto out;
                }
                if(arg1_struct->filename == NULL){
                    printk(KERN_ERR "Invalid pointer to filename\n");
                    retval = -EFAULT;
                    goto out;
                }
                filename = getname(arg1_struct->filename);
                if(!filename)
                    goto out;
                if(!access_ok(VERIFY_WRITE, arg1_struct->ibuf, arg1_struct->ilen)|| arg1_struct->ibuf == NULL){
                    printk(KERN_ERR "ibuf is NOT a valid memory");
                    retval = -EFAULT;
                    goto out;
                }
                ibuf = kmalloc(arg1_struct->ilen, GFP_KERNEL);
                if(!ibuf){
                    printk(KERN_ERR "unable to allocate memory for ibuf");
                    goto out;
                }
                retval = get_integrity_val(filename,
                                           ibuf, arg1_struct->ilen,
                                           I_ATTR);

                if(!retval){
                    if(copy_to_user(arg1_struct->ibuf, ibuf, arg1_struct->ilen)){
                        printk(KERN_ERR "Could not copy to user\n");
                        return -EFAULT;
                    }
                }
                break;
            case 2:
                if(!access_ok(VERIFY_WRITE, arg, sizeof(mode2_args)))
                    goto out;

                arg2_struct = kmalloc(sizeof(mode2_args), GFP_KERNEL);
                if(!arg2_struct)
                    goto out;

                if(copy_from_user(arg2_struct, arg, sizeof(mode2_args))){
                    printk(KERN_ERR "copy_from_user unsuccessful while copying structure 2.\n");
                    goto out;
                }
                if(arg2_struct->ilen == 0 || arg2_struct->clen == 0){
                    printk(KERN_ERR "Too less bytes to writeto or read from. intigrity buffer or credential buffer length is 0");
                    retval = -EINVAL;
                    goto out;
                }
                if(arg2_struct->filename == NULL){
                    printk(KERN_ERR "Invalid pointer to filename\n");
                    retval = -EFAULT;
                    goto out;
                }
                filename = getname(arg2_struct->filename);
                if(!filename)
                    goto out;
                if(!access_ok(VERIFY_WRITE, arg2_struct->ibuf, arg2_struct->ilen)|| arg2_struct->ibuf == NULL){
                    printk(KERN_ERR "ibuf is NOT a valid memory");
                    retval = -EFAULT;
                    goto out;
                }
                if(!access_ok(VERIFY_READ, arg2_struct->credbuf, arg2_struct->clen) ||
                   arg2_struct->credbuf == NULL){
                    printk(KERN_ERR "credbuf is NOT a valid memory");
                    retval = -EFAULT;
                    goto out;
                }
                
                credbuf = getname(arg2_struct->credbuf);
                if(!credbuf)
                    goto out;
                
                if(strcmp(key, credbuf) == 0){

                    ibuf = kmalloc(arg2_struct->ilen, GFP_KERNEL);
                    if(!ibuf){
                        printk(KERN_ERR "unable to allocate memory for ibuf");
                        goto out;
                    }
                    __initialize_with_null(ibuf, arg2_struct->ilen);

#ifdef EXTRA_CREDIT
                    if(arg2_struct->hash_type != NULL){
                        hash_type = getname(arg2_struct->hash_type);
                        printk(KERN_INFO "The hash type:%s", hash_type);
                        if(!hash_type)
                            goto out;
                    }else{
                            hash_type = "md5";
                    }
                    retval = calculate_integrity(filename, arg2_struct->ibuf,
                                                 arg2_struct->ilen, 1, hash_type);
                    printk(KERN_INFO "This is the extra stuff.\n");
#else
                    retval = calculate_integrity(filename, ibuf,
                                                 arg2_struct->ilen, 1, "md5");
                    if(!retval){
                        if(copy_to_user(arg2_struct->ibuf, ibuf, arg2_struct->ilen)){
                            return -EFAULT;
                        }
                    }
#endif
                }
                else{
                    retval = -EACCES;
                    goto out;
                }
                break;
            case 3:
                if(!access_ok(VERIFY_WRITE, arg, sizeof(mode3_args)))
                    goto out;
                arg3_struct = kmalloc(sizeof(mode3_args), GFP_KERNEL);
                if(!arg3_struct)
                    goto out;
                if(copy_from_user(arg3_struct, arg, sizeof(mode3_args))){
                    printk(KERN_ERR "copy_from_user unsuccessful while copying structure 2.\n");
                    goto out;
                }
                if(arg3_struct->filename == NULL){
                    printk(KERN_ERR "Invalid pointer to filename\n");
                    goto out;
                }
                filename = getname(arg3_struct->filename);
                if(!filename)
                    goto out;
                retval = secure_open(filename, arg3_struct->oflag,
                                     arg3_struct->mode);
                printk(KERN_INFO "Case 3 exceuted and returned fd: %ld", retval);
                break;
            default:
                printk(KERN_ERR "No such mode");
                retval = -EINVAL;
                break;
        }
    }
out: //clear stuffs
    
    if(flag)
        kfree(flag);
    if(arg1_struct)
        kfree(arg1_struct);
    if(arg2_struct)
        kfree(arg2_struct);
    if(arg3_struct)
        kfree(arg3_struct);
    if(filename)
        putname(filename);
    if(hash_type)
        putname(hash_type);
    if(ibuf)
        kfree(ibuf);
    if(credbuf)
        putname(credbuf);
    return retval;
}//end xintegrity

static int __init init_sys_xintegrity(void)
{
    printk("installed new sys_xintegrity module\n");
    if (sysptr == NULL)
        sysptr = xintegrity;
    return 0;
}
static void  __exit exit_sys_xintegrity(void)
{
    if (sysptr != NULL)
        sysptr = NULL;
    printk("removed sys_xintegrity module\n");
    printk("------------------------------------------------------\n");
}
module_init(init_sys_xintegrity);
module_exit(exit_sys_xintegrity);
MODULE_LICENSE("GPL");
