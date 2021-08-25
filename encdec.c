#include <linux/ctype.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "encdec.h"

#define MODULE_NAME "encdec"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YOUR NAME");

char *ccBuf = NULL;
char  *xorBuf = NULL;
char *temp = NULL;

int 	encdec_open(struct inode *inode, struct file *filp);
int 	encdec_release(struct inode *inode, struct file *filp);
int 	encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);

ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

int memory_size = 0;

MODULE_PARM(memory_size, "i");

int major = 0;

struct file_operations fops_caesar = {
        .open 	 =	encdec_open,
        .release =	encdec_release,
        .read 	 =	encdec_read_caesar,
        .write 	 =	encdec_write_caesar,
        .llseek  =	NULL,
        .ioctl 	 =	encdec_ioctl,
        .owner 	 =	THIS_MODULE
};

struct file_operations fops_xor = {
        .open 	 =	encdec_open,
        .release =	encdec_release,
        .read 	 =	encdec_read_xor,
        .write 	 =	encdec_write_xor,
        .llseek  =	NULL,
        .ioctl 	 =	encdec_ioctl,
        .owner 	 =	THIS_MODULE
};

// Implemetation suggestion:
// -------------------------
// Use this structure as your file-object's private data structure
typedef struct {
    unsigned char key;
    int read_state;
} encdec_private_date;

int init_module(void)
{
    major = register_chrdev(major, MODULE_NAME, &fops_caesar);
    if(major < 0)
    {
        return major;
    }

    // Implemetation suggestion:
    // -------------------------
    // 1. Allocate memory for the two device buffers using kmalloc (each of them should be of size 'memory_size')
    ccBuf = (char*)kmalloc(memory_size * sizeof(char), GFP_KERNEL);
    if (!ccBuf ) {
        return -1;
    }
    xorBuf = (char*)kmalloc(memory_size * sizeof(char), GFP_KERNEL);
    if (!xorBuf) {
        return -1;
    }
    return 0;
}

void cleanup_module(void)
{
    // Implemetation suggestion:
    // -------------------------
    // 1. Unregister the device-driver
    unregister_chrdev(major, MODULE_NAME);
    // 2. Free the allocated device buffers using kfree
    kfree(ccBuf);
    kfree(xorBuf);
}

int encdec_open(struct inode *inode, struct file *filp)
{
    int minor = MINOR(inode->i_rdev);

    // Implemetation suggestion:
    // -------------------------
    // 1. Set 'filp->f_op' to the correct file-operations structure (use the minor value to determine which)
    if (minor == 1) {
        filp->f_op = &fops_xor;
    }
    else if (minor == 0) {
        filp->f_op = &fops_caesar;
    }
    // 2. Allocate memory for 'filp->private_data' as needed (using kmalloc)
    (encdec_private_date*)filp->private_data = kmalloc(sizeof(encdec_private_date), GFP_KERNEL);
    if (filp->private_data == NULL)
        return -1;

    ((encdec_private_date*)(filp->private_data))->key = 0;
    ((encdec_private_date*)(filp->private_data))->read_state = ENCDEC_READ_STATE_DECRYPT;

    if ((minor == 1) || (minor == 0))
        return 0;

    return  -ENODEV;
}

int encdec_release(struct inode *inode, struct file *filp)
{
    // Implemetation suggestion:
    // -------------------------
    // 1. Free the allocated memory for 'filp->private_data' (using kfree)
    kfree(filp->private_data);

    return 0;
}

int encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
    // Implemetation suggestion:
    // -------------------------
    // 1. Update the relevant fields in 'filp->private_data' according to the values of 'cmd' and 'arg'

    if(cmd==ENCDEC_CMD_CHANGE_KEY) {
        ((encdec_private_date *) (filp->private_data))->key = arg;
    }
    else if(cmd==ENCDEC_CMD_SET_READ_STATE) {
        ((encdec_private_date *) (filp->private_data))->read_state = arg;
    }
    else if(cmd== ENCDEC_CMD_ZERO) {
        if (MINOR(inode->i_rdev) == 0)
            memset(ccBuf, 0, memory_size);
        else
            memset(xorBuf, 0, memory_size);
    }else{
        return -ENOTTY;
    }
    return 0;
}
ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos ){
    int rd_state = ((encdec_private_date *)(filp->private_data))->read_state;
    if(memory_size-filp->f_pos < count){
        return -EINVAL;
    }
    copy_to_user(buf, &ccBuf[filp->f_pos], count);
    if(rd_state==ENCDEC_READ_STATE_DECRYPT){
        int  key = ((encdec_private_date *)(filp->private_data))->key;
        int i;
        for( i=0 ; i < count ; i++){
            buf[i] = ((buf[i] - key) + 128) % 128;

        }
    }

    filp->f_pos += count;
    return count;


}
ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos) {

    int key = ((encdec_private_date *)(filp->private_data))->key;
    if(memory_size - filp->f_pos < count){
        return -ENOSPC;
    }
    temp = (char*)kmalloc(memory_size * sizeof(char), GFP_USER);
    if(temp!=NULL){
        copy_from_user(temp, buf, count);
    }
    int i;
    for( i=0 ; i < count ; i++){
        ccBuf[filp->f_pos+i]=(temp[i]+key)%128 ;
    }
    filp->f_pos+=count;
    kfree(temp);
    return count;

}
ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos ){
    int rd_state = ((encdec_private_date *)(filp->private_data))->read_state;
    if(memory_size-filp->f_pos < count){
        return -EINVAL;
    }
    copy_to_user(buf, &xorBuf[filp->f_pos], count);
    if(rd_state==ENCDEC_READ_STATE_DECRYPT){
        int  key = ((encdec_private_date *)(filp->private_data))->key;
        int i;
        for( i=0 ; i < count ; i++){
            buf[i] = buf[i]^key;

        }
    }

    filp->f_pos += count;
    return count;
}

ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos){
    int key = ((encdec_private_date *)(filp->private_data))->key;
    if(memory_size - filp->f_pos < count){
        return -ENOSPC;
    }
    temp = (char*)kmalloc(memory_size * sizeof(char), GFP_USER);
    if(temp!=NULL){
        memset(temp, 0, memory_size);
        copy_from_user(temp, buf, count);
    }
    int i;
    for( i=0 ; i < count ; i++){
        xorBuf[filp->f_pos+i]=temp[i]^ key;
    }
    filp->f_pos+=count;
    kfree(temp);
    return count;

}
// Add implementations for:
// ------------------------
// 1. ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos );
// 2. ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos);
// 3. ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos );
// 4. ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos);