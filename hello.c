#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h> 
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include </usr/include/x86_64-linux-gnu/asm/unistd_64.h>
#include <linux/icmp.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/device.h>


MODULE_LICENSE("GPL");



static struct cdev cipher;
static struct cdev cipher_key;
static char * key;
static char *key_proc;
static char * msg;
static char *result;
static unsigned long buff_size;
static unsigned long buff_size2;
static unsigned long buff_size3;
void rc4(unsigned char *, unsigned char *, unsigned char *, int );

static int my_open(struct inode *inode, struct file *f)
{
	try_module_get(THIS_MODULE);
	return 0;
}

static ssize_t my_read_msg(struct file *f, char __user *user_buff, size_t s, loff_t *offset)
{
	static int flag=0;

	if(flag)
	{
		flag=0;
		return 0;
	}

	flag=1;
	if(copy_to_user(user_buff,msg,buff_size) )
		return -EFAULT; 
		
	printk(KERN_ALERT "%s\n", result);

	return 0;
}

static ssize_t my_read_key(struct file *f, char __user *user_buff, size_t s, loff_t *offset)
{

	printk(KERN_ALERT "Go away, you cannot see the key! \n");
	return 0;
}

static ssize_t my_write_msg(struct file *f,const char __user *user_buff, size_t s, loff_t *offset)
{
	
	if(s>4096)
		buff_size=4096;
	else
		buff_size=s;

	if(copy_from_user(msg,user_buff,buff_size))
		return -EFAULT;
	
	int length=strlen(msg);
	result=(char *)kmalloc(4096,GFP_KERNEL);
	rc4(msg,key,result,length);

	return buff_size;	

}
static ssize_t my_write_key (struct file *f, const char __user *user_buff, size_t s, loff_t *offset)
{
	if (s> 128)
		buff_size2=128;
	else
		buff_size2=s;

	if(copy_from_user(key,user_buff,buff_size2))
		return -EFAULT;

	return buff_size2;
}

static int my_release (struct inode *inode, struct file *f)
{
	module_put(THIS_MODULE);
	return 0;
}

const struct file_operations fops_msg={
.owner=THIS_MODULE,
.open=my_open,
.read=my_read_msg,
.write=my_write_msg,
.release=my_release
};

const struct file_operations fops_key={
	.owner=THIS_MODULE,
	.open=my_open,
	.read=my_read_key,
	.write=my_write_key,
	.release=my_release
};

void rc4(unsigned char * p, unsigned char * k, unsigned char *c, int l)
{
	unsigned char s[256];
	unsigned char t[256];
	unsigned char temp;
	unsigned char kk;
	int i,j,x;
	for(i=0;i<256;i++)
	{
		s[i]=i;
		t[i]=k[ i % 4];
	}
	j=0;
	for(i=0;i<256;i++)
	{
		j=(j+s[i]+t[i])%256;
		temp=s[i];
		s[i]=s[j];
		s[j]=temp;
	}
	i=j=-1;
	for(x=0;x<l;x++)
	{
		i=(i+1)%256;
		j=(j+s[i])%256;
		temp=s[i];
		s[i]=s[j];
		s[j]=temp;
		kk=(s[i]+s[j])%256;
		c[x]=p[x]^s[kk];
	}
}

static ssize_t proc_read_msg(struct file *f, char *buff, size_t s,loff_t *off)
{
	if(strcmp(key,key_proc)==0)
	{
		printk(KERN_ALERT "%s\n", msg);
	}else
	{ 
		printk(KERN_ALERT "%s\n",result); 
	}

	return 0;
}


int proc_open(struct inode *inode, struct file *f)
{
	try_module_get(THIS_MODULE);
	return 0;
}


static ssize_t proc_write_key(struct file *f, const char __user *buff, size_t s, loff_t *off)
{
	int c;

	if(*off>0 || s>128)
		return -EFAULT;
	if(copy_from_user(key_proc,buff,s))
		return -EFAULT;

	c=strlen(key_proc);
	return c;

}

static ssize_t write_msg(struct file *f, const char *buff, size_t s, loff_t *off)
{
	printk(KERN_ALERT "You cannot write in this file \n");
	return -1;
}


int proc_close(struct inode *inode, struct file *f)
{
	module_put(THIS_MODULE);
	return 0;
}

static ssize_t proc_read_key(struct file *f, char *buff, size_t l, loff_t *off)
{
	printk(KERN_ALERT "You cannot read the key\n");
	return 0;
}

static const struct file_operations proc_fops_key={
	.owner=THIS_MODULE,
	.open=proc_open,
	.release=proc_close,
	.read=proc_read_key,
	.write=proc_write_key
};

static const struct file_operations proc_fops_msg={
	.owner=THIS_MODULE,
	.open=proc_open,
	.release=proc_close,
	.read=proc_read_msg,
	.write=write_msg,
};

static int __init fun_init(void)
{
	printk(KERN_ALERT "init \n");
	key=(char*)kmalloc(128,GFP_KERNEL);
	memset(key,NULL,128);
	msg=(char*)kmalloc(4096,GFP_KERNEL);
	memset(msg,NULL,4096);
	key_proc=(char*)kmalloc(128,GFP_KERNEL);
	memset(key_proc,NULL,128);


	register_chrdev_region(MKDEV(2,0),2,"my_cipher");
	
	cdev_init(&cipher,&fops_msg);
	cdev_init(&cipher_key,&fops_key);
	

	cdev_add(&cipher, MKDEV(2,0),1);
       	cdev_add(&cipher_key,MKDEV(2,1),1);

	proc_create("cipher_key",0,NULL,&proc_fops_key);
	proc_create("cipher",0,NULL,&proc_fops_msg);

	return 0;
}

static void __exit fun_cleanup(void)
{
	printk(KERN_ALERT "exit \n");
	cdev_del(&cipher);
	cdev_del(&cipher_key);
	
	unregister_chrdev_region(MKDEV(2,0),2);
	
	remove_proc_entry("cipher",NULL);
	remove_proc_entry("cipher_key",NULL);
}

module_init(fun_init);
module_exit(fun_cleanup);








