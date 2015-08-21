#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/fsnotify.h>

#include "ext4.h"
#include "ext4_jbd2.h"

struct kmem_cache *ext4_unrm_node_cachep;

extern int ext4_add_entry(handle_t *handle, struct dentry *dentry,
			  struct inode *inode);
extern void ext4_dec_count(handle_t *handle, struct inode *inode);

void ext4_unrm_prune(struct work_struct *work)
{
	struct ext4_unrm_node *node;
	struct radix_tree_root *root;
	struct inode *dir, *inode;
	handle_t *handle;

	node = container_of(work, struct ext4_unrm_node, work.work);
	root = node->s_unrm;
	dir = node->dir;
	inode = node->inode;

	mutex_lock(&inode->i_mutex);
	handle = ext4_journal_start(dir, EXT4_HT_DIR,
				    EXT4_DATA_TRANS_BLOCKS(dir->i_sb));
	if (IS_ERR(handle)) {
		mutex_unlock(&inode->i_mutex);
		return;
	}

	if (node->is_dir)
		ext4_unrm_finish_rmdir(handle, dir, inode);
	else
		ext4_unrm_finish_unlink(handle, inode);

	mutex_unlock(&inode->i_mutex);

	list_del(&node->list);

	if (list_empty(node->dirlist)) {
		radix_tree_delete(root, dir->i_ino);
		kfree(node->dirlist);
	}

	kmem_cache_free(ext4_unrm_node_cachep, node);

	if (handle)
		ext4_journal_stop(handle);

}

int ext4_unrm_save(struct inode *dir, struct dentry *dentry, bool is_dir)
{
	struct radix_tree_root *root;
	struct ext4_sb_info *sbi;
	struct inode *inode;
	struct ext4_unrm_node *newnode;
	struct list_head *dirlist;
	int err, delay;

	inode = dentry->d_inode;
	sbi = inode->i_sb->s_fs_info;
	root = &(sbi->s_unrm);
	delay = 30000;

	newnode = kmem_cache_alloc(ext4_unrm_node_cachep, GFP_KERNEL);
	if (!newnode)
		return -ENOMEM;
	newnode->inode = inode;
	newnode->dentry = dentry;
	newnode->dir = dir;
	newnode->s_unrm = root;
	newnode->is_dir = is_dir;

	INIT_DELAYED_WORK(&newnode->work, ext4_unrm_prune);
	err = queue_delayed_work(sbi->unrm_wq, &newnode->work,
				msecs_to_jiffies(delay));

	if (!err) {
		ext4_msg(sb, KERN_ERR,
			 "unrm: Unable to queue delayed work, aborting");
		goto error;
	}

	dirlist = radix_tree_lookup(root, dir->i_ino)
	if (dirlist) {
		newnode->dirlist = dirlist;
		list_add_tail(&newnode->list, dirlist);
	} else {
		dirlist = kmalloc(sizeof(struct list_head), GFP_KERNEL);
		INIT_LIST_HEAD(dirlist);
		list_add(&newnode->list, dirlist);

		newnode->dirlist = dirlist;
		radix_tree_insert(root, dir->i_ino, dirlist);
	}

	/*
	 * Do not destroy our dentry yet, a dentry won't
	 * be destroyed when it still has references
	 * to it
	 */
	dget(dentry);

	return 0;

error:
	kmem_cache_free(ext4_unrm_node_cachep, newnode);
	return err;
}

int init_unrm_node_cache(void)
{
	ext4_unrm_node_cachep = kmem_cache_create("ext4_unrm_node_cache",
			sizeof(struct ext4_unrm_node),
			0, SLAB_PANIC,
			NULL);
	if (!ext4_unrm_node_cachep)
		return -ENOMEM;

	return 0;
}

void destroy_unrm_node_cache(void)
{
	rcu_barrier();
	kmem_cache_destroy(ext4_unrm_node_cachep);
}

void ext4_unrm_init(struct ext4_sb_info *sbi)
{
	INIT_RADIX_TREE(&sbi->s_unrm, GFP_KERNEL|GFP_ATOMIC);
	if (!sbi->unrm_wq)
		sbi->unrm_wq = create_singlethread_workqueue("unrm_wq");
}

void ext4_unrm_cleanup(struct ext4_sb_info *sbi)
{
	if (sbi->unrm_wq) {
		flush_workqueue(sbi->unrm_wq);
		destroy_workqueue(sbi->unrm_wq);
	}
}

void ext4_unrm_finish_rmdir(handle_t *handle, struct inode *dir,
				struct inode *inode)
{
	atomic_set(&inode->i_count, 1);
	inode->i_version++;
	clear_nlink(inode);
	inode->i_size = 0;
	ext4_orphan_add(handle, inode);
	inode->i_ctime = dir->i_ctime = dir->i_mtime = ext4_current_time(inode);
	ext4_mark_inode_dirty(handle, inode);
	ext4_dec_count(handle, dir);
	ext4_update_dx_flag(dir);
	ext4_mark_inode_dirty(handle, dir);

	iput(inode);
}

/*
 * ext4_unrm_finish_unlink
 * aka The point of no return
 */
void ext4_unrm_finish_unlink(handle_t *handle, struct inode *inode)
{

	/* BUG: lookup_fast fails and every rm->unrm->rm
	 * sequence of actions on a particular file
	 * results in an accumulation of igets :-\
	 * Use atomic_set as temp fix, we should
	 * be the only users of the inode at this point...
	 */
	atomic_set(&inode->i_count, 1);
	drop_nlink(inode);
	if (!inode->i_nlink)
		ext4_orphan_add(handle, inode);
	inode->i_ctime = ext4_current_time(inode);
	ext4_mark_inode_dirty(handle, inode);

	iput(inode); /* will call evict! */
}

int ext4_do_unrm(struct super_block *sb, struct inode *dir)
{
	struct ext4_sb_info *sbi;
	struct radix_tree_root *root;
	struct list_head *dirlist;
	struct ext4_unrm_node *node, *safenode;
	handle_t *handle;
	int err;
	bool success;

	sbi = EXT4_SB(sb);
	root = &sbi->s_unrm;
	dirlist = radix_tree_lookup(root, dir->i_ino);

	if (!dirlist || list_empty(dirlist))
		return 0; /* then we're just done, nothing to do */

	/* Begin questionable shenanigans */
	list_for_each_entry_safe(node, safenode, dirlist, list) {
		/* Cancel delayed work */
		success = cancel_delayed_work(&node->work);
		if (!success) {
			ext4_msg(sb, KERN_ERR,
				 "do unrm: Unable to do unrm, cannot cancel delayed work");
			goto out;
		}

		handle = ext4_journal_start(dir, EXT4_HT_DIR,
					    EXT4_DATA_TRANS_BLOCKS(sb));
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		node->inode->i_ctime = ext4_current_time(node->inode);

		err = ext4_add_entry(handle, node->dentry, node->inode);
		if (!err) {
			if (!node->dentry->d_inode)
				d_instantiate(node->dentry, node->inode);

			ext4_mark_inode_dirty(handle, dir);

			if (IS_DIRSYNC(dir))
				ext4_handle_sync(handle);

		} else {
			ext4_journal_stop(handle);
			return err;
		}

		ext4_journal_stop(handle);

		list_del(&node->list);

out:
		if (list_empty(node->dirlist)) {
			radix_tree_delete(root, dir->i_ino);
			kfree(node->dirlist);
		}
		if (node->is_dir) {
			node->dentry->d_inode->i_flags &= ~S_DEAD;
			fsnotify_mkdir(dir, node->dentry);
			ext4_do_unrm(sb, node->inode);
		}
		kmem_cache_free(ext4_unrm_node_cachep, node);
	}

	return 0;
}
