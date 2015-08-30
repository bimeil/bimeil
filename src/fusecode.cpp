#include <atomic>
#include <string.h>
#include <unistd.h>
#include <thread>
#include <sstream>
#include <vector>
#include <sys/socket.h>

#define FUSE_USE_VERSION 30
#include <fuse.h>

#include "lib.h"
#include "base64.h"
#include "main.h"

using namespace std;

static struct stat device_stat;
static struct fuse_operations my_oper;

std::atomic<int> mount_count_fuse(0);
vector< pair<string, string> > mount_points;

static int my_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	if (strcmp(path, "/") != 0)
		return -ENOENT;
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, "data", NULL, 0);
	return 0;
}

static int my_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;
	if (strcmp(path, "/") == 0) {
		memset(stbuf, 0, sizeof(struct stat));
		stbuf->st_mode = S_IFDIR | 0777;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, "/data") == 0) {
		memcpy(stbuf, &device_stat, sizeof(struct stat));
	} else
		res = -ENOENT;
	return res;
}

static int my_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	auto p = (class Drive*)fuse_get_context()->private_data;
	return lib_read(buf, size, offset, p);
}
static int my_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	auto p = (class Drive*)fuse_get_context()->private_data;
	return lib_write(buf, size, offset, p);
}

static void *my_init(struct fuse_conn_info *conn) { return fuse_get_context()->private_data; }

void SetupFuse(size_t size)
{
	memset(&my_oper, 0, sizeof(my_oper));
	my_oper.init = my_init;
	my_oper.readdir = my_readdir;
	my_oper.getattr = my_getattr;
	my_oper.read = my_read;
	my_oper.write = my_write;

	memset(&device_stat, 0, sizeof(device_stat));
	//device_stat.st_mode = S_IFBLK | 0770;
	device_stat.st_mode = S_IFREG | 06660;
	device_stat.st_nlink = 1;
	device_stat.st_size = size;
	device_stat.st_blksize = BLOCK_SIZE;
	device_stat.st_blocks = size/512;
}

void my_fuse_mount(const string&link_path, int flags, Drive*pdrive, string fs_type) {
	auto txt_id = base64_encode(lib_drive_id(pdrive), 3);
	mkdir(app_run_dir, 0770);
	string fuse_mp_encypt = app_run_dir;
	string fuse_mp_clear  = app_run_dir;
	
	fuse_mp_encypt+= "encypt/";
	fuse_mp_clear += "clear/";
	mkdir(fuse_mp_encypt.c_str(), 0770);
	mkdir(fuse_mp_clear.c_str(), 0770);
	
	fuse_mp_encypt+= txt_id;
	fuse_mp_clear += txt_id;
	mkdir(fuse_mp_encypt.c_str(), 0770);
	mkdir(fuse_mp_clear.c_str(), 0770);
	
	std::thread([fuse_mp_encypt, pdrive, link_path] {
		GuardT<char*> foreground(strdup("-f"), free);
		GuardT<char*> single_thread(strdup("-s"), free);
		GuardT<char*> mount_point(strdup(fuse_mp_encypt.c_str()), free);
		char* fuse_argv[4] = {main_argv[0], foreground, single_thread, mount_point};
		++mount_count_fuse;
		fuse_main(4, fuse_argv, &my_oper, pdrive);
		--mount_count_fuse;
		rmdir(fuse_mp_encypt.c_str());
		lib_unmount(pdrive);
		if(link_path!="")
			unlink(link_path.c_str());
		if(mount_count_fuse==0) {
			auto ws = make_client(worker_daemon_name.c_str());
			char v = qc_umount_file_followup;
			send(ws, &v, 1, 0);
		}
	}).detach();
	string fuse_data = fuse_mp_encypt + "/data";

	//Fuse has an init but no 'ready' callback.
	bool mounted=0;
	for(int i=0; i<10; ++i) {
		struct stat s;
		if(stat(fuse_data.c_str(), &s)!=0) {
			usleep(100000);
			continue;
		}
		mounted=1;
		break;
	}
	if(mounted==0) {
		fprintf(stderr, "It appears we failed to mount %s\n", txt_id.c_str());
		throw std::exception();
	}

	if(fs_type!="")
	{
		//If we're here we created the drive and initalizing it.
		stringstream ss;
		ss << "mkfs -t " << fs_type << " " << fuse_data;
		system(ss.str().c_str());
	}

	mount_points.push_back(make_pair(fuse_mp_encypt, fuse_mp_clear));

	stringstream ss;
	if(flags&1)
		ss << "mount -o loop,ro " << fuse_data << " " << fuse_mp_clear;
	else
		ss << "mount -o loop "    << fuse_data << " " << fuse_mp_clear;
	system(ss.str().c_str());
	if(link_path != "") {
		if(flags&2){
			string d = app_run_dir;
			d+="clear/";
			symlink(d.c_str(), link_path.c_str());
		}
		else
			symlink(fuse_mp_clear.c_str(), link_path.c_str());
	}
}
