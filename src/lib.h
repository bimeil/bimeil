#include <memory>
#include <map>
#include <string>
#include <exception>
#include <functional>

#define WARN __attribute__((warn_unused_result))

typedef unsigned char u8;
typedef unsigned int u32;
static_assert(sizeof(u32) == 4, "u32 is incorrect");
typedef unsigned long long u64;
static_assert(sizeof(u64) == 8, "u64 is incorrect");
typedef long long s64;
static_assert(sizeof(s64) == 8, "s64 is incorrect");

#define TOKENPASTE(x, y) x ## y
#define TOKENPASTE2(x, y) TOKENPASTE(x, y)
#define EXIT Guard TOKENPASTE2(guard_, __LINE__)

class Guard { std::function<void()> f; public: Guard(std::function<void()> f):f(f){} ~Guard() { f(); } };
template<class T> class GuardT{
	T v; std::function<void(T)> f;
public:
	GuardT(T v, std::function<void(T)> f): v(v), f(f){}
	GuardT(GuardT&& g) { v=g.v; f=g.f; g.clear(); }
	~GuardT() { if(f)f(v); }
	operator T() { return v; }
	void clear() { v=0; f=0; }
	T get() { return v; }
};

//////////////////////////////////////////////////

enum MountError : u8 { MountError_ok = 0, BadPath, invalidPass, user_inconsistant_blocksize, already_mounted, 
	UnsupportedVersion, page_in_use, error_on_write, couldnt_umount, no_kh_space, 
	driveExist, kh_exist, corrupted_link_page, CantCreateDriveMounted,
	internalErrorSha = 64, internalErrorPread,
};

class Drive;

enum { DRIVE_VERSION = 0, BLOCK_SIZE = 1024 * 32, AES_KEY_BITS = 128 };

WARN MountError lib_mount(bool ro, const char*path, const char*pw, s64 rounds);
void lib_unmount(Drive*p);
WARN MountError lib_createdrive(const char*path_, const char*pw, s64 rounds, int cipher, bool overwrite, Drive **pp);
WARN MountError lib_fill(int fd, s64 amount_of_blocks);
WARN s64 lib_device_size(Drive*p);
s64 lib_get_size_of_file(const std::string&path);
WARN MountError lib_add_drive(const char*pw, s64 rounds, Drive *p);


WARN const std::map<u32, std::unique_ptr<Drive> > * lib_list(const char*path_);

WARN int lib_read(void *buf, size_t size, size_t offset, Drive*p);
WARN int lib_write(const void *buf, size_t size, size_t offset, Drive*p);
WARN const u8* lib_drive_id(Drive*p);
WARN Drive* lib_find_drive(const char*fn, const char*id);

Guard lib_init2(); //WARNING this cleanups when it goes out of scope. During the call it may throw an exception
//WARN int lib_init(); //The above is more simple
void lib_cleanup();
WARN std::string EscapeFilePath(const char*l);
WARN std::string myrealpath(const char*path_);
uint64_t GetBlockSize64(int fd);

enum QueueCommand { qc_ping=1, qc_retry, qc_mount, qc_umount_file, qc_umount_file_followup, qc_create_drive, qc_list, qc_add_drive, qc_daemon_close };
