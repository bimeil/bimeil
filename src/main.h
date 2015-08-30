#include <atomic>
#include <vector>
GuardT<int> make_server(const char*path);
GuardT<int> wait_conn(int s);
GuardT<int> make_client(const char*socket_path);

GuardT<int> connect_daemon();

extern char inbuf[1024*4], outbuf[1024*4];
extern const char app_run_dir[];

extern int main_argc;
extern char **main_argv;

void set_process_name(const char*name_);
std::string get_directory(const std::string&fn);

extern std::atomic<int> mount_count_fuse;
extern std::vector<std::pair<std::string, std::string> > mount_points;
void SetupFuse(size_t size);
void my_fuse_mount(const std::string&link_path, int flags, Drive*pdrive, std::string fs_type);
extern std::string client_name, worker_daemon_name;

class ExitException : public std::exception {};
