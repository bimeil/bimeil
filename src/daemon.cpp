#include <atomic>
#include <mutex>
#include <cstring>
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <signal.h>
#include <unistd.h>
#include <thread>
#include <cstdio>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/wait.h>

#include "base64.h"
#include "lib.h"
#include "main.h"

#define USE_THREAD 0 //You'd only want this on to debug. You'll need to keep main from exiting

using namespace std;

const char app_run_dir[]="/run/bimeil/";
char inbuf[1024*4], outbuf[1024*4];
string worker_daemon_name, worker_src_fn;
int global_ro=1;
map<string, pid_t> workers;
static struct sigaction old_SA_RESTART;

void worker_daemon(const string&fn, int s);

///////////////////////////////////////////////////////////////////

GuardT<int> make_server(const char*path) {
	GuardT<int> s(socket(AF_UNIX, SOCK_STREAM, 0), close);
	if(s<=0) {
		perror("Server socket error:");
		throw std::exception();
	}
	struct sockaddr_un local;
	memset(&local, 0, sizeof(local));
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, path);
	
	auto len = strlen(local.sun_path) + sizeof(local.sun_family);

	if (bind((int)s, (struct sockaddr *)&local, len) == -1) {
		if(errno == EADDRINUSE)
			return GuardT<int>(0, 0);
		perror("Server bind error");
		throw std::exception();
	}
	if (listen(s, 5) == -1) {
		perror("Server listen error:");
		throw std::exception();
	}

	int flag = 1;
	//int result =
	setsockopt((int)s, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

	return move(s);
}

GuardT<int> wait_conn(int s) {
	struct sockaddr_un remote;
	socklen_t t = sizeof(remote);
	GuardT<int> s2(accept(s, (struct sockaddr *)&remote, &t), close);
	if (s2<=0) {
		perror("accept");
		throw std::exception();
	}
	return move(s2);
}

GuardT<int> make_client(const char*socket_path)
{
	GuardT<int> s(socket(AF_UNIX, SOCK_STREAM, 0), close);
	struct sockaddr_un remote;
	memset(&remote, 0, sizeof(struct sockaddr_un));
	if (s <= 0) {
		perror("socket");
		throw std::exception();
	}
	
	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, socket_path);
	auto len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		if(errno==ECONNREFUSED)
			return GuardT<int>(0,0);
		perror("connect");
		throw std::exception();
	}
	
	int flag = 1;
	//int result =
	setsockopt((int)s, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
	return move(s);
}

bool forward_worker_daemon(ssize_t daemon_bytes, int cs) 
{
	string fn, ln_dir, pw;
	const char*p=&inbuf[10];
	fn = p;
	p+=fn.size()+1;
	ln_dir=p;

	string path = realpath(fn.c_str(), 0);
	if(path=="") {
		outbuf[0]=BadPath;
		send(cs, outbuf, 1, 0);
		return 0;
	}

	//wfn == worker file name. There's also 'worker_src_fn' which is the regular fn
	string wfn=app_run_dir;
	wfn+="w_" + EscapeFilePath(fn.c_str());

	for(int tries=0; tries<2; ++tries)
	{
		pid_t child=0;
		auto wsrv = make_server(wfn.c_str());
		if((int)wsrv != 0) {
			if(USE_THREAD) {
				std::thread([wsrv2=move(wsrv), wfn, fn]() mutable{
					EXIT([&]{rmdir(wfn.c_str());});
					worker_daemon(fn, (int)wsrv2);
				}).detach();
			}
			else {
				child=fork();
				if(child<0) {
					perror("Worker fork failed");
					throw std::exception();
				}
				else if(child==0) {
					EXIT([&]{rmdir(wfn.c_str());});
					worker_daemon(fn, (int)wsrv);
					return true;
				}
				else {
					wsrv.clear();
				}
			}
		}
		//ws == worker socket
		auto ws = make_client(wfn.c_str());
		if((int)ws==0){
			unlink(wfn.c_str());
			continue;
		}
		else if ((int)ws<0) {
			perror("Couldn't connect to worker");
			throw std::exception();
		}
		
		//This is used in the signal handler to quit if no more child workers are running
		if(child!=0)
			workers.insert(make_pair(fn, child));
		
		if(send(ws, inbuf, daemon_bytes, 0)!=daemon_bytes) {
			fprintf(stderr, "send return incorrect amount in forward_worker_daemon\n");
			throw std::exception();
		}
		auto l = recv(ws, inbuf, sizeof inbuf, 0);
		if(l>0) {
			send(cs, inbuf, l, 0);
		}		
		break;
	}
	return 0;
}

void self_exit() {
	if(workers.size()!=0)
		return;
	//send a msg to ourself to exit
	std::thread([]{
		char b[1];
		b[0]=qc_daemon_close;
		auto s = connect_daemon();
		send(s, b, 1, 0);
	}).detach();
}

void my_sigchld_handler(int sig) {
	pid_t p;
	int status;
	while ((p=waitpid(-1, &status, WNOHANG)) != -1)
	{
		for(auto i=workers.begin(); i!=workers.end(); ++i){
			if(i->second == p)
				workers.erase(i);
		}
	}
	self_exit();
}

void do_daemon(int s) {
	set_process_name("D");
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = my_sigchld_handler;
		sa.sa_flags = SA_RESTART;
		sigaction(SIGCHLD, &sa, &old_SA_RESTART);
	}
	while(1) {
		auto cs = wait_conn(s);
		if(cs<=0) {
			perror("do_daemon error 1");
			throw std::exception();
		}
		int l2=0;
		if((l2=recv(cs, inbuf, sizeof(inbuf), 0))==1 && inbuf[0]==qc_ping)
		{
			outbuf[0]=qc_ping;
			send(cs, outbuf, 1, 0);
		}
		else
		{
			printf("ping error %d %d\n", l2, inbuf[0]);
			throw std::exception();
		}

		auto recv_len = recv(cs, inbuf, sizeof(inbuf), 0);
		if(recv_len<=0) {
			perror("do_daemon error 2");
			throw std::exception();
		}
		
		switch(inbuf[0]) {
		case qc_ping:
			outbuf[0]=qc_ping;
			send(cs, outbuf, 1, 0);
			continue;
		case qc_daemon_close:
			if(workers.size()==0) throw ExitException(); else continue;
		case qc_mount:
		case qc_create_drive:
			forward_worker_daemon(recv_len, cs);
			break;
		case qc_umount_file:
			{
				string umount_fn = (const char*)&inbuf[10];
				if(umount_fn == "--all") {
					for(auto i=workers.begin(); i!=workers.end(); ++i)
					{
						auto& fn = i->first;
						string wfn=app_run_dir;
						wfn+="w_" + EscapeFilePath(fn.c_str());
						
						auto ws = make_client(wfn.c_str());
						if((int)ws>0) {
							if(send(ws, inbuf, recv_len, 0)!=recv_len)
								continue;
							if(recv(ws, outbuf, sizeof outbuf, 0)!=1)
								continue;
						}
					}
					char t=0;
					send(cs, &t, 1, 0);
				}
				else {
					string wfn=app_run_dir;
					wfn+="w_" + EscapeFilePath(umount_fn.c_str());
					auto ws = make_client(wfn.c_str());
					if((int)ws<=0) {
						char c = -1;
						send(cs, &c, 1, 0);
						break;
					}
					if(send(ws, inbuf, recv_len, 0)!=recv_len || recv(ws, outbuf, sizeof outbuf, 0)!=1)
					{
						char t=-1;
						send(cs, &t, 1, 0);
					}
					send(cs, outbuf, 1, 0);
				}
			}
			self_exit();
			break;
		case qc_list:
			{
				for(auto i=workers.begin(); i!=workers.end(); ++i)
				{
					auto& fn = i->first;
					string wfn=app_run_dir;
					wfn+="w_" + EscapeFilePath(fn.c_str());
					
					auto ws = make_client(wfn.c_str());
					if((int)ws>0) {
						char qclist = qc_list;
						send(ws, &qclist, 1, 0);
						int l;
						while((l=recv(ws, inbuf, sizeof(inbuf), 0))>0)
							send(cs, inbuf, l, 0);
					}
				}
				char t=0;
				send(cs, &t, 1, 0);
			}
			break;
		case qc_add_drive:
			{
				bool hit=false;
				memcpy(outbuf, inbuf, recv_len);
				//We don't know which worker has the ID so we send the msg to all.
				for(auto i=workers.begin(); i!=workers.end(); ++i)
				{
					auto& fn = i->first;
					string wfn=app_run_dir;
					wfn+="w_"+ EscapeFilePath(fn.c_str());
					auto ws = make_client(wfn.c_str());
					if((int)ws>0) {
						send(ws, &outbuf, recv_len, 0);
						auto bytes = recv(ws, inbuf, sizeof(inbuf), 0);
						if(bytes != 1) {
							fprintf(stderr, "Unexpected recv amount in D add_drive\n");
						}
						if(*inbuf != -1) {
							send(cs, inbuf, 1, 0);
							hit = true;
							break;
						}
					}
				}
				if(hit==false) {
					char t=-1;
					send(cs, &t, 1, 0);
				}
			}
			break;
		default:
			printf("Daemon error: Unknown command %d \n", inbuf[0]);
			throw std::exception();
		}
	}
	throw std::exception();
}

GuardT<int> connect_daemon() {
	mkdir(app_run_dir, 0770);
	
	string mfn=app_run_dir;
	mfn+="daemon";
	
	for(int tries=0; tries<2; ++tries) {
		auto ds = make_server(mfn.c_str());
		if((int)ds != 0) {
			if(USE_THREAD){
				std::thread([ds2=move(ds)]() mutable {do_daemon(ds2);}).detach();
			}
			else{
				pid_t child=fork();
				if(child<0) {
					perror("Fork failed");
					throw std::exception();
				}
				else if(child==0) {
					do_daemon(ds);
					throw ExitException();
				}
				else {
					ds.clear();
				}
			}
		}
		
		auto cs = make_client(mfn.c_str());
		if((int)cs==0) {
			unlink(mfn.c_str());
			continue;
		}
		if(cs<=0) {
			perror("Couldn't connect to daemon");
			throw std::exception();
		}

		outbuf[0]=qc_ping;
		send(cs, outbuf, 1, 0);

		int bytes;
		if((bytes=recv(cs, inbuf, sizeof(inbuf), 0))<=0){
			printf("Error on recv in connect_daemon %d\n", bytes);
			throw std::exception();
		}
		return move(cs);
	}
	throw std::exception();
}

////////////////////////// Worker Daemon //////////////////////////

mutex mount_mutex;
vector<Drive*> mounted;

void do_mount_logic(const string&fn, const string&symlinkfn, int ro) {
	auto drives_map = lib_list(fn.c_str());
	mount_mutex.lock();
	int multi_add = (drives_map->size()>mounted.size()+1)?2:0;
	for(auto i=drives_map->begin(); i!=drives_map->end(); ++i) {
		auto drive = i->second.get();
		if(find(mounted.begin(), mounted.end(), drive)!=mounted.end())
			continue;
		my_fuse_mount(symlinkfn, (ro?1:0)|multi_add, drive, "");
		mounted.push_back(drive);
	}
	mount_mutex.unlock();
}
void daemon_untrack(const Drive*p) {
	mount_mutex.lock();
	mounted.erase(remove(mounted.begin(), mounted.end(), p), mounted.end());
	mount_mutex.unlock();
}
WARN int worker_daemon_mount(bool ro, const string& fn, const string& pw, const string& symlinkfn, s64 rounds)
{
	auto ret = lib_mount(ro, fn.c_str(), pw.c_str(), rounds);
	if(ret == 0)
		do_mount_logic(fn, symlinkfn, ro);
	return ret;
}
WARN int worker_daemon_create(const string& fn, const string& pw, s64 rounds, const string& linkFn, const string& type, int cipher, bool overwrite)
{
	Drive *p;
	auto ret = lib_createdrive(fn.c_str(), pw.c_str(), rounds, cipher, overwrite, &p);
	if(ret != 0 || type=="-")
		return ret;

	my_fuse_mount(linkFn, 0, p, type);
	mount_mutex.lock();
	mounted.push_back(p);
	mount_mutex.unlock();
	return ret;
}

void worker_daemon(const string&fn, int s) {
	set_process_name("W");
	sigaction(SIGCHLD, &old_SA_RESTART, 0);

	auto libcleanup = lib_init2();

	worker_daemon_name=app_run_dir;
	worker_daemon_name+="w_" + EscapeFilePath(fn.c_str());
	worker_src_fn = fn;
	
	SetupFuse(lib_get_size_of_file(fn));
	while(1) {
		auto w = wait_conn(s);
		ssize_t bytes;
		bytes = recv(w, inbuf, sizeof(inbuf), 0);
		if(bytes <= 0) {
			continue;
		}
		
		switch(inbuf[0]) {
		case qc_mount:
			{
				string fn, pw, mp;
				s64 rounds;
				memcpy(&rounds, &inbuf[1], 8);
				bool ro = inbuf[9];
				const char*p=&inbuf[10];
				fn = p;
				p+=fn.size()+1;
				pw=p;
				p+=pw.size()+1;
				mp=p;
				global_ro = ro;
				int ret = worker_daemon_mount(ro, fn, pw, mp, rounds);
				outbuf[0]=ret;
				send(w, outbuf, 1, 0);
			}
			break;
		case qc_create_drive:
			{
				string fn, pw, linkFn, type;
				s64 rounds;
				memcpy(&rounds, &inbuf[1], 8);
				char flags = inbuf[9];
				auto overwrite = (flags&2)!=0;
				auto cipher = flags>>2;
				const char*p=&inbuf[10];
				fn = p;
				p+=fn.size()+1;
				pw=p;
				p+=pw.size()+1;
				linkFn=p;
				p+=linkFn.size()+1;
				type=p;
				auto ret = worker_daemon_create(fn, pw, rounds, linkFn, type, cipher, overwrite);
				outbuf[0]=ret;
				send(w, outbuf, 1, 0);
			}
			break;
		case qc_umount_file:
			for(auto i = mount_points.begin(); i<mount_points.end(); ++i) {
				auto clear_mp = i->second;
				string umount_fuse = "umount " + clear_mp;
				system(umount_fuse.c_str());
				rmdir(clear_mp.c_str());
				umount_fuse = "umount " + i->first;
				system(umount_fuse.c_str());
				rmdir(i->first.c_str());
			}
			//fallthrough
		case qc_umount_file_followup:
			{
				int allUnloaded=0;
				for(int i=0; i<100;++i) {
					if(mount_count_fuse==0) {
						allUnloaded=1;
						usleep(10000);
						break;
					}
				}
				outbuf[0] = allUnloaded ? 0 : couldnt_umount;
				send(w, outbuf, 1, 0);
				if(allUnloaded) {
					throw ExitException();
				}
			}
			break;
		case qc_list:
			{
				auto m = lib_list(worker_src_fn.c_str());
				auto p = &outbuf[0];
				p[0]=0;
				for(auto i = m->begin(); i != m->end(); ++i) {
					auto base64id = base64_encode(lib_drive_id(i->second.get()), 3);
					strcat(p, base64id.c_str());
					p+=base64id.size();
					*p++='\n';
				}
				send(w, outbuf, p-outbuf, 0);
			}
			break;
		case qc_add_drive:
			{
				string id, pw;
				s64 rounds;
				memcpy(&rounds, &inbuf[1], 8);

				const char*p=&inbuf[10];
				id = p;
				p+=id.size()+1;
				pw=p;

				auto drive_temp = base64_decode(id);
				auto pdrive = lib_find_drive(worker_src_fn.c_str(), drive_temp.c_str());
				if(pdrive) {
					auto v = lib_add_drive(pw.c_str(), rounds, pdrive);
					if(v == 0)
						do_mount_logic(worker_src_fn, "", global_ro);
					send(w, &v, 1, 0);
				}
				else {
					char v=-1;
					send(w, &v, 1, 0);
				}
			}
			break;
		default:
			printf("Daemon worker: Unknown command %d\n", inbuf[0]);
			throw std::exception();
		}
	}
	fprintf(stderr, "Error: Unexpected exit of worker_daemon loop\n");
	throw std::exception();
}
