#include <iostream>
#include <map>
#include <memory>
#include <ctime>
#include <vector>
#include <algorithm>
#include <cstring>
#include <string>
#include <unistd.h>
#include <functional>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <thread>
#include <fcntl.h>

#include <termios.h>

using namespace std;
#include "lib.h"
#include "crypt.h"
#include "main.h"

int main_argc;
char **main_argv;

#define VERSION_STRING "0.1 beta"
const s64 default_rounds = 500000;

static char linebuf[1024*4];

//This is used to hide the arguements from ps. It's hacky but appears to work.
void set_process_name(const char*name_) {
	string name="bimeil ";
	name += name_;
	memset(main_argv[0], 0, strlen(main_argv[main_argc-1])+(main_argv[main_argc-1]-main_argv[0]));
	strcpy(main_argv[0], name.c_str());
}


//WARNING does not support negative values. A negative value mean an error.
//These values are 1 off from an overflow error. 20M and 20m mean the same thing. Lower case m is not mebibytes
//printf("%lld\n", myatol("8388607t"));
//printf("%lld\n", myatol("8796093022207M"));
s64 myatol(const char*p) {
	s64 v=0;
	//ignore leading spaces
	while(*p == ' ')
		++p;
	while(*p>='0' && *p<='9')
	{
		v*=10;
		v+= *p-'0';
		++p;
	}
	if(v==0)
		return -1;
	if (*p==0)
		return v;

	s64 pre_shift = v;
	switch(*p|32) { //make upper case ascii letters into lower case
	case 'k': v<<=10; if(v>>10!=pre_shift) return -4; break;
	case 'm': v<<=20; if(v>>20!=pre_shift) return -4; break;
	case 'g': v<<=30; if(v>>30!=pre_shift) return -4; break;
	case 't': v<<=40; if(v>>40!=pre_shift) return -4; break;
	default: return -2;
	}
	++p;
	//ignore trailing spaces
	while(*p == ' ')
		++p;
	if(*p!=0)
		return -3;
	return v;
}
WARN string get_directory(const string&fn) {
	size_t i;
	for(i=fn.size()-1; i>0&&fn[i]!='/'; --i)
	{}
	string a;
	a.append(fn[0], fn[i]);
	return a;
}
ssize_t getpass() {
	struct termios o, t;
	linebuf[0]=0;
	if (tcgetattr(fileno(stdin), &o) != 0)
		return -1;
	t = o;
	t.c_lflag &= ~ECHO;
	if (tcsetattr (fileno(stdin), TCSAFLUSH, &t) != 0)
		return -1;
	cin.getline(linebuf, sizeof linebuf);
	(void) tcsetattr(fileno(stdin), TCSAFLUSH, &o);
	return 0;
}

void print_help() {
	printf("mount [rw|ro] [filename] [-l directory] [-p passphrase] [-r rounds]\n");
	printf("umount [filename|all|-all|--all|-a|--a]\n");
	printf("create n [filename] [-s size] #new file\n");
	printf("create a [filename] [-s size] #append file\n");
	printf("create d [filename] [-p passphrase] [-r rounds] [-l directory] [-t fs_type] [-c cipher] [--overwrite] #create drive\n");
	printf("add [drive_id] [-p passphrase] [-r rounds]\n");
	printf("list\n");
	printf("time [rounds|'cipher']\n");
	printf("version (" VERSION_STRING ")\n");
	printf("\nYou may use first letter of each command. Refer to documentation for more info\n");
	printf("Warning it is easy to lose data. Read about this in the documentation\n");
}

void recv_cmd(int s, const string& errmsg) {
	int bytes;
	if((bytes=recv(s, inbuf, sizeof(inbuf), 0))!=1) {
		fprintf(stderr, "Error in recv_cmd. Unexpected amount of bytes (%d)\n", bytes);
		return;
	}
	u8 v = *inbuf;
	switch(v) {
	case 255: fprintf(stderr, "Error %s\n", errmsg.c_str()); break;
	case MountError_ok: break; //Don't need to say anything
	case BadPath: fprintf(stderr, "Bad filename\n"); break;
	case invalidPass: fprintf(stderr, "Invalid password\n"); break;
	case already_mounted: fprintf(stderr, "Drive mounted\n"); break;
	case driveExist: fprintf(stderr, "Will not create. Drive already exists\n"); break;
	case no_kh_space: fprintf(stderr, "Could not add drive. No empty slot\n"); break;
	case kh_exist: fprintf(stderr, "Drive already linked\n"); break;
	case page_in_use: fprintf(stderr, "Can't create drive. Location is already in use. Try another passphrase\n"); break;
	case corrupted_link_page: fprintf(stderr, "Link page corrupted\n"); break;
	case CantCreateDriveMounted: fprintf(stderr, "Can't overwrite. Drive is currently mounted\n"); break;
	default:
		fprintf(stderr, "Err #%d\n", v); break;
	}
}

void createdrive(const string& rel_fn, const string& pw, s64 rounds, const string& linkFn, const string& type, Cipher cipher, bool overwrite)
{
	string fn = myrealpath(rel_fn.c_str());
	if(fn == "") {
		fprintf(stderr, "Bad filepath: %s\n", rel_fn.c_str());
		return;
	}
	if((fn.size() + pw.size() + linkFn.size() + type.size() + 4 + 10)>sizeof(inbuf))
	{
		fprintf(stderr, "absolute fn||pw||link||type is too long\n");
		throw std::exception();
	}

	auto s = connect_daemon();
	outbuf[0] = qc_create_drive;
	memcpy(&outbuf[1], &rounds, 8);
	outbuf[9] = (overwrite?2:0)|(cipher<<2);
	char*p=&outbuf[10];
	memcpy(p, fn.c_str(), fn.size()+1);
	p+=fn.size()+1;
	memcpy(p, pw.c_str(), pw.size()+1);
	p+=pw.size()+1;
	memcpy(p, linkFn.c_str(), linkFn.size()+1);
	p+=linkFn.size()+1;
	memcpy(p, type.c_str(), type.size()+1);
	p+=type.size()+1;

	send(s, outbuf, p - outbuf, 0);

	recv_cmd(s, "create drive");
}
void create(char mode, const string& rel_fn, s64 size) {
	string fn;
	s64 block_amount = size / BLOCK_SIZE;
	if(block_amount > UINT32_MAX-1) {
		fprintf(stderr, "Error: File too large. Exiting\n");
		throw std::exception();
	}
	if(mode == 'a')
	{
		fn = myrealpath(rel_fn.c_str());
		if(fn == ""){
			fprintf(stderr, "File to append does not exist. \"%s\"\n", rel_fn.c_str());
			return;
		}

		auto libcleanup = lib_init2();

		struct stat64 s;
		stat64(fn.c_str(), &s);
		GuardT<int> fd(open(fn.c_str(), O_RDWR | O_LARGEFILE | O_APPEND), close);
		if (fd <= 0) {
			perror("Error on openA in create");
			throw std::exception();
		}
		s64 current_size = (s.st_size!=0)? s.st_size : GetBlockSize64(fd);
		auto starting_offset = (current_size/BLOCK_SIZE)*BLOCK_SIZE;
		lseek64(fd, starting_offset, SEEK_SET);
		s64 block_amount = size/BLOCK_SIZE - starting_offset/BLOCK_SIZE;
		if(lib_fill(fd, block_amount)!=0) {
			fprintf(stderr, "Error in lib_fill\n");
			throw std::exception();
		}
	}
	else if(mode == 'n'){
		if(myrealpath(rel_fn.c_str()) !="") {
			fprintf(stderr, "File already exist. If you want to resume creating use append. \"%s\"\n", fn.c_str());
			return;
		}
		string fn_dir=get_directory(rel_fn);
		if(fn_dir == "") {
			fprintf(stderr, "Directory for file is invalid \"%s\" -> \"%s\"\n", rel_fn.c_str(), fn_dir.c_str());
			return;
		}
		auto libcleanup = lib_init2();
		s64 block_amount = size / BLOCK_SIZE;
		if(block_amount > UINT32_MAX) {
			fprintf(stderr, "Error: File too large. Exiting\n");
			throw std::exception();
		}
		GuardT<int> fd(open(rel_fn.c_str(), O_RDWR | O_LARGEFILE | O_CREAT | O_EXCL, 0), close);
		if (fd <= 0){
			perror("Error on openA in create");
			throw std::exception();
		}
		if(lib_fill(fd, block_amount)!=0) {
			fprintf(stderr, "Error in lib_fill\n");
			throw std::exception();
		}
	}
	else
		throw std::exception();
}

int create_cmd(int argc, char *argv[]) {
	string fn, pw, linkFn, fstype, size, cipher_name;
	bool fs_set=0, overwrite=0;
	s64 rounds = default_rounds;

	if(argc<3)
		return -1;
		
	char mode = *argv[2];
	if(mode!= 'n' && mode !='a' && mode !='d') {
		fprintf(stderr, "create must start with n, a or d\n");
		return 0;
	}

	for(int i=3; i<argc; ++i) {
		string arg=argv[i];
		if(arg=="-s") {
			if(i+1>=argc) return 1;
			if(size!="") return 1;
			size=argv[++i];
		} else if (arg=="-p") {
			if(i+1>=argc) return 1;
			if(pw!="") return 1;
			pw=argv[++i];
		} else if (arg=="-l") {
			if(i+1>=argc) return 1;
			if(linkFn!="") return 1;
			linkFn=argv[++i];
		} else if (arg=="-t") {
			if(i+1>=argc) return 1;
			if(fstype!="") return 1;
			fstype=argv[++i];
			fs_set=true;
		} else if (arg=="-r") {
			if(i+1>=argc) return 1;
			rounds=myatol(argv[++i]);
		} else if (arg=="-c") {
			if(i+1>=argc) return 1;
			cipher_name=argv[++i];
		} else if (arg=="--overwrite") {
			if(overwrite) return 1;
			overwrite=true;
		} else {
			if(fn!="") { return 1; }
			fn = argv[i];
		}
	}
	set_process_name("C");
	
	if(fn=="")
	{
		printf("Please enter the filename\n");
		cin.getline(linebuf, sizeof linebuf);
		if(linebuf[0]==0){
			printf("No value entered. Exiting\n");
			return 0;
		}
		fn = linebuf;
	}
	
	bool fnExist = myrealpath(fn.c_str()) != "";
	if(mode == 'n' && fnExist) {
		fprintf(stderr, "File already exist. If you want to resume creating use append. \"%s\"\n", fn.c_str());
		return 0;
	}
	else if (mode != 'n' && !fnExist) {
		fprintf(stderr, "File does not exist. \"%s\"\n", fn.c_str());
		return 0;
	}
	
	if (mode == 'd') {
		if(size!="") {
			printf("Size is an invalid option in this mode\n");
			return 1;
		}
		if(pw=="")
		{
			for(;;) {
				printf("Please enter the passphrase (or blank to exit)\n");
				getpass();
				if(linebuf[0]==0){
					printf("No value entered. Exiting\n");
					return 0;
				}
				pw=linebuf;
				printf("Confirm passphrase\n");
				getpass();
				if(linebuf[0]==0){
					printf("No value entered. Exiting\n");
					return 0;
				}
				string confirm_pw = linebuf;
				if(pw==confirm_pw)
					break;
				printf("The passphrase did not match\n");
			}
		}
		if(!fs_set)
		{
			printf("What filesystem do you want? Use '-' for none\n[ext4]: ");
			cin.getline(linebuf, sizeof linebuf);
			fstype = linebuf[0]==0?"ext4":linebuf;
		}
		else if(fstype=="")
			fstype="ext4";
		
		if(cipher_name==""){
			printf("What cipher do you want to use? ('aes', 'camellia' or '3des')\n");
			cin.getline(linebuf, sizeof linebuf);
			cipher_name = linebuf;
		}
		Cipher cipher;
		if(cipher_name=="aes")
			cipher = AES;
		else if(cipher_name=="camellia")
			cipher = Camellia;
		else if(cipher_name=="3des")
			cipher = TripleDES;
		else {
			fprintf(stderr, "Incorrect cipher type\n");
			return 0;
		}
		createdrive(fn, pw, rounds, linkFn, fstype, cipher, overwrite);
		return 0;
	}
	else {
		bool EarlyExit=0;
		if(pw!="") {
			printf("Password is an invalid option in this mode\n");
			EarlyExit=1;
		}
		if(linkFn!="") {
			printf("Link is an invalid option in this mode\n");
			EarlyExit=1;
		}
		if(fs_set) {
			printf("Filesystem type is an invalid option in this mode\n");
			EarlyExit=1;
		}
		if(rounds!=default_rounds) {
			printf("Rounds is an invalid option in this mode\n");
			EarlyExit=1;
		}
		if(cipher_name!="") {
			printf("Cipher name is an invalid option in this mode\n");
			EarlyExit=1;
		}
		if(overwrite) {
			printf("Overwrite is an invalid option in this mode\n");
			EarlyExit=1;
		}
		if(EarlyExit)
			return 1;
			
		if(size=="")
		{
			printf("Please enter the file size\n");
			cin.getline(linebuf, sizeof linebuf);
			if(linebuf[0]==0){
				printf("No value entered. Exiting\n");
				return 0;
			}
			size = linebuf;
		}

		create(mode, fn, myatol(size.c_str()));
		return 0;
	}
}

void mount(bool ro, const string& rel_fn, const string& pw, string symlinkfn, s64 rounds) {
	string fn = myrealpath(rel_fn.c_str());
	if(fn == "") {
		fprintf(stderr, "File does not exist: %s\n", rel_fn.c_str());
		return;
	}
	string symfn = myrealpath(symlinkfn.c_str());
	if(myrealpath(symfn.c_str()) != "") {
		fprintf(stderr, "Link filename already exist %s\n", symfn.c_str());
		return;
	}
	
	if(symlinkfn!="" && symlinkfn[0]!='/'){
		if(getcwd(inbuf, sizeof inbuf)==0)
		{
			fprintf(stderr, "cwd + link is too large\n");
			throw std::exception();
		}
		symlinkfn = (string)inbuf + "/" + symlinkfn;
	}
	
	if((fn.size() + symlinkfn.size() + pw.size() + 3 + 4 + 1)>sizeof(inbuf))
	{
		fprintf(stderr, "abs fn||link||pw is too long\n");
		throw std::exception();
	}

	auto w = connect_daemon();

	outbuf[0] = qc_mount;
	memcpy(&outbuf[1], &rounds, 8);
	outbuf[9] = ro?1:0;
	char*p=&outbuf[10];
	memcpy(p, fn.c_str(), fn.size()+1);
	p+=fn.size()+1;
	memcpy(p, pw.c_str(), pw.size()+1);
	p+=pw.size()+1;
	memcpy(p, symlinkfn.c_str(), symlinkfn.size()+1);
	p+=symlinkfn.size()+1;

	send(w, outbuf, p - outbuf, 0);

	recv_cmd(w, "mount");
	return;
}

int mount_cmd(int argc, char *argv[]) {
	string fn, symfn, pw, rw;
	s64 rounds = default_rounds;
	if(argc<=2){
		fprintf(stderr, "Error: after mount you must specify rw (read write) or ro (read only)\n");
		return 0;
	}
	if(argc>=3){
		rw=argv[2];
		if(rw != "rw" && rw!="ro")
		{
			fprintf(stderr, "Error: after mount you must specify rw (read write) or ro (read only)\n");
			return 0;
		}
		for(int i=3; i<argc; ++i) {
			string arg=argv[i];
			if(arg=="-l") {
				if(i+1>=argc) return 1;
				if(symfn!="") return 1;
				symfn=argv[++i];
			} else if (arg=="-p") {
				if(i+1>=argc) return 1;
				if(pw!="") return 1;
				pw=argv[++i];
			} else if (arg=="-r") {
				if(i+1>=argc) return 1;
				rounds = myatol(argv[++i]);
			}
			else if (arg[0]=='-') return 1;
			else {
				if(fn!="") { return 1; }
				fn = argv[i];
			}
		}
	}
	set_process_name("C");
	if(rw=="") {
		printf("Do you want to mount as ready only or read write? (ro/rw)\n");
		if(rw != "rw" && rw!="ro")
		{
			fprintf(stderr, "Error: Must specify ro (read only) or rw (read write)\n");
			return 0;
		}
	}
	bool readonly=rw=="ro";
	if(fn=="")
	{
		printf("Please enter the filename\n");
		cin.getline(linebuf, sizeof linebuf);
		if(linebuf[0]==0){
			fprintf(stderr, "No value entered. Exiting\n");
			return 0;
		}
		fn = linebuf;
	}
	if(myrealpath(fn.c_str()) == "") {
		fprintf(stderr, "File does not exist: %s\n", fn.c_str());
		return 0;
	}
	if(pw=="")
	{
		printf("Please enter the passphrase\n");
		getpass();
		if(linebuf[0]==0) {
			printf("No value entered. Exiting\n");
			return 0;
		}
		pw=linebuf;
	}
	mount(readonly, fn, pw, symfn, rounds);
	return 0;
}

int unmount_cmd(int argc, char *argv[]) {
	string rel_fn;
	if(argc==3)
		rel_fn = argv[2];
	else if (argc==2) {
		static char linebuf[1024*4];
		printf("Please enter the filename\n");
		cin.getline(linebuf, sizeof linebuf);
		if(linebuf[0]==0){
			printf("No value entered. Exiting");
			return 0;
		}
		rel_fn = linebuf;
	}
	else
		return 1;

	string fn = myrealpath(rel_fn.c_str());
	if(fn == "" && rel_fn!="all" && rel_fn!="-all" && rel_fn!="--all"&& rel_fn!="-a" && rel_fn!="--a") {
		fprintf(stderr, "Bad filepath: %s\n", argv[2]);
		return 2;
	}
	if(fn == "" && rel_fn!="")
		fn = "--all";
	if((fn.size() + 11)>sizeof(inbuf))
	{
		fprintf(stderr, "Filename is too long\n");
		return 3;
	}

	set_process_name("C");

	auto w = connect_daemon();

	outbuf[0] = qc_umount_file;
	//preserving 8 bytes for rounds and 1 for read/write
	memcpy(&outbuf[10], fn.c_str(), fn.size()+1);
	if(send(w, outbuf, 10 + fn.size()+1, 0) != (ssize_t)(10 + fn.size()+1))
	{
		fprintf(stderr, "Send incorrect size in unmount_cmd\n");
	}
	
	int bytes;
	if((bytes=recv(w, inbuf, sizeof(inbuf), 0))<=0){
		fprintf(stderr, "Error in unmount_cmd on recv %d\n", bytes);
		throw std::exception();
	}
	if(bytes!=1) {
		fprintf(stderr, "Unexcepted return size in unmount_cmd\n");
		return 0;
	}
	if(inbuf[0]==-1){
		printf("Found nothing to unmount\n");
	}
	return 0;
}
void add(string id, string pw, s64 rounds) {
    auto w = connect_daemon();

    outbuf[0] = qc_add_drive;
    memcpy(&outbuf[1], &rounds, 8);
    //9 is ro.
    char*p=&outbuf[10];
    memcpy(p, id.c_str(), id.size()+1);
    p+=id.size()+1;
    memcpy(p, pw.c_str(), pw.size()+1);
    p+=pw.size()+1;

    send(w, outbuf, p - outbuf, 0);

	recv_cmd(w, "drive is invalid");
}
int add_cmd(int argc, char *argv[]) {
	string id, pw;
	s64 rounds = default_rounds;
	for(int i=2; i<argc; ++i) {
		string arg=argv[i];
		if (arg=="-p") {
			if(i+1>=argc) return -1;
			if(pw!="") return -2;
			pw=argv[++i];
		} else if (arg=="-r") {
			if(i+1>=argc) return 1;
			rounds = myatol(argv[++i]);
		}
		else {
			if(id!="") { return -3; }
			id = argv[i];
		}
	}
	set_process_name("C");
	if(id=="")
	{
		printf("Please enter the id\n");
		cin.getline(linebuf, sizeof linebuf);
		if(linebuf[0]==0){
			printf("No value entered. Exiting");
			return 0;
		}
		id = linebuf;
	}
	if(pw=="")
	{
		printf("Please enter the passphrase\n");
		getpass();
		if(linebuf[0]==0){
			printf("No value entered. Exiting");
			return 0;
		}
		pw=linebuf;
	}
	add(id, pw, rounds);
	return 0;
}

int list_cmd(int argc, char *argv[]) {
	set_process_name("C");	
	auto w = connect_daemon();
	outbuf[0] = qc_list;
	send(w, outbuf, 1, 0);
	ssize_t bytes;
	for(;;) {
		if((bytes=recv(w, &inbuf[0], sizeof(inbuf), 0))<0) {
			perror("Error on recv in list_cmd");
			return 0;
		}
		else if (bytes==0)
			break;
		printf("%s", inbuf);
	}
	return 0;
}
int time_cmd(int argc, char *argv[]) {
	string fn, pw, size;

	if(argc<3) {
		printf("Please include number of rounds\n");
		return 1;
	}
	else if (argc>3)
		return -1;
		
	int rounds = myatol(argv[2]);
	if(rounds > 0) {
		auto libcleanup = lib_init2();

		u8 buf[25];
		struct timeval s, e;
		gettimeofday(&s, 0);
		int r = pbkdf2("passwordPASSWORDpassword", (u8*)"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, rounds, buf, sizeof buf);
		gettimeofday(&e, 0);
		auto sec = e.tv_sec  - s.tv_sec;
		auto usc = e.tv_usec - s.tv_usec;
		printf("Time: %lu\n", sec*1000+usc/1000);

		if(r!=0){
			fprintf(stderr, "Error: pbkdf2 return an error\n");
			throw std::exception();
		}
		return 0;
	} else if (strcmp("cipher", argv[2])==0) {
		auto libcleanup = lib_init2();
		vector<u8> plain(BLOCK_SIZE), cipher(BLOCK_SIZE), testbuf(BLOCK_SIZE), k(256/8);
		secure_rng(&plain[0], BLOCK_SIZE);
		secure_rng(&k[0], 256/8);
		
		printf("Testing the speed of each cipher. A higher count is better. Ciphers are AES, Camellia, 3DES.\n");
		printf("Hardware and virtual machine may affect results\n");
		for(Cipher c = (Cipher)0; c<Cipher_End; c=(Cipher)(c+1)) {
			struct timeval s, e;
			gettimeofday(&s, 0);
			s64 count=0;
			while(true) {
				encrypt(&plain[0], &cipher[0], &k[0], &k[16], BLOCK_SIZE, c);
				gettimeofday(&e, 0);
				auto sec = e.tv_sec  - s.tv_sec;
				auto usc = e.tv_usec - s.tv_usec;
				auto res = sec*1000+usc/1000;
				++count;
				if(res>=500) {
					printf("Encrypt #%d: Count: %lld Time: %ld ms\n", c, count, sec*1000+usc/1000);
					break;
				}
			}
			gettimeofday(&s, 0);
			count = 0;
			while(true) {
				decrypt(&cipher[0], &testbuf[0], &k[0], &k[16], BLOCK_SIZE, c);
				gettimeofday(&e, 0);
				auto sec = e.tv_sec  - s.tv_sec;
				auto usc = e.tv_usec - s.tv_usec;
				auto res = sec*1000+usc/1000;
				++count;
				if(res>500) {
					printf("Decrypt #%d: Count: %lld Time: %ld ms\n", c, count, sec*1000+usc/1000);
					break;
				}
			}
			if(memcmp(&testbuf[0], &plain[0], BLOCK_SIZE)!=0){
				fprintf(stderr, "WTF encrypt/decrypt is broken for cipher #%d\n", c);
			}
		}
		return 0;
	}
	else {
		fprintf(stderr, "Please use the number of rounds (such as 1M or 10K) or 'cipher' as the second argument\n");
		return -1;
	}
}
int main2(int argc, char *argv[]) {
	string cmd = argv[1];
	if ((cmd == "v") || (cmd == "-v") || (cmd == "--v") || (cmd == "version") || (cmd == "-version") || (cmd == "--version"))
	{
		if(argc>2)
			return 1;
		printf("Version %s\n", VERSION_STRING);
		return 0;
	}
	else if(cmd=="m" || cmd=="mount") {
		return mount_cmd(argc, argv);
	}
	else if(cmd=="c" || cmd=="create") {
		return create_cmd(argc, argv);
	}
	else if(cmd=="u" || cmd=="umount" || cmd=="unmount") {
		return unmount_cmd(argc, argv);
	}
	else if(cmd=="a" || cmd=="add") {
		return add_cmd(argc, argv);
	}
	else if(cmd=="l" || cmd=="ls" || cmd=="list") {
		return list_cmd(argc, argv);
	}
	else if(cmd=="t" || cmd=="time") {
		return time_cmd(argc, argv);
	}
	else {
		return -1;
	}
	return -1;
}

void test();
int main(int argc, char *argv[]) {
	main_argc=argc; main_argv=argv;
	
	//test(); return 0;
	//We use try here so if an exception is thrown the destructors/EXIT will execute 
	//rather than terminate from an uncaught exception.
	try {
		if (argc <= 1) {
			print_help();
			return 0;
		}
		auto r = main2(argc, argv);
		if(r<0)
			print_help();
		else if (r>0)
			printf("Missing, invalid or repeat argument\n");
	}
	catch (class ExitException) {
		//For the forked daemons.
	}
	catch(...){
		throw;
	}
}

void test() {
	auto c = lib_init2();
	Drive *p=0, *p2=0, *p3=0;
	if(1){
		create('n', "/dev/shm/tmp", myatol("280M"));
		auto r1 = lib_createdrive("/dev/shm/tmp", "1", default_rounds, AES, true, &p);
		auto r2 = lib_createdrive("/dev/shm/tmp", "2", default_rounds, Camellia, true, &p2);
		auto r3 = lib_createdrive("/dev/shm/tmp", "3", default_rounds, Camellia, true, &p3);
		printf("%d %d %d\n", r1, r2, r3);
		errno=0;
		memset(inbuf, 0, sizeof(inbuf));
		//for(int i=0; i<8145; ++i){
			//lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p);
		for(int i=0; i<500; ++i)
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p);
		for(int i=500; i<1500; ++i) {
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p);
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p2);
		}
		for(int i=1500; i<2000; ++i) {
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p);
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p2);
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p3);
		}
		for(int i=2000; i<2200; ++i) {
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p3);
		}
		for(int i=2200; i<2500; ++i) {
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p);
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p3);
		}
		for(int i=2500; i<2700; ++i) {
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p2);
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p);
			lib_write(inbuf, sizeof(inbuf), i*BLOCK_SIZE, p3);
		}
		lib_unmount(p);
		lib_unmount(p2);
		lib_unmount(p3);
	}
	auto r = lib_mount(1, "/dev/shm/tmp", "1", default_rounds);
	auto r2 = lib_mount(1, "/dev/shm/tmp", "2", default_rounds);
	auto r3 = lib_mount(1, "/dev/shm/tmp", "3", default_rounds);
	printf("%d\n", r);
}
