#include <atomic>
#include <stddef.h>
#include <cstring>
#include <vector>
#include <deque>
#include <algorithm>
#include <limits.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <unistd.h>

#include "base64.h"
#include "lib.h"
#include "crypt.h"

uint64_t GetBlockSize64(int fd);

using namespace std;

struct DriveHeader {
	u8 version:3, cipher:5, id[3];
	u8 key[AES_KEY_BITS / 8];
	u32 iv[3];
};//1+3+16+12=32

struct PBKDF2Header{
	u32 offset;
	u8 key[AES_KEY_BITS / 8], salt[128 / 8];
};//4+16+16=36

enum { DriveBlockPageArrayLength = 4052, PageBlockAmount = 4093 };
struct DriveBlock{
	DriveHeader dh;
	PBKDF2Header kh[8];
	u32 pages[2 * DriveBlockPageArrayLength];
	u32 next_page;
	u8 hash[224 / 8];
};

static_assert(sizeof(DriveBlock) == BLOCK_SIZE, "DriveBlock must == BLOCK_SIZE");
struct PageBlock{ u32 pages[PageBlockAmount * 2]; u32 next_page; u8 hash128[128/8]; u32 reserved; };
static_assert(sizeof(PageBlock) == BLOCK_SIZE, "Pagelock must == BLOCK_SIZE");

template<class T>
uint_fast32_t nearest_binary_search(deque<T>&d, T v) {
	uint_fast32_t s = 0;
	uint_fast32_t e = d.size();
	if (s >= e)
		return e;
	uint_fast32_t p = s;
	while (e - s > 1) {
		p = (s + e) / 2;
		if(v == d[p])
			return p;
		else if (v<d[p])
			e = p;
		else
			s = p;
	}
	if (e!=d.size() && v==d[e])
		return e;
	else
		return s;
}
void insert(deque<u64>&d, u64 v) {
	auto x = nearest_binary_search(d, v);
	if(x == d.size())
		d.push_back(v);
	else
		d.insert(d.begin() + x, v);
}

class Device;
class Drive {
	friend Device;
	Device &device;
	bool IsRO;
	PBKDF2Header kh;
	DriveBlock db;
	u32 header_page;
	PageBlock pageblock1, pageblock2, *curpage, *nextpage;
	int pageblock_count;
	map<u32, u32> offsets;
	vector<u32> page_list_ptrs;
	Cipher cm;
	int fd;

	u8 iv[16];
	static void set_LE(u8*a, u32 v) { a[0] = (v >> 0) & 0xFF; a[1] = (v >> 8) & 0xFF; a[2] = (v >> 16) & 0xFF; a[3] = (v >> 24) & 0xFF; }
	u8* set_iv(u32 page) { set_LE(&iv[12], page); return iv; }

	WARN MountError LoadPageList(u32 phy_page) {
		PageBlock&b = *curpage;
		{
			vector<u8> cipher(BLOCK_SIZE, 0);
			if (pread(fd, &cipher[0], BLOCK_SIZE, phy_page*BLOCK_SIZE) != BLOCK_SIZE)
				return internalErrorPread;
			if (decrypt(&cipher[0], &b, db.dh.key, set_iv(~pageblock_count++), sizeof b, cm) != sizeof b){
				fprintf(stderr, "Error: LoadPageList decrypt returned incorrect size\n");
				terminate();
			}
		}
		
		u8 buf256[256/8];
		if(sha256(&b, offsetof(PageBlock, hash128), &buf256[0])!=0)
			return internalErrorSha;
		for(int i=0; i<16; ++i)	
			buf256[i] ^= buf256[i+16];
		if(memcmp(b.hash128, buf256, 16)!=0)
			return corrupted_link_page;
		
		for (int i = 0; i < PageBlockAmount * 2; i += 2) {
			if (b.pages[i + 1] == UINT32_MAX)
				break;
			offsets[b.pages[i]] = b.pages[i + 1];
		}

		if (b.next_page != UINT_MAX) {
			page_list_ptrs.push_back(b.next_page);
			auto ret = LoadPageList(b.next_page);
			if (ret != MountError_ok)
				return ret;
		}
		return MountError_ok;
	}
	void init_page_list(u32 next_pageblock_address, PageBlock&next_pageblock, u32 logical_page, u32 physical_page) {
		memset(&next_pageblock, -1, sizeof(PageBlock)); //-1 is considered unused. 0 is beginging of file
		next_pageblock.pages[0] = logical_page;
		next_pageblock.pages[1] = physical_page;
		offsets[logical_page] = physical_page;
		page_list_ptrs.push_back(next_pageblock_address);
		write_page_block(next_pageblock_address, next_pageblock, page_list_ptrs.size());
	}
	void write_page_block(u32 page, PageBlock&b, u32 pageblock_count) {
		vector<u8> cipher(BLOCK_SIZE);
		
		if(sha256(&b, offsetof(PageBlock, hash128), &cipher[0])!=0){
			fprintf(stderr, "sha256 failed in write_page_block\n");
			terminate();
		}
		
		for(int i=0; i<16; ++i)
			b.hash128[i] = cipher[i] ^ cipher[i+16];
		
		if (encrypt(&b, &cipher[0], db.dh.key, set_iv(~pageblock_count), BLOCK_SIZE, cm) != BLOCK_SIZE){
			fprintf(stderr, "Error: write_page_block encrypt returned incorrect size\n");
			terminate();
		}
		if (pwrite(fd, &cipher[0], BLOCK_SIZE, page*BLOCK_SIZE) != BLOCK_SIZE) {
			fprintf(stderr, "Error: write_page_block write returned incorrect size\n");
			terminate();
		}
	}
	u32 ReserveBlockPage(u32 logical_page);

	void read_drive_block(Cipher cm) {
		vector<u8> cipher(BLOCK_SIZE, 0);

		auto r = pread(fd, &cipher[0], BLOCK_SIZE, header_page*BLOCK_SIZE);
		if (r != BLOCK_SIZE) {
			fprintf(stderr, "Error: Incorrect read size read_drive_block %ld\n", r);
			terminate();
		}

		if (decrypt(&cipher[0], &db, kh.key, kh.salt, sizeof db, cm) != sizeof db) {
			fprintf(stderr, "Error: read_drive_block decrypt returned incorrect size\n");
			terminate();
		}
	}
	void write_drive_block(Cipher cm) {
		vector<u8> cipher(BLOCK_SIZE, 0);
		
		if (sha224(&db, offsetof(struct DriveBlock, hash), db.hash) != 0) {
			fprintf(stderr, "Error: write_drive_block sha error\n");
			terminate();
		}
		
		if (encrypt(&db, &cipher[0], kh.key, kh.salt, BLOCK_SIZE, cm) != BLOCK_SIZE){
			fprintf(stderr, "Error: write_drive_block encrypt returned incorrect size\n");
			terminate();
		}
		int bytes;
		if ((bytes=pwrite(fd, &cipher[0], BLOCK_SIZE, header_page*BLOCK_SIZE)) != BLOCK_SIZE){
			fprintf(stderr, "Error: write_drive_block write returned incorrect size %d\n", bytes);
			terminate();
		}
	}
	Drive(Device&device, bool ro, const PBKDF2Header &kh, u32 page, int fd) : device(device), IsRO(ro), kh(kh), header_page(page), fd(fd) 
		{cm=(Cipher)-1; curpage=&pageblock1; nextpage=&pageblock2;}
	WARN MountError load();
public:
	WARN bool IsPageInUse(u32 page) {
		if (page == header_page)
			return true;
			
		for (auto i = offsets.begin(); i != offsets.end(); ++i) {
			if (i->second == page)
				return true;
		}
		if (find(page_list_ptrs.begin(), page_list_ptrs.end(), page) != page_list_ptrs.end())
			return true;
		return false;
	}
	WARN static unique_ptr<Drive> mount(Device&device, bool ro, const PBKDF2Header&kh, MountError&err, int fd, u32 max_block_amount) {
		u32 page = kh.offset % max_block_amount;
		unique_ptr<Drive> drive(new Drive(device, ro, kh, page, fd));

		Cipher cm = (Cipher)0;
		for(; cm<Cipher_End; cm=(Cipher)(cm+1)) {
			drive->read_drive_block(cm);
			
			u8 actual_hash[224 / 8];
			if (sha224(&drive->db, offsetof(struct DriveBlock, hash), actual_hash) != 0) {
				err = internalErrorSha;
				return 0;
			}
			if(memcmp(actual_hash, drive->db.hash, sizeof(actual_hash))==0)
				break;
		}
		if (cm == Cipher_End) {
			err = invalidPass;
			return 0;
		}

		err = drive->load();
		return err == MountError_ok ? move(drive) : 0;
	}
	WARN static unique_ptr<Drive> create_drive(Device&device, const PBKDF2Header&kh, MountError&err, int fd, u32 max_block_amount, Cipher cipher, bool overwrite);

	WARN MountError add_drive(const char*pw, s64 rounds);

	void unmount();
	WARN u32 map_page(u32 page) { auto i = offsets.find(page); if(i == offsets.cend()) { return UINT_MAX; } else return i->second; }

	u8 read_plain[BLOCK_SIZE], read_cipher[BLOCK_SIZE], write_plain[BLOCK_SIZE], write_cipher[BLOCK_SIZE];
	u32 read_cache_page = UINT_MAX, write_cache_page = UINT_MAX;
	WARN int read(void*buf, size_t size, size_t offset, int&unset);
	WARN int write(const void*buf, size_t size, size_t offset);
	WARN const u8* get_id() { return db.dh.id; }
	s64 get_device_size();
};

static u8 default_PBKDF2_salt[] = { 0x97, 0xFD, 0xC4, 0x41, 0x9B, 0x76, 0xAB, 0xB4, 0x94, 0x7D, 0x6C, 0x49, 0xAC, 0xDC, 0x25, 0x6C };

class Device
{
	int fd, IsRO;
	u8 PBKDF2_salt[128 / 8];
	map<u32, unique_ptr<Drive> > drives;

	u32 max_block_amount;
	deque<u32> unused_pages;
	vector<Drive*> scanned_drives;

	WARN MountError create_drive(PBKDF2Header&kh, Cipher cipher, bool overwrite, Drive**pp) {
		u32 page = kh.offset % max_block_amount;
		if (drives.find(page) != drives.cend())
			return CantCreateDriveMounted;

		if(scanned_drives.size()!=0) {
			auto pos = nearest_binary_search(unused_pages, page);
			if (pos==unused_pages.size() || unused_pages[pos] != page)
				return page_in_use;
		}

		MountError err;
		unique_ptr<Drive> drive = Drive::create_drive(*this, kh, err, fd, max_block_amount, cipher, overwrite);
		if (err != MountError_ok)
			return err;

		drives[page] = move(drive);
		*pp = drives[page].get();
		SyncUnusedPages(); //Need to build unused pages even if there isn't anything to sync
		return MountError_ok;
	}
	void SyncUnusedPages() {
		if(scanned_drives.size()==0) {
			Drive*pmax=0; u32 max=0;
			for(auto i=drives.begin(); i!=drives.end(); ++i) {
				//i->second.get()->ScanForErrors();
				if(i->second.get()->offsets.size() > max) {
					pmax = i->second.get();
					max = i->second.get()->offsets.size();
				}
			}
			if(pmax==0) {
				for(uint_fast32_t i=0; i<max_block_amount; ++i)
					unused_pages.push_back(i);
			}
			else {
				auto ii = pmax->offsets.begin();
				uint_fast32_t vv = pmax->offsets.begin() == pmax->offsets.end() ? UINT_MAX : ii->second;
				for(uint_fast32_t i=0; i<max_block_amount; ++i) {
					if(i<vv)
						unused_pages.push_back(i);
					else {
						++ii;
						if(ii==pmax->offsets.end())
							vv = UINT_MAX;
						else
							vv = ii->second;
					}
				}
				for(auto i = pmax->page_list_ptrs.begin(); i!=pmax->page_list_ptrs.end(); ++i)
					RemovePage(*i);
				RemovePage(pmax->header_page);
				scanned_drives.push_back(pmax);
			}
		}
		for(auto di=drives.begin(); di!=drives.end(); ++di) {
			auto p = di->second.get();
			if(find(scanned_drives.begin(), scanned_drives.end(), p)!=scanned_drives.end())
				continue;
			
			for(auto ii=p->offsets.begin(); ii!=p->offsets.end(); ++ii)
				RemovePage(ii->second);
			for(auto i = p->page_list_ptrs.begin(); i!=p->page_list_ptrs.end(); ++i)
				RemovePage(*i);
			RemovePage(p->header_page);
			scanned_drives.push_back(p);
		}
	}
public:
	Device(bool ro, string path) {
		memcpy(PBKDF2_salt, default_PBKDF2_salt, sizeof PBKDF2_salt); static_assert(sizeof PBKDF2_salt == sizeof default_PBKDF2_salt, "PBKDF2_salt size doesn't match");
		
		u64 fileblocksize;
		struct stat64 s;
		if(stat64(path.c_str(), &s)!=0) {
			   perror("stat64 failed in Device()");
			   throw std::exception();
	   }
		IsRO = ro;
		fd = open(path.c_str(), O_LARGEFILE | (ro? O_RDONLY : O_RDWR));
		if(s.st_size!=0)
			fileblocksize = s.st_size / BLOCK_SIZE;
		else 
			fileblocksize = GetBlockSize64(fd) / BLOCK_SIZE;
		max_block_amount = fileblocksize;
		if(fileblocksize >= UINT32_MAX) {
			fprintf(stderr, "Error: File too large. Exiting\n");
			throw std::exception();
		}
		if (fd == 0)
			throw std::exception();
	}
	~Device() {
		close(fd);
	}
	void unload(Drive*p) {
		for(auto i=drives.begin(); i!=drives.end(); ++i) {
			if(i->second.get() == p)
				drives.erase(i);
		}
	}

	u8* get_PBKDF2_salt() { return PBKDF2_salt; }
	s64 get_size() { return max_block_amount * BLOCK_SIZE; }

	WARN u32 DeviceRemainingPageCount() { return unused_pages.size(); }

	WARN MountError mount(bool ro, const char*pw, s64 rounds) {
		PBKDF2Header kh;
		int c;
		if ((c=pbkdf2(pw, PBKDF2_salt, sizeof(PBKDF2_salt), rounds, &kh, sizeof kh))<0) {
			printf("Error: mount pbkdf2 return err. %d\n", c);
			throw std::exception();
		}
		return mount(ro, kh);
	}

	WARN MountError mount(bool ro, PBKDF2Header&kh) {
		u32 page = kh.offset % max_block_amount;
		if (drives.find(page) != drives.cend())
			return already_mounted;

		drives[page] = 0; //0 means curently loading. To avoid circular loading

		MountError err;
		unique_ptr<Drive> drive = Drive::mount(*this, ro, kh, err, fd, max_block_amount);
		if (err != MountError_ok)
			return err;

		drives[page] = move(drive);
		SyncUnusedPages();
		return MountError_ok;
	}
	WARN MountError create_drive(const char*pw, s64 rounds, Cipher cipher, bool overwrite, Drive**pp) {
		PBKDF2Header kh;
		auto ret = pbkdf2(pw, PBKDF2_salt, sizeof(PBKDF2_salt), rounds, &kh, sizeof kh);
		if (ret<0) {
			fprintf(stderr, "Error: pbkdf2 in create_drive returned %d\n", ret);
			terminate();
		}
		return create_drive(kh, cipher, overwrite, pp);
	}
	WARN u32 ReserveAPage(u32 other_ignore_page = UINT_MAX) {
		if (unused_pages.size()==0)
			return UINT_MAX;
		if(unused_pages.size()==1)
			return other_ignore_page != UINT_MAX ? UINT_MAX : unused_pages.front();
		
		while(true) {
			u32 v = secure_rng_u32() % unused_pages.size();
			if(unused_pages[v] == other_ignore_page)
				continue;
			else
				return unused_pages[v];
		}
	}
	int remove_page_counter=0;
	void RemovePage(u32 page) {
		auto pos = nearest_binary_search(unused_pages, page);
		if(pos == unused_pages.size() || unused_pages[pos] != page)
			return;
		unused_pages.erase(unused_pages.begin() + pos);
		if(remove_page_counter++ >= 1024*1024/8){
			remove_page_counter=0;
			unused_pages.shrink_to_fit();
		}
	}
	WARN const map<u32, unique_ptr<Drive> > *getList() { return &drives; }
};

MountError Drive::load() {
	if (db.dh.version != DRIVE_VERSION)
		return UnsupportedVersion;

	cm = (Cipher)db.dh.cipher;
	if(cm<0 || cm>=Cipher_End) {
		return UnsupportedVersion;
	}
	memcpy(&iv[0], &db.dh.iv[0], 12);

	//Load other drives if applicible
	for (uint i = 0; i < sizeof(db.kh) / sizeof(*db.kh); ++i)
	{
		if (db.kh[i].offset == UINT_MAX)
			continue;
		auto ret = device.mount(IsRO, db.kh[i]);
		if (ret != MountError_ok && ret != already_mounted){
			fprintf(stderr, "Error could not load linked drive\n");
			if(IsRO == 0) {
				fprintf(stderr, "Use readonly not to terminate\n");
				terminate();
			}
		}
	}

	for (uint i = 0; i < sizeof(db.pages) / sizeof(db.pages[0]); i += 2){
		if (db.pages[i + 1] == UINT32_MAX)
			break;
		offsets[db.pages[i]] = db.pages[i + 1];
	}
	if (db.next_page != UINT_MAX) {
		page_list_ptrs.push_back(db.next_page);
		auto ret = LoadPageList(db.next_page);
		if (ret != MountError_ok)
			return ret;
	}
	return MountError_ok;
}

u32 Drive::ReserveBlockPage(u32 logical_page) {
	if (device.DeviceRemainingPageCount() == 0)
		return UINT_MAX;

	auto ppage = device.ReserveAPage();
	if (offsets.size() < DriveBlockPageArrayLength)
	{
		db.pages[offsets.size() * 2] = logical_page;
		db.pages[offsets.size() * 2 + 1] = ppage;
		offsets[logical_page] = ppage;
		device.RemovePage(ppage);
		write_drive_block(cm);
		return ppage;
	}
	else if (offsets.size() == DriveBlockPageArrayLength) {
		if (device.DeviceRemainingPageCount() < 2)
			return UINT_MAX;

		auto list_ppage = device.ReserveAPage(ppage);
		init_page_list(list_ppage, *curpage, logical_page, ppage);
		db.next_page = list_ppage;
		write_drive_block(cm);
		device.RemovePage(list_ppage);
		device.RemovePage(ppage);
		return ppage;
	}
	else if ((offsets.size() - DriveBlockPageArrayLength) % PageBlockAmount != 0) {
		auto i = (offsets.size() - DriveBlockPageArrayLength) % PageBlockAmount;
		curpage->pages[i * 2] = logical_page;
		curpage->pages[i * 2 + 1] = ppage;
		offsets[logical_page] = ppage;
		write_page_block(page_list_ptrs.back(), *curpage, page_list_ptrs.size() - 1);
		device.RemovePage(ppage);
		return ppage;
	}
	else if ((offsets.size() - DriveBlockPageArrayLength) % PageBlockAmount == 0) {
		if (device.DeviceRemainingPageCount() < 2)
			return UINT_MAX;
		
		auto list_ppage = device.ReserveAPage(ppage);
		init_page_list(list_ppage, *nextpage, logical_page, ppage);
		curpage->next_page = list_ppage;
		write_page_block(list_ppage, *curpage, page_list_ptrs.size() - 1);
		{auto t = curpage; curpage = nextpage; nextpage = t;}
		device.RemovePage(list_ppage);
		device.RemovePage(ppage);
		return ppage;
	}
	else {
		fprintf(stderr, "I fail at logic 446\n");
		std::terminate();
	}
}

int Drive::read(void*buf, size_t size, size_t offset, int&unset) {
	u32 lpage = offset / BLOCK_SIZE;
	size_t o = offset % BLOCK_SIZE;
	ssize_t bytes;
	auto ppage = map_page(lpage);
	if (ppage == UINT_MAX) {
		unset=1;
		if (device.DeviceRemainingPageCount() == 0)
			return 0;
			
		read_cache_page=UINT_MAX;
		//Holy crap what a bug. We can't do this because sometimes the size may be
		//something like 128K which is 32*4K blocks. Several of the blocks in the middle
		//may be unlinked causing the rest it assumed to be not linked/zero. Fuck that was hard
		//memset(buf, 0, size);
		//return size;
	}

	if (read_cache_page != lpage) {
		if(ppage==UINT_MAX) {
			memset(read_plain, 0, BLOCK_SIZE);
		} else {
			if ((bytes=pread(fd, read_cipher, BLOCK_SIZE, ppage*BLOCK_SIZE)) != BLOCK_SIZE) return bytes;
			if ((bytes=decrypt(read_cipher, read_plain, db.dh.key, set_iv(lpage), BLOCK_SIZE, cm)) != BLOCK_SIZE) return bytes;
			read_cache_page = lpage;
		}
	}
	if (o == 0 && size >= BLOCK_SIZE) {
		memcpy(buf, read_plain, BLOCK_SIZE);
		if (size > BLOCK_SIZE)
			return BLOCK_SIZE + read(&((u8*)buf)[BLOCK_SIZE], size - BLOCK_SIZE, offset + BLOCK_SIZE, unset);
		else
			return BLOCK_SIZE;
	}
	else {
		auto len = min(BLOCK_SIZE - o, size);
		memcpy(buf, &read_plain[o], len);

		if (size > len)
			return len + read(&((u8*)buf)[len], size - len, offset + len, unset);
		else
			return len;
	}
}

int Drive::write(const void*buf, size_t size, size_t offset) {
	read_cache_page = UINT_MAX;
	if(IsRO) {
		fprintf(stderr, "Error: Trying to write when drive as been marked read only. Terminating!\n");
		std::terminate();
		return -1;
	}
	u32 lpage = offset / BLOCK_SIZE;
	size_t o = offset % BLOCK_SIZE;
	ssize_t bytes;
	bool IsNewPage=0;
	auto ppage = map_page(lpage);
	if (ppage == UINT_MAX) {
		ppage = ReserveBlockPage(lpage);
		if (ppage == UINT_MAX) {
			errno = ENOSPC;
			return -1;
		}
		IsNewPage=1;
	}
	if (o == 0 && size >= BLOCK_SIZE) {
		if ((bytes=encrypt(buf, &write_cipher[0], db.dh.key, set_iv(lpage), BLOCK_SIZE, cm)) != BLOCK_SIZE) {
			fprintf(stderr, "encrypt incorrect size in write 1 - %ld\n", bytes);
			std::terminate();
		}
		
		if ((bytes=pwrite(fd, &write_cipher[0], BLOCK_SIZE, ppage*BLOCK_SIZE)) != BLOCK_SIZE)
			return bytes;
			
		if (size > BLOCK_SIZE)
			return BLOCK_SIZE + write(&((u8*)buf)[BLOCK_SIZE], size - BLOCK_SIZE, offset + BLOCK_SIZE);
		else
			return BLOCK_SIZE;
	}
	else if (write_cache_page != lpage) {
		if(IsNewPage)
			memset(write_plain, 0, BLOCK_SIZE);
		else {
			if ((bytes=pread(fd, write_cipher, BLOCK_SIZE, ppage*BLOCK_SIZE)) != BLOCK_SIZE) return bytes;
			if ((bytes=decrypt(write_cipher, write_plain, db.dh.key, set_iv(lpage), BLOCK_SIZE, cm)) != BLOCK_SIZE) {
				fprintf(stderr, "decrypt incorrect size in write %ld\n", bytes);
				std::terminate();
			}
		}
		write_cache_page = lpage;
	}

	auto len = min(BLOCK_SIZE - o, size);
	memcpy(&write_plain[o], buf, len);
	if ((bytes=encrypt(write_plain, write_cipher, db.dh.key, set_iv(lpage), BLOCK_SIZE, cm)) != BLOCK_SIZE) {
		fprintf(stderr, "encrypt incorrect size in write 2 - %ld\n", bytes);
		std::terminate();
	}

	if ((bytes=pwrite(fd, write_cipher, BLOCK_SIZE, ppage*BLOCK_SIZE)) != BLOCK_SIZE) return bytes;
	if (size > len)
		return len + write(&((u8*)buf)[len], size - len, offset + len);
	else
		return len;
}

s64 Drive::get_device_size() { return device.get_size(); }

map<string, unique_ptr<Device> > device_map;

WARN string myrealpath(const char*path_) {
	auto path_tempvar = unique_ptr<const char>(realpath(path_, 0));
	string path = !path_tempvar? "" : path_tempvar.get();
	return path;
}
WARN MountError lib_mount(bool ro, const char*path_, const char*pw, s64 rounds) {
	string path = myrealpath(path_);
	if(path=="")
		return BadPath;
	auto v = device_map.find(path);
	if (v != device_map.cend()){
		return v->second->mount(ro, pw, rounds);
	}
	else {
		auto d = make_unique<Device>(ro, path);
		auto r = d->mount(ro, pw, rounds);
		if (r == MountError_ok) {
			device_map[path] = move(d);
		}
		return r;
	}
}

WARN MountError lib_add_drive(const char*pw, s64 rounds, Drive *p) { return p->add_drive(pw, rounds); }
WARN MountError lib_createdrive(const char*path_, const char*pw, s64 rounds, int cipher, bool overwrite, Drive **pp) {
	string path = myrealpath(path_);
	auto v = device_map.find(path);
	if (v != device_map.cend()) {
		return v->second->create_drive(pw, rounds, (Cipher)cipher, overwrite, pp);
	}
	else{
		auto d = make_unique<Device>(0, path);
		auto r = d->create_drive(pw, rounds, (Cipher)cipher, overwrite, pp);
		if (r == MountError_ok){
			device_map[path] = move(d);
		}
		return r;
	}
}

WARN MountError Drive::add_drive(const char*pw, s64 rounds) {
	PBKDF2Header src_drive_kh;
	//check if pw is valid
	{
		PBKDF2Header &kh = src_drive_kh;
		int c;
		if ((c=pbkdf2(pw, device.get_PBKDF2_salt(), 128/8, rounds, &kh, sizeof kh))<0) {
			printf("Error: add_drive pbkdf2 return err. %d\n", c);
			throw std::exception();
		}
		u32 page = kh.offset % (device.get_size() / BLOCK_SIZE);
		unique_ptr<Drive> drive(new Drive(device, IsRO, kh, page, fd));

		Cipher cm=(Cipher)0;
		for(; cm<Cipher_End; cm=(Cipher)(cm+1)) {
			drive->read_drive_block(cm);

			u8 actual_hash[224 / 8];
			if (sha224(&drive->db, offsetof(struct DriveBlock, hash), actual_hash) != 0)
				return internalErrorSha;

			if (memcmp(actual_hash, db.hash, sizeof(db.hash)) == 0)
				break;
		}
		if(cm == Cipher_End)
			return invalidPass;
			
		auto err = drive->load();
		if (err != MountError_ok)
			return err;
	}
	
	read_drive_block(cm);
	bool hit=0;
	for(int i=0; i<8; ++i) {
		if(db.kh[i].offset!=UINT32_MAX) {
			if(memcmp(&db.kh[i], &src_drive_kh, sizeof src_drive_kh)==0){
				return kh_exist;
			}
			continue;
		}
		memcpy(&db.kh[i], &src_drive_kh, sizeof src_drive_kh);
		write_drive_block(cm);
		hit=1;
		break;
	}
	return hit? MountError_ok : no_kh_space;
}
void Drive::unmount() { device.unload(this); /*WARNING device still knows about what pages this drive uses*/  }
void lib_unmount(Drive*p) { p->unmount(); }

unique_ptr<Drive> Drive::create_drive(Device&device, const PBKDF2Header&kh, MountError&err, int fd, u32 max_block_amount, Cipher cipher, bool overwrite) {
	u32 page = kh.offset % max_block_amount;
	unique_ptr<Drive> drive(new Drive(device, 0, kh, page, fd));
	auto &db = drive->db;
	auto &dh = db.dh;

	if (overwrite==false) {
		u8 actual_hash[224 / 8];
		
		Cipher cm=(Cipher)0;
		for(; cm<Cipher_End; cm=(Cipher)(cm+1)) {
			drive->read_drive_block(cm);
			if (sha224(&db, offsetof(struct DriveBlock, hash), actual_hash) != 0) {
				err = internalErrorSha;
				return 0;
			}
			
			if (memcmp(actual_hash, db.hash, sizeof(db.hash)) == 0) {
				err = driveExist;
				return 0;
			}
		}
	}
	else {
		auto m = device.getList();
		if(m->find(page)!=m->end()) {
			err = CantCreateDriveMounted;
		}
	}

	memset(&db, -1, sizeof(DriveBlock));

	dh.version = DRIVE_VERSION;
	dh.cipher = cipher;
	secure_rng(dh.id, 3);
	secure_rng(dh.key, sizeof(dh.key));
	secure_rng(dh.iv, sizeof(dh.iv));

	drive->write_drive_block(cipher);

	err = drive->load();
	return err==MountError_ok? move(drive) : 0;
}

WARN MountError lib_fill(int fd, s64 amount_of_blocks) {
	u8 buf[BLOCK_SIZE];
	int last_percentage=-1;
	for(s64 i=0; i<amount_of_blocks; ++i) {
		int v = ((float)i/amount_of_blocks)*10000;
		if(v!=last_percentage) {
			printf("Progress: %.2f\r", (float)v/100);
			last_percentage=v;
		}
		secure_rng(buf, BLOCK_SIZE);
		if(write(fd, buf, BLOCK_SIZE) != BLOCK_SIZE)
			return error_on_write;
	}
	return MountError_ok;
}

WARN const map<u32, unique_ptr<Drive> >* lib_list(const char*path_) {
	string path = myrealpath(path_);
	auto v = device_map.find(path);
	if (v == device_map.cend())
		return 0;
	return v->second->getList();
}

WARN Drive* lib_find_drive(const char*fn, const char*id) {
	auto drive_map = lib_list(fn);
	for(auto i = drive_map->begin(); i!=drive_map->end(); ++i) {
		Drive*pdrive = i->second.get();
		if(memcmp(pdrive->get_id(), id, 3)==0) {
			return pdrive;
		}
	}
	return 0;
}

WARN const u8* lib_drive_id(Drive*p) { return p->get_id(); }
WARN s64 lib_device_size(Drive*p) { return p->get_device_size(); }

WARN int lib_read(void *buf, size_t size, size_t offset, Drive*p) {
	int unset=0;
	return p->read(buf, size, offset, unset);
}
WARN int lib_write(const void *buf, size_t size, size_t offset, Drive*p) {
	
	auto ret = p->write(buf, size, offset);
	if(((int)size!=ret || errno!=0 ) && !(errno ==ENOSPC && ret ==0)){
		auto id = base64_encode(p->get_id(), 3);
		fprintf(stderr, "Write size %ld offset %ld ret %d errno %d id %s\n", size, offset, ret, errno, id.c_str());
	}
	return ret;
}

//in short it makes '/' into '`', '`' into '~`' and '~' into '~~'
string EscapeFilePath(const char*l) {
	string ret;
	const char*r = l;
	while(1){
		if(*r=='`') {
			ret.append(l, r-l);
			ret.append("~`");
			l=r+1; r=l;
		} else if(*r=='~') {
			ret.append(l, r-l);
			ret.append("~~");
			l=r+1; r=l;
		} else if(*r=='/') {
			ret.append(l, r-l);
			ret.append("`");
			l=r+1; r=l;
		}
		else if(*r == 0)
		{
			ret.append(l, r-l);
			return ret;
		}
		else {
			++r;
		}
	}
}

s64 lib_get_size_of_file(const string&path){
	struct stat64 s;
	stat64(path.c_str(), &s);
	if(s.st_size!=0) {
		return (s.st_size / BLOCK_SIZE) * BLOCK_SIZE;
	}
	else {
		GuardT<int> fd (open(path.c_str(), O_LARGEFILE | O_RDONLY), close);
		return (GetBlockSize64(fd) / BLOCK_SIZE) * BLOCK_SIZE;
	}	
}
