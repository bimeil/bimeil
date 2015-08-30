bimeil is an open source on the fly disk encryption for Linux. It's main goal is to support multiple drives in a single file. With one large file you can 1) keep your tax, medical and bank records private 2) Keep your homemade porn away from your accountant 3) Keep your fetish porn away from your significant other.

When mounting a drive it will appear as if the drive has the full size of the file available. You must mount all drives to get the true amount of space used and available. You may mount drives in readonly mode to avoid corrupting via accidental writes.

#Pros and Cons to other encryption
##Pros
- Source code is small and not difficult to audit
- Can create as many drives as you want on a single file/disk (storage permitting)
- All drives appear to use up the entire disk space. No one can tell
- Suitable for portability (read more below).
- Userspace/FUSE powered (no need to enable or customize your kernel)
- Strong/high pbkdf2 default (500000 compared to truecrypt outdated 1000)
##Cons
- Bookkeeping overhead in storage and memory
- May corrupt drives not mounted (readonly mode can prevent this)
- New and not well tested. **Likely loss of data**

#Building

	g++ --std=c++1y -D_FILE_OFFSET_BITS=64 -I/usr/include/nspr -I/usr/include/nss src/*.cpp -lnss3 -lfuse -lrt -lpthread

#Usage

	bimeil create n file -s 50M #50 megabytes
	bimeil create d file -l softlink_drive0 #you're prompt for various things such as the passphrase and encryption cipher
	cp -R /boot softlink_drive0 #let's write to our drive
	bimeil umount file
	ls #softlink_drive0 is gone
	bimeil mount rw file -l d0
	find /boot -type f -exec cmp {} d0{} \; #Our files correct. However it's still a beta. Try with several gb
	bimeil u file #u is short for umount/unmount

#Warnings

This is beta software. You may lose data or have randomly corrupted data. If you are using removable media always umount before disconnecting. The app does not check if it's using removable media and doesn't use the flush option. You should use `bimeil umount file` to unmount but using `umount` on the clear and encrypt fuse folder in `/run/bimeil` is fine as well. `umount -a` is another option.

Some ciphers are faster than others. Run `bimeil time cipher` to see the speeds. Some may be faster due to hardware acceleration. This code needs to be optimized. Memory usage may get high if using large storage (such as 500+gb). I suspect map has a high amount of overhead and another algorithm is better suited.

#How it works

Currently this uses your cipher of choice between AES, Camellia and 3DES using 128bit keys and CBC. The IV is 128bits with the first 96bits random and last 32bits predictable and unique. pbkdf2 has a default of 500000 rounds. pbkdf2 produces the block offset ( mod filesize/blocksize(32K) ), key and IV. The block is decrypted by the key and IV (trying each cipher once) and considered a correct password if the header+SHA224 is correct. Page links integrity is checked using SHA256 but xor in half. This is safe since we're using it as a checksum.

The pages and data block use a 128bit key and 96bit IV found in the header (not from pbkdf2). The last 32 bit of the IV is predictable and unique. The IV is either the logical block value or negative page index. The 32bits is impossible to collide if the drive isn't several terabytes large.

libnss3 is used for crypto, mount handles the filesystem logic and provides data as a file read/write (with seek). Fuse provides me with an interface to create a file and execute my code during file read/write allowing me to encrypt/decrypt to disk in realtime.

#Portability

On most systems with a desktop environment iceweasel or firefox is installed and libnss3 is part of the package. nss3 is used for the crypto and the rest of the dependencies are install on most systems by default. The app create sockets fuse files and directories in `/run/bimeil`. After umounting and removing the folder (which is cleared on reboot) it should appear `bimeil` as never ran unless something noticed and put it in a log file.


