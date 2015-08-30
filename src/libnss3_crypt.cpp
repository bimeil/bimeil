#include "lib.h"
#include "crypt.h"
#include <nss.h>
#include <nss/pk11pub.h>

static int init_count = 0;
static int init_retval= 0;
WARN int lib_init() {
	if(init_count++ == 0)
		init_retval = NSS_NoDB_Init(".");
	return init_retval!=0;
}
void lib_cleanup() {
	if(--init_count==0)
		NSS_Shutdown();
}

Guard lib_init2() {
	if (lib_init() != 0) {
		fprintf(stderr, "Could not init lib\n");
		throw std::exception();
	}
	return Guard(lib_cleanup);
}

WARN int sha_it(const void*data, int length, u8*result, int res_len, SECOidTag id)
{
	PK11SlotInfo *slot = PK11_GetInternalKeySlot();
	if (!slot)
		return -1;
	PK11Context *context = PK11_CreateDigestContext(id);
	if(!context)
		return -2;
	if (PK11_DigestBegin(context) != SECSuccess)
		return -3;
	if (PK11_DigestOp(context, (unsigned char*)data, length) != SECSuccess)
		return -4;

	uint len;
	if (PK11_DigestFinal(context, result, &len, res_len) != SECSuccess)
		return -5;

	PK11_DestroyContext(context, PR_TRUE);
	PK11_FreeSlot(slot);
	return 0;
}
WARN int sha224(const void*data, int length, u8*sha224_result) { return sha_it(data, length, sha224_result, 224/8, SEC_OID_SHA224); }
WARN int sha256(const void*data, int length, u8*sha256_result) { return sha_it(data, length, sha256_result, 256/8, SEC_OID_SHA256); }

void secure_rng(void*bytes, int length) {
	if(PK11_GenerateRandom((u8*)bytes, length)!=SECSuccess) {
		fprintf(stderr, "Error in secure_rng\n");
		std::terminate(); 
	}
}
WARN u32 secure_rng_u32() { u32 r; secure_rng(&r, 4); return r; }

static PK11Context* CreateEncryptContext(u8*key, u8*iv128, bool encrypt, Cipher cipher) {

	CK_MECHANISM_TYPE cipherMech;
	switch (cipher) {
		case AES: cipherMech = CKM_AES_CBC; break;
		case Camellia: cipherMech = CKM_CAMELLIA_CBC; break;
		case TripleDES: cipherMech = CKM_DES3_CBC; break;
		default: std::terminate();
	}
	
	auto slot = PK11_GetBestSlot(cipherMech, NULL);
	if (slot == NULL)
		return 0;

	SECItem keyItem;
	keyItem.type = siBuffer;
	keyItem.data = key;
	keyItem.len = 128/8;

	auto SymKey = PK11_ImportSymKey(slot, cipherMech, PK11_OriginUnwrap, encrypt?CKA_ENCRYPT:CKA_DECRYPT, &keyItem, NULL);
	if (SymKey == NULL)
		return 0;

	SECItem ivItem;
	ivItem.type = siBuffer;
	ivItem.data = iv128;
	ivItem.len = 128/8;

	auto SecParam = PK11_ParamFromIV(cipherMech, &ivItem);
	if (SecParam == NULL)
		return 0;

	return PK11_CreateContextBySymKey(cipherMech, encrypt?CKA_ENCRYPT:CKA_DECRYPT, SymKey, SecParam);
}

WARN int crypt(const void*i, void*o, u8*key128, u8*iv128, int length, Cipher cipher, bool encrypt) {
	const u8*in_data = (const u8*)i;
	u8* out_data=(u8*)o;
	int tmp1_outlen=0;
	unsigned int tmp2_outlen=0;

	auto EncContext = CreateEncryptContext(key128, iv128, encrypt, cipher);
	if(EncContext==0)
		return -4;

	auto rv1 = PK11_CipherOp(EncContext, out_data, &tmp1_outlen, length, in_data, length);
	auto rv2 = PK11_DigestFinal(EncContext, out_data+tmp1_outlen, &tmp2_outlen, length-tmp1_outlen);
	PK11_DestroyContext(EncContext, PR_TRUE);
	auto result_len = tmp1_outlen + tmp2_outlen;
	if (rv1 != SECSuccess || rv2 != SECSuccess)
		return -5;

	return result_len;
}
WARN int encrypt(const void*i, void*o, u8*key128, u8*iv128, int length, Cipher cipher) { return crypt(i, o, key128, iv128, length, cipher, 1); }
WARN int decrypt(const void*i, void*o, u8*key128, u8*iv128, int length, Cipher cipher) { return crypt(i, o, key128, iv128, length, cipher, 0); }

WARN int pbkdf2(u8*pass_, int passlen, u8*salt_, size_t salt_len, int rounds, u8*buf, size_t buf_len) {

	SECItem pass, salt;
	pass.type = siBuffer;
	pass.data = pass_;
	pass.len = passlen;

	salt.type = siBuffer;
	salt.data = salt_;
	salt.len = salt_len;

	auto cipher = SEC_OID_PKCS5_PBKDF2;

	auto algid = PK11_CreatePBEV2AlgorithmID(cipher, cipher, SEC_OID_HMAC_SHA1, buf_len, rounds, &salt);
	if (algid==0)
		return -1;

	auto slot =  PK11_GetInternalKeySlot();
	if (slot == 0)
		return -2;

	auto symKey = PK11_PBEKeyGen(slot, algid, &pass, PR_FALSE, 0);
	if (symKey == 0)
		return -3;

	PK11_ExtractKeyValue(symKey);
	const SECItem *data = PK11_GetKeyData(symKey);
	if (data == 0)
		return -4;

	if(data->len!=buf_len)
		return -5;

	memcpy(buf, data->data, data->len);
	return 0;
}
WARN int pbkdf2(const char*pass_, const u8*salt_, size_t salt_len, int rounds, void*buf, size_t buf_len) {
	auto pass_len = strlen(pass_);
	GuardT<char*> pass(strdup(pass_), free);

	auto salt=new u8[salt_len];
	memcpy(salt, salt_, salt_len);
	return pbkdf2((u8*)pass.get(), pass_len, (u8*)salt, salt_len, rounds, (u8*)buf, buf_len);
}
