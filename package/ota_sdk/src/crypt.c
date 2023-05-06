#include <string.h>
#include<stdbool.h>
#include <stdio.h>
#include <openssl/md5.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include "internal.h"


/*****************************base64*******************************/
static const char *BASE64_CHARSETS[2] = {
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
};

enum {
	BASE64_STD = 0,
	BASE64_URL
};

static int base64_encode(const void *source, int len, char *out, int type)
{
	int i;
	const char *b64chars = BASE64_CHARSETS[type];
	const unsigned char *src = (unsigned char *)source;
	char *dst = out;

	for (i = 0; i < len; i += 3) {
		unsigned char idx = src[i] >> 2;
		*dst++ = b64chars[idx];
		idx = (src[i] << 4) & 0x30;
		if (i + 1 >= len) {
			*dst++ = b64chars[idx];
			*dst++ = '=';
			*dst++ = '=';
			break;
		}
		idx |= (src[i + 1] >> 4);
		*dst++ = b64chars[idx];
		idx = (src[i + 1] << 2) & 0x3c;
		if (i + 2 >= len) {
			*dst++ = b64chars[idx];
			*dst++ = '=';
			break;
		}
		idx |= ((src[i + 2] >> 6) & 0x03);
		*dst++ = b64chars[idx];
		*dst++ = b64chars[src[i + 2] & 0x3f];
	}
	*dst = 0;
	return dst - out;
}

static int base64_decode(const char *src, void *dst, int type)
{
	const char *b64chars = BASE64_CHARSETS[type], *p, *s = src;
	unsigned char *d = (unsigned char *)dst;
	int i, n, len = strlen(src);

	for (i = 0; i < len; i += 4) {
		unsigned char t[4] = { 0xff, 0xff, 0xff, 0xff };
		for (n = 0; n < 4; n++) {
			if (i + n >= len || s[i + n] == '=') {
				break;
			}
			p = strchr(b64chars, s[i + n]);
			if (p) {
				t[n] = p - b64chars;
			}
		}
		*d++ = (((t[0] << 2)) & 0xFC) | ((t[1] >> 4) & 0x03);
		if (s[i + 2] == '=') {
			break;
		}
		*d++ = (((t[1] << 4)) & 0xF0) |  ((t[2] >> 2) & 0x0F);
		if (s[i + 3] == '=') {
			break;
		}
		*d++ = (((t[2] << 6)) & 0xF0) | (t[3] & 0x3F);
	}
	return d - (unsigned char *)dst;
}


int crypt_md5_file(const char *file, char *md5)
{
	int len = 0;
	char buf[1024 * 4] = { };
	MD5_CTX context;
	unsigned char md5buf[16] = { };

	FILE *fp = fopen(file, "rb");
	if (!fp) {
		return -1;
	}

	MD5_Init(&context);
	while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
		MD5_Update(&context, buf, len);
	}
	MD5_Final(md5buf, &context);

	fclose(fp);

	for (len = 0; len < 16; len++) {
		snprintf(md5 + len * 2, 3, "%02x", md5buf[len]);
	}

	return 0;
}

static bool md5_encrypt(const char *input_arg1, const char *input_arg2, char *out_md5)
{
	unsigned char md[MD5_DIGEST_LENGTH] = { };
	char data[256] = { 0 };
	MD5_CTX c;
	int i;

	/*
	* 校验input_arg1与input_arg2的合法性
	*/
	if (input_arg1 == NULL || input_arg2 == NULL) {
		return false;
	}

	memset(out_md5, 0, MD5_DIGEST_LENGTH * 2 + 1);
	snprintf(data, sizeof(data), "%s%s", input_arg1, input_arg2);

	// 1. 初始化
	MD5_Init(&c);
	// 2. 添加数据
	MD5_Update(&c, (const void *)data, strlen((char *)data));
	// 3. 计算结果
	MD5_Final(md, &c);

	//4. 输出结果
	for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
		sprintf((char *)&out_md5[i * 2], "%02x", md[i]);
	}

	return true;
}

int crypt_gen_triple_key_from_devinfo(const char *devid, const char *dev_sec, struct _triple_key *outkey)
{

	if (!md5_encrypt(devid, dev_sec, outkey->sign_key)) {
		LogError("md5_en_crypt error");
		return -1;
	}

	if (!md5_encrypt(outkey->sign_key, dev_sec, outkey->encrypt_key)) {
		LogError("md5_en_crypt error");
		return -1;
	}

	if (!md5_encrypt(outkey->sign_key, devid, outkey->decrypt_key)) {
		LogError("md5_en_crypt error");
		return -1;
	}

	return 0;
}

/*****************************AES*******************************/
/**
 * @brief *Function: int pkcs7_padding(char *data, int dataSize, int dataLen)
 *Describe: pkcs7填充
 *Param   : data    : 数据
 *          dataSize: 存储 data的数组容量
 *          dataLen : data 的长度
 *return  ：-1 data数据为空
 *          -2 填充后的数据越界
 *          >0 填充后的数据长度
 *
 */
static int fpkcs7_padding(char *data, int dataSize, int dataLen)
{
	uint8_t paddingNum;

	if (dataLen <= 0) {
		return -1;
	}

	if ((dataLen + 17) >= dataSize) {
		return -2;
	}

	paddingNum = 16 - (dataLen % 16);

	memset(&data[dataLen], paddingNum, paddingNum);

	data[dataLen + paddingNum] = '\0';

	return dataLen + paddingNum;
}

/**************************************************************************************
 *Function: int pkcs7_cuttingg(char *data, int dataLen)
 *Describe: pkcs7去除填充
 *Param   : data    : 数据
 *          dataLen : data 的长度
 *return  ：-1 data数据为空
 *          -3 填充检查失败
 *          >0 填充后的数据长度
 ***************************************************************************************/
static int pkcs7_cuttingg(char *data, int dataLen)
{
	uint8_t paddingNum;
	int i;

	if (dataLen <= 0) {
		return -1;
	}

	paddingNum = data[dataLen - 1];

	//check
	for (i = 0; i < paddingNum; i++) {
		if (data[dataLen - paddingNum + i] != paddingNum) {
			return -3;
		}
	}

	memset(&data[dataLen - paddingNum], 0, paddingNum);
	data[dataLen - paddingNum] = '\0';

	return dataLen - paddingNum;
}

bool crypt_aes256_encrypt(const char *context, const char *key, char *body)
{
	char buf_normal[SEND_BUFF_LEN] = { 0 };
	unsigned char buf_encrypt[SEND_BUFF_LEN] = { 0 }; //存储加密后的内容
	AES_KEY aesKey;
	int aes_in_len;
	int i;

	snprintf(buf_normal, sizeof(buf_normal), "%s", context); //要加密的内容
	if (context == NULL || key == NULL || body == NULL) {
		LogError("aes256_crypt parameter error");
		return false;
	}

	aes_in_len = fpkcs7_padding(buf_normal, sizeof(buf_normal), strlen(buf_normal)); //填充

	// 加密
	AES_set_encrypt_key((unsigned char *)key, 256, &aesKey);
	for (i = 0; i < aes_in_len / AES_BLOCK_SIZE; i++) {
		AES_ecb_encrypt((const unsigned char *)buf_normal + AES_BLOCK_SIZE * i,
						(unsigned char *)buf_encrypt + AES_BLOCK_SIZE * i,
						&aesKey,
						AES_ENCRYPT);
	}

	base64_encode(buf_encrypt, aes_in_len, body, BASE64_STD);

	return true;
}

bool crypt_aes256_decrypt(const char *context, const char *key, char *body)
{
	char de_context[RECV_BUFF_LEN] = { 0 }; //存储要解密的内容
	char aes_debase64[RECV_BUFF_LEN] = { 0 }; //存储base64转UTF-8的内容
	int base64_len;
	AES_KEY aesde_key;
	int i;

	if (context == NULL || key == NULL || body == NULL) {
		LogError("aes256_crypt parameter error");
		return false;
	}

	snprintf(de_context, sizeof(de_context), "%s", context);
	base64_len = base64_decode(de_context, aes_debase64, BASE64_STD);
	AES_set_decrypt_key((unsigned char *)key, 256, &aesde_key);
	for (i = 0; i < base64_len / AES_BLOCK_SIZE; i++) {
		AES_ecb_encrypt((const unsigned char *)aes_debase64 + AES_BLOCK_SIZE * i,
						(unsigned char *)body + AES_BLOCK_SIZE * i,
						&aesde_key,
						AES_DECRYPT);
	}
	pkcs7_cuttingg(body, strlen(body));

	return true;
}

/*****************************sign*******************************/
bool crypt_sign(const char *context, const char  *deviceId, int time, const char *Model,
				int Nonce, const char *signKey, unsigned char *XSign)
{
	char buf_context[SEND_BUFF_LEN] = { 0 };
	HMAC_CTX hmac = { };
	unsigned int len = 0;

	if (deviceId == NULL) {
		snprintf(buf_context, sizeof(buf_context), "%s%s%10d%6d", context, Model, time, Nonce); //数据
	} else {
		snprintf(buf_context, sizeof(buf_context), "%s%s%s%10d%6d", context, deviceId, Model, time, Nonce); //数据
	}

	LogInfo("content: %s\n", buf_context);
	LogInfo("signKey=%s", signKey);
	LogInfo("time:%d", time);
	LogInfo("Nonce:%d", Nonce);

	HMAC_CTX_init(&hmac);
	HMAC_Init_ex(&hmac, signKey, strlen(signKey), EVP_sha256(), NULL);
	HMAC_Update(&hmac, (unsigned char *)buf_context, strlen(buf_context));
	HMAC_Final(&hmac, XSign, &len);
	HMAC_CTX_cleanup(&hmac);

	return true;
}




