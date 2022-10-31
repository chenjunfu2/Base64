#pragma once

//***************define***************//
#define NULL 0
#define CONST const
//***************define***************//

//***************class***************//
class Base64
{
public:
	typedef unsigned char UCHAR;
	typedef unsigned char* PUCHAR;
	typedef const unsigned char CUCHAR;
	typedef const unsigned char* PCUCHAR;
	typedef long LONG;
	typedef unsigned long ULONG;
	typedef unsigned long long ULONGLONG;
	typedef void VOID;
	typedef void* PVOID;
	typedef const void* PCVOID;
	typedef bool BOOL;
protected:
	UCHAR FullCode;//填充字符
	UCHAR BaseText[65];//加密字符集 Use:[0]~[64] Full:[64]=0 Text:[0]~[63]
	UCHAR BaseTextMap[256];//加密字符集映射：通过加密字符获得该字符在字符集中的位置（映射集）
public:
	Base64(VOID);
	Base64(UCHAR, PCUCHAR);
	Base64(PCUCHAR);
	Base64(UCHAR);
	~Base64(VOID) = default;

	VOID SetBaseText(PCUCHAR);//设置加密字符串
	PCUCHAR GetBaseText(VOID) CONST;//获取加密字符串

	VOID SetFullCode(UCHAR);//设置填充字符
	UCHAR GetFullCode(VOID) CONST;//获取填充字符

	PCUCHAR GetBaseTextMap(VOID) CONST;//获取映射表

	ULONGLONG GetEnCodeSize(PCVOID, ULONGLONG) CONST;//获取加密后字符串长度
	VOID EnCode(PCVOID, ULONGLONG, PUCHAR) CONST;//加密指定内存的指定字节数到指定字符串

	ULONGLONG GetDeCodeSize(PCUCHAR, ULONGLONG) CONST;//获取解密后数据字节长度
	BOOL DeCode(PCUCHAR, ULONGLONG, PVOID) CONST;//解密指定字符串到指定内存的指定字节数
};
//***************class***************//

//***************funtion***************//
Base64::Base64(VOID) :
	FullCode('='),
	BaseText("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
{
	for (ULONG i = 0; i < 256; i += 1)
		BaseTextMap[i] = 64;//全部初始化为64

	for (ULONG i = 0; i < 64; i += 1)
		BaseTextMap[BaseText[i]] = (UCHAR)i;//创建字符集映射

	return;
}

Base64::Base64(UCHAR F, PCUCHAR B) :
	FullCode(F)
{
	for (ULONG i = 0; i < 256; i += 1)
		BaseTextMap[i] = 64;//全部初始化为64

	for (ULONG i = 0; i < 64; i += 1)
	{
		BaseText[i] = B[i];//拷贝传入字符集
		BaseTextMap[BaseText[i]] = (UCHAR)i;//同时映射字符集
	}
	BaseText[64] = '\0';

	return;
}

Base64::Base64(UCHAR F) :
	FullCode(F),
	BaseText("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
{
	for (ULONG i = 0; i < 256; i += 1)
		BaseTextMap[i] = 64;//全部初始化为64

	for (ULONG i = 0; i < 64; i += 1)
		BaseTextMap[BaseText[i]] = (UCHAR)i;//创建字符集映射

	return;
}

Base64::Base64(PCUCHAR B) :
	FullCode('=')
{
	for (ULONG i = 0; i < 256; i += 1)
		BaseTextMap[i] = 64;//全部初始化为64

	for (ULONG i = 0; i < 64; i += 1)
	{
		BaseText[i] = B[i];//拷贝传入字符集
		BaseTextMap[BaseText[i]] = (UCHAR)i;//同时映射字符集
	}
	BaseText[64] = '\0';

	return;
}


Base64::VOID Base64::SetBaseText(PCUCHAR pcBaseText)
{
	for (ULONG i = 0; i < 64; i += 1)
		BaseTextMap[BaseText[i]] = 64;//读取映射字符集并重新归位（避免全部初始化，减少性能开销）

	for (ULONG i = 0; i < 64; i += 1)
	{
		BaseText[i] = pcBaseText[i];//设置字符集
		BaseTextMap[BaseText[i]] = (UCHAR)i;//同时映射字符集
	}
	BaseText[64] = '\0';

	return;
}

Base64::PCUCHAR Base64::GetBaseText(VOID) CONST
{
	return BaseText;
}

Base64::VOID Base64::SetFullCode(UCHAR cFullCode)
{
	FullCode = cFullCode;
}

Base64::UCHAR Base64::GetFullCode(VOID) CONST
{
	return FullCode;
}

Base64::PCUCHAR Base64::GetBaseTextMap(VOID) CONST
{
	return BaseTextMap;
}

Base64::ULONGLONG Base64::GetEnCodeSize(PCVOID pcEnCodeData, ULONGLONG ullEncodeSize) CONST
{
	return ullEncodeSize <= 3 ? 4: (ullEncodeSize / 3 * 4 + ((ullEncodeSize % 3) ? 4 : 0));
}

Base64::VOID Base64::EnCode(PCVOID pcData, ULONGLONG size, PUCHAR pEncode) CONST
{
	PCUCHAR pcCode = (PCUCHAR)pcData;
	ULONGLONG i, j;

	for (i = 3, j = 4; i <= size; i += 3, j += 4)
	{
		pEncode[j - 4] = BaseText[(pcCode[i - 3] >> 2)];
		pEncode[j - 3] = BaseText[(((pcCode[i - 3] & 0x03) << 4) | ((pcCode[i - 2] & 0xF0) >> 4))];
		pEncode[j - 2] = BaseText[(((pcCode[i - 2] & 0x0F) << 2) | ((pcCode[i - 1] & 0xC0) >> 6))];
		pEncode[j - 1] = BaseText[pcCode[i - 1] & 0x3F];
	}

	switch ((size % 3) - 1)
	{
	case 0:
		pEncode[j - 4] = BaseText[(pcCode[i - 3] >> 2)];
		pEncode[j - 3] = BaseText[((pcCode[i - 3] & 0x03) << 4)];
		pEncode[j - 2] = FullCode;
		pEncode[j - 1] = FullCode;
		break;
	case 1:
		pEncode[j - 4] = BaseText[(pcCode[i - 3] >> 2)];
		pEncode[j - 3] = BaseText[(((pcCode[i - 3] & 0x03) << 4) | ((pcCode[i - 2] & 0xF0) >> 4))];
		pEncode[j - 2] = BaseText[(((pcCode[i - 2] & 0x0F) << 2) | ((pcCode[i - 1] & 0xC0) >> 6))];
		pEncode[j - 1] = FullCode;
		break;
	default:
		break;
	}

	return;
}

Base64::ULONGLONG Base64::GetDeCodeSize(PCUCHAR pcDeCodeText, ULONGLONG ullDecodeSize) CONST
{
	ULONGLONG fs = 0;
	if (pcDeCodeText)
	{
		if (pcDeCodeText[ullDecodeSize - 2] == FullCode)
			fs = 2;
		else if (pcDeCodeText[ullDecodeSize - 1] == FullCode)
			fs = 1;
	}

	return (ullDecodeSize <= 4 ? 3 : ullDecodeSize / 4 * 3) - fs;
}

Base64::BOOL Base64::DeCode(PCUCHAR pcCode, ULONGLONG size, PVOID pData) CONST
{
	PUCHAR cpDecode = (PUCHAR)pData;
	ULONGLONG i, j;
	UCHAR cCode[4] = { 0 };

	if (size % 4 != 0)
		return false;

	if (pcCode[size - 2] == FullCode)
		size -= 3;
	else if (pcCode[size - 1] == FullCode)
			size -= 2;

	for (i = 4, j = 3; i <= size; i += 4, j += 3)
	{
		for (LONG k = -4; k < 0; k += 1)
		{
			if ((cCode[k + 4] = BaseTextMap[pcCode[i + k]]) == 64)
				return false;
		}

		cpDecode[j - 3] = (cCode[0] << 2) | ((cCode[1] & 0x30) >> 4);
		cpDecode[j - 2] = (((cCode[1] & 0x0F) << 4) | ((cCode[2] & 0x3C) >> 2));
		cpDecode[j - 1] = ((cCode[2] & 0x03) << 6) | (cCode[3] >> 0);
	}

	switch ((size % 4) - 1)
	{
	case 0:
		for (LONG k = -4; k < -2; k += 1)
		{
			if ((cCode[k + 4] = BaseTextMap[pcCode[i + k]]) == 64)
				return false;
		}
		
		cpDecode[j - 3] = (cCode[0] << 2) | ((cCode[1] & 0x30) >> 4);
		break;
	case 1:
		for (LONG k = -4; k < -1; k += 1)
		{
			if ((cCode[k + 4] = BaseTextMap[pcCode[i + k]]) == 64)
				return false;
		}

		cpDecode[j - 3] = (cCode[0] << 2) | ((cCode[1] & 0x30) >> 4);
		cpDecode[j - 2] = (((cCode[1] & 0x0F) << 4) | ((cCode[2] & 0x3C) >> 2));
		break;
	default:
		break;
	}

	return true;
}
//***************funtion***************//

//***************undef***************//
#undef NULL
#undef CONST
//***************undef***************//



//***************test***************//
/*
	Base64 be64;

	char trye[] = "你好，世界！";//xOO6w6OsysC956Oh

	char* be = new char[be64.GetEnCodeSize(trye, strlen(trye)) + 1]{ 0 };
	be64.EnCode(trye, strlen(trye), be);
	printf("%s", be);

	putchar('\n');

	char tryd[] = "xOO6w6OsysC956Oh";//你好，世界！
	Base64 bd64;

	char* bd = new char[bd64.GetDeCodeSize(tryd, strlen(tryd)) + 1]{ 0 };
	if (bd64.DeCode(tryd, strlen(tryd), bd))
		printf("%s", bd);
	else
		printf("出错了");

	putchar('\n');


	delete[] be;
	delete[] bd;

	system("pause");
*/
/*
	string IO;
	Base64 b64((const unsigned char*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs.uvwxy,0123456789+/");	

	b64.SetBaseText("9876543210ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/");


	printf("请输入你要加密的字符串:");
	cin >> IO;
	
	char* be = new char[b64.GetEnCodeSize(NULL, IO.size()) + 1];
	b64.EnCode((unsigned char*)IO.c_str(), (Base64::ULONGLONG)IO.size(), (unsigned char*)be);
	printf("%s\n", be);
	delete[] be;
	


	printf("请输入你要解密的字符串:");
	cin >> IO;
	
	char* bd = new char[b64.GetDeCodeSize((unsigned char*)IO.c_str(), IO.size()) + 1];
	b64.DeCode((unsigned char*)IO.c_str(), (Base64::ULONGLONG)IO.size(), (unsigned char*)bd);
	printf("%s\n", bd);
	delete[] bd;
	
	system("pause");
*/

//***************test***************//