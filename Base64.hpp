#ifndef Base64_hpp
#define Base64_hpp

//***************define***************//
#define DEFAULT_BASECODE "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"//MIME Base64
#define DEFAULT_FULLCODE '='//MIME Base64

#define INIT_THROW true//�׳���ʼ���쳣


#if INIT_THROW
#define THROW_ERROR(reason) throw(reason)
#else
#define THROW_ERROR(reason)
#endif
//***************define***************//

//***************include***************//
#include <string.h>
//***************include***************//

//***************class***************//

class Base64
{
public:
	typedef char CHAR;
	typedef char *PCHAR;
	typedef const char CCHAR;
	typedef const char *PCCHAR;
	typedef unsigned char UCHAR;
	typedef unsigned char *PUCHAR;
	typedef const unsigned char CUCHAR;
	typedef const unsigned char *PCUCHAR;
	typedef long LONG;
	typedef unsigned long ULONG;
	typedef unsigned long long ULONGLONG;
	typedef void VOID;
	typedef void *PVOID;
	typedef const void *PCVOID;
	typedef bool BOOL;
protected:
#define BASECODE_COUNT ((ULONG)(64))//BASE64
#define BASECODEAP_COUNT (((ULONG)((UCHAR)(-1)))+1)//UCHAR_MAX+1

	UCHAR ucFullCode;//����ַ�
	UCHAR ucBaseCode[BASECODE_COUNT + sizeof('\0')];//�����ַ��� Use:[0]~[64] Full:[64]=0 Text:[0]~[63]
	UCHAR ucBaseCodeMap[BASECODEAP_COUNT];//�����ַ���ӳ�䣺ͨ�������ַ���ø��ַ����ַ����е�λ�ã�ӳ�伯��

	mutable ULONG ulLastError;//������һ��������
	mutable BOOL bAvailable;//���Ƿ���ã����ucBaseCode�����ݲ���ȷ��ӳ�䲻�ɹ����ֵΪfalse���಻���ã�������ã������ڱ�֤�������ݲ�����ܴ�������ܵ���

	//�ַ���ӳ�亯��
	BOOL MapTheBaseCode(VOID) noexcept;
public:
	Base64(PCUCHAR _ucBaseCode = (PCUCHAR)DEFAULT_BASECODE, UCHAR _ucFullCode = DEFAULT_FULLCODE);//������
	Base64(const Base64 &) = default;
	Base64(Base64 &&) = default;
	~Base64(VOID) = default;

	BOOL SetBaseCode(PCUCHAR pcucBaseCode) noexcept;//���ü����ַ���
	PCUCHAR GetBaseCode(VOID) const noexcept;//��ȡ�����ַ���

	BOOL SetFullCode(UCHAR cucFullCode) noexcept;//��������ַ�
	UCHAR GetFullCode(VOID) const noexcept;//��ȡ����ַ�

	ULONGLONG GetEnCodeSize(PCVOID pData, ULONGLONG ullDataSize) const noexcept;//��ȡ���ܺ��ַ�������
	BOOL EnCode(PCVOID pData, ULONGLONG ullDataSize, PUCHAR pCode, ULONGLONG ullCodeSize) noexcept;//����ָ���ڴ��ָ���ֽ�����ָ���ַ���

	ULONGLONG GetDeCodeSize(PCUCHAR pCode, ULONGLONG ullCodeSize) const noexcept;//��ȡ���ܺ������ֽڳ���
	BOOL DeCode(PCUCHAR pCode, ULONGLONG ullCodeSize, PVOID pData, ULONGLONG ullDataSize) noexcept;//����ָ���ַ�����ָ���ڴ��ָ���ֽ���

	VOID SetLastError(ULONG ulErrorCode) noexcept;//�������һ��������
	ULONG GetLastError(VOID) const noexcept;//��ȡ���һ��������
	PCCHAR GetErrorReason(ULONG ulErrorCode) const noexcept;//�Ӵ������ô���ԭ��

private:
	enum enErrorCode
	{
		NO_ERROR = 0,//�޴���
		CIPHER_REPEATING_CHAR,//���ܴ��г����ظ��ַ�
		FILL_CODE_IN_CIPHER,//���ܴ��г�������ַ�
		NULL_DATA_POINTER,//����ָ��Ϊ��
		NULL_CODE_POINTER,//�ַ�ָ��Ϊ��
		TARGET_TOO_SMALL,//�ӽ���Ŀ�겻�������ɽ��

		UNKNOW_ERROR,//δ֪����
	};

	static inline Base64::PCCHAR pErrorReason[UNKNOW_ERROR + 1] =
	{
		"�޴���",
		"���ܴ��г����ظ��ַ�",
		"���ܴ��г�������ַ�",
		"����ָ��Ϊ��",
		"�ַ�ָ��Ϊ��",
		"Ŀ���ڴ�̫С",

		"δ֪����",
	};
};

//***************class***************//

//***************funtion***************//

Base64::BOOL Base64::MapTheBaseCode(VOID) noexcept
{
	//��ucBaseCodeMap��ʼ��ΪBASECODE_COUNT,�Ա��ں�������з��ִ���
	memset(ucBaseCodeMap, BASECODE_COUNT, BASECODEAP_COUNT * sizeof(UCHAR));

	for (ULONG i = 0; i < BASECODE_COUNT; i += 1)
	{
		if (ucBaseCodeMap[ucBaseCode[i]] != BASECODE_COUNT)
		{
			return false;//�ظ��ַ�
		}
		ucBaseCodeMap[ucBaseCode[i]] = (UCHAR)i;//ӳ������ַ�(���ٽ�����)
	}

	return true;
}

Base64::Base64(PCUCHAR _ucBaseCode, UCHAR _ucFullCode) :
	ucFullCode(_ucFullCode), ulLastError(NO_ERROR), bAvailable(false)//���ø���Ϊ������״̬
{
	//���������ַ���
	memcpy(ucBaseCode, _ucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//��ȫ������ַ���ĩβ��ֵΪ0

	//�������ַ��Ƿ�λ�ڼ��ܴ���
	if (strchr((PCCHAR)ucBaseCode, ucFullCode) != NULL)
	{
		SetLastError(FILL_CODE_IN_CIPHER);
		THROW_ERROR("���ܴ��г�������ַ�!");//����ַ����ַ����е�ĳ���ַ���ͬ
		return;
	}

	//ӳ����ܴ�
	if (!MapTheBaseCode())
	{
		SetLastError(CIPHER_REPEATING_CHAR);
		THROW_ERROR("���ܴ��г����ظ��ַ�!");
		return;
	}

	//�ɹ���ʼ�����������
	bAvailable = true;
}


Base64::BOOL Base64::SetBaseCode(PCUCHAR pcucBaseCode) noexcept
{
	//���ø���Ϊ������״̬
	bAvailable = false;

	//���������ַ���
	memcpy(ucBaseCode, pcucBaseCode, BASECODE_COUNT);
	ucBaseCode[64] = '\0';//��ȫ������ַ���ĩβ��ֵΪ0

	//ӳ����ܴ�
	if (!MapTheBaseCode())
	{
		SetLastError(CIPHER_REPEATING_CHAR);
		return false;
	}

	//���ͨ��������Ϊ����״̬
	bAvailable = true;
	return true;
}

Base64::PCUCHAR Base64::GetBaseCode(VOID) const noexcept
{
	return ucBaseCode;
}


Base64::BOOL Base64::SetFullCode(UCHAR cucFullCode) noexcept
{
	//���ø���Ϊ������״̬
	bAvailable = false;
	//��������ַ�
	ucFullCode = cucFullCode;

	//��֤�ַ�
	if (strchr((PCCHAR)ucBaseCode, ucFullCode) != NULL)//���ط�NULL��������ַ��ڼ��ܴ���
	{
		SetLastError(FILL_CODE_IN_CIPHER);
		return false;
	}

	//���ͨ����������Ϊ����״̬
	bAvailable = true;
	return true;
}

Base64::UCHAR Base64::GetFullCode(VOID) const noexcept
{
	return ucFullCode;
}

Base64::ULONGLONG Base64::GetEnCodeSize(PCVOID pData, ULONGLONG ullDataSize) const noexcept
{
	return ullDataSize <= 3 ? 4 : (ullDataSize / 3 * 4 + ((ullDataSize % 3) ? 4 : 0));
}

Base64::BOOL Base64::EnCode(PCVOID pData, ULONGLONG ullDataSize, PUCHAR pCode, ULONGLONG ullCodeSize) noexcept
{
	//���״̬Ϊ������
	if (!bAvailable)
	{
		return false;
	}

	if (pData == NULL || ullDataSize == 0)
	{
		SetLastError(NULL_DATA_POINTER);
		return false;
	}

	if (pCode == NULL || ullCodeSize == 0)
	{
		SetLastError(NULL_CODE_POINTER);
		return false;
	}

	if (GetEnCodeSize(pData, ullDataSize) > ullCodeSize)
	{
		SetLastError(TARGET_TOO_SMALL);
		return false;
	}

	PCUCHAR pEncodeData = (PCUCHAR)pData;
	ULONGLONG i, j;

	for (i = 3, j = 4; i <= ullDataSize; i += 3, j += 4)
	{
		//����3�ֽ����ݵ�4��Base64�ַ�
		pCode[j - 4] = ucBaseCode[(pEncodeData[i - 3] >> 2)];
		pCode[j - 3] = ucBaseCode[(((pEncodeData[i - 3] & 0x03) << 4) | ((pEncodeData[i - 2] & 0xF0) >> 4))];
		pCode[j - 2] = ucBaseCode[(((pEncodeData[i - 2] & 0x0F) << 2) | ((pEncodeData[i - 1] & 0xC0) >> 6))];
		pCode[j - 1] = ucBaseCode[pEncodeData[i - 1] & 0x3F];
	}

	switch ((ullDataSize % 3) - 1)
	{
		case 0:
			//����ʣ���ַ�����������ַ�
			pCode[j - 4] = ucBaseCode[(pEncodeData[i - 3] >> 2)];
			pCode[j - 3] = ucBaseCode[((pEncodeData[i - 3] & 0x03) << 4)];
			pCode[j - 2] = ucFullCode;
			pCode[j - 1] = ucFullCode;
			break;
		case 1:
			//����ʣ���ַ�����������ַ�
			pCode[j - 4] = ucBaseCode[(pEncodeData[i - 3] >> 2)];
			pCode[j - 3] = ucBaseCode[(((pEncodeData[i - 3] & 0x03) << 4) | ((pEncodeData[i - 2] & 0xF0) >> 4))];
			pCode[j - 2] = ucBaseCode[(((pEncodeData[i - 2] & 0x0F) << 2) | ((pEncodeData[i - 1] & 0xC0) >> 6))];
			pCode[j - 1] = ucFullCode;
			break;
		default:
			break;
	}

	return true;
}


Base64::ULONGLONG Base64::GetDeCodeSize(PCUCHAR pCode, ULONGLONG ullCodeSize) const noexcept
{
	ULONGLONG ullFullCodeCount = 0;
	if (pCode != NULL)
	{
		if (pCode[ullCodeSize - 2] == ucFullCode)
		{
			ullFullCodeCount = 2;
		}
		else if (pCode[ullCodeSize - 1] == ucFullCode)
		{
			ullFullCodeCount = 1;
		}
	}

	return (ullCodeSize <= 4 ? 3 : ullCodeSize / 4 * 3) - ullFullCodeCount;
}

Base64::BOOL Base64::DeCode(PCUCHAR pCode, ULONGLONG ullCodeSize, PVOID pData, ULONGLONG ullDataSize) noexcept
{
	//���״̬Ϊ������
	if (!bAvailable)
	{
		return false;
	}

	if (pCode == NULL || ullCodeSize == 0)
	{
		SetLastError(NULL_CODE_POINTER);
		return false;
	}

	if (pData == NULL || ullDataSize == 0)
	{
		SetLastError(NULL_DATA_POINTER);
		return false;
	}

	if (GetDeCodeSize(pCode, ullCodeSize) > ullDataSize)
	{
		SetLastError(TARGET_TOO_SMALL);
		return false;
	}

	//����4�ı���
	if (ullCodeSize % 4 != 0)
	{
		return false;
	}

	//����ʵ��Ҫ��������ݣ��ų�����ַ���
	if (pCode[ullCodeSize - 2] == ucFullCode)
	{
		ullCodeSize -= 3;
	}
	else if (pCode[ullCodeSize - 1] == ucFullCode)
	{
		ullCodeSize -= 2;
	}

	PUCHAR pDecodeData = (PUCHAR)pData;
	ULONGLONG i, j;
	UCHAR ucCode[4] = {0};

	for (i = 4, j = 3; i <= ullCodeSize; i += 4, j += 3)
	{
		//����ӳ�䲢����Ƿ������ӳ�伯��
		for (LONG k = -4; k < 0; k += 1)
		{
			if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
			{
				return false;
			}
		}

		//����4��Base64�ַ���3���ֽ�����
		pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
		pDecodeData[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
		pDecodeData[j - 1] = ((ucCode[2] & 0x03) << 6) | (ucCode[3] >> 0);
	}

	switch ((ullCodeSize % 4) - 1)
	{
		case 0:
			//����ӳ�䲢����Ƿ������ӳ�伯��
			for (LONG k = -4; k < -2; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
				{
					return false;
				}
			}

			//����ʣ���ַ�
			pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			break;
		case 1:
			//����ӳ�䲢����Ƿ������ӳ�伯��
			for (LONG k = -4; k < -1; k += 1)
			{
				if ((ucCode[k + 4] = ucBaseCodeMap[pCode[i + k]]) == BASECODE_COUNT)//���ַ�����ӳ�伯��
				{
					return false;
				}
			}

			//����ʣ���ַ�
			pDecodeData[j - 3] = (ucCode[0] << 2) | ((ucCode[1] & 0x30) >> 4);
			pDecodeData[j - 2] = (((ucCode[1] & 0x0F) << 4) | ((ucCode[2] & 0x3C) >> 2));
			break;
		default:
			break;
	}

	return true;
}


Base64::VOID Base64::SetLastError(ULONG ulErrorCode) noexcept
{
	ulLastError = ulErrorCode;
}

Base64::ULONG Base64::GetLastError(VOID) const noexcept
{
	return ulLastError;
}

Base64::PCCHAR Base64::GetErrorReason(ULONG ulErrorCode) const noexcept
{
	if (ulLastError >= UNKNOW_ERROR)
	{
		return pErrorReason[UNKNOW_ERROR];
	}

	return pErrorReason[ulErrorCode];
}
//***************funtion***************//

#endif // !Base64_hpp