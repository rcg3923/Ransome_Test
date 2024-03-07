#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

// �� �� �����̵Ǵ��� �˷��ִ� �Լ�
int count;

// ====================================================================//
//           BcryptGenRandom �� �̿��Ͽ� ���� �����ϴ� �Լ�            //
// ====================================================================//

int gen_key(unsigned char* key, size_t key_size)
{
    BCRYPT_ALG_HANDLE hAlg;
    NTSTATUS status;
    //Bcrypt ���̺귯�� �ε�
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (status != 0)
    {
        printf("BCrpytOpenAlgorithmProvider Failed with error : 0x%x \n", status);
        return 1;
    }

    // BcryptGenRandom �Լ��� ����Ͽ� ���� ����
    status = BCryptGenRandom(hAlg, key, key_size, 0);
    if (status != 0)
    {
        printf("BCryptGenRandom Failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 1;
    }

    // Bcrypt ���̺귯�� ��ε�
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return 0;
}
// ====================================================================//
//                          �����  ���ִ� �Լ�                        //
// ====================================================================//

void print_hex(const unsigned char* data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        if (i % 16 == 0)
            printf("\n");
        printf(" %02x ", data[i]);
        
    }
    printf("\n");
}
 
 
 
// ====================================================================//
//                       ���� Ž���ϰ� �������ִ� �Լ�                 //
// ====================================================================//

void f_search(const char *path, const char *pattern, char f_names[100][MAX_PATH])
{
    WIN32_FIND_DATA FindFileData;
    HANDLE hFind;
    char search_path[MAX_PATH];

    // �˻� ��� ����
    sprintf(search_path, "%s\\%s", path, pattern);

    // ù ��° ���� ã��
    hFind = FindFirstFile(search_path, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf(" NOT FOUNDED");
        return;
    }

    // ã�� ���� f_names ������ ����

    int i = 0;
    do {
        strcpy(f_names[i], FindFileData.cFileName);
        i++;
        count++;
    } while (FindNextFile(hFind, &FindFileData) != 0);

    FindClose(hFind);
}

// ====================================================================//
//                       ���� ������ ����ϰ� �����ϴ� �Լ�            //
// ====================================================================//


int get_file_size(char f_names[100][MAX_PATH], long f_size[100])
{
    // ���� Ž���ҋ� ī��Ʈ�� ���������� �����ؼ� ���� Ž���ؼ� ����ְ�,
    // �� ���� ������ ����Ҷ� for�� ����ؼ� ī��Ʈ�������������� �ݺ��ϸ�/
    // ��� ������ ���� �� ����.
    for (int i = 0; i < count; i++)
    {
        FILE *file;

        // ���� ����
        file = fopen(f_names[i], "rb");
        if (file == NULL)
        {
            perror("Error Opening File");
            return -1; // ���� �߻� �� -1 ��ȯ
        }

        // ���� ������ �̵��Ͽ� ���� ũ�� ���
        if (fseek(file, 0, SEEK_END) != 0)
        {
            perror("Error Seeking End Of File");
            fclose(file);
            return -1; // ���� �߻� �� -1 ��ȯ
        }

        // ������ ���� ��ġ�� ���� ũ��� ����
        f_size[i] = ftell(file);
        if (f_size[i] == -1)
        {
            perror("Error getting file size");
            fclose(file);
            return -1; // ���� �߻� �� -1 ��ȯ
        }

        fclose(file);
    } 
}
// ====================================================================//
//                     AES ��ȣȭ �Լ�                                 //
// ====================================================================//

int aes_encrypt_file(const char* input_filename, const char* output_filename, const unsigned char* key, const unsigned char* iv)
{
    FILE* input_file = fopen(input_filename, "rb");
    if (!input_file)
    {
        printf("Failed to open input file\n");
        return 1;
    }
    FILE* output_file = fopen(output_filename, "wb");
    if (!output_file)
    {
        fclose(input_file);
        printf("Failed to create output file\n");
        return 1;
    }

    // �Է� ������ ���� ũ�⸦ ���
    fseek(input_file, 0, SEEK_END);
    long input_file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    //AES �˰��� ������ ����

    BCRYPT_ALG_HANDLE hAes;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        printf("BCryptOpenAlgorithmProvider Failed with status: 0x%x\n", status);
        fclose(input_file);
        fclose(output_file);
        return 1;
    }

    // AES �˰��� �ڵ� ����
    status = BCryptSetProperty(hAes, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CCM, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status))
    {
        printf("BcryptSetProperty Failed with status : 0x%x\n", status);
        fclose(input_file);
        fclose(output_file);
        BCryptCloseAlgorithmProvider(hAes, 0);
        return 1;
    }

    // AES Ű ����
    BCRYPT_KEY_HANDLE hKey;
    status = BCryptGenerateSymmetricKey(hAes, &hKey, NULL, 0, (PBYTE)key, AES_KEY_SIZE, 0);
    if (!NT_SUCCESS(status))
    {
        printf("BcryptGenerateSymmetricKey Failed with status : 0x%x\n", status);
        fclose(input_file);
        fclose(output_file);
        BCryptCloseAlgorithmProvider(hAes, 0);
        return 1;
    }

    // �Է� ���� �Ҵ�
    unsigned char* input_buffer = (unsigned char*)malloc(input_file_size);
    if (!input_buffer)
    {
        printf("Memory allocation Failed\n");
        fclose(input_file);
        fclose(output_file);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAes, 0);
        return 1;
    }

    // ���� �б�
    fread(input_buffer, 1, input_file_size, input_file);

    // ��ȣ�� ���� �Ҵ�

    size_t encrypted_buffer_size = input_file_size + AES_BLOCK_SIZE; //�е��� ���
    unsigned char* encrypted_buffer = (unsigned char*)malloc(encrypted_buffer_size);
    if (!encrypted_buffer)
    {
        printf("Memory allocation Failed\n");
        free(input_buffer);
        fclose(input_file);
        fclose(output_file);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAes, 0);
        return 1;
    }

    // AES ��ȣȭ
    DWORD dwDataLen;
    status = BCryptEncrypt(hKey,
                           input_buffer,
                           input_file_size,
                           NULL, (PBYTE)iv,
                           AES_IV_SIZE,
                           encrypted_buffer,
                           encrypted_buffer_size,
                           &dwDataLen,
                           BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(status))
    {
        printf("BcryptEncrypt Failed with status : 0x%x\n", status);
        free(input_buffer);
        free(encrypted_buffer);
        fclose(input_file);
        fclose(output_file);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAes, 0);
        return 1;
    }

    // ��ȣ�� ����;
    fwrite(encrypted_buffer, 1, dwDataLen, output_file);

    // ����
    free(input_buffer);
    free(encrypted_buffer);
    fclose(input_file);
    fclose(output_file);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAes, 0);
    
    printf("Encrpyt Success\n");
}


// ====================================================================//
//                     RSA ����Ű ��ȣȭ �Լ�                          //
// ====================================================================//


int main(void)
{
    // ====================================================================//
    //                  1.   genkey()�Լ�                                  //
    // ====================================================================//
    unsigned char iv[32];
    unsigned char iv_1[16];
    unsigned char key_512[64];
    unsigned char key_1[32];
    unsigned char key_2[32];

    unsigned char iv_2[16];
    unsigned char key_3[32];

    // key ���� �Լ� ȣ���Ͽ� �� ������ ���� ���� ����
    gen_key(iv, sizeof(iv));
    gen_key(key_512, sizeof(key_512));
    memcpy(key_1, key_512, 32); // copy first 32 bytes to key_1
    memcpy(key_2, key_512 + 32, 32); // copy next 32 bytes to key_2
    memcpy(iv_1, iv, 16); // copy first 32bytes to key_1
    memcpy(iv_2, iv + 16, 16); // copy next 32bytes to key_2
    gen_key(key_3, 32);

    printf("IV: ");
    print_hex(iv, sizeof(iv));

    printf("IV_1 : ");
    print_hex(iv_1, sizeof(iv_1)); 

    printf("Key_512: ");
    print_hex(key_512, sizeof(key_512));

    printf("key_1 : ");
    print_hex(key_1, sizeof(key_1));
    
    printf("key_2 : ");
    print_hex(key_2, sizeof(key_2));

    printf("iv_2 : ");
    print_hex(iv_2, sizeof(iv_2));

    printf("key_3 : ");
    print_hex(key_3, sizeof(key_3));


    // key_512, key_1, key_2, iv_2, key_3 ���� �Ȱ���

    // ====================================================================//
    //              2.   f_search()�Լ�, get_file_size() �Լ�              //
    // ====================================================================//

    const char* path = "."; // ���� ���͸�
    const char* pattern = "*.txt*";// �ؽ�Ʈ���ϸ� or ��ü�����ϸ� "*.*"

    char f_names[100][MAX_PATH]; // ���͸� �ȿ� ���ϵ��� �����ϱ� ���� ����
    long f_size[100]; // ���ϵ��� ũ�⸦ �����ϱ� ���� ����


    f_search(path, pattern, f_names);
    get_file_size(f_names, f_size);

    // �� ������ �������� f_names �� f_size �� ���� ���� �� �� ������ ����� ����� , 0 , 0  ,, 1,  1 �̷�������
    for (int i = 0; i < count; i++)
    {
        printf("%d ��° File : %s , Size : %d \n", i+ 1, f_names[i], f_size[i]);
    }

    // ====================================================================//
   //                  3.   AES  256 CBC ���� ���� ��ȣȭ                //
   // ====================================================================//
  
   // ��ȣȭ�� ���� ��ο� �̸�
    for (int i = 0; i < 1; i++) // �׽�Ʈ�� 1����
   {
        const char* input_filename = f_names[i];
        const char* output_name = "ecrypted.fas";

        // ���� ��ȣȭ 
        aes_encrypt_file(input_filename, output_name, key_1, iv);
   }
   
    return 0;
}