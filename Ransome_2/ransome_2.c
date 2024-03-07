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

// 몇 번 진행이되는지 알려주는 함수
int count;

// ====================================================================//
//           BcryptGenRandom 을 이용하여 난수 생성하는 함수            //
// ====================================================================//

int gen_key(unsigned char* key, size_t key_size)
{
    BCRYPT_ALG_HANDLE hAlg;
    NTSTATUS status;
    //Bcrypt 라이브러리 로드
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (status != 0)
    {
        printf("BCrpytOpenAlgorithmProvider Failed with error : 0x%x \n", status);
        return 1;
    }

    // BcryptGenRandom 함수를 사용하여 난수 생성
    status = BCryptGenRandom(hAlg, key, key_size, 0);
    if (status != 0)
    {
        printf("BCryptGenRandom Failed\n");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 1;
    }

    // Bcrypt 라이브러리 언로드
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return 0;
}
// ====================================================================//
//                          출력을  해주는 함수                        //
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
//                       파일 탐색하고 저장해주는 함수                 //
// ====================================================================//

void f_search(const char *path, const char *pattern, char f_names[100][MAX_PATH])
{
    WIN32_FIND_DATA FindFileData;
    HANDLE hFind;
    char search_path[MAX_PATH];

    // 검색 경로 생성
    sprintf(search_path, "%s\\%s", path, pattern);

    // 첫 번째 파일 찾기
    hFind = FindFirstFile(search_path, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf(" NOT FOUNDED");
        return;
    }

    // 찾은 파일 f_names 변수에 저장

    int i = 0;
    do {
        strcpy(f_names[i], FindFileData.cFileName);
        i++;
        count++;
    } while (FindNextFile(hFind, &FindFileData) != 0);

    FindClose(hFind);
}

// ====================================================================//
//                       파일 사이즈 계산하고 저장하는 함수            //
// ====================================================================//


int get_file_size(char f_names[100][MAX_PATH], long f_size[100])
{
    // 파일 탐색할떄 카운트도 전역변수로 선언해서 파일 탐색해서 집어넣고,
    // 그 다음 사이즈 계산할때 for문 사용해서 카운트보다작을때까지 반복하면/
    // 모든 사이즈 구할 수 있음.
    for (int i = 0; i < count; i++)
    {
        FILE *file;

        // 파일 열기
        file = fopen(f_names[i], "rb");
        if (file == NULL)
        {
            perror("Error Opening File");
            return -1; // 에러 발생 시 -1 반환
        }

        // 파일 끝까지 이동하여 파일 크기 계산
        if (fseek(file, 0, SEEK_END) != 0)
        {
            perror("Error Seeking End Of File");
            fclose(file);
            return -1; // 에러 발생 시 -1 반환
        }

        // 파일의 현재 위치를 파일 크기로 설정
        f_size[i] = ftell(file);
        if (f_size[i] == -1)
        {
            perror("Error getting file size");
            fclose(file);
            return -1; // 에러 발생 시 -1 반환
        }

        fclose(file);
    } 
}
// ====================================================================//
//                     AES 암호화 함수                                 //
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

    // 입력 파일의 버퍼 크기를 계산
    fseek(input_file, 0, SEEK_END);
    long input_file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    //AES 알고리즘 제공자 열기

    BCRYPT_ALG_HANDLE hAes;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        printf("BCryptOpenAlgorithmProvider Failed with status: 0x%x\n", status);
        fclose(input_file);
        fclose(output_file);
        return 1;
    }

    // AES 알고리즘 핸들 설정
    status = BCryptSetProperty(hAes, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CCM, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status))
    {
        printf("BcryptSetProperty Failed with status : 0x%x\n", status);
        fclose(input_file);
        fclose(output_file);
        BCryptCloseAlgorithmProvider(hAes, 0);
        return 1;
    }

    // AES 키 생성
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

    // 입력 버퍼 할당
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

    // 파일 읽기
    fread(input_buffer, 1, input_file_size, input_file);

    // 암호문 버퍼 할당

    size_t encrypted_buffer_size = input_file_size + AES_BLOCK_SIZE; //패딩을 고려
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

    // AES 암호화
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

    // 암호문 쓰기;
    fwrite(encrypted_buffer, 1, dwDataLen, output_file);

    // 정리
    free(input_buffer);
    free(encrypted_buffer);
    fclose(input_file);
    fclose(output_file);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAes, 0);
    
    printf("Encrpyt Success\n");
}


// ====================================================================//
//                     RSA 공개키 암호화 함수                          //
// ====================================================================//


int main(void)
{
    // ====================================================================//
    //                  1.   genkey()함수                                  //
    // ====================================================================//
    unsigned char iv[32];
    unsigned char iv_1[16];
    unsigned char key_512[64];
    unsigned char key_1[32];
    unsigned char key_2[32];

    unsigned char iv_2[16];
    unsigned char key_3[32];

    // key 생성 함수 호출하여 각 변수에 대한 난수 생성
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


    // key_512, key_1, key_2, iv_2, key_3 생성 똑같이

    // ====================================================================//
    //              2.   f_search()함수, get_file_size() 함수              //
    // ====================================================================//

    const char* path = "."; // 현재 디렉터리
    const char* pattern = "*.txt*";// 텍스트파일만 or 전체를원하면 "*.*"

    char f_names[100][MAX_PATH]; // 디렉터리 안에 파일들을 저장하기 위한 변수
    long f_size[100]; // 파일들의 크기를 저장하기 위한 변수


    f_search(path, pattern, f_names);
    get_file_size(f_names, f_size);

    // 이 과정이 끝나고나면 f_names 와 f_size 에 각각 파일 과 그 파일의 사이즈가 저장됨 , 0 , 0  ,, 1,  1 이런식으로
    for (int i = 0; i < count; i++)
    {
        printf("%d 번째 File : %s , Size : %d \n", i+ 1, f_names[i], f_size[i]);
    }

    // ====================================================================//
   //                  3.   AES  256 CBC 모드로 파일 암호화                //
   // ====================================================================//
  
   // 암호화할 파일 경로와 이름
    for (int i = 0; i < 1; i++) // 테스트로 1번만
   {
        const char* input_filename = f_names[i];
        const char* output_name = "ecrypted.fas";

        // 파일 암호화 
        aes_encrypt_file(input_filename, output_name, key_1, iv);
   }
   
    return 0;
}