#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define N 4

void print_blck(const uint8_t (*block)[N]) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            printf("%02x ", block[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

const uint8_t S[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t reverse_S[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// MixColumns
const uint8_t MIX_COLUMNS_MATRIX[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

// InvMixColumns
const uint8_t INV_MIX_COLUMNS_MATRIX[4][4] = {
    {0x0E, 0x0B, 0x0D, 0x09},
    {0x09, 0x0E, 0x0B, 0x0D},
    {0x0D, 0x09, 0x0E, 0x0B},
    {0x0B, 0x0D, 0x09, 0x0E}
};

void SubBytes(uint8_t (*block)[N]) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            block[i][j] = S[block[i][j]];
        }
    }
}

void InvSubBytes(uint8_t (*block)[N]) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            block[i][j] = reverse_S[block[i][j]];
        }
    }
}

void cyclic_shift_left(uint8_t *block) {
    const uint8_t first = block[0];
    for (int i = 0; i < N - 1; i++) {
        block[i] = block[i + 1];
    }
    block[N - 1] = first;
}

void cyclic_shift_right(uint8_t *block) {
    const uint8_t last = block[N - 1];
    for (int i = N - 1; i > 0; i--) {
        block[i] = block[i - 1];
    }
    block[0] = last;
}

void ShiftRows(uint8_t (*block)[N]) {
    for (int i = 1; i < N; i++) {
        for (int j = 1; j < i + 1; j++) {
            cyclic_shift_left(block[i]);
        }
    }
}

void InvShiftRows(uint8_t (*block)[N]) {
    for (int i = 1; i < N; i++) {
        for (int j = 1; j < i + 1; j++) {
            cyclic_shift_right(block[i]);
        }
    }
}

static uint8_t GF_mul(uint8_t a, uint8_t b) {
    uint8_t c = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) c ^= a;
        const uint8_t hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1B;
        b >>= 1;
    }
    return c;
}

void MixColumns(uint8_t (*block)[N]) {
    uint8_t tmp[N];

    for (int j = 0; j < N; j++) {
        // Сохраняем текущий столбец
        for (int i = 0; i < N; i++) {
            tmp[i] = block[i][j];
        }

        for (int i = 0; i < N; i++) {
            block[i][j] = 0;
            for (int k = 0; k < N; k++) {
                // Для коэффициентов 1 умножение не требуется
                if (MIX_COLUMNS_MATRIX[i][k] == 1) {
                    block[i][j] ^= tmp[k];
                } else {
                    block[i][j] ^= GF_mul(MIX_COLUMNS_MATRIX[i][k], tmp[k]);
                }
            }
        }
    }
}

void InvMixColumns(uint8_t (*block)[N]) {
    uint8_t tmp[N];

    for (int j = 0; j < N; j++) {
        // Сохраняем текущий столбец
        for (int i = 0; i < N; i++) {
            tmp[i] = block[i][j];
        }

        // Применяем обратное преобразование используя матрицу
        for (int i = 0; i < N; i++) {
            block[i][j] = 0;
            for (int k = 0; k < N; k++) {
                block[i][j] ^= GF_mul(INV_MIX_COLUMNS_MATRIX[i][k], tmp[k]);
            }
        }
    }
}


// Функция для преобразования символа в число
uint8_t char_to_value(const char c) {
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10; // 'A'-'F' → 10-15
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10; // 'a'-'f' → 10-15
    } else if (c >= '0' && c <= '9') {
        return c - '0'; // '0'-'9' → 0-9
    } else {
        return 0;
    }
}

// two chars to byte
uint8_t two_chars_to_byte(const char char1, const char char2) {
    uint8_t val1 = char_to_value(char1);
    uint8_t val2 = char_to_value(char2);

    return (val1 << 4) | val2; // Shift val1 for 4 bits and unite with val2
}

void read_key(const char *filename, uint8_t *master_key) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Can`t open file");
    }

    char hex[32];
    const size_t read_bytes = fread(hex, 1, 32, file);
    fclose(file);

    if (read_bytes < 32) {
        printf("File doesn't contain enough bytes. Only %zu bytes were read.\n", read_bytes);
    } else {
        for (int i = 0; i < 16; i++) {
            master_key[i] = two_chars_to_byte(hex[2 * i], hex[2 * i + 1]);
        }
    }
}

// Константы раунда для функции расширения ключа
const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

void SubWord(uint8_t *word) {
    for (int i = 0; i < 4; i++) {
        word[i] = S[word[i]];
    }
}

void RotWord(uint8_t *word) {
    uint8_t temp = word[0];
    for (int i = 0; i < 3; i++) {
        word[i] = word[i + 1];
    }
    word[3] = temp;
}

// Функция для расширения ключа
// masterKey - исходный ключ (16 байт для AES-128)
// expandedKey - расширенный ключ (176 байт для AES-128: 11 раундовых ключей по 16 байт)
void KeyExpansion(const uint8_t *masterKey, uint8_t *expandedKey) {
    // Копируем исходный ключ в начало расширенного ключа
    memcpy(expandedKey, masterKey, 16);

    // Временная переменная для хранения текущего слова (4 байта)
    uint8_t temp[4];

    // Количество 32-битных слов для генерации
    // Для AES-128 нужно 44 слова (11 раундовых ключей по 4 слова)
    int Nk = 4;      // Размер ключа в 32-битных словах (4 для AES-128)
    int Nr = 10;     // Количество раундов (10 для AES-128)
    int Nb = 4;      // Размер блока в 32-битных словах (всегда 4 для AES)

    // Общее количество 32-битных слов в расширенном ключе
    int words = Nb * (Nr + 1);

    // Генерация расширенного ключа
    for (int i = Nk; i < words; i++) {
        // Копируем предыдущее слово
        for (int j = 0; j < 4; j++) {
            temp[j] = expandedKey[(i - 1) * 4 + j];
        }

        // Для слов, номер которых кратен Nk
        if (i % Nk == 0) {
            // Циклический сдвиг влево
            RotWord(temp);
            // Замена байтов
            SubWord(temp);
            // XOR с константой раунда
            temp[0] ^= Rcon[i / Nk];
        }

        // Каждое новое слово = предыдущее слово ^ слово, находящееся Nk позиций назад
        for (int j = 0; j < 4; j++) {
            expandedKey[i * 4 + j] = expandedKey[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}

// Функция для печати расширенного ключа по раундам
void PrintExpandedKey(const uint8_t *expandedKey) {
    for (int round = 0; round <= 10; round++) {
        printf("Раундовый ключ %2d: ", round);
        for (int i = 0; i < 16; i++) {
            printf("%02x ", expandedKey[round * 16 + i]);
        }
        printf("\n");
    }
}

void AddRoundKey(uint8_t (*block)[N], const uint8_t *roundKey) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            block[i][j] ^= roundKey[i * N + j];
        }
    }
}

void AES_Encrypt(uint8_t (*block)[N], const uint8_t *expandedKey) {
    // Начальное добавление раундового ключа
    AddRoundKey(block, expandedKey);

    // 9 основных раундов
    for (int round = 1; round < 10; round++) {
        SubBytes(block);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, expandedKey + round * 16);
    }

    // Последний раунд (без MixColumns)
    SubBytes(block);
    ShiftRows(block);
    AddRoundKey(block, expandedKey + 160); // 10-й раундовый ключ
}

void AES_Decrypt(uint8_t (*block)[N], const uint8_t *expandedKey) {
    // Начальное добавление последнего раундового ключа
    AddRoundKey(block, expandedKey + 160);

    // 9 основных раундов в обратном порядке
    for (int round = 9; round > 0; round--) {
        InvShiftRows(block);
        InvSubBytes(block);
        AddRoundKey(block, expandedKey + round * 16);
        InvMixColumns(block);
    }

    // Последний раунд (без InvMixColumns)
    InvShiftRows(block);
    InvSubBytes(block);
    AddRoundKey(block, expandedKey); // Начальный ключ
}

#define BLOCK_SIZE 16  // AES использует блоки по 16 байт

// Функция для XOR двух блоков
void xor_blocks(uint8_t (*block)[N], const uint8_t *other) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            block[i][j] ^= other[i * N + j];
        }
    }
}

void encrypt_file(const char *input_filename, const char *output_filename, const uint8_t *expandedKey) {
    FILE *input_file = fopen(input_filename, "rb");
    FILE *output_file = fopen(output_filename, "wb");
    if (input_file == NULL) {
        printf("Не удалось открыть входной файл\n");
        return;
    }
    if (output_file == NULL) {
        printf("Не удалось открыть выходной файл\n");
        fclose(input_file);
        return;
    }

    fseek(input_file, 0, SEEK_END);
    const long file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);

    uint8_t block[N][N];
    size_t bytes_read;
    int padding_bytes = 0;
    const int is_whole_blocks = (file_size % BLOCK_SIZE == 0);

    // CBC mode - используем первые 16 байт расширенного ключа как IV
    uint8_t gamma[BLOCK_SIZE];
    memcpy(gamma, expandedKey, BLOCK_SIZE);

    while ((bytes_read = fread(&block[0][0], 1, BLOCK_SIZE, input_file)) > 0) {
        if (bytes_read < BLOCK_SIZE) {
            printf("block size = %p\n", &bytes_read);
            printf("Before padding:\n");
            print_blck(block);

            padding_bytes = BLOCK_SIZE - bytes_read;
            memset(&block[bytes_read / N][bytes_read % N], 0xFF, BLOCK_SIZE - bytes_read);
            printf("After padding:\n");
            print_blck(block);
        }

        // CBC: XOR с гаммой
        xor_blocks(block, gamma);

        // Шифрование блока
        AES_Encrypt(block, expandedKey);

        // Сохраняем зашифрованный блок как новую гамму
        memcpy(gamma, &block[0][0], BLOCK_SIZE);

        fwrite(&block[0][0], 1, BLOCK_SIZE, output_file);
        printf("Before padding:\n");
        print_blck(block);
    }

    // Добавление дополнительных блоков
    if (is_whole_blocks) {
        printf("adding blocks FF\n");
        memset(&block[0][0], 0xFF, BLOCK_SIZE);
        fwrite(&block[0][0], 1, BLOCK_SIZE, output_file);
        fwrite(&block[0][0], 1, BLOCK_SIZE, output_file);
    } else {
        printf("adding padding block\n");
        memset(&block[0][0], 0xFF, BLOCK_SIZE);
        block[0][0] = (uint8_t)padding_bytes;
        fwrite(&block[0][0], 1, BLOCK_SIZE, output_file);
    }

    fclose(input_file);
    fclose(output_file);
    printf("Шифрование файла завершено.\n");
}

void decrypt_file(const char *input_filename, const char *output_filename, const uint8_t *expandedKey) {
    FILE *input_file = fopen(input_filename, "rb");
    FILE *output_file = fopen(output_filename, "wb");

    if (input_file == NULL) {
        printf("Не удалось открыть входной файл\n");
        return;
    }
    if (output_file == NULL) {
        printf("Не удалось открыть выходной файл\n");
        fclose(input_file);
        return;
    }

    uint8_t block[N][N];
    fseek(input_file, 0, SEEK_END);
    const long file_size = ftell(input_file);

    if (file_size % BLOCK_SIZE != 0 || file_size < BLOCK_SIZE * 2) {
        printf("Неверный размер файла\n");
        fclose(input_file);
        fclose(output_file);
        return;
    }

    // Читаем последний блок для определения паддинга
    fseek(input_file, -BLOCK_SIZE, SEEK_END);
    fread(&block[0][0], 1, BLOCK_SIZE, input_file);
    fseek(input_file, 0, SEEK_SET);

    bool is_buffer_zero = true;
    int zeros = 0;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        if (block[i/N][i%N] != 0xFF) {
            is_buffer_zero = false;
            zeros = block[0][0];
            break;
        }
    }

    const long blocks_to_read = (file_size / BLOCK_SIZE) - 2;

    // CBC mode
    uint8_t gamma[BLOCK_SIZE];
    uint8_t newGamma[BLOCK_SIZE];
    memcpy(gamma, expandedKey, BLOCK_SIZE);

    // Обработка первого блока
    fread(&block[0][0], 1, BLOCK_SIZE, input_file);
    memcpy(newGamma, &block[0][0], BLOCK_SIZE);
    AES_Decrypt(block, expandedKey);
    xor_blocks(block, gamma);
    fwrite(&block[0][0], 1, BLOCK_SIZE, output_file);
    memcpy(gamma, newGamma, BLOCK_SIZE);

    // Обработка остальных блоков
    for (long i = 1; i < blocks_to_read; i++) {
        fread(&block[0][0], 1, BLOCK_SIZE, input_file);
        memcpy(newGamma, &block[0][0], BLOCK_SIZE);
        AES_Decrypt(block, expandedKey);
        xor_blocks(block, gamma);
        fwrite(&block[0][0], 1, BLOCK_SIZE, output_file);
        memcpy(gamma, newGamma, BLOCK_SIZE);
    }

    // Обработка последнего блока с учётом паддинга
    if (!is_buffer_zero) {
        fread(&block[0][0], 1, BLOCK_SIZE, input_file);
        AES_Decrypt(block, expandedKey);
        xor_blocks(block, gamma);
        fwrite(&block[0][0], 1, BLOCK_SIZE - zeros, output_file);
    }

    fclose(input_file);
    fclose(output_file);
    printf("Расшифрование файла завершено.\n");
}



int main() {

    uint8_t block[N][N] = {
    {0xd4, 0xe0, 0xb8, 0x1e},
    {0x27, 0xbf, 0xb4, 0x41},
    {0x11, 0x98, 0x5D, 0x52},
    {0xae, 0xf1, 0xe5, 0x30}
    };


    uint8_t masterKey[16];
    uint8_t expandedKey[176];


    const char *key_filename = "/Users/cartman/files/psu/AES/masterKey";
    const char *text_filename = "/Users/cartman/files/psu/AES/img.png";
    const char *encrypted_filename = "/Users/cartman/files/psu/AES/encrypted";
    const char *decrypted_filename = "/Users/cartman/files/psu/AES/decrypted.png";

    read_key(key_filename, masterKey);
    printf("Master key: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", masterKey[i]);
    }
    printf("\n\n");

    // Расширяем ключ
    KeyExpansion(masterKey, expandedKey);

    // Выводим все раундовые ключи
    // printf("Расширенный ключ (по раундам):\n");
    // PrintExpandedKey(expandedKey);

    // // Печать исходного блока
    // printf("Исходный блок:\n");
    // print_blck(block);
    //
    // // Шифрование
    // AES_Encrypt(block, expandedKey);
    // printf("После шифрования:\n");
    // print_blck(block);
    //
    // // Расшифрование
    // AES_Decrypt(block, expandedKey);
    // printf("После расшифрования:\n");
    // print_blck(block);

    encrypt_file(text_filename, encrypted_filename, expandedKey);
    decrypt_file(encrypted_filename, decrypted_filename, expandedKey);


    return 0;
}




// void MixColumns(uint8_t (*block)[N]) {
//     uint8_t tmp[4];
//
//     for (int j = 0; j < N; j++) {
//         // Сохраняем текущий столбец
//         for (int i = 0; i < 4; i++) {
//             tmp[i] = block[i][j];
//         }
//
//         // Применяем прямое преобразование MixColumns
//         block[0][j] = GF_mul(0x02, tmp[0]) ^ GF_mul(0x03, tmp[1]) ^ tmp[2] ^ tmp[3];
//         block[1][j] = tmp[0] ^ GF_mul(0x02, tmp[1]) ^ GF_mul(0x03, tmp[2]) ^ tmp[3];
//         block[2][j] = tmp[0] ^ tmp[1] ^ GF_mul(0x02, tmp[2]) ^ GF_mul(0x03, tmp[3]);
//         block[3][j] = GF_mul(0x03, tmp[0]) ^ tmp[1] ^ tmp[2] ^ GF_mul(0x02, tmp[3]);
//     }
// }
//
// void InvMixColumns(uint8_t (*block)[N]) {
//     uint8_t tmp[4];
//
//     for (int j = 0; j < N; j++) {
//         // Сохраняем текущий столбец
//         for (int i = 0; i < 4; i++) {
//             tmp[i] = block[i][j];
//         }
//
//         // Применяем обратное преобразование
//         block[0][j] = GF_mul(0x0E, tmp[0]) ^ GF_mul(0x0B, tmp[1]) ^ GF_mul(0x0D, tmp[2]) ^ GF_mul(0x09, tmp[3]);
//         block[1][j] = GF_mul(0x09, tmp[0]) ^ GF_mul(0x0E, tmp[1]) ^ GF_mul(0x0B, tmp[2]) ^ GF_mul(0x0D, tmp[3]);
//         block[2][j] = GF_mul(0x0D, tmp[0]) ^ GF_mul(0x09, tmp[1]) ^ GF_mul(0x0E, tmp[2]) ^ GF_mul(0x0B, tmp[3]);
//         block[3][j] = GF_mul(0x0B, tmp[0]) ^ GF_mul(0x0D, tmp[1]) ^ GF_mul(0x09, tmp[2]) ^ GF_mul(0x0E, tmp[3]);
//     }
// }


/*
d4 e0 b8 1e
bf b4 41 27
5d 52 11 98
30 ae f1 e5

04 e0 48 28
66 cb f8 06
81 19 d3 26
e5 9a 7a 4c

d4 e0 b8 1e
bf b4 41 27
5d 52 11 98
30 ae f1 e5

 */

// HARD CODE variant

// // Умножение на 2 в GF(2^8)
// uint8_t mul2(uint8_t a) {
//     return (a << 1) ^ (a & 0x80 ? 0x1B : 0x00);
// }
//
// // Умножение на 3 в GF(2^8): (a * 2) ⊕ a
// uint8_t mul3(uint8_t a) {
//     return mul2(a) ^ a;
// }
// // Умножение на 9 в GF(2^8)
// uint8_t mul9(uint8_t a) {
//     return mul2(mul2(mul2(a))) ^ a;
// }
//
// // Умножение на 11 (0x0B) в GF(2^8)
// uint8_t mul11(uint8_t a) {
//     return mul2(mul2(mul2(a))) ^ mul2(a) ^ a;
// }
//
// // Умножение на 13 (0x0D) в GF(2^8)
// uint8_t mul13(uint8_t a) {
//     return mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ a;
// }
//
// // Умножение на 14 (0x0E) в GF(2^8)
// uint8_t mul14(uint8_t a) {
//     return mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ mul2(a);
// }
//
// void MixColumns(uint8_t (*block)[N]) {
//     uint8_t tmp[N];
//
//     for (int j = 0; j < N; j++) {
//         for (int i = 0; i < N; i++) {
//             tmp[i] = block[i][j];
//         }
//
//         block[0][j] = mul2(tmp[0]) ^ mul3(tmp[1]) ^ tmp[2] ^ tmp[3];
//         block[1][j] = tmp[0] ^ mul2(tmp[1]) ^ mul3(tmp[2]) ^ tmp[3];
//         block[2][j] = tmp[0] ^ tmp[1] ^ mul2(tmp[2]) ^ mul3(tmp[3]);
//         block[3][j] = mul3(tmp[0]) ^ tmp[1] ^ tmp[2] ^ mul2(tmp[3]);
//     }
// }
//
// void InvMixColumns(uint8_t (*block)[N]) {
//     uint8_t tmp[N];
//
//     for (int j = 0; j < N; j++) {
//         for (int i = 0; i < N; i++) {
//             tmp[i] = block[i][j];
//         }
//
//         block[0][j] = mul14(tmp[0]) ^ mul11(tmp[1]) ^ mul13(tmp[2]) ^ mul9(tmp[3]);
//         block[1][j] = mul9(tmp[0]) ^ mul14(tmp[1]) ^ mul11(tmp[2]) ^ mul13(tmp[3]);
//         block[2][j] = mul13(tmp[0]) ^ mul9(tmp[1]) ^ mul14(tmp[2]) ^ mul11(tmp[3]);
//         block[3][j] = mul11(tmp[0]) ^ mul13(tmp[1]) ^ mul9(tmp[2]) ^ mul14(tmp[3]);
//     }
// }