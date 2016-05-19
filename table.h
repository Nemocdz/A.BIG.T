#pragma once



void get_table(const unsigned char* key);
void table_encrypt(unsigned char *buf, size_t len);
void table_decrypt(unsigned char *buf, size_t len);



