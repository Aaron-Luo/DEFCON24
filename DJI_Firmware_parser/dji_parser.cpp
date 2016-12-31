#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#pragma pack(1)
struct section_info_header
{
	unsigned char checksum;
	unsigned char encrypt_flag;
	unsigned char unk[2];
	int magic;
	int offset;
	int size;
	int size2;
	unsigned char md5_before_decrypt[16];
	unsigned char md5_after_decrypt[16];
};
#pragma pack()
char* check_rom_firmware (char* buffer,int id_major,int id_minor)
{
	unsigned int i;
	for ( i = 0; i < 0x21; ++i )
	{
		if ( id_major == buffer[188 * i + 132] && id_minor == buffer[188 * i + 136] )
		return (char *)&buffer[188 * i];
	}
	return 0;
}
#define offset_rom_update_firmware_info 0xce3488

void hexdump(void *ptr, int buflen) {
  unsigned char *buf = (unsigned char*)ptr;
  int i, j;
  for (i=0; i<buflen; i+=16) {
    printf("%06x: ", i);
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%02x ", buf[i+j]);
      else
        printf("   ");
    printf(" ");
    for (j=0; j<16; j++) 
      if (i+j < buflen)
        printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
    printf("\n");
  }
}
int main(void)
{
	FILE *fp = fopen("P3S_FW_V01.10.0090.bin","rb");
	if (fp)
	{
		fseek(fp,0,SEEK_END);
		int filesize = ftell(fp);
		rewind(fp);
		char *buffer = new char [filesize];
		fread(buffer,1,filesize,fp);
		int firmware_count = *(unsigned short*)(&buffer[0x2C]);
		printf("Firmware section count: %d\n",firmware_count);
		section_info_header *sh = (section_info_header*)&buffer[0x40];
		char *rom_offset = &buffer[offset_rom_update_firmware_info];
		for (int i=0;i<firmware_count;i++)
		{
			int majorid = sh[i].checksum&0x1F;
			int minorid = sh[i].checksum>>5;
			char *rom_info = check_rom_firmware(rom_offset,majorid,minorid);
			if (rom_info)
			{
				printf("Offset: 0x%08x\tMajor: %02d Minor: %02d\tModuleName: %s\tBinaryName: %15s\tSize: %d\n",sh[i].offset,majorid,minorid,&rom_info[2],&rom_info[66],sh[i].size);
				char buf[10];
				sprintf(buf,"%d",i);
				FILE *fp2 = fopen(&rom_info[66],"wb");
				fwrite(buffer+sh[i].offset,1,sh[i].size,fp2);
				fclose(fp2);
			}
			else
			{
				hexdump(&sh[i],sizeof(section_info_header));
				printf("Binary offset: %x\tMajor: %02d Minor: %02d\tOffset: 0x%08x\tSize: %d\n",(int)&sh[i]-(int)buffer,majorid,minorid,sh[i].offset,sh[i].size);
			}
		}
		delete [] buffer;
		fclose(fp);
	}
	return 0;
}