/*
 * elfss.c 
 *
 * (C) Li hsilin
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#define ELF_MAGIC        "\x7F" "ELF"
#define EOFF_CLASS       0x04
#define EOFF_PHOFF32     0x1C
#define EOFF_PHOFF64     0x20
#define EOFF_PHENTSIZE32 0x2A
#define EOFF_PHENTSIZE64 0x36
#define EOFF_PHNUM32     0x2C
#define EOFF_PHNUM64     0x38

#define PT_NULL         0x00000000
#define PT_LOAD         0x00000001
#define PT_DYNAMIC      0x00000002
#define PT_INTERP       0x00000003
#define PT_NOTE         0x00000004
#define PT_SHLIB        0x00000005
#define PT_PHDR         0x00000006
#define PT_LOOS         0x60000000
#define PT_HIOS         0x6FFFFFFF
#define PT_LOPROC       0x70000000
#define PT_HIPROC       0x7FFFFFFF
#define PT_GNU_EH_FRAME 0x6474E550
#define PT_GNU_STACK    0x6474E551
#define PT_GNU_RELRO    0x6474E552

#define SHT_NULL        0x00000000
#define SHT_PROGBITS    0x00000001
#define SHT_SYMTAB      0x00000002
#define SHT_STRTAB      0x00000003
#define SHT_RELA        0x00000004
#define SHT_HASH        0x00000005
#define SHT_DYNAMIC     0x00000006
#define SHT_NOTE        0x00000007
#define SHT_NOBITS      0x00000008
#define SHT_REL         0x00000009
#define SHT_SHLIB       0x0000000A
#define SHT_DYNSYM      0x0000000B
#define SHT_INIT_ARRAY	0x0000000E
#define SHT_FINI_ARRAY	0x0000000F
#define SHT_LOPROC      0x70000000
#define SHT_HIPROC      0x70000000
#define SHT_LOUSER      0x70000000
#define SHT_HIUSER      0x70000000
#define SHT_GNU_HASH	0x6FFFFFF6
#define SHT_VERSYM	0x6FFFFFFF
#define SHT_VERNEED	0x6FFFFFFE

#define EI_NIDENT 16
#define DECLARE_STRUCT_EHDR(bit)\
typedef struct {\
	uint8_t       e_ident[EI_NIDENT];\
        uint16_t      e_type;\
        uint16_t      e_machine;\
        uint32_t      e_version;\
        uint##bit##_t e_entry;\
        int##bit##_t  e_phoff;\
        int##bit##_t  e_shoff;\
        uint32_t      e_flags;\
        uint16_t      e_ehsize;\
        uint16_t      e_phentsize;\
        uint16_t      e_phnum;\
        uint16_t      e_shentsize;\
        uint16_t      e_shnum;\
        uint16_t      e_shstrndx;\
} ehdr##bit##_t;
DECLARE_STRUCT_EHDR(32)
DECLARE_STRUCT_EHDR(64)

typedef struct phdr32_st {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
} phdr32_t;
typedef struct phdr64_st {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
} phdr64_t;
#define DECLARE_STRUCT_SHDR(bit)\
typedef struct shdr##bit##_st {\
	uint32_t      s_name;\
	uint32_t      s_type;\
	uint##bit##_t s_flags;\
	uint##bit##_t s_addr;\
	uint##bit##_t s_offset;\
	uint##bit##_t s_size;\
	uint32_t      s_link;\
	uint32_t      s_info;\
	uint##bit##_t s_addralign;\
	uint##bit##_t s_entsize;\
} shdr##bit##_t;
DECLARE_STRUCT_SHDR(32)
DECLARE_STRUCT_SHDR(64)

typedef uint8_t  e_class_t;

static ehdr32_t* read_ehdr32(FILE* f);
static ehdr64_t* read_ehdr64(FILE* f);

static phdr32_t* read_phdr32(FILE*, const ehdr32_t*);
static phdr64_t* read_phdr64(FILE*, const ehdr64_t*);

static shdr32_t* read_shdr32(FILE*, const ehdr32_t*);
static shdr64_t* read_shdr64(FILE*, const ehdr64_t*);

static char*     read_shstrtab32(FILE*, ehdr32_t*, shdr32_t*);
static char*     read_shstrtab64(FILE*, ehdr64_t*, shdr64_t*);

static void      print_phdr32(phdr32_t *phdr_ptr, size_t count);
static void      print_phdr64(phdr64_t *phdr_ptr, size_t count);

static void      print_shdr32(shdr32_t* shdr_ptr, const char* shstrtab, size_t count);
static void      print_shdr64(shdr64_t* shdr_ptr, const char* shstrtab, size_t count);

static char*     read_shstrtab64(FILE* f, ehdr64_t* ehdr_ptr, shdr64_t* shdr_ptr);
static char*     read_shstrtab32(FILE* f, ehdr32_t* ehdr_ptr, shdr32_t* shdr_ptr);

static void      print_mapping64(const ehdr64_t*, const phdr64_t*, const shdr64_t*, const char*);
static void      print_mapping32(const ehdr32_t*, const phdr32_t*, const shdr32_t*, const char*);

static const char* phdr_type_name(int);
static const char* shdr_type_name(int);
static void      phdr_flags_name(uint32_t pflags, char (*flags_str)[4]);

static int       seekread(FILE*, unsigned long, void*, size_t);
static int       check_magic(FILE *f);
static int       read_eh_class(FILE* f);
static void      usage(void);

static void usage(void) {
	puts("Usage: elfss <ELF_file>");
}

static const char* phdr_type_name(int type) {
	switch(type) {
		case PT_NULL        : return "NULL";
		case PT_LOAD        : return "LOAD";
		case PT_DYNAMIC     : return "DYNAMIC";
		case PT_INTERP      : return "INTERP";
		case PT_NOTE        : return "NOTE";
		case PT_SHLIB       : return "SHLIB";
		case PT_PHDR        : return "PHDR";
		case PT_LOOS        : return "LOOS";
		case PT_HIOS        : return "HIOS";
		case PT_LOPROC      : return "LOPROC"; 
		case PT_HIPROC      : return "HIPROC";
		case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
		case PT_GNU_STACK   : return "GNU_STACK";
		case PT_GNU_RELRO   : return "GNU_RELRO";
	}
	return "?";
}

static const char* shdr_type_name(int type) {
	switch(type) {
		case SHT_NULL      : return "NULL";
		case SHT_PROGBITS  : return "PROGBITS";
		case SHT_SYMTAB    : return "SYMTAB";
		case SHT_STRTAB    : return "STRTAB";
		case SHT_RELA      : return "RELA";
		case SHT_HASH      : return "HASH";
		case SHT_DYNAMIC   : return "DYNAMIC";
		case SHT_INIT_ARRAY: return "INIT_ARRAY";
		case SHT_FINI_ARRAY: return "FINI_ARRAY";
		case SHT_NOTE      : return "NOTE";
		case SHT_NOBITS    : return "NOBITS";
		case SHT_REL       : return "REL";
		case SHT_SHLIB     : return "SHLIB";
		case SHT_DYNSYM    : return "DYNSYM";
		case SHT_GNU_HASH  : return "GNU_HASH";
		case SHT_VERSYM    : return "VERSYM";
		case SHT_VERNEED   : return "VERNEED";
	}
return "?";
}

static int seekread(FILE *f, unsigned long off, void *ptr, size_t siz) {
	if(fseek(f, off, SEEK_SET)) {
		perror("fseek");
		return -1;
	}

	if(fread(ptr, siz, 1, f) != 1) {
		perror("fread");
		return -1;
	}
	return 0;
}

static int check_magic(FILE *f) {
	char magic[4];
	if(seekread(f, 0, magic, sizeof(magic))) exit(-1); 		/* Read MAGIC NUMBER */
	if(strncmp(magic, ELF_MAGIC, sizeof magic)) {
		return -1;
	}
	return 0;
}

/* Read 1 or 2 to signify 32- or 64-bit format */
static int read_eh_class(FILE* f) {
	e_class_t       eclass;
	if(seekread(f, EOFF_CLASS, &eclass, sizeof eclass))
		return 0;
	return eclass;
}
#define DECLARE_FUN_READ_SHSTRTAB(bit)\
static char *read_shstrtab##bit(FILE* f, ehdr##bit##_t* ehdr_ptr, shdr##bit##_t* shdr_ptr) {\
		int offset = shdr_ptr[ehdr_ptr->e_shstrndx].s_offset;\
		int siz = shdr_ptr[ehdr_ptr->e_shstrndx].s_size;\
		char *p = malloc(siz);\
		if(NULL == p) {\
			perror("malloc");\
			exit(-1);\
		}\
		seekread(f, offset, p, siz);\
		return p;\
}
DECLARE_FUN_READ_SHSTRTAB(32)
DECLARE_FUN_READ_SHSTRTAB(64)

#define DECLARE_FUN_PRINT_EHDR(bit)\
static ehdr##bit##_t* read_ehdr##bit(FILE* f) {\
	ehdr##bit##_t *p = malloc(sizeof(ehdr##bit##_t));\
	if(NULL == p) {\
		perror("malloc");\
		exit(-1);\
	}\
	if(seekread(f, 0, p, sizeof(ehdr##bit##_t)))\
		return NULL;\
	return p;\
}
DECLARE_FUN_PRINT_EHDR(32)
DECLARE_FUN_PRINT_EHDR(64)


#define DECLARE_FUN_READ_PS_HDR(_h, bit) \
static _h##hdr##bit##_t* read_##_h##hdr##bit(FILE *f, const ehdr##bit##_t *ehdr_ptr) {\
	assert(f && ehdr_ptr);\
	if(sizeof(_h##hdr##bit##_t) > ehdr_ptr->e_##_h##hentsize) {\
		fprintf(stderr, "E: Invalid value `%hd' with e_" #_h  "hentsize\n",\
				ehdr_ptr->e_##_h##hentsize);\
		return NULL;\
	}\
	const size_t hdrsize = ehdr_ptr->e_##_h##hentsize * ehdr_ptr->e_##_h##hnum;\
	void *ptr = malloc(hdrsize);\
	if(NULL == ptr) {\
		perror("malloc");\
		return NULL;\
	}\
	if(seekread(f, ehdr_ptr->e_##_h##hoff, ptr, hdrsize))\
		return NULL;\
	return ptr;\
}											\

DECLARE_FUN_READ_PS_HDR(p, 32)
DECLARE_FUN_READ_PS_HDR(p, 64)
DECLARE_FUN_READ_PS_HDR(s, 32)
DECLARE_FUN_READ_PS_HDR(s, 64)

static void phdr_flags_name(uint32_t pflags, char (*flags_str)[4]) {
		memset(*flags_str, ' ', 3);
		(*flags_str)[0] = pflags & 0x4 ? 'R' : ' ';
		(*flags_str)[1] = pflags & 0x2 ? 'W' : ' ';
		(*flags_str)[2] = pflags & 0x1 ? 'E' : ' ';
		(*flags_str)[3] = '\0';
}

#define DECLARE_FUN_PRINT_PHDR(bit)\
static void print_phdr##bit(phdr##bit##_t *phdr_ptr, size_t count) {\
	assert(phdr_ptr && count);\
	const int pw = 2 + bit/4;\
	int i;\
	printf("%-2s %-14s %-*s %-*s %-*s %-*s %-*s %-5s %-5s\n",\
			"Nr", "Type",\
			pw, "Offset", pw, "VirtAddr", pw, "PhysAddr",\
			pw, "FileSiz", pw, "MemSiz",\
			"Flags", "Align");\
	char* fmt = 32 == bit\
		?"%2d %-14s 0x%0*lX 0x%0*lX 0x%0*lX 0x%0*lX 0x%0*lX %-5s 0x%-3X\n"\
		:"%2d %-14s 0x%0*llX 0x%0*llX 0x%0*llX 0x%0*llX 0x%0*llX %-5s 0x%-3X\n";\
	char flags[4];\
	for (i=0; i<count; i++) {\
		phdr_flags_name(phdr_ptr[i].p_flags, &flags);\
		printf(fmt,\
				i, phdr_type_name(phdr_ptr[i].p_type),\
				pw-2, phdr_ptr[i].p_offset,\
				pw-2, phdr_ptr[i].p_vaddr,\
				pw-2, phdr_ptr[i].p_paddr,\
				pw-2, phdr_ptr[i].p_filesz,\
				pw-2, phdr_ptr[i].p_memsz,\
				flags, phdr_ptr[i].p_align);\
	}\
}
DECLARE_FUN_PRINT_PHDR(32)
DECLARE_FUN_PRINT_PHDR(64)


#define DECLARE_FUN_PRINT_SHDR(bit)\
static void print_shdr##bit(shdr##bit##_t* shdr_ptr, const char* shstrtab, size_t count) {\
	int i;\
	const int pw = 2 + bit/4;\
	printf("%2s %-20s %-12s %-*s %-*s %-*s %-*s %-5s %-5s %-5s %-5s\n",\
			"Nr", "Name", "Type", \
			pw, "Address", pw, "Offset", pw, "Size", pw, "EntSize",\
			"Flags", "Link", "Info", "Align");\
	char* fmt = 32 == bit\
		? "%2d %-20s %-12s 0x%0*X 0x%0*X 0x%0*X 0x%0*X %5d %5d %5d %5d\n"\
		: "%2d %-20s %-12s 0x%0*lX 0x%0*lX 0x%0*lX 0x%0*lX %5d %5d %5d %5d\n";\
	for (i=0; i<count; i++) {\
		printf(fmt,\
				i, shstrtab + shdr_ptr[i].s_name, \
				shdr_type_name(shdr_ptr[i].s_type),\
				pw-2, shdr_ptr[i].s_addr,\
				pw-2, shdr_ptr[i].s_offset,\
				pw-2, shdr_ptr[i].s_size,\
				pw-2, shdr_ptr[i].s_entsize,\
				shdr_ptr[i].s_flags, shdr_ptr[i].s_link,\
				shdr_ptr[i].s_info, shdr_ptr[i].s_addralign\
		      );\
	}\
}
DECLARE_FUN_PRINT_SHDR(32)
DECLARE_FUN_PRINT_SHDR(64)

#define DECLARE_FUN_PRINT_MAPPING(bit) \
static void print_mapping##bit(\
		const ehdr##bit##_t* ehdr_ptr,\
		const phdr##bit##_t* phdr_ptr,\
		const shdr##bit##_t* shdr_ptr,\
		const char* shstrtab_ptr) {\
	int pi, si;\
	assert(ehdr_ptr && phdr_ptr && shdr_ptr && shstrtab_ptr);\
	printf("  Nr SecName\n");\
	for (pi=0; pi<ehdr_ptr->e_phnum; pi++) {\
		printf("  %02d", pi);\
		for (si=0; si<ehdr_ptr->e_shnum; si++)\
			if(phdr_ptr[pi].p_offset <= shdr_ptr[si].s_offset\
					&& phdr_ptr[pi].p_offset + phdr_ptr[pi].p_filesz > shdr_ptr[si].s_offset)\
				printf(" %s", shstrtab_ptr + shdr_ptr[si].s_name);\
		putchar('\n');\
	}\
}
DECLARE_FUN_PRINT_MAPPING(32)
DECLARE_FUN_PRINT_MAPPING(64)

#define DECLARE_FUN_PRINT_ALL(bit)\
static void print_all##bit(FILE *f) {\
	ehdr##bit##_t* ehdr_ptr = NULL;\
	phdr##bit##_t* phdr_ptr = NULL;\
	shdr##bit##_t* shdr_ptr = NULL;\
	char *shstrtab = NULL;\
	assert(f);\
	\
	ehdr_ptr = read_ehdr##bit(f);\
	if(NULL == ehdr_ptr) {\
		fprintf(stderr, "E: Read ELF header failed.\n");\
		goto clean;\
	}\
	phdr_ptr = read_phdr##bit(f, ehdr_ptr);\
	if(NULL == phdr_ptr) {\
		fprintf(stderr, "E: Read Program header failed.\n");\
		goto clean;\
	}\
	\
	if(NULL == phdr_ptr) {\
		fprintf(stderr, "E: Read Program header failed.\n");\
		goto clean;\
	}\
	shdr_ptr = read_shdr##bit(f, ehdr_ptr);\
	if(NULL == shdr_ptr) {\
		fprintf(stderr, "E: Read Section header failed.\n");\
		goto clean;\
	}\
	\
	shstrtab = read_shstrtab##bit(f, ehdr_ptr, shdr_ptr);\
	if(NULL == shstrtab) {\
		fprintf(stderr, "E: Read .shstrtab section failed.\n");\
		goto clean;\
	}\
	\
	printf("\n Program header:\n");\
	print_phdr##bit(phdr_ptr, ehdr_ptr->e_phnum);\
	printf("\n Section header:\n");\
	print_shdr##bit(shdr_ptr, shstrtab, ehdr_ptr->e_shnum);\
	printf("\n Section to Segment mapping:\n");\
	print_mapping##bit(ehdr_ptr, phdr_ptr, shdr_ptr, shstrtab);\
	return;\
clean:\
	if(shstrtab) free(shstrtab);\
	if(shdr_ptr) free(shdr_ptr);\
	if(phdr_ptr) free(phdr_ptr);\
	if(ehdr_ptr) free(ehdr_ptr);\
	exit(-1);\
}
DECLARE_FUN_PRINT_ALL(32)
DECLARE_FUN_PRINT_ALL(64)

int main(int argc, char** argv) {
	FILE* f;
	void *ehdr_ptr, *phdr_ptr, *shdr_ptr;
	int eclass, entnum;

	if (argc != 2) {
		usage();
		exit(-1);
	}

	f = fopen(argv[1], "r");
	if (NULL == f) {
		perror("fopen");
		exit(-1);
	}

	if(check_magic(f)) {
		fputs("E: Not a ELF format file.\n", stderr);
		exit(-1);
	}

	eclass = read_eh_class(f);
	if(eclass == 1) {
		puts("32-bit ELF file");
		print_all32(f);
	} else if(eclass == 2) {
		puts("64-bit ELF file");
		print_all64(f);
	} else {
		fprintf(stderr, "E: Unknown value `%d' for e_ident[EI_CLASS]\n", eclass);
		exit(-1);
	}
	exit(0);
}
