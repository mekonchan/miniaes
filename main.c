#include "common.h"
#include "mini-aes.h"
#include <time.h>
#include <math.h>
#include<sys/utsname.h>   /* Header for 'uname'  */

void print_n_choose_2();
void check_for_same_key();
void check_for_same_key_fix_key();
void same_key_analysis(u16 c, u16 *key, u8 Nr);
void analyze_mini_aes_key_sch();
void analyze_mini_aes_a();
void print_latex_x_xor_sx();
void print_latex_x_xor_2sx();
void print_latex_x_xor_3sx();
void print_x_xor_sx_preimage(u8 x);
void analysis_x_xor_sx();
void analysis_x_xor_2sx();
void analysis_x_xor_3sx();
void solve_key_eqns(u8 w0);
void build_mult_by_x_table(u8 x);
//void timestamp (void);

void check_for_same_key();
void formulaAES();
void test();
void checkformula();

u32 value;
#define PRINT_TO_FILE


int main() {
    
//    test();
//    formulaAES();
//    check_for_same_key();
    checkformula();
    return 0;
}

void test(){
    
    	//u16 key[3] = { 0xC3F0, 0x30FF, 0x6696 };
	u16 key[16];
	u32 masterkey = 0x0000C3F0;
	s8 i;
	u8 Nr;
	u8 keylen;

	u64 masterkey64 = 0;
	u64 key64[12];

	// AES 64-bit Block

	/*
	 *
	//sbox4x4_8bit_Construct();
	pf("Test NibbleSub64 -> %016llX\n", NibbleSub64(0x0123456789ABCDEF));

	pf("Test NibbleSub64Inv -> %016llX\n", NibbleSub64Inv(NibbleSub64(0x0123456789ABCDEF)));

	pf("Test ShiftRow64    -> %016llX\n", ShiftRow64(0x0123456789ABCDEF));
	pf("Test ShiftRow64Inv -> %016llX\n", ShiftRow64Inv(ShiftRow64(0x0123456789ABCDEF)));

	pf("Nibble1 %X\n", MixColumn64_Nibble1(0x0123));
	pf("Nibble2 %X\n", MixColumn64_Nibble2(0x0123));
	pf("Nibble3 %X\n", MixColumn64_Nibble3(0x0123));
	pf("Nibble4 %X\n", MixColumn64_Nibble4(0x0123));
	u64 m64 = 0x0123456789ABCDEF;
	pf("Test MixColumn64    -> %016llX\n", MixColumn64(m64));
	pf("Test MixColumn64Inv -> %016llX\n", MixColumn64Inv(MixColumn64(m64)));
	//MixColumn64_Table_Construct();
	 *
	 */
	// key schedule
	/*
	keySchedule64(masterkey64, key64);

	pf("Number of rounds = %d\n", R);
	// encrypt
	u64 c64 = 0x9C63000011112222;
	pf("\nptext = %016llX\n", c64);
	pf("subkeys =\n"); for (i=0; i<(R+2); i++) pf("%016llX\n", key64[i]); pf("\n");

	c64 = encrypt64(c64, key64);
	pf("Encrypt -> %016llX\n\n", c64);

	pf("ctext = %016llX\n", c64);
	pf("subkeys =\n"); for (i=(R+1); i>=0; i--) pf("%016llX\n", key64[i]); pf("\n");
	c64 = decrypt64(c64, key64);
	pf("Decrypt -> %016llX\n", c64);

	u8 index = 3;
	u64 subkey = key64[index];
	pf("Test computing backwards %016llX : %016llX [%016llX]\n", subkey, subkeyComputeBackward(subkey, index), key64[index-1]);
	pf("Test computing forwards  %016llX : %016llX [%016llX]\n", subkey, subkeyComputeForward(subkey, index), key64[index+1]);
	*/
	// AES 64-bit Block

	//*
	pf("Testing je %x\n", NibbleSub(0x0123));
	pf("Test ShiftRow -> %04X\n", ShiftRow(0x4567));
	//MixColumn_Table_Construct();

	u16 c = 0x9c63; // the plaintext in Raphael's paper

//	u16 c = 0;
	masterkey = 0x0;
	keylen = 4;

	// key schedule
	keySchedule(masterkey, key, keylen, &Nr);

	// encrypt
	pf("\nptext = %04X\n", c);
	pf("subkeys = "); for (i=0; i<(Nr+1); i++) pf("%04X ", key[i]); pf("\n");

	c = encrypt(c, key, Nr);
	pf("Encrypt -> %04X\n\n", c);

//	pf("ctext = %04X\n", c);
//	pf("subkeys = "); for (i=Nr; i>=0; i--) pf("%04X ", key[i]); pf("\n");
//	c = decrypt(c, key, Nr);
//	pf("Decrypt -> %04X\n", c);
}

void check_for_same_key() {
	struct utsname uname_pointer; // to obtain system information
	u16 key[16];
	u16 keyRef[16]; // the reference key, in our case, the all-zero key
	u32 masterkey = 0x0000C3F0;
	u64 i;
	u8 j, k;
	u8 Nr;
	u8 keylen;
	u32 ci;
	u16 c, cx, x;
	u64 max, count=1, clen, total_all=0, total_comb=0, count_plaintexts=0;

	// array for n choose 2. The index refers to n
	u16 n_choose_2[40] = {   0,   0,   1,   3,   6,  10,  15,  21,  28,  36,
							45,  55,  66,  78,  91, 105, 120, 136, 153, 171,
						   190, 210, 231, 253, 276, 300, 325, 351, 378, 406,
						   435, 465, 496, 528, 561, 595, 630, 666, 703, 741 };

	FILE *ou;
	uname(&uname_pointer);

	/*
	 * new structure for file name (starting 2 Jul 2018)
	 *  - out-mini-aes[key length in bits]: e.g.: out-mini-aes16
	 *  - [number of rounds]r
	 *  - nod: no details (optional), if stated, then details regarding the keys will not be printed
	 *  - pf2: print format version 2
	 */
	if ((ou=fopen("out-mini-aes16-1r.txt", "w")) == NULL)
		pf("Cannot open file");

	// deprecated as at 5 Jul 2018
	//if ((ou=fopen("out-mini-aes16-3r.txt", "w")) == NULL)
	//	pf("Cannot open file");

	clock_t t1;
	time_t w1;

	t1 = clock();
	w1 = time(NULL);
	fpf(ou, "\n");
//	timestamp();

	keylen = 4;

	max = (u64)pow(2, keylen*4);

	// limitation
	if (keylen == 6) {
		max = (u64)pow(2, 17);
	}

	pf("max = %lu\n", max);

	clen = (u64)pow(2, 16);

	for (ci = 0; ci < clen; ++ci) {

		cx = c = ci;
		masterkey = 0;
		// [0] KEY SCHEDULE
		// the typical MiniAES
		keySchedule(masterkey, keyRef, keylen, &Nr);
        Nr = 1; // override, if you want

		// [A] testing no key schedule but subkey the same in all rounds
        // the MiniAES-A
		/*
		Nr = 2;
		for (j = 0; j < (Nr+1); ++j) {
			key[j] = masterkey;
		}
		*/

		// [B] testing no key schedule: the 1st subkey is the same as masterkey, the rest are all zeros
        // the MiniAES-B
		/*
		Nr = 10;
		key[0] = masterkey;
		for (j = 1; j < (Nr+1); ++j) {
			key[j] = 0;
		}
		// for keylen=6, 8
		key[ 0] = ((masterkey & 0xffff0000) >> 16);
		key[Nr] =   masterkey & 0x0000ffff;
		*/

		//fpf(ou, "subkeys = "); for (i=0; i<(Nr+1); i++) fpf(ou, "%04X ", key[i]); fpf(ou, "\n");
		x = encrypt(cx, keyRef, Nr);

		//same_key_analysis(cx, key, Nr);
		for (i = 1; i < max; ++i) {
			masterkey = i;

			// [0] KEY SCHEDULE
			// the typical MiniAES
			keySchedule(masterkey, key, keylen, &Nr);
            Nr = 1; // override, is you want

			// [A] testing no key schedule but subkey the same in all rounds
            // the MiniAES-A
			/*
			Nr = 2;
			for (j = 0; j < (Nr+1); ++j) {
				key[j] = masterkey;
			}
			*/

			// [B] testing no key schedule: the 1st subkey is the same as masterkey, the rest are all zeros
            // the MiniAES-B
			/*
			Nr = 10;
			key[0] = masterkey;
			for (j = 1; j < (Nr+1); ++j) {
				key[j] = 0;
			}
			// for keylen=6, 8
			key[ 0] = ((masterkey & 0xffff0000) >> 16);
			key[Nr] =   masterkey & 0x0000ffff;
			*/

			if (encrypt(c, key, Nr) == x) {

#ifdef PRINT_TO_FILE
				// old way of printing
				/*
				fpf(ou, "(m,k) = (%x %x)\n", c, i);
				fpf(ou, "subkeys = ");
				for (j=0; j<(Nr+1); j++)
					fpf(ou, "%04X ", key[j]);
				*/

				// new print format to save space (print format version 2: pf2):
				// key :: subkeys
				fpf(ou, "%x :: ", i);
				for (j=0; j<(Nr+1); j++)
					fpf(ou, "%04X ", key[j]);
				fpf(ou, "\n");
#endif

				//same_key_analysis(c, key, Nr);
				count++; // counting number of keys that yield the collision
			}
		}

		if (count > 1) {
			count_plaintexts++; // increment the plaintext count

			// print the all-zero keys
#ifdef PRINT_TO_FILE
			fpf(ou, "%x :: ", masterkey);
			for (j=0; j<(Nr+1); j++)
				fpf(ou, "%04X ", keyRef[j]);
			fpf(ou, "\n");

			fpf(ou, "Total: %d; p = %x c = %x\n\n", count, cx, x);
#endif
			total_all += count;
			total_comb += n_choose_2[count];

			count = 1; // reset to 1
		}
	}

	fpf(ou, "Total number of keys: %d\n\n", total_all);
	fpf(ou, "Total number of plaintexts: %d\n\n", count_plaintexts);
	fpf(ou, "Average number keys per plaintext that yield collision: %f\n\n", total_all*1.0/count_plaintexts*1.0);
	fpf(ou, "Number of colliding pairs: %d\n\n", total_comb);

	fpf(ou, "\nDONE!!\n\n");

	fpf(ou,"System name - %s \n", uname_pointer.sysname);
	fpf(ou,"Nodename    - %s \n", uname_pointer.nodename);
	fpf(ou,"Release     - %s \n", uname_pointer.release);
	fpf(ou,"Version     - %s \n", uname_pointer.version);
	fpf(ou,"Machine     - %s \n\n", uname_pointer.machine);
	//fpf(ou,"Domain name - %s n", uname_pointer.domainname);

	fpf(ou, "CPU Time : %f seconds\n", (clock() - t1) / (double)(CLOCKS_PER_SEC));
	fpf(ou, "Wall Time: %f seconds\n", (double)time(NULL) - (double)w1);

	pf("CPU Time : %f seconds\n", (clock() - t1) / (double)(CLOCKS_PER_SEC));
	pf("Wall Time: %f seconds\n", (double)time(NULL) - (double)w1);
//	timestamp();
	fclose(ou);
}

void formulaAES() {

  u16 P[16];
  u16 C[16];
  u16 Km[20];

  printf("Enter Plaintext in hexadecimal (4 bit) \n");
  do {
    scanf("%x", & value);
    if (value < 65536) {
      break;
    }
  }
  while (1);

  u16 v0 = (value & 0xf000) >> 12;
  u16 v1 = (value & 0x0f00) >> 8;
  u16 v2 = (value & 0x00f0) >> 4;
  u16 v3 = (value & 0x000f);

  printf("Enter KeyMaster in hexadecimal (5 bit) \n");
  do {
    scanf("%x", & value);
    if (value < 1048576) {
      break;
    }
  }
  while (1);

  u16 m0 = (value & 0xf0000) >> 16;
  u16 m1 = (value & 0x0f000) >> 12;
  u16 m2 = (value & 0x00f00) >> 8;
  u16 m3 = (value & 0x000f0) >> 4;
  u16 m4 = (value & 0x0000f);

  if (v0 == 0x0000) {
    P[15] = 0x0;
    P[14] = 0x0;
    P[13] = 0x0;
    P[12] = 0x0;
  } else if (v0 == 0x0001) {
    P[15] = 0x0;
    P[14] = 0x0;
    P[13] = 0x0;
    P[12] = 0x1;
  } else if (v0 == 0x0002) {
    P[15] = 0x0;
    P[14] = 0x0;
    P[13] = 0x1;
    P[12] = 0x0;
  } else if (v0 == 0x0003) {
    P[15] = 0x0;
    P[14] = 0x0;
    P[13] = 0x1;
    P[12] = 0x1;
  } else if (v0 == 0x0004) {
    P[15] = 0x0;
    P[14] = 0x1;
    P[13] = 0x0;
    P[12] = 0x0;
  } else if (v0 == 0x0005) {
    P[15] = 0x0;
    P[14] = 0x1;
    P[13] = 0x0;
    P[12] = 0x1;
  } else if (v0 == 0x0006) {
    P[15] = 0x0;
    P[14] = 0x1;
    P[13] = 0x1;
    P[12] = 0x0;
  } else if (v0 == 0x0007) {
    P[15] = 0x0;
    P[14] = 0x1;
    P[13] = 0x1;
    P[12] = 0x1;
  } else if (v0 == 0x0008) {
    P[15] = 0x1;
    P[14] = 0x0;
    P[13] = 0x0;
    P[12] = 0x0;
  } else if (v0 == 0x0009) {
    P[15] = 0x1;
    P[14] = 0x0;
    P[13] = 0x0;
    P[12] = 0x1;
  } else if (v0 == 0x000A) {
    P[15] = 0x1;
    P[14] = 0x0;
    P[13] = 0x1;
    P[12] = 0x0;
  } else if (v0 == 0x000B) {
    P[15] = 0x1;
    P[14] = 0x0;
    P[13] = 0x1;
    P[12] = 0x1;
  } else if (v0 == 0x000C) {
    P[15] = 0x1;
    P[14] = 0x1;
    P[13] = 0x0;
    P[12] = 0x0;
  } else if (v0 == 0x000D) {
    P[15] = 0x1;
    P[14] = 0x1;
    P[13] = 0x0;
    P[12] = 0x1;
  } else if (v0 == 0x000E) {
    P[15] = 0x1;
    P[14] = 0x1;
    P[13] = 0x1;
    P[12] = 0x0;
  } else if (v0 == 0x000F) {
    P[15] = 0x1;
    P[14] = 0x1;
    P[13] = 0x1;
    P[12] = 0x1;
  }
  ////////////////////////////////
  if (v1 == 0x0000) {
    P[11] = 0x0;
    P[10] = 0x0;
    P[9] = 0x0;
    P[8] = 0x0;
  } else if (v1 == 0x0001) {
    P[11] = 0x0;
    P[10] = 0x0;
    P[9] = 0x0;
    P[8] = 0x1;
  } else if (v1 == 0x0002) {
    P[11] = 0x0;
    P[10] = 0x0;
    P[9] = 0x1;
    P[8] = 0x0;
  } else if (v1 == 0x0003) {
    P[11] = 0x0;
    P[10] = 0x0;
    P[9] = 0x1;
    P[8] = 0x1;
  } else if (v1 == 0x0004) {
    P[11] = 0x0;
    P[10] = 0x1;
    P[9] = 0x0;
    P[8] = 0x0;
  } else if (v1 == 0x0005) {
    P[11] = 0x0;
    P[10] = 0x1;
    P[9] = 0x0;
    P[8] = 0x1;
  } else if (v1 == 0x0006) {
    P[11] = 0x0;
    P[10] = 0x1;
    P[9] = 0x1;
    P[8] = 0x0;
  } else if (v1 == 0x0007) {
    P[11] = 0x0;
    P[10] = 0x1;
    P[9] = 0x1;
    P[8] = 0x1;
  } else if (v1 == 0x0008) {
    P[11] = 0x1;
    P[10] = 0x0;
    P[9] = 0x0;
    P[8] = 0x0;
  } else if (v1 == 0x0009) {
    P[11] = 0x1;
    P[10] = 0x0;
    P[9] = 0x0;
    P[8] = 0x1;
  } else if (v1 == 0x000A) {
    P[11] = 0x1;
    P[10] = 0x0;
    P[9] = 0x1;
    P[8] = 0x0;
  } else if (v1 == 0x000B) {
    P[11] = 0x1;
    P[10] = 0x0;
    P[9] = 0x1;
    P[8] = 0x1;
  } else if (v1 == 0x000C) {
    P[11] = 0x1;
    P[10] = 0x1;
    P[9] = 0x0;
    P[8] = 0x0;
  } else if (v1 == 0x000D) {
    P[11] = 0x1;
    P[10] = 0x1;
    P[9] = 0x0;
    P[8] = 0x1;
  } else if (v1 == 0x000E) {
    P[11] = 0x1;
    P[10] = 0x1;
    P[9] = 0x1;
    P[8] = 0x0;
  } else if (v1 == 0x000F) {
    P[11] = 0x1;
    P[10] = 0x1;
    P[9] = 0x1;
    P[8] = 0x1;
  }
  /////////////
  if (v2 == 0x0000) {
    P[7] = 0x0;
    P[6] = 0x0;
    P[5] = 0x0;
    P[4] = 0x0;
  } else if (v2 == 0x0001) {
    P[7] = 0x0;
    P[6] = 0x0;
    P[5] = 0x0;
    P[4] = 0x1;
  } else if (v2 == 0x0002) {
    P[7] = 0x0;
    P[6] = 0x0;
    P[5] = 0x1;
    P[4] = 0x0;
  } else if (v2 == 0x0003) {
    P[7] = 0x0;
    P[6] = 0x0;
    P[5] = 0x1;
    P[4] = 0x1;
  } else if (v2 == 0x0004) {
    P[7] = 0x0;
    P[6] = 0x1;
    P[5] = 0x0;
    P[4] = 0x0;
  } else if (v2 == 0x0005) {
    P[7] = 0x0;
    P[6] = 0x1;
    P[5] = 0x0;
    P[4] = 0x1;
  } else if (v2 == 0x0006) {
    P[7] = 0x0;
    P[6] = 0x1;
    P[5] = 0x1;
    P[4] = 0x0;
  } else if (v2 == 0x0007) {
    P[7] = 0x0;
    P[6] = 0x1;
    P[5] = 0x1;
    P[4] = 0x1;
  } else if (v2 == 0x0008) {
    P[7] = 0x1;
    P[6] = 0x0;
    P[5] = 0x0;
    P[4] = 0x0;
  } else if (v2 == 0x0009) {
    P[7] = 0x1;
    P[6] = 0x0;
    P[5] = 0x0;
    P[4] = 0x1;
  } else if (v2 == 0x000A) {
    P[7] = 0x1;
    P[6] = 0x0;
    P[5] = 0x1;
    P[4] = 0x0;
  } else if (v2 == 0x000B) {
    P[7] = 0x1;
    P[6] = 0x0;
    P[5] = 0x1;
    P[4] = 0x1;
  } else if (v2 == 0x000C) {
    P[7] = 0x1;
    P[6] = 0x1;
    P[5] = 0x0;
    P[4] = 0x0;
  } else if (v2 == 0x000D) {
    P[7] = 0x1;
    P[6] = 0x1;
    P[5] = 0x0;
    P[4] = 0x1;
  } else if (v2 == 0x000E) {
    P[7] = 0x1;
    P[6] = 0x1;
    P[5] = 0x1;
    P[4] = 0x0;
  } else if (v2 == 0x000F) {
    P[7] = 0x1;
    P[6] = 0x1;
    P[5] = 0x1;
    P[4] = 0x1;
  }
  /////////
  if (v3 == 0x0000) {
    P[3] = 0x0;
    P[2] = 0x0;
    P[1] = 0x0;
    P[0] = 0x0;
  } else if (v3 == 0x0001) {
    P[3] = 0x0;
    P[2] = 0x0;
    P[1] = 0x0;
    P[0] = 0x1;
  } else if (v3 == 0x0002) {
    P[3] = 0x0;
    P[2] = 0x0;
    P[1] = 0x1;
    P[0] = 0x0;
  } else if (v3 == 0x0003) {
    P[3] = 0x0;
    P[2] = 0x0;
    P[1] = 0x1;
    P[0] = 0x1;
  } else if (v3 == 0x0004) {
    P[3] = 0x0;
    P[2] = 0x1;
    P[1] = 0x0;
    P[0] = 0x0;
  } else if (v3 == 0x0005) {
    P[3] = 0x0;
    P[2] = 0x1;
    P[1] = 0x0;
    P[0] = 0x1;
  } else if (v3 == 0x0006) {
    P[3] = 0x0;
    P[2] = 0x1;
    P[1] = 0x1;
    P[0] = 0x0;
  } else if (v3 == 0x0007) {
    P[3] = 0x0;
    P[2] = 0x1;
    P[1] = 0x1;
    P[0] = 0x1;
  } else if (v3 == 0x0008) {
    P[3] = 0x1;
    P[2] = 0x0;
    P[1] = 0x0;
    P[0] = 0x0;
  } else if (v3 == 0x0009) {
    P[3] = 0x1;
    P[2] = 0x0;
    P[1] = 0x0;
    P[0] = 0x1;
  } else if (v3 == 0x000A) {
    P[3] = 0x1;
    P[2] = 0x0;
    P[1] = 0x1;
    P[0] = 0x0;
  } else if (v3 == 0x000B) {
    P[3] = 0x1;
    P[2] = 0x0;
    P[1] = 0x1;
    P[0] = 0x1;
  } else if (v3 == 0x000C) {
    P[3] = 0x1;
    P[2] = 0x1;
    P[1] = 0x0;
    P[0] = 0x0;
  } else if (v3 == 0x000D) {
    P[3] = 0x1;
    P[2] = 0x1;
    P[1] = 0x0;
    P[0] = 0x1;
  } else if (v3 == 0x000E) {
    P[3] = 0x1;
    P[2] = 0x1;
    P[1] = 0x1;
    P[0] = 0x0;
  } else if (v3 == 0x000F) {
    P[3] = 0x1;
    P[2] = 0x1;
    P[1] = 0x1;
    P[0] = 0x1;
  }

  /////////////////////////

  if (m0 == 0x0000) {
    Km[19] = 0x0;
    Km[18] = 0x0;
    Km[17] = 0x0;
    Km[16] = 0x0;
  } else if (m0 == 0x0001) {
    Km[19] = 0x0;
    Km[18] = 0x0;
    Km[17] = 0x0;
    Km[16] = 0x1;
  } else if (m0 == 0x0002) {
    Km[19] = 0x0;
    Km[18] = 0x0;
    Km[17] = 0x1;
    Km[16] = 0x0;
  } else if (m0 == 0x0003) {
    Km[19] = 0x0;
    Km[18] = 0x0;
    Km[17] = 0x1;
    Km[16] = 0x1;
  } else if (m0 == 0x0004) {
    Km[19] = 0x0;
    Km[18] = 0x1;
    Km[17] = 0x0;
    Km[16] = 0x0;
  } else if (m0 == 0x0005) {
    Km[19] = 0x0;
    Km[18] = 0x1;
    Km[17] = 0x0;
    Km[16] = 0x1;
  } else if (m0 == 0x0006) {
    Km[19] = 0x0;
    Km[18] = 0x1;
    Km[17] = 0x1;
    Km[16] = 0x0;
  } else if (m0 == 0x0007) {
    Km[19] = 0x0;
    Km[18] = 0x1;
    Km[17] = 0x1;
    Km[16] = 0x1;
  } else if (m0 == 0x0008) {
    Km[19] = 0x1;
    Km[18] = 0x0;
    Km[17] = 0x0;
    Km[16] = 0x0;
  } else if (m0 == 0x0009) {
    Km[19] = 0x1;
    Km[18] = 0x0;
    Km[17] = 0x0;
    Km[16] = 0x1;
  } else if (m0 == 0x000A) {
    Km[19] = 0x1;
    Km[18] = 0x0;
    Km[17] = 0x1;
    Km[16] = 0x0;
  } else if (m0 == 0x000B) {
    Km[19] = 0x1;
    Km[18] = 0x0;
    Km[17] = 0x1;
    Km[16] = 0x1;
  } else if (m0 == 0x000C) {
    Km[19] = 0x1;
    Km[18] = 0x1;
    Km[17] = 0x0;
    Km[16] = 0x0;
  } else if (m0 == 0x000D) {
    Km[19] = 0x1;
    Km[18] = 0x1;
    Km[17] = 0x0;
    Km[16] = 0x1;
  } else if (m0 == 0x000E) {
    Km[19] = 0x1;
    Km[18] = 0x1;
    Km[17] = 0x1;
    Km[16] = 0x0;
  } else if (m0 == 0x000F) {
    Km[19] = 0x1;
    Km[18] = 0x1;
    Km[17] = 0x1;
    Km[16] = 0x1;
  }
  ////////////////////////////////
  if (m1 == 0x0000) {
    Km[15] = 0x0;
    Km[14] = 0x0;
    Km[13] = 0x0;
    Km[12] = 0x0;
  } else if (m1 == 0x0001) {
    Km[15] = 0x0;
    Km[14] = 0x0;
    Km[13] = 0x0;
    Km[12] = 0x1;
  } else if (m1 == 0x0002) {
    Km[15] = 0x0;
    Km[14] = 0x0;
    Km[13] = 0x1;
    Km[12] = 0x0;
  } else if (m1 == 0x0003) {
    Km[15] = 0x0;
    Km[14] = 0x0;
    Km[13] = 0x1;
    Km[12] = 0x1;
  } else if (m1 == 0x0004) {
    Km[15] = 0x0;
    Km[14] = 0x1;
    Km[13] = 0x0;
    Km[12] = 0x0;
  } else if (m1 == 0x0005) {
    Km[15] = 0x0;
    Km[14] = 0x1;
    Km[13] = 0x0;
    Km[12] = 0x1;
  } else if (m1 == 0x0006) {
    Km[15] = 0x0;
    Km[14] = 0x1;
    Km[13] = 0x1;
    Km[12] = 0x0;
  } else if (m1 == 0x0007) {
    Km[15] = 0x0;
    Km[14] = 0x1;
    Km[13] = 0x1;
    Km[12] = 0x1;
  } else if (m1 == 0x0008) {
    Km[15] = 0x1;
    Km[14] = 0x0;
    Km[13] = 0x0;
    Km[12] = 0x0;
  } else if (m1 == 0x0009) {
    Km[15] = 0x1;
    Km[14] = 0x0;
    Km[13] = 0x0;
    Km[12] = 0x1;
  } else if (m1 == 0x000A) {
    Km[15] = 0x1;
    Km[14] = 0x0;
    Km[13] = 0x1;
    Km[12] = 0x0;
  } else if (m1 == 0x000B) {
    Km[15] = 0x1;
    Km[14] = 0x0;
    Km[13] = 0x1;
    Km[12] = 0x1;
  } else if (m1 == 0x000C) {
    Km[15] = 0x1;
    Km[14] = 0x1;
    Km[13] = 0x0;
    Km[12] = 0x0;
  } else if (m1 == 0x000D) {
    Km[15] = 0x1;
    Km[14] = 0x1;
    Km[13] = 0x0;
    Km[12] = 0x1;
  } else if (m1 == 0x000E) {
    Km[15] = 0x1;
    Km[14] = 0x1;
    Km[13] = 0x1;
    Km[12] = 0x0;
  } else if (m1 == 0x000F) {
    Km[15] = 0x1;
    Km[14] = 0x1;
    Km[13] = 0x1;
    Km[12] = 0x1;
  }
  /////////////
  if (m2 == 0x0000) {
    Km[11] = 0x0;
    Km[10] = 0x0;
    Km[9] = 0x0;
    Km[8] = 0x0;
  } else if (m2 == 0x0001) {
    Km[11] = 0x0;
    Km[10] = 0x0;
    Km[9] = 0x0;
    Km[8] = 0x1;
  } else if (m2 == 0x0002) {
    Km[11] = 0x0;
    Km[10] = 0x0;
    Km[9] = 0x1;
    Km[8] = 0x0;
  } else if (m2 == 0x0003) {
    Km[11] = 0x0;
    Km[10] = 0x0;
    Km[9] = 0x1;
    Km[8] = 0x1;
  } else if (m2 == 0x0004) {
    Km[11] = 0x0;
    Km[10] = 0x1;
    Km[9] = 0x0;
    Km[8] = 0x0;
  } else if (m2 == 0x0005) {
    Km[11] = 0x0;
    Km[10] = 0x1;
    Km[9] = 0x0;
    Km[8] = 0x1;
  } else if (m2 == 0x0006) {
    Km[11] = 0x0;
    Km[10] = 0x1;
    Km[9] = 0x1;
    Km[8] = 0x0;
  } else if (m2 == 0x0007) {
    Km[11] = 0x0;
    Km[10] = 0x1;
    Km[9] = 0x1;
    Km[8] = 0x1;
  } else if (m2 == 0x0008) {
    Km[11] = 0x1;
    Km[10] = 0x0;
    Km[9] = 0x0;
    Km[8] = 0x0;
  } else if (m2 == 0x0009) {
    Km[11] = 0x1;
    Km[10] = 0x0;
    Km[9] = 0x0;
    Km[8] = 0x1;
  } else if (m2 == 0x000A) {
    Km[11] = 0x1;
    Km[10] = 0x0;
    Km[9] = 0x1;
    Km[8] = 0x0;
  } else if (m2 == 0x000B) {
    Km[11] = 0x1;
    Km[10] = 0x0;
    Km[9] = 0x1;
    Km[8] = 0x1;
  } else if (m2 == 0x000C) {
    Km[11] = 0x1;
    Km[10] = 0x1;
    Km[9] = 0x0;
    Km[8] = 0x0;
  } else if (m2 == 0x000D) {
    Km[11] = 0x1;
    Km[10] = 0x1;
    Km[9] = 0x0;
    Km[8] = 0x1;
  } else if (m2 == 0x000E) {
    Km[11] = 0x1;
    Km[10] = 0x1;
    Km[9] = 0x1;
    Km[8] = 0x0;
  } else if (m2 == 0x000F) {
    Km[11] = 0x1;
    Km[10] = 0x1;
    Km[9] = 0x1;
    Km[8] = 0x1;
  }
  /////////
  if (m3 == 0x0000) {
    Km[7] = 0x0;
    Km[6] = 0x0;
    Km[5] = 0x0;
    Km[4] = 0x0;
  } else if (m3 == 0x0001) {
    Km[7] = 0x0;
    Km[6] = 0x0;
    Km[5] = 0x0;
    Km[4] = 0x1;
  } else if (m3 == 0x0002) {
    Km[7] = 0x0;
    Km[6] = 0x0;
    Km[5] = 0x1;
    Km[4] = 0x0;
  } else if (m3 == 0x0003) {
    Km[7] = 0x0;
    Km[6] = 0x0;
    Km[5] = 0x1;
    Km[4] = 0x1;
  } else if (m3 == 0x0004) {
    Km[7] = 0x0;
    Km[6] = 0x1;
    Km[5] = 0x0;
    Km[4] = 0x0;
  } else if (m3 == 0x0005) {
    Km[7] = 0x0;
    Km[6] = 0x1;
    Km[5] = 0x0;
    Km[4] = 0x1;
  } else if (m3 == 0x0006) {
    Km[7] = 0x0;
    Km[6] = 0x1;
    Km[5] = 0x1;
    Km[4] = 0x0;
  } else if (m3 == 0x0007) {
    Km[7] = 0x0;
    Km[6] = 0x1;
    Km[5] = 0x1;
    Km[4] = 0x1;
  } else if (m3 == 0x0008) {
    Km[7] = 0x1;
    Km[6] = 0x0;
    Km[5] = 0x0;
    Km[4] = 0x0;
  } else if (m3 == 0x0009) {
    Km[7] = 0x1;
    Km[6] = 0x0;
    Km[5] = 0x0;
    Km[4] = 0x1;
  } else if (m3 == 0x000A) {
    Km[7] = 0x1;
    Km[6] = 0x0;
    Km[5] = 0x1;
    Km[4] = 0x0;
  } else if (m3 == 0x000B) {
    Km[7] = 0x1;
    Km[6] = 0x0;
    Km[5] = 0x1;
    Km[4] = 0x1;
  } else if (m3 == 0x000C) {
    Km[7] = 0x1;
    Km[6] = 0x1;
    Km[5] = 0x0;
    Km[4] = 0x0;
  } else if (m3 == 0x000D) {
    Km[7] = 0x1;
    Km[6] = 0x1;
    Km[5] = 0x0;
    Km[4] = 0x1;
  } else if (m3 == 0x000E) {
    Km[7] = 0x1;
    Km[6] = 0x1;
    Km[5] = 0x1;
    Km[4] = 0x0;
  } else if (m3 == 0x000F) {
    Km[7] = 0x1;
    Km[6] = 0x1;
    Km[5] = 0x1;
    Km[4] = 0x1;
  }
  //////////
  if (m4 == 0x0000) {
    Km[3] = 0x0;
    Km[2] = 0x0;
    Km[1] = 0x0;
    Km[0] = 0x0;
  } else if (m4 == 0x0001) {
    Km[3] = 0x0;
    Km[2] = 0x0;
    Km[1] = 0x0;
    Km[0] = 0x1;
  } else if (m4 == 0x0002) {
    Km[3] = 0x0;
    Km[2] = 0x0;
    Km[1] = 0x1;
    Km[0] = 0x0;
  } else if (m4 == 0x0003) {
    Km[3] = 0x0;
    Km[2] = 0x0;
    Km[1] = 0x1;
    Km[0] = 0x1;
  } else if (m4 == 0x0004) {
    Km[3] = 0x0;
    Km[2] = 0x1;
    Km[1] = 0x0;
    Km[0] = 0x0;
  } else if (m4 == 0x0005) {
    Km[3] = 0x0;
    Km[2] = 0x1;
    Km[1] = 0x0;
    Km[0] = 0x1;
  } else if (m4 == 0x0006) {
    Km[3] = 0x0;
    Km[2] = 0x1;
    Km[1] = 0x1;
    Km[0] = 0x0;
  } else if (m4 == 0x0007) {
    Km[3] = 0x0;
    Km[2] = 0x1;
    Km[1] = 0x1;
    Km[0] = 0x1;
  } else if (m4 == 0x0008) {
    Km[3] = 0x1;
    Km[2] = 0x0;
    Km[1] = 0x0;
    Km[0] = 0x0;
  } else if (m4 == 0x0009) {
    Km[3] = 0x1;
    Km[2] = 0x0;
    Km[1] = 0x0;
    Km[0] = 0x1;
  } else if (m4 == 0x000A) {
    Km[3] = 0x1;
    Km[2] = 0x0;
    Km[1] = 0x1;
    Km[0] = 0x0;
  } else if (m4 == 0x000B) {
    Km[3] = 0x1;
    Km[2] = 0x0;
    Km[1] = 0x1;
    Km[0] = 0x1;
  } else if (m4 == 0x000C) {
    Km[3] = 0x1;
    Km[2] = 0x1;
    Km[1] = 0x0;
    Km[0] = 0x0;
  } else if (m4 == 0x000D) {
    Km[3] = 0x1;
    Km[2] = 0x1;
    Km[1] = 0x0;
    Km[0] = 0x1;
  } else if (m4 == 0x000E) {
    Km[3] = 0x1;
    Km[2] = 0x1;
    Km[1] = 0x1;
    Km[0] = 0x0;
  } else if (m4 == 0x000F) {
    Km[3] = 0x1;
    Km[2] = 0x1;
    Km[1] = 0x1;
    Km[0] = 0x1;
  }

  //    int C[16];
  //    //U[0] --> U[15]
  //    u16 U[16] = { 0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1};
  //    u16 Km[20] = { 0x1,0x0,0x1,0x0,0x1,0x0,0x0,0x0,0x1,0x0,0x1,0x0,0x1,0x0,0x0,0x0,0x1,0x1,0x0,0x0};
  //    
  //    pf("\nP: ");
  //    for(int i = 15;i>=0;i--){
  //        if(i==3){
  //            pf(" ");
  //        }
  //        else if(i==7){
  //            pf(" ");
  //        }
  //        if(i==11){
  //            pf(" ");
  //        }
  //        
  //        pf("%X",U[i]);
  //    }
  //    pf("\n");
  //    
  //    pf("K: ");
  //    for(int i = 19;i>=0;i--){
  //        if(i==3){
  //            pf(" ");
  //        }
  //        else if(i==7){
  //            pf(" ");
  //        }
  //        if(i==11){
  //            pf(" ");
  //        }
  //        if(i==15){
  //            pf(" ");
  //        }
  //        
  //        pf("%X",Km[i]);
  //    }
  //    pf("\n");

C[15] = (((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[13] ^ Km[13]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[14] ^ Km[14]) ^ (P[15] ^ Km[15]) ^ 1) ^ ((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[14] ^ Km[14]) ^ (P[15] ^ Km[15]) ^ 1) ^ (((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[1] ^ Km[1]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[2] ^ Km[2]) ^ (P[3] ^ Km[3]) ^ 1))) ^ (Km[15] ^ (Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1));
C[14] = ((((P[12] ^ Km[12])*(P[13] ^ Km[13]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13]) ^ (P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ 1) ^ ((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[13] ^ Km[13]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[14] ^ Km[14]) ^ (P[15] ^ Km[15]) ^ 1)) ^ (((P[0] ^ Km[0])*(P[1] ^ Km[1]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1]) ^ (P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ 1))) ^ (Km[14] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1));
C[13] = ((((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13]) ^ (P[15] ^ Km[15])) ^ ((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[14] ^ Km[14]) ^ (P[15] ^ Km[15]) ^ 1) ^ ((P[12] ^ Km[12])*(P[13] ^ Km[13]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13]) ^ (P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ 1)) ^ (((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1]) ^ (P[3] ^ Km[3])) ^ ((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[2] ^ Km[2]) ^ (P[3] ^ Km[3]) ^ 1))) ^ (Km[13] ^ (Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1));
C[12] = ((0 ^ ((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[14] ^ Km[14]) ^ (P[15] ^ Km[15]) ^ 1) ^ ((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13]) ^ (P[15] ^ Km[15]))) ^ (0 ^ ((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[2] ^ Km[2]) ^ (P[3] ^ Km[3]) ^ 1))) ^ (Km[12] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3]) ^ 1);
C[11] = ((((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[13] ^ Km[13]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[14] ^ Km[14]) ^ (P[15] ^ Km[15]) ^ 1)) ^ (((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[1] ^ Km[1]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[2] ^ Km[2]) ^ (P[3] ^ Km[3]) ^ 1) ^ ((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[2] ^ Km[2]) ^ (P[3] ^ Km[3]) ^ 1))) ^ (Km[11] ^ (Km[15] ^ (Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1)));
C[10] = ((((P[12] ^ Km[12])*(P[13] ^ Km[13]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13]) ^ (P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ 1)) ^ (((P[0] ^ Km[0])*(P[1] ^ Km[1]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1]) ^ (P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ 1) ^ ((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[1] ^ Km[1]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[2] ^ Km[2]) ^ (P[3] ^ Km[3]) ^ 1))) ^ (Km[10] ^ (Km[14] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1)));
C[9]  = ((((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[15] ^ Km[15]) ^ (P[12] ^ Km[12])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13]) ^ (P[15] ^ Km[15])) ^ ((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[14] ^ Km[14]) ^ (P[15] ^ Km[15]) ^ 1)) ^ (((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1]) ^ (P[3] ^ Km[3])) ^ ((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[2] ^ Km[2]) ^ (P[3] ^ Km[3]) ^ 1) ^ ((P[0] ^ Km[0])*(P[1] ^ Km[1]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1]) ^ (P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ 1))) ^ (Km[9] ^ (Km[13] ^ (Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1)));
C[8]  = ((0 ^ ((P[12] ^ Km[12])*(P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[12] ^ Km[12]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[13] ^ Km[13])*(P[14] ^ Km[14]) ^ (P[14] ^ Km[14])*(P[15] ^ Km[15]) ^ (P[14] ^ Km[14]) ^ (P[15] ^ Km[15]) ^ 1)) ^ (0 ^ ((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1])*(P[2] ^ Km[2]) ^ (P[2] ^ Km[2])*(P[3] ^ Km[3]) ^ (P[2] ^ Km[2]) ^ (P[3] ^ Km[3]) ^ 1) ^ ((P[0] ^ Km[0])*(P[1] ^ Km[1])*(P[3] ^ Km[3]) ^ (P[0] ^ Km[0])*(P[2] ^ Km[2]) ^ (P[0] ^ Km[0])*(P[3] ^ Km[3]) ^ (P[1] ^ Km[1]) ^ (P[3] ^ Km[3])))) ^ (Km[8] ^ (Km[12] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3]) ^ 1));
C[7]  = (((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[5] ^ Km[5]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[6] ^ Km[6]) ^ (P[7] ^ Km[7]) ^ 1) ^ ((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[6] ^ Km[6]) ^ (P[7] ^ Km[7]) ^ 1) ^ (((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[9] ^ Km[9]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[10] ^ Km[10]) ^ (P[11] ^ Km[11]) ^ 1))) ^ (Km[7] ^ (Km[11] ^ (Km[15] ^ (Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1))));
C[6]  = ((((P[4] ^ Km[4])*(P[5] ^ Km[5]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5]) ^ (P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ 1) ^ ((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[5] ^ Km[5]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[6] ^ Km[6]) ^ (P[7] ^ Km[7]) ^ 1)) ^ (((P[8] ^ Km[8])*(P[9] ^ Km[9]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9]) ^ (P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ 1))) ^ (Km[6] ^ (Km[10] ^ (Km[14] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1))));
C[5]  = ((((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5]) ^ (P[7] ^ Km[7])) ^ ((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[6] ^ Km[6]) ^ (P[7] ^ Km[7]) ^ 1) ^ ((P[4] ^ Km[4])*(P[5] ^ Km[5]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5]) ^ (P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ 1)) ^ (((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9]) ^ (P[11] ^ Km[11])) ^ ((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[10] ^ Km[10]) ^ (P[11] ^ Km[11]) ^ 1))) ^ (Km[5] ^ (Km[9] ^ (Km[13] ^ (Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1))));
C[4]  = ((0 ^ ((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[6] ^ Km[6]) ^ (P[7] ^ Km[7]) ^ 1) ^ ((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5]) ^ (P[7] ^ Km[7]))) ^ (0 ^ ((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[10] ^ Km[10]) ^ (P[11] ^ Km[11]) ^ 1))) ^ (Km[4] ^ (Km[8] ^ (Km[12] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3]) ^ 1)));
C[3]  = ((((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[5] ^ Km[5]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[6] ^ Km[6]) ^ (P[7] ^ Km[7]) ^ 1)) ^ (((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[9] ^ Km[9]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[10] ^ Km[10]) ^ (P[11] ^ Km[11]) ^ 1) ^ ((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[10] ^ Km[10]) ^ (P[11] ^ Km[11]) ^ 1))) ^ (Km[3] ^ (Km[7] ^ (Km[11] ^ (Km[15] ^ (Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1)))));
C[2]  = ((((P[4] ^ Km[4])*(P[5] ^ Km[5]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5]) ^ (P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ 1)) ^ (((P[8] ^ Km[8])*(P[9] ^ Km[9]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9]) ^ (P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ 1) ^ ((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[9] ^ Km[9]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[10] ^ Km[10]) ^ (P[11] ^ Km[11]) ^ 1))) ^ (Km[2] ^ (Km[6] ^ (Km[10] ^ (Km[14] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1)))));
C[1]  = ((((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[7] ^ Km[7]) ^ (P[4] ^ Km[4])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5]) ^ (P[7] ^ Km[7])) ^ ((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[6] ^ Km[6]) ^ (P[7] ^ Km[7]) ^ 1)) ^ (((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9]) ^ (P[11] ^ Km[11])) ^ ((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[10] ^ Km[10]) ^ (P[11] ^ Km[11]) ^ 1) ^ ((P[8] ^ Km[8])*(P[9] ^ Km[9]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9]) ^ (P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ 1))) ^ (Km[1] ^ (Km[5] ^ (Km[9] ^ (Km[13] ^ (Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1)))));
C[0]  = ((0 ^ ((P[4] ^ Km[4])*(P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[4] ^ Km[4]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[5] ^ Km[5])*(P[6] ^ Km[6]) ^ (P[6] ^ Km[6])*(P[7] ^ Km[7]) ^ (P[6] ^ Km[6]) ^ (P[7] ^ Km[7]) ^ 1)) ^ (0 ^ ((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9])*(P[10] ^ Km[10]) ^ (P[10] ^ Km[10])*(P[11] ^ Km[11]) ^ (P[10] ^ Km[10]) ^ (P[11] ^ Km[11]) ^ 1) ^ ((P[8] ^ Km[8])*(P[9] ^ Km[9])*(P[11] ^ Km[11]) ^ (P[8] ^ Km[8])*(P[10] ^ Km[10]) ^ (P[8] ^ Km[8])*(P[11] ^ Km[11]) ^ (P[9] ^ Km[9]) ^ (P[11] ^ Km[11])))) ^ (Km[0] ^ (Km[4] ^ (Km[8] ^ (Km[12] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3]) ^ 1))));

u16 K0_[16];
u16 K1_[16];

K0_[15] = Km[15];
K0_[14] = Km[14];
K0_[13] = Km[13];
K0_[12] = Km[12];
K0_[11] = Km[11];
K0_[10] = Km[10];
K0_[9]  = Km[9];
K0_[8]  = Km[8];
K0_[7]  = Km[7];
K0_[6]  = Km[6];
K0_[5]  = Km[5];
K0_[4]  = Km[4];
K0_[3]  = Km[3];
K0_[2]  = Km[2];
K0_[1]  = Km[1];
K0_[0]  = Km[0];

K1_[15] = Km[15] ^ (Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1);
K1_[14] = Km[14] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1);
K1_[13] = Km[13] ^ (Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1);
K1_[12] = Km[12] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3]) ^ 1;

K1_[11] = Km[11] ^ (Km[15] ^ (Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1));
K1_[10] = Km[10] ^ (Km[14] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1));
K1_[9]  = Km[9] ^ (Km[13] ^ (Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1));
K1_[8]  = Km[8] ^ (Km[12] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3]) ^ 1);

K1_[7]  = Km[7] ^ (Km[11] ^ (Km[15] ^ (Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1)));
K1_[6]  = Km[6] ^ (Km[10] ^ (Km[14] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1)));
K1_[5]  = Km[5] ^ (Km[9] ^ (Km[13] ^ (Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1)));
K1_[4]  = Km[4] ^ (Km[8] ^ (Km[12] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3]) ^ 1));

K1_[3]  = Km[3] ^ (Km[7] ^ (Km[11] ^ (Km[15] ^ (Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1))));
K1_[2]  = Km[2] ^ (Km[6] ^ (Km[10] ^ (Km[14] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1))));
K1_[1]  = Km[1] ^ (Km[5] ^ (Km[9] ^ (Km[13] ^ (Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1))));
K1_[0]  = Km[0] ^ (Km[4] ^ (Km[8] ^ (Km[12] ^ (Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3]) ^ 1)));
        
pf("K0: ");
      for(int i = 15;i>=0;i--){
          if(i==3){
              pf(" ");
          }
          else if(i==7){
              pf(" ");
          }
          if(i==11){
              pf(" ");
          }
          pf("%X",K0_[i]);
      }
      pf("\n");

pf("K1: ");
      for(int i = 15;i>=0;i--){
          if(i==3){
              pf(" ");
          }
          else if(i==7){
              pf(" ");
          }
          if(i==11){
              pf(" ");
          }
          pf("%X",K1_[i]);
      }
      pf("\n");

  u16 cSegment[4];

  cSegment[0] = ((C[15] * 8) + (C[14] * 4) + (C[13] * 2) + (C[12] * 1));
  cSegment[1] = ((C[11] * 8) + (C[10] * 4) + (C[9] * 2) + (C[8] * 1));
  cSegment[2] = ((C[7] * 8) + (C[6] * 4) + (C[5] * 2) + (C[4] * 1));
  cSegment[3] = ((C[3] * 8) + (C[2] * 4) + (C[1] * 2) + (C[0] * 1));



  pf("Ciphertext: ");
  for (int i = 0; i < 4; i++) {
    pf("%X", cSegment[i]);
  }
  pf("\n");

}

void checkformula(){
      
    u16 M[16];
    u16 Km[20];
    u16 j[31];
    
    printf("Enter Plaintext in hexadecimal (4 bit) \n");
  do {
    scanf("%x", & value);
    if (value < 65536) {
      break;
    }
  }
  while (1);

  u16 v0 = (value & 0xf000) >> 12;
  u16 v1 = (value & 0x0f00) >> 8;
  u16 v2 = (value & 0x00f0) >> 4;
  u16 v3 = (value & 0x000f);

  printf("Enter Km in hexadecimal (5 bit) \n");
  do {
    scanf("%x", & value);
    if (value < 1048576) {
      break;
    }
  }
  while (1);

  u16 m0 = (value & 0xf0000) >> 16;
  u16 m1 = (value & 0x0f000) >> 12;
  u16 m2 = (value & 0x00f00) >> 8;
  u16 m3 = (value & 0x000f0) >> 4;
  u16 m4 = (value & 0x0000f);

  if (v0 == 0x0000) {
    M[15] = 0x0;
    M[14] = 0x0;
    M[13] = 0x0;
    M[12] = 0x0;
  } else if (v0 == 0x0001) {
    M[15] = 0x0;
    M[14] = 0x0;
    M[13] = 0x0;
    M[12] = 0x1;
  } else if (v0 == 0x0002) {
    M[15] = 0x0;
    M[14] = 0x0;
    M[13] = 0x1;
    M[12] = 0x0;
  } else if (v0 == 0x0003) {
    M[15] = 0x0;
    M[14] = 0x0;
    M[13] = 0x1;
    M[12] = 0x1;
  } else if (v0 == 0x0004) {
    M[15] = 0x0;
    M[14] = 0x1;
    M[13] = 0x0;
    M[12] = 0x0;
  } else if (v0 == 0x0005) {
    M[15] = 0x0;
    M[14] = 0x1;
    M[13] = 0x0;
    M[12] = 0x1;
  } else if (v0 == 0x0006) {
    M[15] = 0x0;
    M[14] = 0x1;
    M[13] = 0x1;
    M[12] = 0x0;
  } else if (v0 == 0x0007) {
    M[15] = 0x0;
    M[14] = 0x1;
    M[13] = 0x1;
    M[12] = 0x1;
  } else if (v0 == 0x0008) {
    M[15] = 0x1;
    M[14] = 0x0;
    M[13] = 0x0;
    M[12] = 0x0;
  } else if (v0 == 0x0009) {
    M[15] = 0x1;
    M[14] = 0x0;
    M[13] = 0x0;
    M[12] = 0x1;
  } else if (v0 == 0x000A) {
    M[15] = 0x1;
    M[14] = 0x0;
    M[13] = 0x1;
    M[12] = 0x0;
  } else if (v0 == 0x000B) {
    M[15] = 0x1;
    M[14] = 0x0;
    M[13] = 0x1;
    M[12] = 0x1;
  } else if (v0 == 0x000C) {
    M[15] = 0x1;
    M[14] = 0x1;
    M[13] = 0x0;
    M[12] = 0x0;
  } else if (v0 == 0x000D) {
    M[15] = 0x1;
    M[14] = 0x1;
    M[13] = 0x0;
    M[12] = 0x1;
  } else if (v0 == 0x000E) {
    M[15] = 0x1;
    M[14] = 0x1;
    M[13] = 0x1;
    M[12] = 0x0;
  } else if (v0 == 0x000F) {
    M[15] = 0x1;
    M[14] = 0x1;
    M[13] = 0x1;
    M[12] = 0x1;
  }
  ////////////////////////////////
  if (v1 == 0x0000) {
    M[11] = 0x0;
    M[10] = 0x0;
    M[9] = 0x0;
    M[8] = 0x0;
  } else if (v1 == 0x0001) {
    M[11] = 0x0;
    M[10] = 0x0;
    M[9] = 0x0;
    M[8] = 0x1;
  } else if (v1 == 0x0002) {
    M[11] = 0x0;
    M[10] = 0x0;
    M[9] = 0x1;
    M[8] = 0x0;
  } else if (v1 == 0x0003) {
    M[11] = 0x0;
    M[10] = 0x0;
    M[9] = 0x1;
    M[8] = 0x1;
  } else if (v1 == 0x0004) {
    M[11] = 0x0;
    M[10] = 0x1;
    M[9] = 0x0;
    M[8] = 0x0;
  } else if (v1 == 0x0005) {
    M[11] = 0x0;
    M[10] = 0x1;
    M[9] = 0x0;
    M[8] = 0x1;
  } else if (v1 == 0x0006) {
    M[11] = 0x0;
    M[10] = 0x1;
    M[9] = 0x1;
    M[8] = 0x0;
  } else if (v1 == 0x0007) {
    M[11] = 0x0;
    M[10] = 0x1;
    M[9] = 0x1;
    M[8] = 0x1;
  } else if (v1 == 0x0008) {
    M[11] = 0x1;
    M[10] = 0x0;
    M[9] = 0x0;
    M[8] = 0x0;
  } else if (v1 == 0x0009) {
    M[11] = 0x1;
    M[10] = 0x0;
    M[9] = 0x0;
    M[8] = 0x1;
  } else if (v1 == 0x000A) {
    M[11] = 0x1;
    M[10] = 0x0;
    M[9] = 0x1;
    M[8] = 0x0;
  } else if (v1 == 0x000B) {
    M[11] = 0x1;
    M[10] = 0x0;
    M[9] = 0x1;
    M[8] = 0x1;
  } else if (v1 == 0x000C) {
    M[11] = 0x1;
    M[10] = 0x1;
    M[9] = 0x0;
    M[8] = 0x0;
  } else if (v1 == 0x000D) {
    M[11] = 0x1;
    M[10] = 0x1;
    M[9] = 0x0;
    M[8] = 0x1;
  } else if (v1 == 0x000E) {
    M[11] = 0x1;
    M[10] = 0x1;
    M[9] = 0x1;
    M[8] = 0x0;
  } else if (v1 == 0x000F) {
    M[11] = 0x1;
    M[10] = 0x1;
    M[9] = 0x1;
    M[8] = 0x1;
  }
  /////////////
  if (v2 == 0x0000) {
    M[7] = 0x0;
    M[6] = 0x0;
    M[5] = 0x0;
    M[4] = 0x0;
  } else if (v2 == 0x0001) {
    M[7] = 0x0;
    M[6] = 0x0;
    M[5] = 0x0;
    M[4] = 0x1;
  } else if (v2 == 0x0002) {
    M[7] = 0x0;
    M[6] = 0x0;
    M[5] = 0x1;
    M[4] = 0x0;
  } else if (v2 == 0x0003) {
    M[7] = 0x0;
    M[6] = 0x0;
    M[5] = 0x1;
    M[4] = 0x1;
  } else if (v2 == 0x0004) {
    M[7] = 0x0;
    M[6] = 0x1;
    M[5] = 0x0;
    M[4] = 0x0;
  } else if (v2 == 0x0005) {
    M[7] = 0x0;
    M[6] = 0x1;
    M[5] = 0x0;
    M[4] = 0x1;
  } else if (v2 == 0x0006) {
    M[7] = 0x0;
    M[6] = 0x1;
    M[5] = 0x1;
    M[4] = 0x0;
  } else if (v2 == 0x0007) {
    M[7] = 0x0;
    M[6] = 0x1;
    M[5] = 0x1;
    M[4] = 0x1;
  } else if (v2 == 0x0008) {
    M[7] = 0x1;
    M[6] = 0x0;
    M[5] = 0x0;
    M[4] = 0x0;
  } else if (v2 == 0x0009) {
    M[7] = 0x1;
    M[6] = 0x0;
    M[5] = 0x0;
    M[4] = 0x1;
  } else if (v2 == 0x000A) {
    M[7] = 0x1;
    M[6] = 0x0;
    M[5] = 0x1;
    M[4] = 0x0;
  } else if (v2 == 0x000B) {
    M[7] = 0x1;
    M[6] = 0x0;
    M[5] = 0x1;
    M[4] = 0x1;
  } else if (v2 == 0x000C) {
    M[7] = 0x1;
    M[6] = 0x1;
    M[5] = 0x0;
    M[4] = 0x0;
  } else if (v2 == 0x000D) {
    M[7] = 0x1;
    M[6] = 0x1;
    M[5] = 0x0;
    M[4] = 0x1;
  } else if (v2 == 0x000E) {
    M[7] = 0x1;
    M[6] = 0x1;
    M[5] = 0x1;
    M[4] = 0x0;
  } else if (v2 == 0x000F) {
    M[7] = 0x1;
    M[6] = 0x1;
    M[5] = 0x1;
    M[4] = 0x1;
  }
  /////////
  if (v3 == 0x0000) {
    M[3] = 0x0;
    M[2] = 0x0;
    M[1] = 0x0;
    M[0] = 0x0;
  } else if (v3 == 0x0001) {
    M[3] = 0x0;
    M[2] = 0x0;
    M[1] = 0x0;
    M[0] = 0x1;
  } else if (v3 == 0x0002) {
    M[3] = 0x0;
    M[2] = 0x0;
    M[1] = 0x1;
    M[0] = 0x0;
  } else if (v3 == 0x0003) {
    M[3] = 0x0;
    M[2] = 0x0;
    M[1] = 0x1;
    M[0] = 0x1;
  } else if (v3 == 0x0004) {
    M[3] = 0x0;
    M[2] = 0x1;
    M[1] = 0x0;
    M[0] = 0x0;
  } else if (v3 == 0x0005) {
    M[3] = 0x0;
    M[2] = 0x1;
    M[1] = 0x0;
    M[0] = 0x1;
  } else if (v3 == 0x0006) {
    M[3] = 0x0;
    M[2] = 0x1;
    M[1] = 0x1;
    M[0] = 0x0;
  } else if (v3 == 0x0007) {
    M[3] = 0x0;
    M[2] = 0x1;
    M[1] = 0x1;
    M[0] = 0x1;
  } else if (v3 == 0x0008) {
    M[3] = 0x1;
    M[2] = 0x0;
    M[1] = 0x0;
    M[0] = 0x0;
  } else if (v3 == 0x0009) {
    M[3] = 0x1;
    M[2] = 0x0;
    M[1] = 0x0;
    M[0] = 0x1;
  } else if (v3 == 0x000A) {
    M[3] = 0x1;
    M[2] = 0x0;
    M[1] = 0x1;
    M[0] = 0x0;
  } else if (v3 == 0x000B) {
    M[3] = 0x1;
    M[2] = 0x0;
    M[1] = 0x1;
    M[0] = 0x1;
  } else if (v3 == 0x000C) {
    M[3] = 0x1;
    M[2] = 0x1;
    M[1] = 0x0;
    M[0] = 0x0;
  } else if (v3 == 0x000D) {
    M[3] = 0x1;
    M[2] = 0x1;
    M[1] = 0x0;
    M[0] = 0x1;
  } else if (v3 == 0x000E) {
    M[3] = 0x1;
    M[2] = 0x1;
    M[1] = 0x1;
    M[0] = 0x0;
  } else if (v3 == 0x000F) {
    M[3] = 0x1;
    M[2] = 0x1;
    M[1] = 0x1;
    M[0] = 0x1;
  }

  /////////////////////////

  if (m0 == 0x0000) {
    Km[19] = 0x0;
    Km[18] = 0x0;
    Km[17] = 0x0;
    Km[16] = 0x0;
  } else if (m0 == 0x0001) {
    Km[19] = 0x0;
    Km[18] = 0x0;
    Km[17] = 0x0;
    Km[16] = 0x1;
  } else if (m0 == 0x0002) {
    Km[19] = 0x0;
    Km[18] = 0x0;
    Km[17] = 0x1;
    Km[16] = 0x0;
  } else if (m0 == 0x0003) {
    Km[19] = 0x0;
    Km[18] = 0x0;
    Km[17] = 0x1;
    Km[16] = 0x1;
  } else if (m0 == 0x0004) {
    Km[19] = 0x0;
    Km[18] = 0x1;
    Km[17] = 0x0;
    Km[16] = 0x0;
  } else if (m0 == 0x0005) {
    Km[19] = 0x0;
    Km[18] = 0x1;
    Km[17] = 0x0;
    Km[16] = 0x1;
  } else if (m0 == 0x0006) {
    Km[19] = 0x0;
    Km[18] = 0x1;
    Km[17] = 0x1;
    Km[16] = 0x0;
  } else if (m0 == 0x0007) {
    Km[19] = 0x0;
    Km[18] = 0x1;
    Km[17] = 0x1;
    Km[16] = 0x1;
  } else if (m0 == 0x0008) {
    Km[19] = 0x1;
    Km[18] = 0x0;
    Km[17] = 0x0;
    Km[16] = 0x0;
  } else if (m0 == 0x0009) {
    Km[19] = 0x1;
    Km[18] = 0x0;
    Km[17] = 0x0;
    Km[16] = 0x1;
  } else if (m0 == 0x000A) {
    Km[19] = 0x1;
    Km[18] = 0x0;
    Km[17] = 0x1;
    Km[16] = 0x0;
  } else if (m0 == 0x000B) {
    Km[19] = 0x1;
    Km[18] = 0x0;
    Km[17] = 0x1;
    Km[16] = 0x1;
  } else if (m0 == 0x000C) {
    Km[19] = 0x1;
    Km[18] = 0x1;
    Km[17] = 0x0;
    Km[16] = 0x0;
  } else if (m0 == 0x000D) {
    Km[19] = 0x1;
    Km[18] = 0x1;
    Km[17] = 0x0;
    Km[16] = 0x1;
  } else if (m0 == 0x000E) {
    Km[19] = 0x1;
    Km[18] = 0x1;
    Km[17] = 0x1;
    Km[16] = 0x0;
  } else if (m0 == 0x000F) {
    Km[19] = 0x1;
    Km[18] = 0x1;
    Km[17] = 0x1;
    Km[16] = 0x1;
  }
  ////////////////////////////////
  if (m1 == 0x0000) {
    Km[15] = 0x0;
    Km[14] = 0x0;
    Km[13] = 0x0;
    Km[12] = 0x0;
  } else if (m1 == 0x0001) {
    Km[15] = 0x0;
    Km[14] = 0x0;
    Km[13] = 0x0;
    Km[12] = 0x1;
  } else if (m1 == 0x0002) {
    Km[15] = 0x0;
    Km[14] = 0x0;
    Km[13] = 0x1;
    Km[12] = 0x0;
  } else if (m1 == 0x0003) {
    Km[15] = 0x0;
    Km[14] = 0x0;
    Km[13] = 0x1;
    Km[12] = 0x1;
  } else if (m1 == 0x0004) {
    Km[15] = 0x0;
    Km[14] = 0x1;
    Km[13] = 0x0;
    Km[12] = 0x0;
  } else if (m1 == 0x0005) {
    Km[15] = 0x0;
    Km[14] = 0x1;
    Km[13] = 0x0;
    Km[12] = 0x1;
  } else if (m1 == 0x0006) {
    Km[15] = 0x0;
    Km[14] = 0x1;
    Km[13] = 0x1;
    Km[12] = 0x0;
  } else if (m1 == 0x0007) {
    Km[15] = 0x0;
    Km[14] = 0x1;
    Km[13] = 0x1;
    Km[12] = 0x1;
  } else if (m1 == 0x0008) {
    Km[15] = 0x1;
    Km[14] = 0x0;
    Km[13] = 0x0;
    Km[12] = 0x0;
  } else if (m1 == 0x0009) {
    Km[15] = 0x1;
    Km[14] = 0x0;
    Km[13] = 0x0;
    Km[12] = 0x1;
  } else if (m1 == 0x000A) {
    Km[15] = 0x1;
    Km[14] = 0x0;
    Km[13] = 0x1;
    Km[12] = 0x0;
  } else if (m1 == 0x000B) {
    Km[15] = 0x1;
    Km[14] = 0x0;
    Km[13] = 0x1;
    Km[12] = 0x1;
  } else if (m1 == 0x000C) {
    Km[15] = 0x1;
    Km[14] = 0x1;
    Km[13] = 0x0;
    Km[12] = 0x0;
  } else if (m1 == 0x000D) {
    Km[15] = 0x1;
    Km[14] = 0x1;
    Km[13] = 0x0;
    Km[12] = 0x1;
  } else if (m1 == 0x000E) {
    Km[15] = 0x1;
    Km[14] = 0x1;
    Km[13] = 0x1;
    Km[12] = 0x0;
  } else if (m1 == 0x000F) {
    Km[15] = 0x1;
    Km[14] = 0x1;
    Km[13] = 0x1;
    Km[12] = 0x1;
  }
  /////////////
  if (m2 == 0x0000) {
    Km[11] = 0x0;
    Km[10] = 0x0;
    Km[9] = 0x0;
    Km[8] = 0x0;
  } else if (m2 == 0x0001) {
    Km[11] = 0x0;
    Km[10] = 0x0;
    Km[9] = 0x0;
    Km[8] = 0x1;
  } else if (m2 == 0x0002) {
    Km[11] = 0x0;
    Km[10] = 0x0;
    Km[9] = 0x1;
    Km[8] = 0x0;
  } else if (m2 == 0x0003) {
    Km[11] = 0x0;
    Km[10] = 0x0;
    Km[9] = 0x1;
    Km[8] = 0x1;
  } else if (m2 == 0x0004) {
    Km[11] = 0x0;
    Km[10] = 0x1;
    Km[9] = 0x0;
    Km[8] = 0x0;
  } else if (m2 == 0x0005) {
    Km[11] = 0x0;
    Km[10] = 0x1;
    Km[9] = 0x0;
    Km[8] = 0x1;
  } else if (m2 == 0x0006) {
    Km[11] = 0x0;
    Km[10] = 0x1;
    Km[9] = 0x1;
    Km[8] = 0x0;
  } else if (m2 == 0x0007) {
    Km[11] = 0x0;
    Km[10] = 0x1;
    Km[9] = 0x1;
    Km[8] = 0x1;
  } else if (m2 == 0x0008) {
    Km[11] = 0x1;
    Km[10] = 0x0;
    Km[9] = 0x0;
    Km[8] = 0x0;
  } else if (m2 == 0x0009) {
    Km[11] = 0x1;
    Km[10] = 0x0;
    Km[9] = 0x0;
    Km[8] = 0x1;
  } else if (m2 == 0x000A) {
    Km[11] = 0x1;
    Km[10] = 0x0;
    Km[9] = 0x1;
    Km[8] = 0x0;
  } else if (m2 == 0x000B) {
    Km[11] = 0x1;
    Km[10] = 0x0;
    Km[9] = 0x1;
    Km[8] = 0x1;
  } else if (m2 == 0x000C) {
    Km[11] = 0x1;
    Km[10] = 0x1;
    Km[9] = 0x0;
    Km[8] = 0x0;
  } else if (m2 == 0x000D) {
    Km[11] = 0x1;
    Km[10] = 0x1;
    Km[9] = 0x0;
    Km[8] = 0x1;
  } else if (m2 == 0x000E) {
    Km[11] = 0x1;
    Km[10] = 0x1;
    Km[9] = 0x1;
    Km[8] = 0x0;
  } else if (m2 == 0x000F) {
    Km[11] = 0x1;
    Km[10] = 0x1;
    Km[9] = 0x1;
    Km[8] = 0x1;
  }
  /////////
  if (m3 == 0x0000) {
    Km[7] = 0x0;
    Km[6] = 0x0;
    Km[5] = 0x0;
    Km[4] = 0x0;
  } else if (m3 == 0x0001) {
    Km[7] = 0x0;
    Km[6] = 0x0;
    Km[5] = 0x0;
    Km[4] = 0x1;
  } else if (m3 == 0x0002) {
    Km[7] = 0x0;
    Km[6] = 0x0;
    Km[5] = 0x1;
    Km[4] = 0x0;
  } else if (m3 == 0x0003) {
    Km[7] = 0x0;
    Km[6] = 0x0;
    Km[5] = 0x1;
    Km[4] = 0x1;
  } else if (m3 == 0x0004) {
    Km[7] = 0x0;
    Km[6] = 0x1;
    Km[5] = 0x0;
    Km[4] = 0x0;
  } else if (m3 == 0x0005) {
    Km[7] = 0x0;
    Km[6] = 0x1;
    Km[5] = 0x0;
    Km[4] = 0x1;
  } else if (m3 == 0x0006) {
    Km[7] = 0x0;
    Km[6] = 0x1;
    Km[5] = 0x1;
    Km[4] = 0x0;
  } else if (m3 == 0x0007) {
    Km[7] = 0x0;
    Km[6] = 0x1;
    Km[5] = 0x1;
    Km[4] = 0x1;
  } else if (m3 == 0x0008) {
    Km[7] = 0x1;
    Km[6] = 0x0;
    Km[5] = 0x0;
    Km[4] = 0x0;
  } else if (m3 == 0x0009) {
    Km[7] = 0x1;
    Km[6] = 0x0;
    Km[5] = 0x0;
    Km[4] = 0x1;
  } else if (m3 == 0x000A) {
    Km[7] = 0x1;
    Km[6] = 0x0;
    Km[5] = 0x1;
    Km[4] = 0x0;
  } else if (m3 == 0x000B) {
    Km[7] = 0x1;
    Km[6] = 0x0;
    Km[5] = 0x1;
    Km[4] = 0x1;
  } else if (m3 == 0x000C) {
    Km[7] = 0x1;
    Km[6] = 0x1;
    Km[5] = 0x0;
    Km[4] = 0x0;
  } else if (m3 == 0x000D) {
    Km[7] = 0x1;
    Km[6] = 0x1;
    Km[5] = 0x0;
    Km[4] = 0x1;
  } else if (m3 == 0x000E) {
    Km[7] = 0x1;
    Km[6] = 0x1;
    Km[5] = 0x1;
    Km[4] = 0x0;
  } else if (m3 == 0x000F) {
    Km[7] = 0x1;
    Km[6] = 0x1;
    Km[5] = 0x1;
    Km[4] = 0x1;
  }
  //////////
  if (m4 == 0x0000) {
    Km[3] = 0x0;
    Km[2] = 0x0;
    Km[1] = 0x0;
    Km[0] = 0x0;
  } else if (m4 == 0x0001) {
    Km[3] = 0x0;
    Km[2] = 0x0;
    Km[1] = 0x0;
    Km[0] = 0x1;
  } else if (m4 == 0x0002) {
    Km[3] = 0x0;
    Km[2] = 0x0;
    Km[1] = 0x1;
    Km[0] = 0x0;
  } else if (m4 == 0x0003) {
    Km[3] = 0x0;
    Km[2] = 0x0;
    Km[1] = 0x1;
    Km[0] = 0x1;
  } else if (m4 == 0x0004) {
    Km[3] = 0x0;
    Km[2] = 0x1;
    Km[1] = 0x0;
    Km[0] = 0x0;
  } else if (m4 == 0x0005) {
    Km[3] = 0x0;
    Km[2] = 0x1;
    Km[1] = 0x0;
    Km[0] = 0x1;
  } else if (m4 == 0x0006) {
    Km[3] = 0x0;
    Km[2] = 0x1;
    Km[1] = 0x1;
    Km[0] = 0x0;
  } else if (m4 == 0x0007) {
    Km[3] = 0x0;
    Km[2] = 0x1;
    Km[1] = 0x1;
    Km[0] = 0x1;
  } else if (m4 == 0x0008) {
    Km[3] = 0x1;
    Km[2] = 0x0;
    Km[1] = 0x0;
    Km[0] = 0x0;
  } else if (m4 == 0x0009) {
    Km[3] = 0x1;
    Km[2] = 0x0;
    Km[1] = 0x0;
    Km[0] = 0x1;
  } else if (m4 == 0x000A) {
    Km[3] = 0x1;
    Km[2] = 0x0;
    Km[1] = 0x1;
    Km[0] = 0x0;
  } else if (m4 == 0x000B) {
    Km[3] = 0x1;
    Km[2] = 0x0;
    Km[1] = 0x1;
    Km[0] = 0x1;
  } else if (m4 == 0x000C) {
    Km[3] = 0x1;
    Km[2] = 0x1;
    Km[1] = 0x0;
    Km[0] = 0x0;
  } else if (m4 == 0x000D) {
    Km[3] = 0x1;
    Km[2] = 0x1;
    Km[1] = 0x0;
    Km[0] = 0x1;
  } else if (m4 == 0x000E) {
    Km[3] = 0x1;
    Km[2] = 0x1;
    Km[1] = 0x1;
    Km[0] = 0x0;
  } else if (m4 == 0x000F) {
    Km[3] = 0x1;
    Km[2] = 0x1;
    Km[1] = 0x1;
    Km[0] = 0x1;
  }
  
    u16 Kma[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
   
    //SIMPLEST FORM
//    j[31] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ M[14] ^ Km[14] ^ M[15] ^ Km[15] ^ 1 ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ M[12] ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ M[14] ^ Km[14] ^ M[15] ^ Km[15] ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ M[2] ^ Km[2] ^ M[3] ^ Km[3] ^ 1 ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1;
//    j[30] = (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ M[14] ^ Kma[14] ^ M[15] ^ Kma[15] ^ 1 ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ M[12] ^ Kma[12] ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ (M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ M[14] ^ Kma[14] ^ M[15] ^ Kma[15] ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ M[2] ^ Kma[2] ^ M[3] ^ Kma[3] ^ 1 ^ Kma[15] ^ Kma[0]*Kma[1]*Kma[2] ^ Kma[0] ^ Kma[1]*Kma[2]*Kma[3] ^ Kma[1]*Kma[2] ^ Kma[2]*Kma[3] ^ Kma[2] ^ Kma[3] ^ 1;
//    
//    j[29] = (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ M[12] ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ M[13] ^ Km[13] ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ 1 ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[14] ^ Km[14]) ^ M[15] ^ Km[15] ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ M[0] ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ M[1] ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ 1 ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1;
//    j[28] = (M[12] ^ Kma[12])*(M[13] ^ Kma[13]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[12] ^ Kma[12])*(M[15] ^ Kma[15]) ^ M[12] ^ Kma[12] ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ (M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ M[13] ^ Kma[13] ^ (M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ 1 ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ (M[14] ^ Kma[14]) ^ M[15] ^ Kma[15] ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[0] ^ Kma[0])*(M[3] ^ Kma[3]) ^ M[0] ^ Kma[0] ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ M[1] ^ Kma[1] ^ (M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ 1 ^ Kma[14] ^ Kma[0]*Kma[1]*Kma[3] ^ Kma[0]*Kma[1] ^ Kma[0]*Kma[2] ^ Kma[1]*Kma[3] ^ Kma[2] ^ Kma[3] ^ 1;
//    
//    j[27] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ M[13] ^ Km[13] ^ M[15] ^ Km[15] ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ M[12] ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ M[14] ^ Km[14] ^ M[15] ^ Km[15] ^ 1 ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ M[12] ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ M[13] ^ Km[13] ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ M[1] ^ Km[1] ^ M[3] ^ Km[3] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ M[0] ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ M[2] ^ Km[2] ^ M[3] ^ Km[3] ^ 1 ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1;
//    j[26] = (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[12] ^ Kma[12])*(M[15] ^ Kma[15]) ^ M[13] ^ Kma[13] ^ M[15] ^ Kma[15] ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ M[12] ^ Kma[12] ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ (M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ M[14] ^ Kma[14] ^ M[15] ^ Kma[15] ^ 1 ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[12] ^ Kma[12])*(M[15] ^ Kma[15]) ^ M[12] ^ Kma[12] ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ (M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ M[13] ^ Kma[13] ^ (M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[0] ^ Kma[0])*(M[3] ^ Kma[3]) ^ M[1] ^ Kma[1] ^ M[3] ^ Kma[3] ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ M[0] ^ Kma[0] ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ M[2] ^ Kma[2] ^ M[3] ^ Kma[3] ^ 1 ^ Kma[13] ^ Kma[0]*Kma[1] ^ Kma[0]*Kma[2]*Kma[3] ^ Kma[0]*Kma[2] ^ Kma[0]*Kma[3] ^ Kma[0] ^ Kma[1]*Kma[2]*Kma[3] ^ Kma[1]*Kma[2] ^ Kma[1]*Kma[3] ^ Kma[1] ^ Kma[2]*Kma[3] ^ 1;
//    
//    j[25] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ M[12] ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ M[14] ^ Km[14] ^ M[15] ^ Km[15] ^ 1 ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ M[13] ^ Km[13] ^ M[15] ^ Km[15] ^ 0 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ M[0] ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ M[2] ^ Km[2] ^ M[3] ^ Km[3] ^ 1 ^ Km[12] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3] ^ 1;
//    j[24] = (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ M[12] ^ Kma[12] ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ (M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ M[14] ^ Kma[14] ^ M[15] ^ Kma[15] ^ 1 ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[12] ^ Kma[12])*(M[15] ^ Kma[15]) ^ M[13] ^ Kma[13] ^ M[15] ^ Kma[15] ^ 0 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ M[0] ^ Kma[0] ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ M[2] ^ Kma[2] ^ M[3] ^ Kma[3] ^ 1 ^ Kma[12] ^ Kma[0]*Kma[1]*Kma[3] ^ Kma[0]*Kma[2] ^ Kma[0]*Kma[3] ^ Kma[1] ^ Kma[3] ^ 1;
//
//    j[23] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ M[14] ^ Km[14] ^ M[15] ^ Km[15] ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ M[2] ^ Km[2] ^ M[3] ^ Km[3] ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ M[0] ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ M[2] ^ Km[2] ^ M[3] ^ Km[3] ^ 1 ^ Km[11] ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1;
//    j[22] = (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ M[14] ^ Kma[14] ^ M[15] ^ Kma[15] ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ M[2] ^ Kma[2] ^ M[3] ^ Kma[3] ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ M[0] ^ Kma[0] ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ M[2] ^ Kma[2] ^ M[3] ^ Kma[3] ^ 1 ^ Kma[11] ^ Kma[15] ^ Kma[0]*Kma[1]*Kma[2] ^ Kma[0] ^ Kma[1]*Kma[2]*Kma[3] ^ Kma[1]*Kma[2] ^ Kma[2]*Kma[3] ^ Kma[2] ^ Kma[3] ^ 1;
//
//    j[21] = (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ M[12] ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ M[13] ^ Km[13] ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ M[1] ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ M[2] ^ Km[2] ^ M[3] ^ Km[3] ^ 1 ^ Km[10] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1;
//    j[20] = (M[12] ^ Kma[12])*(M[13] ^ Kma[13]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[12] ^ Kma[12])*(M[15] ^ Kma[15]) ^ M[12] ^ Kma[12] ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ (M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ M[13] ^ Kma[13] ^ (M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[0] ^ Kma[0])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ M[1] ^ Kma[1] ^ (M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ M[2] ^ Kma[2] ^ M[3] ^ Kma[3] ^ 1 ^ Kma[10] ^ Kma[14] ^ Kma[0]*Kma[1]*Kma[3] ^ Kma[0]*Kma[1] ^ Kma[0]*Kma[2] ^ Kma[1]*Kma[3] ^ Kma[2] ^ Kma[3] ^ 1;
//
//    j[19] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ M[13] ^ Km[13] ^ M[15] ^ Km[15] ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ M[12] ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ M[14] ^ Km[14] ^ M[15] ^ Km[15] ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ M[1] ^ Km[1] ^ (M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ M[2] ^ Km[2] ^ M[3] ^ Km[3] ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ M[0] ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ M[1] ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ 1 ^ Km[9] ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1;
//    j[18] = (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[15] ^ Kma[15]) ^ (M[12] ^ Kma[12])*(M[14] ^ Kma[14]) ^ (M[12] ^ Kma[12])*(M[15] ^ Kma[15]) ^ M[13] ^ Kma[13] ^ M[15] ^ Kma[15] ^ (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ M[12] ^ Kma[12] ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ (M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ M[14] ^ Kma[14] ^ M[15] ^ Kma[15] ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[0] ^ Kma[0])*(M[3] ^ Kma[3]) ^ M[1] ^ Kma[1] ^ (M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[0] ^ Kma[0]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ M[2] ^ Kma[2] ^ M[3] ^ Kma[3] ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[0] ^ Kma[0])*(M[3] ^ Kma[3]) ^ M[0] ^ Kma[0] ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ M[1] ^ Kma[1] ^ (M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ 1 ^ Kma[9] ^ Kma[13] ^ Kma[0]*Kma[1] ^ Kma[0]*Kma[2]*Kma[3] ^ Kma[0]*Kma[2] ^ Kma[0]*Kma[3] ^ Kma[0] ^ Kma[1]*Kma[2]*Kma[3] ^ Kma[1]*Kma[2] ^ Kma[1]*Kma[3] ^ Kma[1] ^ Kma[2]*Kma[3] ^ 1;
//
//    j[17] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ M[12] ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ M[14] ^ Km[14] ^ M[15] ^ Km[15] ^ 1 ^ 0 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ M[0] ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ M[2] ^ Km[2] ^ M[3] ^ Km[3] ^ 1 ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ M[1] ^ Km[1] ^ M[3] ^ Km[3] ^ Km[8] ^ Km[12] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3] ^ 1;
//    j[16] = (M[12] ^ Kma[12])*(M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ M[12] ^ Kma[12] ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ (M[13] ^ Kma[13])*(M[14] ^ Kma[14]) ^ (M[14] ^ Kma[14])*(M[15] ^ Kma[15]) ^ M[14] ^ Kma[14] ^ M[15] ^ Kma[15] ^ 1 ^ 0 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ M[0] ^ Kma[0] ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ (M[1] ^ Kma[1])*(M[2] ^ Kma[2]) ^ (M[2] ^ Kma[2])*(M[3] ^ Kma[3]) ^ M[2] ^ Kma[2] ^ M[3] ^ Kma[3] ^ 1 ^ (M[0] ^ Kma[0])*(M[1] ^ Kma[1])*(M[3] ^ Kma[3]) ^ (M[0] ^ Kma[0])*(M[2] ^ Kma[2]) ^ (M[0] ^ Kma[0])*(M[3] ^ Kma[3]) ^ M[1] ^ Kma[1] ^ M[3] ^ Kma[3] ^ Kma[8] ^ Kma[12] ^ Kma[0]*Kma[1]*Kma[3] ^ Kma[0]*Kma[2] ^ Kma[0]*Kma[3] ^ Kma[1] ^ Kma[3] ^ 1;
//
//    j[15] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ M[6] ^ Km[6] ^ M[7] ^ Km[7] ^ 1 ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ M[6] ^ Km[6] ^ M[7] ^ Km[7] ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ M[11] ^ Km[11] ^ 1 ^ Km[7] ^ Km[11] ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1;
//    j[14] = (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ M[6] ^ Kma[6] ^ M[7] ^ Kma[7] ^ 1 ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[4] ^ Kma[4]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ M[6] ^ Kma[6] ^ M[7] ^ Kma[7] ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ M[10] ^ Kma[10] ^ M[11] ^ Kma[11] ^ 1 ^ Kma[7] ^ Kma[11] ^ Kma[15] ^ Kma[0]*Kma[1]*Kma[2] ^ Kma[0] ^ Kma[1]*Kma[2]*Kma[3] ^ Kma[1]*Kma[2] ^ Kma[2]*Kma[3] ^ Kma[2] ^ Kma[3] ^ 1;
//
//    j[13] = (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ M[4] ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ M[5] ^ Km[5] ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ 1 ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ M[6] ^ Km[6] ^ M[7] ^ Km[7] ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ M[8] ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ M[9] ^ Km[9] ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ 1 ^ Km[6] ^ Km[10] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1;
//    j[12] = (M[4] ^ Kma[4])*(M[5] ^ Kma[5]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[4] ^ Kma[4])*(M[7] ^ Kma[7]) ^ M[4] ^ Kma[4] ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ M[5] ^ Kma[5] ^ (M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ 1 ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ M[6] ^ Kma[6] ^ M[7] ^ Kma[7] ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[8] ^ Kma[8])*(M[11] ^ Kma[11]) ^ M[8] ^ Kma[8] ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ (M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ M[9] ^ Kma[9] ^ (M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ 1 ^ Kma[6] ^ Kma[10] ^ Kma[14] ^ Kma[0]*Kma[1]*Kma[3] ^ Kma[0]*Kma[1] ^ Kma[0]*Kma[2] ^ Kma[1]*Kma[3] ^ Kma[2] ^ Kma[3] ^ 1;
//
//    j[11] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ M[5] ^ Km[5] ^ M[7] ^ Km[7] ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ M[4] ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ M[6] ^ Km[6] ^ M[7] ^ Km[7] ^ 1 ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ M[4] ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ M[5] ^ Km[5] ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ M[9] ^ Km[9] ^ M[11] ^ Km[11] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ M[8] ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ M[11] ^ Km[11] ^ 1 ^ Km[5] ^ Km[9] ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1;
//    j[10] = (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[4] ^ Kma[4])*(M[7] ^ Kma[7]) ^ M[5] ^ Kma[5] ^ M[7] ^ Kma[7] ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ M[4] ^ Kma[4] ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ M[6] ^ Kma[6] ^ M[7] ^ Kma[7] ^ 1 ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[4] ^ Kma[4])*(M[7] ^ Kma[7]) ^ M[4] ^ Kma[4] ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ M[5] ^ Kma[5] ^ (M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[8] ^ Kma[8])*(M[11] ^ Kma[11]) ^ M[9] ^ Kma[9] ^ M[11] ^ Kma[11] ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ M[8] ^ Kma[8] ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ (M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ M[10] ^ Kma[10] ^ M[11] ^ Kma[11] ^ 1 ^ Kma[5] ^ Kma[9] ^ Kma[13] ^ Kma[0]*Kma[1] ^ Kma[0]*Kma[2]*Kma[3] ^ Kma[0]*Kma[2] ^ Kma[0]*Kma[3] ^ Kma[0] ^ Kma[1]*Kma[2]*Kma[3] ^ Kma[1]*Kma[2] ^ Kma[1]*Kma[3] ^ Kma[1] ^ Kma[2]*Kma[3] ^ 1;
//
//    j[9] = 0 ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ M[4] ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ M[6] ^ Km[6] ^ M[7] ^ Km[7] ^ 1 ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ M[5] ^ Km[5] ^ M[7] ^ Km[7] ^ 0 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ M[8] ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ M[11] ^ Km[11] ^ 1 ^ Km[4] ^ Km[8] ^ Km[12] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3] ^ 1;
//    j[8] = 0 ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ M[4] ^ Kma[4] ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ M[6] ^ Kma[6] ^ M[7] ^ Kma[7] ^ 1 ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[4] ^ Kma[4])*(M[7] ^ Kma[7]) ^ M[5] ^ Kma[5] ^ M[7] ^ Kma[7] ^ 0 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ M[8] ^ Kma[8] ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ (M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ M[10] ^ Kma[10] ^ M[11] ^ Kma[11] ^ 1 ^ Kma[4] ^ Kma[8] ^ Kma[12] ^ Kma[0]*Kma[1]*Kma[3] ^ Kma[0]*Kma[2] ^ Kma[0]*Kma[3] ^ Kma[1] ^ Kma[3] ^ 1;
//
//    j[7] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ M[6] ^ Km[6] ^ M[7] ^ Km[7] ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ M[11] ^ Km[11] ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ M[8] ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ M[11] ^ Km[11] ^ 1 ^ Km[3] ^ Km[7] ^ Km[11] ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3] ^ 1;
//    j[6] = (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ M[6] ^ Kma[6] ^ M[7] ^ Kma[7] ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ M[10] ^ Kma[10] ^ M[11] ^ Kma[11] ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ M[8] ^ Kma[8] ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ (M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ M[10] ^ Kma[10] ^ M[11] ^ Kma[11] ^ 1 ^ Kma[3] ^ Kma[7] ^ Kma[11] ^ Kma[15] ^ Kma[0]*Kma[1]*Kma[2] ^ Kma[0] ^ Kma[1]*Kma[2]*Kma[3] ^ Kma[1]*Kma[2] ^ Kma[2]*Kma[3] ^ Kma[2] ^ Kma[3] ^ 1;
//
//    j[5] = (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ M[4] ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ M[5] ^ Km[5] ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ M[8] ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ M[9] ^ Km[9] ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ M[11] ^ Km[11] ^ 1 ^ Km[2] ^ Km[6] ^ Km[10] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3] ^ 1;
//    j[4] = (M[4] ^ Kma[4])*(M[5] ^ Kma[5]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[4] ^ Kma[4])*(M[7] ^ Kma[7]) ^ M[4] ^ Kma[4] ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ M[5] ^ Kma[5] ^ (M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[8] ^ Kma[8])*(M[11] ^ Kma[11]) ^ M[8] ^ Kma[8] ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ (M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ M[9] ^ Kma[9] ^ (M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ M[10] ^ Kma[10] ^ M[11] ^ Kma[11] ^ 1 ^ Kma[2] ^ Kma[6] ^ Kma[10] ^ Kma[14] ^ Kma[0]*Kma[1]*Kma[3] ^ Kma[0]*Kma[1] ^ Kma[0]*Kma[2] ^ Kma[1]*Kma[3] ^ Kma[2] ^ Kma[3] ^ 1;
//
//    j[3] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ M[5] ^ Km[5] ^ M[7] ^ Km[7] ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ M[4] ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ M[6] ^ Km[6] ^ M[7] ^ Km[7] ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ M[9] ^ Km[9] ^ M[11] ^ Km[11] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ M[8] ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ M[11] ^ Km[11] ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ M[8] ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ M[9] ^ Km[9] ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ 1 ^ Km[1] ^ Km[5] ^ Km[9] ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3] ^ 1;
//    j[2] = (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[7] ^ Kma[7]) ^ (M[4] ^ Kma[4])*(M[6] ^ Kma[6]) ^ (M[4] ^ Kma[4])*(M[7] ^ Kma[7]) ^ M[5] ^ Kma[5] ^ M[7] ^ Kma[7] ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ M[4] ^ Kma[4] ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ M[6] ^ Kma[6] ^ M[7] ^ Kma[7] ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[8] ^ Kma[8])*(M[11] ^ Kma[11]) ^ M[9] ^ Kma[9] ^ M[11] ^ Kma[11] ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ M[8] ^ Kma[8] ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ (M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ M[10] ^ Kma[10] ^ M[11] ^ Kma[11] ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[8] ^ Kma[8])*(M[11] ^ Kma[11]) ^ M[8] ^ Kma[8] ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ (M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ M[9] ^ Kma[9] ^ (M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ 1 ^ Kma[1] ^ Kma[5] ^ Kma[9] ^ Kma[13] ^ Kma[0]*Kma[1] ^ Kma[0]*Kma[2]*Kma[3] ^ Kma[0]*Kma[2] ^ Kma[0]*Kma[3] ^ Kma[0] ^ Kma[1]*Kma[2]*Kma[3] ^ Kma[1]*Kma[2] ^ Kma[1]*Kma[3] ^ Kma[1] ^ Kma[2]*Kma[3] ^ 1;
//
//    j[1] = 0 ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ M[4] ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ M[6] ^ Km[6] ^ M[7] ^ Km[7] ^ 1 ^ 0 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ M[8] ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ M[11] ^ Km[11] ^ 1 ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ M[9] ^ Km[9] ^ M[11] ^ Km[11] ^ Km[0] ^ Km[4] ^ Km[8] ^ Km[12] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3] ^ 1;
//    j[0] = 0 ^ (M[4] ^ Kma[4])*(M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ M[4] ^ Kma[4] ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ (M[5] ^ Kma[5])*(M[6] ^ Kma[6]) ^ (M[6] ^ Kma[6])*(M[7] ^ Kma[7]) ^ M[6] ^ Kma[6] ^ M[7] ^ Kma[7] ^ 1 ^ 0 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ M[8] ^ Kma[8] ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ (M[9] ^ Kma[9])*(M[10] ^ Kma[10]) ^ (M[10] ^ Kma[10])*(M[11] ^ Kma[11]) ^ M[10] ^ Kma[10] ^ M[11] ^ Kma[11] ^ 1 ^ (M[8] ^ Kma[8])*(M[9] ^ Kma[9])*(M[11] ^ Kma[11]) ^ (M[8] ^ Kma[8])*(M[10] ^ Kma[10]) ^ (M[8] ^ Kma[8])*(M[11] ^ Kma[11]) ^ M[9] ^ Kma[9] ^ M[11] ^ Kma[11] ^ Kma[0] ^ Kma[4] ^ Kma[8] ^ Kma[12] ^ Kma[0]*Kma[1]*Kma[3] ^ Kma[0]*Kma[2] ^ Kma[0]*Kma[3] ^ Kma[1] ^ Kma[3] ^ 1;
//    
    
    //CROSS OUT SAME PLAINTEXT IN BOTH EQ
    
    j[31] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3];
j[30] = (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[13]) ^ (M[12])*(M[14]) ^ (M[13])*(M[15]) ^ (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[1]) ^ (M[0])*(M[2]) ^ (M[1])*(M[3]);

j[29] = (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ Km[13] ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[14] ^ Km[14]) ^ Km[15] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3];
j[28] = (M[12])*(M[13]) ^ (M[12])*(M[14])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[13])*(M[15]) ^ (M[14])*(M[15]) ^ (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[13]) ^ (M[12])*(M[14]) ^ (M[13])*(M[15]) ^ M[14] ^ (M[0])*(M[1]) ^ (M[0])*(M[2])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[1])*(M[3]) ^ (M[2])*(M[3]);

j[27] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ Km[14] ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[2] ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[2]*Km[3];
j[26] = (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[12])*(M[13]) ^ (M[12])*(M[14])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[13])*(M[15]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]);

j[25] =(M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ Km[14] ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ Km[13] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[2] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1];
j[24]= (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]);

j[23] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ Km[14] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[11] ^ Km[0]*Km[1]*Km[2] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3];
j[22] = (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[13]) ^ (M[12])*(M[14]) ^ (M[13])*(M[15]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[1]) ^ (M[0])*(M[2]) ^ (M[1])*(M[3]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]);

j[21] = (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ Km[13] ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[10] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3];
j[20] = (M[12])*(M[13]) ^ (M[12])*(M[14])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[13])*(M[15]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1]) ^ (M[0])*(M[2])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ M[0] ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[1])*(M[3]) ^ (M[2])*(M[3]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[1]) ^ (M[0])*(M[2]) ^ (M[1])*(M[3]);

j[19] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ Km[14] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[2] ^ Km[3] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[9] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[2]*Km[3];
j[18] = (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]) ^ M[3] ^ (M[0])*(M[1]) ^ (M[0])*(M[2])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ M[0] ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[1])*(M[3]) ^ (M[2])*(M[3]);

j[17] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ Km[14] ^ Km[15] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[2] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ Km[3] ^ Km[8] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3];
j[16] = (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]);

j[15] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[7] ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3];
j[14] = (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[5]) ^ (M[4])*(M[6]) ^ (M[5])*(M[7]) ^ (M[4])*(M[5])*(M[6]) ^ M[4] ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10]) ^ (M[9])*(M[11]);

j[13] = (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ Km[5] ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ Km[7] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ Km[9] ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3];
j[12] = (M[4])*(M[5]) ^ (M[4])*(M[6])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[5])*(M[7]) ^ (M[6])*(M[7]) ^ (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[5]) ^ (M[4])*(M[6]) ^ (M[5])*(M[7]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[9])*(M[11]) ^ (M[10])*(M[11]);

j[11] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ Km[6] ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[5] ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3];
j[10] = (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[4])*(M[5])*(M[6]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[4])*(M[5]) ^ (M[4])*(M[6])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[5])*(M[7]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]);

j[9] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ Km[6] ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ Km[5] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[11] ^ Km[12] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3];
j[8] = (M[4])*(M[5])*(M[6]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]);

j[7] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ Km[6] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[11] ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2];
j[6] = (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[5]) ^ (M[4])*(M[6]) ^ (M[5])*(M[7]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10]) ^ (M[9])*(M[11]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]);

j[5] = (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ Km[5] ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11])^ Km[9] ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ Km[11] ^ Km[6] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[3];
j[4] = (M[4])*(M[5]) ^ (M[4])*(M[6])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[5])*(M[7]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[9])*(M[11]) ^ (M[10])*(M[11]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10]) ^ (M[9])*(M[11]);

j[3] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ Km[6] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[9] ^ Km[11] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[11] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[2]*Km[3];
j[2] = (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[4])*(M[5])*(M[6]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[9])*(M[11]) ^ (M[10])*(M[11]);

j[1] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ Km[6] ^ Km[7] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[9] ^ Km[0] ^ Km[4] ^ Km[12] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3];
j[0] = (M[4])*(M[5])*(M[6]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]) ^ M[10] ^ M[11] ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ M[11];
 
    
//    j[31] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3];
//    j[30] = (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[13]) ^ (M[12])*(M[14]) ^ (M[13])*(M[15]) ^ (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[1]) ^ (M[0])*(M[2]) ^ (M[1])*(M[3]);
//
//    j[29] = (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ Km[13] ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[14] ^ Km[14]) ^ Km[15] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3];
//    j[28] = (M[12])*(M[13]) ^ (M[12])*(M[14])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[13])*(M[15]) ^ (M[14])*(M[15]) ^ (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[13]) ^ (M[12])*(M[14]) ^ (M[13])*(M[15]) ^ M[14] ^ (M[0])*(M[1]) ^ (M[0])*(M[2])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[1])*(M[3]) ^ (M[2])*(M[3]);
//
//    j[27] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ Km[14] ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[2] ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[2]*Km[3];
//    j[26] = (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[12])*(M[13]) ^ (M[12])*(M[14])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[13])*(M[15]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]);
//
//    j[25] =(M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ Km[14] ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ Km[13] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[2] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1];
//    j[24]= (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]);
//
//    j[23] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ Km[14] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[11] ^ Km[0]*Km[1]*Km[2] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3];
//    j[22] = (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[13]) ^ (M[12])*(M[14]) ^ (M[13])*(M[15]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[1]) ^ (M[0])*(M[2]) ^ (M[1])*(M[3]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]);
//
//    j[21] = (M[12] ^ Km[12])*(M[13] ^ Km[13]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ Km[13] ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[10] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3];
//    j[20] = (M[12])*(M[13]) ^ (M[12])*(M[14])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[13])*(M[15]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1]) ^ (M[0])*(M[2])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ M[0] ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[1])*(M[3]) ^ (M[2])*(M[3]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[1]) ^ (M[0])*(M[2]) ^ (M[1])*(M[3]);
//
//    j[19] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[14] ^ Km[14]) ^ (M[12] ^ Km[12])*(M[15] ^ Km[15]) ^ (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ Km[12] ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ Km[14] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[2] ^ Km[3] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ Km[1] ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[9] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[2]*Km[3];
//    j[18] = (M[12])*(M[13])*(M[15]) ^ (M[12])*(M[14]) ^ (M[12])*(M[15]) ^ (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]) ^ M[3] ^ (M[0])*(M[1]) ^ (M[0])*(M[2])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]) ^ M[0] ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[1])*(M[3]) ^ (M[2])*(M[3]);
//
//    j[17] = (M[12] ^ Km[12])*(M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ (M[13] ^ Km[13])*(M[14] ^ Km[14]) ^ (M[14] ^ Km[14])*(M[15] ^ Km[15]) ^ Km[14] ^ Km[15] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ Km[0] ^ (M[1] ^ Km[1])*(M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ (M[1] ^ Km[1])*(M[2] ^ Km[2]) ^ (M[2] ^ Km[2])*(M[3] ^ Km[3]) ^ Km[2] ^ (M[0] ^ Km[0])*(M[1] ^ Km[1])*(M[3] ^ Km[3]) ^ (M[0] ^ Km[0])*(M[2] ^ Km[2]) ^ (M[0] ^ Km[0])*(M[3] ^ Km[3]) ^ Km[3] ^ Km[8] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3];
//    j[16] = (M[12])*(M[13])*(M[14]) ^ (M[13])*(M[14])*(M[15]) ^ (M[13])*(M[14]) ^ (M[14])*(M[15]) ^ (M[0])*(M[1])*(M[2]) ^ (M[1])*(M[2])*(M[3]) ^ (M[1])*(M[2]) ^ (M[2])*(M[3]) ^ (M[0])*(M[1])*(M[3]) ^ (M[0])*(M[2]) ^ (M[0])*(M[3]);
//
//    j[15] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[7] ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2] ^ Km[3];
//    j[14] = (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[5]) ^ (M[4])*(M[6]) ^ (M[5])*(M[7]) ^ (M[4])*(M[5])*(M[6]) ^ M[4] ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10]) ^ (M[9])*(M[11]);
//
//    j[13] = (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ Km[5] ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ Km[7] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ Km[9] ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[2] ^ Km[3];
//    j[12] = (M[4])*(M[5]) ^ (M[4])*(M[6])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[5])*(M[7]) ^ (M[6])*(M[7]) ^ (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[5]) ^ (M[4])*(M[6]) ^ (M[5])*(M[7]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[9])*(M[11]) ^ (M[10])*(M[11]);
//
//    j[11] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ Km[6] ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[5] ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[1] ^ Km[2]*Km[3];
//    j[10] = (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[4])*(M[5])*(M[6]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[4])*(M[5]) ^ (M[4])*(M[6])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[5])*(M[7]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]);
//
//    j[9] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ Km[6] ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ Km[5] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[11] ^ Km[12] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3];
//    j[8] = (M[4])*(M[5])*(M[6]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]);
//
//    j[7] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ Km[6] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[11] ^ Km[15] ^ Km[0]*Km[1]*Km[2] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[2]*Km[3] ^ Km[2];
//    j[6] = (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[5]) ^ (M[4])*(M[6]) ^ (M[5])*(M[7]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10]) ^ (M[9])*(M[11]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]);
//
//    j[5] = (M[4] ^ Km[4])*(M[5] ^ Km[5]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ Km[5] ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11])^ Km[9] ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ Km[11] ^ Km[6] ^ Km[14] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[1] ^ Km[0]*Km[2] ^ Km[1]*Km[3] ^ Km[3];
//    j[4] = (M[4])*(M[5]) ^ (M[4])*(M[6])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[5])*(M[7]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[9])*(M[11]) ^ (M[10])*(M[11]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10]) ^ (M[9])*(M[11]);
//
//    j[3] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[6] ^ Km[6]) ^ (M[4] ^ Km[4])*(M[7] ^ Km[7]) ^ (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ Km[6] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[9] ^ Km[11] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[10] ^ Km[11] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[8] ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ Km[13] ^ Km[0]*Km[1] ^ Km[0]*Km[2]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[0] ^ Km[1]*Km[2]*Km[3] ^ Km[1]*Km[2] ^ Km[1]*Km[3] ^ Km[2]*Km[3];
//    j[2] = (M[4])*(M[5])*(M[7]) ^ (M[4])*(M[6]) ^ (M[4])*(M[7]) ^ (M[4])*(M[5])*(M[6]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]) ^ (M[8])*(M[9]) ^ (M[8])*(M[10])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[9])*(M[11]) ^ (M[10])*(M[11]);
//
//    j[1] = (M[4] ^ Km[4])*(M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ Km[4] ^ (M[5] ^ Km[5])*(M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ (M[5] ^ Km[5])*(M[6] ^ Km[6]) ^ (M[6] ^ Km[6])*(M[7] ^ Km[7]) ^ Km[6] ^ Km[7] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ (M[9] ^ Km[9])*(M[10] ^ Km[10]) ^ (M[10] ^ Km[10])*(M[11] ^ Km[11]) ^ M[10] ^ Km[10] ^ (M[8] ^ Km[8])*(M[9] ^ Km[9])*(M[11] ^ Km[11]) ^ (M[8] ^ Km[8])*(M[10] ^ Km[10]) ^ (M[8] ^ Km[8])*(M[11] ^ Km[11]) ^ Km[9] ^ Km[0] ^ Km[4] ^ Km[12] ^ Km[0]*Km[1]*Km[3] ^ Km[0]*Km[2] ^ Km[0]*Km[3] ^ Km[1] ^ Km[3];
//    j[0] = (M[4])*(M[5])*(M[6]) ^ (M[5])*(M[6])*(M[7]) ^ (M[5])*(M[6]) ^ (M[6])*(M[7]) ^ (M[8])*(M[9])*(M[10]) ^ (M[9])*(M[10])*(M[11]) ^ (M[9])*(M[10]) ^ (M[10])*(M[11]) ^ M[10] ^ M[11] ^ (M[8])*(M[9])*(M[11]) ^ (M[8])*(M[10]) ^ (M[8])*(M[11]) ^ M[11];
 

  
    u16 valKm[4];
    u16 valKma[4];

  valKm[0] = ((j[31] * 8) + (j[29] * 4) + (j[27] * 2) + (j[25] * 1));
  valKm[1] = ((j[23] * 8) + (j[21] * 4) + (j[19] * 2) + (j[17] * 1));
  valKm[2] = ((j[15] * 8) + (j[13] * 4) + (j[11] * 2) + (j[9] * 1));
  valKm[3] = ((j[7] * 8) + (j[5] * 4) + (j[3] * 2) + (j[1] * 1));
  
  valKma[0] = ((j[30] * 8) + (j[28] * 4) + (j[26] * 2) + (j[24] * 1));
  valKma[1] = ((j[22] * 8) + (j[20] * 4) + (j[18] * 2) + (j[16] * 1));
  valKma[2] = ((j[14] * 8) + (j[12] * 4) + (j[10] * 2) + (j[8] * 1));
  valKma[3] = ((j[6] * 8) + (j[4] * 4) + (j[2] * 2) + (j[0] * 1));
  
  
  pf("Km: ");
  for (int i = 0; i < 4; i++) {
    pf("%X", valKm[i]);
  }
  pf("\n");
  
  pf("Kma: ");
  for (int i = 0; i < 4; i++) {
    pf("%X", valKma[i]);
  }
  pf("\n");

    
}