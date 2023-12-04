/*************************************************************************************************
* 
*   A5/1 stream cipher
*       Initialization:
*           input: 64-bit key, and 22-bit frame number
*       Three Linear Feedbac Shift Registers
*        LFSR_#[REGISTER_SIZE], Clocking Bit: [BIT_POSITION], Tapping Bits: [TAPPING_BIT_POSITION]
*            LFSR_1[19], Clocking Bit: 8,  Tapping Bits: 18, 17, 16, 13
*            LFSR_2[22], Clocking Bit: 10, Tapping Bits: 21, 20
*            LFSR_3[23], Clocking Bit: 10, Tapping Bits: 22, 21, 20, 7
*
*        Output
* 
*        Process:
*           All bits are 0, the key setup and IV setup are performed.
*           All three registers are clocked and they key bits followed by the IV bits are XOR'd
*               with all the MSB of all 3 registers. The initialization phase takes 64+22 = 86
*               clock cycles to get S_i.
*
*        Operation:
*            - Post initialization, the cipher generates the key stream by clocking the LFSR's.
*            - The clocking of each LFSR is controlled by the majority of the three clocking bits.
*            - THe output bit is generated by XOR the outputs of the three LFSR's.
* 
*************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KEY_SIZE   64
#define FRAME_SIZE 22

// register size
#define REG_1_SIZE 19
#define REG_2_SIZE 22
#define REG_3_SIZE 23

// Note MSB is 0 idx
// clocking bit
#define REG_1_CB 10
#define REG_2_CB 11
#define REG_3_CB 12

// tapping bit size
#define REG_1_TB_SIZE 4
#define REG_2_TB_SIZE 2
#define REG_3_TB_SIZE 4

// tapping bits
const int REG_1_TB[REG_1_TB_SIZE] = { 0, 1, 2, 5 };
const int REG_2_TB[REG_2_TB_SIZE] = { 0, 1 };
const int REG_3_TB[REG_3_TB_SIZE] = { 0, 1, 2, 15 };


typedef enum bit {
    zero,
    one
} bit;


typedef struct a51 {
    bit *reg_1;
    bit *reg_2;
    bit *reg_3;
} a51;

bit maj (bit i, bit j, bit k) {
    return (i+j+k) >= 2;
}

void printRegisters( a51 alg );

bit leftShift ( bit **reg_cpy, int shift_amt, int size, const int tb[], const int tb_size ) {
    // returns: the carry/pushed off bit
    bit *reg  = *reg_cpy;
    bit carry = reg[0];

    for (int count=0; count<shift_amt; count++) {
        
        // XOR corresp tapping bits to determine new LSB 
        
        bit new_lsb = reg[tb[0]];
        for( int i=1; i<tb_size; i++) {
            int tap_idx = tb[i];
            new_lsb ^= reg[tap_idx];
        } 

        for (int i=0; i<size-1; i++) {
            reg[i]=reg[i+1]; 
        }

        reg[size-1] = new_lsb;
    }

    return carry;
}

bit *genKey (int size) {
    bit* key = calloc( size, sizeof(bit));

    // seed random number generator w/ curr time
    srand(time(NULL));

    // rand() returns num in range [0, 32767]
    for ( int i=0; i<size; i++) {
        int rand_bit = rand() % 2;
        key[i] = rand_bit;
    }

    return key;

}

void printBits( bit *bits, const char* name, int size ) {
    printf("%s:\n[", name);
    for (int i=0; i<size; i++) {
        printf("%d", bits[i]);
        if (i != size-1) {
            printf(" ");
        }
    }
    printf("];\n");
}

void loadRegisters ( bit data[], int data_size, a51 *alg_cpy) {
    a51 alg    = *alg_cpy;
    bit* reg_1 = alg.reg_1;
    bit* reg_2 = alg.reg_2;
    bit* reg_3 = alg.reg_3;
    
    // input key to each register
    for (int i=0; i<data_size; i++) {
        // bitwise XOR (^)
        leftShift(&reg_1, 1, REG_1_SIZE, REG_1_TB, REG_1_TB_SIZE);
        leftShift(&reg_2, 1, REG_2_SIZE, REG_2_TB, REG_2_TB_SIZE);
        leftShift(&reg_3, 1, REG_3_SIZE, REG_3_TB, REG_3_TB_SIZE);

        // the LSB is already the result of XORing the tapping bits
        reg_1[REG_1_SIZE-1] ^= data[i];
        reg_2[REG_2_SIZE-1] ^= data[i];
        reg_3[REG_3_SIZE-1] ^= data[i];

        // if ( (i<4) | !((i+1)%4) ) {
        //     printf("\nRUN #%d \n", i+1);
        //     printRegisters(alg); 
        // }
    } 
}

void printRegisters( a51 alg ) {
    printBits(alg.reg_1, "Register 1", REG_1_SIZE);
    printBits(alg.reg_2, "Register 2", REG_2_SIZE);
    printBits(alg.reg_3, "Register 3", REG_3_SIZE);
}

bit run ( a51 *alg_cpy ) {
    a51 alg = *alg_cpy;
    bit* reg_1 = alg.reg_1;
    bit* reg_2 = alg.reg_2;
    bit* reg_3 = alg.reg_3;

    bit maj_bit =   maj ( 
                        reg_1[ REG_1_CB ],
                        reg_2[ REG_2_CB ],
                        reg_3[ REG_3_CB ]
                    );

    if ( reg_1[ REG_1_CB ] ==  maj_bit ) leftShift(&reg_1, 1, REG_1_SIZE, REG_1_TB, REG_1_TB_SIZE);
    if ( reg_2[ REG_2_CB ] ==  maj_bit ) leftShift(&reg_2, 1, REG_2_SIZE, REG_2_TB, REG_2_TB_SIZE);
    if ( reg_3[ REG_3_CB ] ==  maj_bit ) leftShift(&reg_3, 1, REG_3_SIZE, REG_3_TB, REG_3_TB_SIZE);


    // XOR the MSB of all 3 registers, outputs KS bit
    return reg_1[0] ^ reg_2[0] ^ reg_3[0];
}

bit *encrypt ( bit *pt, bit *ks, int size ) {
    // for the length of plaintext, xor with key_stream.
    // output : ciphertext stream
 
    bit *ct = calloc(size, sizeof(bit));

    if (ct) {
        for ( int i=0; i<size; i++) {
            /// XOR pt bit with output of alg
            ct[i] = pt[i] ^ ks[i];
        }
    }
    return ct;
}

bit *decrypt ( bit *ct, bit *ks, int size ) {
    // for the length of ciphertext, xor with key_stream.
    // output : message stream
 
    bit *message = calloc(size, sizeof(bit));

    if (ct) {
        for ( int i=0; i<size; i++) {
            /// XOR pt bit with output of alg
            message[i] = ct[i] ^ ks[i];
        }
    }
    return message;
}


// char *toBinStr ( str, size ) {
//     // assume 8bit ascii, +1 for '\0'
//     char *output = malloc((size*8)+1);
//     
//     for ( int i=0; i<size; i++) {
//             
//      
//     }
// 
// } 

int main () {


    // init a51 registers
    a51 alg = {
        calloc( REG_1_SIZE, sizeof(bit )),
        calloc( REG_2_SIZE, sizeof(bit )),
        calloc( REG_3_SIZE, sizeof(bit ))
    };


    bit *key        = genKey(KEY_SIZE);        // 64-bit key
    bit *frame      = genKey(FRAME_SIZE);      // 22-bit frame num

    //    bit key[KEY_SIZE]     = { 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0,
    //        0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0,
    //        0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0,
    //        0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1,
    //        1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0,
    //        1, 1, 1, 0
    //    }; 
    //    bit frame[FRAME_SIZE] = {
    //        1, 1, 0, 0, 1, 0, 1,
    //        1, 0, 1, 0, 0, 0, 1,
    //        1, 1, 0, 0, 0, 1, 0,
    //        0
    //    };

    printBits(key,   "64-bit key (private)",  KEY_SIZE);
    printBits(frame, "22-bit frame (public)", FRAME_SIZE);
    printf("\n__ INITIAL STATE __\n");
    printRegisters(alg);
    
    printf("\n__ 64-BIT KEY LOADED IN REGISTERS STATE __\n");
    loadRegisters(key, KEY_SIZE, &alg);
    printRegisters(alg);

    printf("\n__ 22-BIT FRAME LOADED IN REGISTERS STATE __\n");
    loadRegisters(frame, FRAME_SIZE, &alg);
    printRegisters(alg);

    printf("\n__ POST 100 RUN CYCLE __\n");
    for (int i=0; i<100; i++) {
        run(&alg);
        // if ( (i<5) | !((i+1)%5) ) {
        //     printf("\nRUN #%d \n", i+1);
        //     printRegisters(alg); 
        // }
    }
    printRegisters(alg);

    printf("\n__ READY TO ENCRYPT __\n");
    

    // const char* plaintext = "The Quick Brown Fox Jumps Over The Lazy Dog! :)";
    bit msg[40]  = { 0,1,0,0,1,0,0,0,0,1,0,0,0,1,0,1,0,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0,0,1,0,0,1,1,1,1 }; // HELLO
    int plaintext_size = 40; 
    bit *plaintext = malloc( plaintext_size*sizeof(bit));

    memcpy( plaintext, &msg, sizeof(bit)*plaintext_size );

    // Create the keystream for the length of the plaintext
    bit *key_stream = calloc(plaintext_size, sizeof(bit));      // output used to encrypt msg 
    if (key_stream) {
        for (int i=0; i<plaintext_size; i++) {
            key_stream[i] = run(&alg);
        }
    }

    printf("\n");
    printBits(key_stream, "KEYSTREAM", plaintext_size);
    printBits(plaintext, "INPUT - PLAINTEXT", plaintext_size);

    printf("\n");
    bit *ciphertext = encrypt( plaintext, key_stream, plaintext_size );
    printBits(ciphertext, "OUTPUT ENCRYPT() - CIPHERTEXT", plaintext_size);

    printf("\n");
    bit *message    = decrypt( ciphertext, key_stream, plaintext_size );
    printBits(message, "OUTPUT DECRYPT() - MESSAGE", plaintext_size);

    // clean up
    free(alg.reg_1);
    free(alg.reg_2);
    free(alg.reg_3);
    // free(key);
    //free(frame);
    free(key_stream);
    free(ciphertext);
    free(message);

    return 0;
}

