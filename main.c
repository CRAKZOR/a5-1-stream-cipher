#include <stdio.h>
#include <stdlib.h>

typedef enum bit {
    zero = 0,
    one  = 1
} bit;

typedef struct A51 {
    bit  x[19];
    bit  y[22];
    bit  z[23];
} A51;


A51 * newA51(bit key[64], int debug_mode)
{
    A51 * stream = calloc(1, sizeof(A51));

    for(int index = 0; index < 23; index ++){
        if(index < 19){
            stream->x[index] = key[index];
        }
        if(index < 22){
            stream->y[index] = key[index + 19];
        }
        stream->z[index] = key[index + 41];
    } 

    if(debug_mode){
        printf("X-> "); 
        for(int i = 0; i < 19; i++){
            printf("%d", stream->x[i]); 
        }
        printf(" <-\n");

        printf("Y-> "); 
        for(int i = 0; i < 19; i++){
            printf("%d", stream->y[i]); 
        }
        printf(" <-\n");
        printf("Z-> "); 
        for(int i = 0; i < 19; i++){
            printf("%d", stream->z[i]); 
        }
        printf(" <-\n");
    }
    

    return  stream;
}

int cmp_A51_arr_to_key_arr_debug(A51 * stream, bit key[64])
{
    for(int i = 0; i < 19; i++){
        if(stream->x[i] != key[i]){
            printf("err in x arr at stream->x[%d] = %d != %d\n", i, stream->y[i], key[i + 41]);
            return 0;
        }
    }
    for(int i = 0; i < 22; i++){
        if(stream->y[i] != key[i + 19]){
            printf("err in y arr at stream->y[%d] = %d != %d\n", i, stream->y[i], key[i + 41]);
            return 0;
        }
    }
    for(int i = 0; i < 23; i++){
        if(stream->z[i] != key[i + 41]){
            printf("err in z arr at stream->z[%d] (%d != %d)\n", i, stream->z[i], key[i + 41]);
            return 0;
        }
    }
    return 1;
}



bit * decimal_to_64_bit(int decimal)
{

    bit * testing = (bit*)calloc(64, sizeof(one));
    long start_bit = 1;

    for(int index = 63; index >= 0; index--){
        if( (decimal / (start_bit << (index))) != 0 ){
            testing[index] = one;
            decimal -= start_bit << (index);
        }
        else{
            testing[index] = zero;
        }
    }

    return testing;
}


void dump_64_bit_array_big_endian(bit * array)
{
    for(int index = 63; index > 0; index--){
        printf("%d, ", array[index]);
    }
    printf("%d\n", array[0]);
}


void dump_64_bit_array_little_endian(bit * array)
{
    for(int index = 0; index < 64; index++){
        printf("%d, ", array[index]);
    }
    printf("%d\n", array[64]);
}

void dump_A51(A51 * stream)
{
    printf("\n");
    for(int i = 0; i < 19; i++){
        printf("%d", stream->x[i]);

    }
    for(int i = 0; i < 22; i++){
        printf("%d", stream->y[i]);
    }
    for(int i = 0; i < 22; i++){
        printf("%d", stream->z[i]);
    }
    printf("\n");
}

int main () {
    /*************************************************************************************************
    * 
    *   A5/1 stream cipher
    *       Initialization:
    *           input: 64-bit key, and 22-bit frame number
    *       Three Linear Feedbac Shift Registers
    *        LFSR_#[REGISTER_SIZE], Clocking Bit: [BIT_POSITION]
    *            LFSR_1[19], Clocking Bit: 8
    *            LFSR_2[22], Clocking Bit: 10
    *            LFSR_3[23], Clocking Bit: 10
    * 
    *        Process:
    *            Run 100 cycles without producing output
    *        Operation:
    *            - Post initialization, the cipher generates the key stream by clocking the LFSR's.
    *            - The clocking of each LFSR is controlled by the majority of the three clocking bits.
    *            - THe output bit is generated by XOR the outputs of the three LFSR's.
    * 
    *************************************************************************************************/

    int message = 80085;

    bit * message_bits = decimal_to_64_bit(message);

    dump_64_bit_array_little_endian(message_bits);

    A51 * cipher = newA51(message_bits, 1);


    dump_A51(cipher);

    if(!cmp_A51_arr_to_key_arr_debug(cipher, message_bits)){
        printf("SOMTHING WENT REALLY FUCKING BAD\n");
    }

    free(message_bits);

    return 0;
}

