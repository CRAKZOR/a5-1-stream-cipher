#include <stdio.h>
#include <stdlib.h>

typedef enum bit {
    zero = 0,
    one  = 1
} bit;

typedef struct A51 {
    bit  *x;
    bit  *y;
    bit  *z;
} A51;


A51 * newA51(bit key[64], int debug_mode)
{
    A51 * stream = calloc(1, sizeof(A51));
    stream->x = calloc(19, sizeof(one));
    stream->y = calloc(22, sizeof(one));
    stream->z = calloc(23, sizeof(one));

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
        for(int i = 0; i < 22; i++){
            printf("%d", stream->y[i]); 
        }
        printf(" <-\n");
        printf("Z-> "); 
        for(int i = 0; i < 23; i++){
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



bit * decimal_to_64_bit(long decimal)
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

long bit_64_to_decimal(bit* arr)
{   
    long value = 0;

    for(long i = 0; i < 64; i++){
        if(arr[i] == one){
            value += ((long)1) << i;
        }
    }

    return value;
}

void dump_64_bit_array_big_endian(bit * array)
{
    for(int index = 63; index > 0; index--){
        printf("%d, ", array[index]);
    }
    printf("%d\n", array[0]);
}


void dump_bit_array_little_endian(bit * array, int size)
{
    for(int index = 0; index < size - 1; index++){
        printf("%d", array[index]);
    }
    printf("%d\n", array[size - 1]);
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


bit maj(bit x8, bit y10, bit z10)
{
    int one_count = 0;
    int zero_count = 0;

    x8 == one ? one_count++ : zero_count++; 
    y10 == one ? one_count++ : zero_count++; 
    z10 == one ? one_count++ : zero_count++; 

    if(one_count > zero_count){
        return one;
    }
    else{
        return zero;
    }
}


void shift_right_one(bit * arr, int size, int debug)
{
    for(int i = size - 1; i > 0; i--){
        arr[i] = arr[i - 1];
    }

    debug == 1 ? dump_bit_array_little_endian(arr, size) : NULL;
}


void A51_ALGORITHM(A51 ** cipher, bit* message)
{
    for(int step = 0; step < 64; step++){
        bit maj_bit = maj((*cipher)->x[8], (*cipher)->y[10], (*cipher)->z[10]);

        printf("maj_bit = %d, ", maj_bit);
        if(maj_bit == (*cipher)->x[8]){
            bit bit_zero = (*cipher)->x[13] ^ (*cipher)->x[16] ^ (*cipher)->x[17] & (*cipher)->x[18];
            printf("|x shifted x0 = %d|, ", bit_zero);
            shift_right_one((*cipher)->x, 19, 0);
            (*cipher)->x[0] = bit_zero;
        }
        if(maj_bit == (*cipher)->y[10]){
            bit bit_zero = (*cipher)->y[20] ^ (*cipher)->y[21];
            printf("|y shifted y0 = %d|, ", bit_zero);
            shift_right_one((*cipher)->y, 22, 0);
            (*cipher)->y[0] = bit_zero;
        }
        if(maj_bit == (*cipher)->z[10]){
            bit bit_zero = (*cipher)->z[7] ^ (*cipher)->z[20] ^ (*cipher)->z[21] ^ (*cipher)->z[22];
            printf("|z shifted z0 = %d|, ", bit_zero);
            shift_right_one((*cipher)->z, 23, 0);
            (*cipher)->z[0] = bit_zero;
        }

        bit cypher_xor_bit = (*cipher)->x[18] ^ (*cipher)->y[21] ^ (*cipher)->z[22];

        printf("\n");
        dump_bit_array_little_endian((*cipher)->x, 19);
        dump_bit_array_little_endian((*cipher)->y, 22);
        dump_bit_array_little_endian((*cipher)->z, 23);
        printf("%d ^ %d ^ %d = %d\n", 
                (*cipher)->x[18],
                (*cipher)->y[21],
                (*cipher)->z[22],
                cypher_xor_bit
        );

        message[step] ^= cypher_xor_bit;
        printf("\n");
    }

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

    long message = 80085;
    long key = 999989797144909907;

    bit * message_bits = decimal_to_64_bit(message);
    dump_bit_array_little_endian(message_bits, 64);
    printf("bit_64_to_decimal = %ld\n", bit_64_to_decimal(message_bits));


    bit * key_bits = decimal_to_64_bit(key);

    dump_bit_array_little_endian(key_bits, 64);

    A51 * cipher = newA51(key_bits, 1);


    dump_A51(cipher);

    if(!cmp_A51_arr_to_key_arr_debug(cipher, key_bits)){
        printf("SOMTHING WENT REALLY FUCKING BAD\n");
    }

    A51_ALGORITHM(&cipher, message_bits);
    


    bit * key_bits_2 = decimal_to_64_bit(key);
    dump_bit_array_little_endian(key_bits_2, 64);
    A51 * cipher_2 = newA51(key_bits_2, 0);
    A51_ALGORITHM(&cipher_2, message_bits);
    


    printf("bit_64_to_decimal = %ld\n", bit_64_to_decimal(message_bits));
    printf("\n");
    dump_bit_array_little_endian(cipher->x, 19);
    dump_bit_array_little_endian(cipher->y, 22);
    dump_bit_array_little_endian(cipher->z, 23);

    free(cipher);
    free(key_bits);

    return 0;
}

