#include <iostream>
#include <iomanip>

using namespace std;

const int LENGTH = 16; // 128/8
const int ROUND = 10;

uint8_t GF256_add(uint8_t a, uint8_t b){
    return a ^ b;
}

uint8_t GF256_mult_x(uint8_t a){
    uint8_t result = a << 1;
    if(a > 127)
        result ^= 0x1b;

    return result;
}

uint8_t GF256_mult_xtimes(uint8_t a, int time){
    uint8_t result = a;
    
    while(time-- > 0)
        result = GF256_mult_x(result);

    return result;
}

uint8_t GF256_mult(uint8_t a, uint8_t b){
    uint8_t result = (GF256_mult_xtimes(a, 0)*((b >> 0) & 1))^
                    (GF256_mult_xtimes(a, 1)*((b >> 1) & 1))^
                    (GF256_mult_xtimes(a, 2)*((b >> 2) & 1))^
                    (GF256_mult_xtimes(a, 3)*((b >> 3) & 1))^
                    (GF256_mult_xtimes(a, 4)*((b >> 4) & 1))^
                    (GF256_mult_xtimes(a, 5)*((b >> 5) & 1))^
                    (GF256_mult_xtimes(a, 6)*((b >> 6) & 1))^
                    (GF256_mult_xtimes(a, 7)*((b >> 7) & 1));
    return result;
}

uint8_t ginvt[256];
// build table of inverse using generator 0x03 and its inverses 0xf6
void buildinv(){
    uint8_t i = 1, j = 1;
    while(1){
        ginvt[i] = j;
        i = GF256_mult(i, 0x03);
        if(i == j) break;
        j = GF256_mult(j, 0xf6);
        ginvt[j] = i;
    }
    ginvt[0] = 0;
}

uint8_t GF256_inv(uint8_t a){
    return ginvt[a];
}

uint8_t leftShift(uint8_t a, int d){
    return ((a << d) | (a >> (8 - d)));
}

// sBox references: https://en.wikipedia.org/wiki/Rijndael_S-box
uint8_t sBox(uint8_t a){
    uint8_t b = ginvt[a];
    return b ^ leftShift(b, 1) ^ leftShift(b, 2) ^ leftShift(b, 3) ^ leftShift(b, 4) ^ 0x63;
}

void rotSubWord(uint8_t* temp){
    uint8_t tmp = temp[0];
    for(int i = 0; i < 4; i++){
        temp[i] = temp[i+1]; //rotWord
        temp[i] = sBox(temp[i]); //subWord
    }
    temp[3] = tmp;
    temp[3] = sBox(temp[3]);
}

void keyExpansion(uint8_t* key, uint8_t* expanded){
    uint8_t RC[10];
    RC[0] = 0x01;
    for(int i = 1; i < ROUND; i++){
        RC[i] = GF256_mult(0x02,RC[i-1]);
    }
    for(int i = 0; i < LENGTH; i++)
        expanded[i] = key[i];
    
    for(int i = 4; i < 4*(ROUND+1); i++){
        uint8_t temp[4] = {expanded[4*(i-1)], expanded[4*(i-1)+1], expanded[4*(i-1)+2], expanded[4*(i-1)+3]};
        if(i % 4 == 0){
            rotSubWord(temp); //rotWord, subWord
            temp[0] ^= RC[(i/4)-1]; //first byte XOR with rc
        }

        for(int j = 0; j < 4; j++)
            expanded[4*i + j] = expanded[4*(i-4)+j] ^ temp[j];
    }
}

void addRoundKeys(uint8_t* state, uint8_t* roundKeys){
    for(int i = 0; i < LENGTH; i++)
        state[i] ^= roundKeys[i];
}

void subBytes(uint8_t* state){
    for(int i = 0; i < LENGTH; i++)
        state[i] = sBox(state[i]);
}

void shiftRows(uint8_t* state){
    uint8_t result[LENGTH];
    for(int i = 0; i < LENGTH; i+=4){
        result[i] = state[i % 16];
        result[i+1] = state[(i+5) % 16];
        result[i+2] = state[(i+10) % 16];
        result[i+3] = state[(i+15) % 16];
    }

    for(int i = 0; i < LENGTH; i++)
        state[i] = result[i];
}

void mixColumns(uint8_t* state){
    uint8_t result[16];
    for(int i = 0; i < 4; i++){ //4 columns
        // 2*b0 + 3*b1 + 1*b2 + 1*b3
        result[4*i] = GF256_mult(state[4*i],0x02)^GF256_mult(state[4*i+1],0x03)^state[4*i+2]^state[4*i+3]; 
        // 1*b0 + 2*b1 + 3*b2 + 1*b3
        result[4*i+1] = GF256_mult(state[4*i+1],0x02)^GF256_mult(state[4*i+2],0x03)^state[4*i]^state[4*i+3]; 
        // 1*b0 + 1*b1 + 2*b2 + 3*b3
        result[4*i+2] = GF256_mult(state[4*i+2],0x02)^GF256_mult(state[4*i+3],0x03)^state[4*i]^state[4*i+1]; 
        // 3*b0 + 1*b1 + 1*b2 + 2*b3
        result[4*i+3] = GF256_mult(state[4*i+3],0x02)^GF256_mult(state[4*i],0x03)^state[4*i+1]^state[4*i+2]; 
    }

    for(int i = 0; i < LENGTH; i++)
        state[i] = result[i];
}

void AES_Encrypt(uint8_t* message, uint8_t* ciphertext, uint8_t* key){
    uint8_t expanded[LENGTH*(ROUND + 1)];
    keyExpansion(key, expanded);

    for(int i = 0; i < LENGTH; i++)
        ciphertext[i] = message[i];
    addRoundKeys(ciphertext, key);
    

    for(int i = 1; i <= ROUND; i++){
        subBytes(ciphertext);
        shiftRows(ciphertext);
        if(i != ROUND) mixColumns(ciphertext);
        addRoundKeys(ciphertext, expanded + 16*i);
        
        cout << "Round " << std::dec << i << ":" << endl;
        for(int j = 0; j < LENGTH; j++)
            cout << setfill('0') << setw(2) << right << std::hex << +ciphertext[j] << ' ';
        cout << endl;
        cout << endl;
    }
}

int main() {
    string plaintext, key_in;
    
    uint8_t message[LENGTH], key[LENGTH], cipherText[LENGTH];

    cout << "Plaintext: ";
    cin >> plaintext;

    cout << "Key: ";
    cin >> key_in;
    
    for (int i = 0; i < LENGTH; i++){
        message[i] = (plaintext[i*2] >= '0' && plaintext[i*2] <= '9' ? plaintext[i*2] - '0' : toupper(plaintext[i*2]) -'A' + 10) * 16; 
        message[i] += (plaintext[i*2 + 1] >= '0' && plaintext[i*2 + 1] <= '9' ? plaintext[i*2 + 1] - '0' : toupper(plaintext[i*2 + 1]) - 'A' + 10);

        key[i] = (key_in[i*2] >= '0' && key_in[i*2] <= '9' ? key_in[i*2] - '0' : toupper(key_in[i*2]) -'A' + 10) * 16; 
        key[i] += (key_in[i*2 + 1] >= '0' && key_in[i*2 + 1] <= '9' ? key_in[i*2 + 1] - '0' : toupper(key_in[i*2 + 1]) - 'A' + 10);
    }

    buildinv();
    AES_Encrypt(message, cipherText, key);
}