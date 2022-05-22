#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

using namespace std;
typedef unsigned char u8;
typedef unsigned int u32;
const size_t CHUNK_SIZE = 64;

string hexStr(array<u8, 32> data) {
    stringstream ss;
    for (size_t i = 0; i < data.size(); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    ss << '\n';
    return ss.str();
}

string hexStr(vector<u8> data) {
    stringstream ss;
    for (size_t i = 0; i < data.size(); i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    ss << '\n';
    return ss.str();
}

template <class T>
T rotr(T n, size_t d) {
    return (n >> d) | (n << (sizeof(T) * 8 - d));
}

struct BufState {
    vector<u8> data;
    size_t len;
    size_t total_len;
    bool single;
    bool total;
};

bool calcChunk(array<u8, CHUNK_SIZE> &chunk, BufState &state) {
    if (state.total) {
        return false;
    }

    if (state.len >= CHUNK_SIZE) {
        for (size_t i = 0; i < CHUNK_SIZE; i++) {
            chunk[i] = state.data[0];
            state.data.erase(state.data.begin());
        }
        state.len -= CHUNK_SIZE;
        return true;
    }

    size_t remaining = state.data.size();
    size_t space = CHUNK_SIZE - remaining;
    size_t available = remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE;
    for (size_t i = 0; i < available; i++) {
        chunk[i] = state.data[0];
        state.data.erase(state.data.begin());
    }

    if (!state.single) {
        chunk[remaining] = 0x80;
        state.single = true;
    }

    if (space >= 8) {
        size_t len = state.total_len;
        chunk[CHUNK_SIZE - 1] = (u8)(len << 3);
        len >>= 5;
        for (size_t i = 1; i < 8; i++) {
            chunk[CHUNK_SIZE - 1 - i] = (u8)len;
            len >>= 8;
        }
        state.total = true;
    }

    return true;
}

array<u8, 32> sha256(vector<u8> data) {
    array<u32, 8> h = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    };
    array<u32, 64> k = {
        0x428a2f98,
        0x71374491,
        0xb5c0fbcf,
        0xe9b5dba5,
        0x3956c25b,
        0x59f111f1,
        0x923f82a4,
        0xab1c5ed5,
        0xd807aa98,
        0x12835b01,
        0x243185be,
        0x550c7dc3,
        0x72be5d74,
        0x80deb1fe,
        0x9bdc06a7,
        0xc19bf174,
        0xe49b69c1,
        0xefbe4786,
        0x0fc19dc6,
        0x240ca1cc,
        0x2de92c6f,
        0x4a7484aa,
        0x5cb0a9dc,
        0x76f988da,
        0x983e5152,
        0xa831c66d,
        0xb00327c8,
        0xbf597fc7,
        0xc6e00bf3,
        0xd5a79147,
        0x06ca6351,
        0x14292967,
        0x27b70a85,
        0x2e1b2138,
        0x4d2c6dfc,
        0x53380d13,
        0x650a7354,
        0x766a0abb,
        0x81c2c92e,
        0x92722c85,
        0xa2bfe8a1,
        0xa81a664b,
        0xc24b8b70,
        0xc76c51a3,
        0xd192e819,
        0xd6990624,
        0xf40e3585,
        0x106aa070,
        0x19a4c116,
        0x1e376c08,
        0x2748774c,
        0x34b0bcb5,
        0x391c0cb3,
        0x4ed8aa4a,
        0x5b9cca4f,
        0x682e6ff3,
        0x748f82ee,
        0x78a5636f,
        0x84c87814,
        0x8cc70208,
        0x90befffa,
        0xa4506ceb,
        0xbef9a3f7,
        0xc67178f2,
    };

    array<u8, 32> hash = {0};
    array<u8, 64> chunk = {0};

    BufState state;
    state.data = data;
    state.len = data.size();
    state.total_len = data.size();
    state.single = false;
    state.total = false;

    while (calcChunk(chunk, state)) {
        array<u32, 8> ah = h;
        array<u32, 16> w = {0};
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 16; j++) {
                if (i == 0) {
                    w[j] = ((u32)chunk[j * 4] << 24) | ((u32)chunk[j * 4 + 1] << 16) | ((u32)chunk[j * 4 + 2] << 8) | (u32)chunk[j * 4 + 3];
                } else {
                    u32 s0 = rotr(w[(j + 1) & 0xf], 7) ^ rotr(w[(j + 1) & 0xf], 18) ^ (w[(j + 1) & 0xf] >> 3);
                    u32 s1 = rotr(w[(j + 14) & 0xf], 17) ^ rotr(w[(j + 14) & 0xf], 19) ^ (w[(j + 14) & 0xf] >> 10);
                    w[j] = w[j] + s0 + w[(j + 9) & 0xf] + s1;
                }

                u32 s1 = rotr(ah[4], 6) ^ rotr(ah[4], 11) ^ rotr(ah[4], 25);
                u32 ch = (ah[4] & ah[5]) ^ ((~ah[4]) & ah[6]);
                u32 temp1 = ah[7] + s1 + ch + k[i << 4 | j] + w[j];
                u32 s0 = rotr(ah[0], 2) ^ rotr(ah[0], 13) ^ rotr(ah[0], 22);
                u32 maj = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
                u32 temp2 = s0 + maj;

                ah[7] = ah[6];
                ah[6] = ah[5];
                ah[5] = ah[4];
                ah[4] = ah[3] + temp1;
                ah[3] = ah[2];
                ah[2] = ah[1];
                ah[1] = ah[0];
                ah[0] = temp1 + temp2;
            }
        }

        for (size_t i = 0; i < 8; i++) {
            h[i] = h[i] + ah[i];
        }
        chunk = {0};
    }

    for (size_t i = 0; i < 8; i++) {
        hash[i * 4] = (u8)(h[i] >> 24);
        hash[i * 4 + 1] = (u8)(h[i] >> 16);
        hash[i * 4 + 2] = (u8)(h[i] >> 8);
        hash[i * 4 + 3] = (u8)h[i];
    }

    return hash;
}

bool testSHA256() {
    array<u8, 32> hash1 = sha256(vector<u8>());
    array<u8, 32> expected1 = array<u8, 32>{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
        0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
        0x78, 0x52, 0xb8, 0x55};

    string input2("The quick brown fox jumps over the lazy dog");
    array<u8, 32> hash2 = sha256(vector<u8>(input2.begin(), input2.end()));
    array<u8, 32> expected2 = array<u8, 32>{
        0xD7, 0xA8, 0xFB, 0xB3, 0x07, 0xD7, 0x80, 0x94, 0x69, 0xCA, 0x9A, 0xBC, 0xB0, 0x08,
        0x2E, 0x4F, 0x8D, 0x56, 0x51, 0xE4, 0x6D, 0x3C, 0xDB, 0x76, 0x2D, 0x02, 0xD0, 0xBF,
        0x37, 0xC9, 0xE5, 0x92};

    string input3("The quick brown fox jumps over the lazy dog.");
    array<u8, 32> hash3 = sha256(vector<u8>(input3.begin(), input3.end()));
    array<u8, 32> expected3 = array<u8, 32>{
        0xEF, 0x53, 0x7F, 0x25, 0xC8, 0x95, 0xBF, 0xA7, 0x82, 0x52, 0x65, 0x29, 0xA9, 0xB6,
        0x3D, 0x97, 0xAA, 0x63, 0x15, 0x64, 0xD5, 0xD7, 0x89, 0xC2, 0xB7, 0x65, 0x44, 0x8C,
        0x86, 0x35, 0xFB, 0x6C};

    for (size_t i = 0; i < hash1.size(); i++) {
        if (hash1[i] != expected1[i] ||
            hash2[i] != expected2[i] ||
            hash3[i] != expected3[i])
                return false;
        }
    return true;
}

int main() {
    string input("Hello world");
    vector<u8> data(input.begin(), input.end());
    array<u8, 32> hash = sha256(data);

    cout << "Input = " << input << '\n';
    cout << "Hash = " << hexStr(hash) << '\n';
    cout << std::boolalpha << "Tests passed: " << testSHA256() << '\n';
}