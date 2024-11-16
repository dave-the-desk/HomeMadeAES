#include <iostream>
#include <string>
#include <iomanip>
#include <vector>
#include <sstream>

using namespace std;
using Matrix = std::vector<std::vector<std::string>>;

// Function declarations
//-------KeyExansion 
vector<string> KeyExpansion(const Matrix& k);

//-------AddRoundKey and helper functions
Matrix AddRoundKey(Matrix key, Matrix state);
string RotWord(string word);
string SubWord(string word);
string XOR(const string &a, const string &b);
Matrix roundKey(const string &key);

//-------ShiftRows and helper functions
Matrix ShiftRows(Matrix input, bool left);
vector<string> circularLeftShiftRow(const vector<string>& row, int shift);
vector<string> circularRightShiftRow(const vector<string>& row, int shift);

//-------SubBytes and helper functions
Matrix SubBytes(Matrix input, bool encrypt);
string InverseSBox(int row, int col);
string SBox(int row, int col);

//-------MixCoumns and helper functions
Matrix MixColumns(const Matrix& state, bool encrypt);
unsigned char gmul(unsigned char a, unsigned char b);

//Misc
Matrix stringToMatrix(string input);
void printMatrix(const std::vector<std::vector<std::string>>& matrix);
int hexCharToDecimal(char hexChar);
Matrix keyBlockMaker(string k);
string MatrixToString(Matrix finale);
string MatrixToStringForDecryption(Matrix finale);




int main() {
    string key = "0123456789abcdeffedcba9876543210";

    vector<string> k = KeyExpansion(keyBlockMaker(key));
    char choice;

    cout << "Encryption or Decryption? (e/d)" << endl;
    cin >> choice;

    if(choice ==  'e'){
        string plaintext = "1123456789abcdeffedcba9876543210";
        Matrix state = stringToMatrix(plaintext);
        cout << "PlainText: " << plaintext << endl;
        cout << "Key: " << key << endl;

        printMatrix(state);

        Matrix starter = AddRoundKey(stringToMatrix(k[0] + k[1] + k[2] + k[3]), state);
        printMatrix(starter);
        
        
        
        for (int i = 1; i < 10; i++) {
            Matrix ken = stringToMatrix(k[(4 * i)] + k[(4 * i) + 1] + k[(4 * i) + 2] + k[(4 * i) + 3]);
            starter = AddRoundKey(ken, MixColumns(ShiftRows(SubBytes(starter, true), true), true));
            printMatrix(starter);
        }
        
        cout << "RESULT: " << endl;
        Matrix finalMatrix = AddRoundKey(stringToMatrix(k[40] + k[41] + k[42] + k[43]), ShiftRows(SubBytes(starter, true), true));
        cout << MatrixToString(finalMatrix) << endl;
    }else if (choice == 'd')
    {
        string ciphertext = "b5be16efe80f32f4fdc03fea2b313c4e";
        Matrix starter = keyBlockMaker(ciphertext);
        cout << "CipherText: " << ciphertext << endl;
        cout << "Key: " << key << endl;
        printMatrix(starter);

            starter = ShiftRows(SubBytes(AddRoundKey(stringToMatrix(k[(4 * 10)] + k[(4 * 10) + 1] + k[(4 * 10) + 2] + k[(4 * 10) + 3]), starter), false), false);

            printMatrix(starter);
        for (int i = 9; i >= 1; i--) {
            Matrix ken = stringToMatrix(k[(4 * i)] + k[(4 * i) + 1] + k[(4 * i) + 2] + k[(4 * i) + 3]);;
            starter = ShiftRows(SubBytes(MixColumns(AddRoundKey(ken, starter), false), false), false);
            printMatrix(starter);
        }


        Matrix finalMatrix = AddRoundKey(stringToMatrix(k[0] + k[1] + k[2] + k[3]), starter);

        cout << "RESULT: " << endl;
        cout << MatrixToStringForDecryption(finalMatrix) << endl;


    }
    

    return 0;
}

string XOR(const string &a, const string &b) {
    string output;
    for (size_t i = 0; i < a.size(); i += 2) {
        int byteA = stoi(a.substr(i, 2), nullptr, 16);
        int byteB = stoi(b.substr(i, 2), nullptr, 16);
        int result = byteA ^ byteB;
        stringstream ss;
        ss << hex << setw(2) << setfill('0') << result;
        output += ss.str();
    }
    return output;
}

string RotWord(string word) {
    uint32_t value = stoul(word, nullptr, 16);
    uint32_t rotatedValue = (value << 8) | (value >> 24);
    stringstream ss;
    ss << hex << setw(8) << setfill('0') << rotatedValue;
    return ss.str().substr(0, 8);
}

string SubWord(string word) {
    string output;
    for (int i = 0; i < 8; i += 2) {
        int row = hexCharToDecimal(word[i]);
        int col = hexCharToDecimal(word[i + 1]);
        output += SBox(row, col);
    }
    return output;
}

Matrix stringToMatrix(string input) {
    Matrix output(4, std::vector<std::string>(4));
    for (int i = 0; i < 16; ++i) {
        int row = i % 4;
        int col = i / 4;
        output[row][col] = input.substr(i * 2, 2);
    }
    return output;
}

void printMatrix(const std::vector<std::vector<std::string>>& matrix) {
    for (const auto& row : matrix) {
        for (const auto& elem : row) {
            cout << elem << " ";
        }
        cout << endl;
    }
    cout << endl;
}

int hexCharToDecimal(char hexChar) {
    if (hexChar >= '0' && hexChar <= '9') return hexChar - '0';
    if (hexChar >= 'A' && hexChar <= 'F') return hexChar - 'A' + 10;
    if (hexChar >= 'a' && hexChar <= 'f') return hexChar - 'a' + 10;
    return -1; // Invalid character
}

// Precomputed round constants
const vector<string> rcon = {
    "01000000", "02000000", "04000000", "08000000", "10000000", 
    "20000000", "40000000", "80000000", "1B000000", "36000000"
};

// Key Expansion Function
vector<string> KeyExpansion(const Matrix& k) {
    vector<string> words(44);
    for (int i = 0; i < 4; i++) {
        string row;
        for (int j = 0; j < 4; j++) {
            row += k[i][j];
        }
        words[i] = row;
    }
    for (int i = 4; i < 44; i++) {
        string temp = words[i - 1];
        if (i % 4 == 0) {
            temp = XOR(SubWord(RotWord(temp)), rcon[(i / 4) - 1]);
        }
        words[i] = XOR(words[i - 4], temp);
    }
    return words;
}

Matrix AddRoundKey(Matrix key, Matrix state) {
    Matrix result(4, std::vector<std::string>(4));
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            result[row][col] = XOR(key[row][col], state[row][col]);
        }
    }
    return result;
}

string SBox(int row, int col) {
    const string sBox[16][16] = {
        {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"},
        {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"},
        {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"},
        {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
        {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"},
        {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"},
        {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"},
        {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"},
        {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"},
        {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"},
        {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"},
        {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"},
        {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
        {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"},
        {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"},
        {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"}
    };
    return sBox[row][col];
}

Matrix keyBlockMaker(string kel) {
    Matrix output(4, std::vector<std::string>(4));
    int i = 0;
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            output[row][col] = kel.substr(i, 2);
            i += 2;
        }
    }
    return output;
}

Matrix SubBytes(Matrix input, bool encrypt) {
    Matrix output(4, std::vector<std::string>(4, ""));
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            int Srow = hexCharToDecimal(input[row][col][0]);
            int Scol = hexCharToDecimal(input[row][col][1]);
            if(encrypt){
                output[row][col] = SBox(Srow, Scol);
            }else{
                output[row][col] = InverseSBox(Srow, Scol);
            }
        }
    }
    return output;
}

Matrix ShiftRows(Matrix input) {
    Matrix output(4, std::vector<std::string>(4, ""));
    for (int row = 0; row < 4; row++) {
        vector<string> temp = circularLeftShiftRow(input[row], row);
        for (int col = 0; col < 4; col++) {
            output[row][col] = temp[col];
        }
    }
    return output;
}

unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b; // XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return p;
}

// MixColumns transformation for AES-128
Matrix MixColumns(const Matrix& state, bool encrypt) {
    Matrix result(4, std::vector<std::string>(4, ""));
    unsigned char a[4];
    unsigned char c[4];

    // Define the MixColumns matrices for encryption and decryption
    const unsigned char encryptMix[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };
    const unsigned char decryptMix[4][4] = {
        {0x0E, 0x0B, 0x0D, 0x09},
        {0x09, 0x0E, 0x0B, 0x0D},
        {0x0D, 0x09, 0x0E, 0x0B},
        {0x0B, 0x0D, 0x09, 0x0E}
    };

    // Select the appropriate mix matrix
    const unsigned char (*mix)[4] = encrypt ? encryptMix : decryptMix;

    for (int col = 0; col < 4; col++) {
        // Convert each hex string in the column to an integer
        for (int row = 0; row < 4; row++) {
            a[row] = static_cast<unsigned char>(std::stoi(state[row][col], nullptr, 16));
        }

        // Perform the MixColumns transformation
        for (int row = 0; row < 4; row++) {
            c[row] = 0;
            for (int k = 0; k < 4; k++) {
                c[row] ^= gmul(mix[row][k], a[k]);
            }
        }

        // Convert the result back to a hex string and store in the result matrix
        for (int row = 0; row < 4; row++) {
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c[row]);
            result[row][col] = ss.str();
        }
    }

    return result;
}


vector<string> circularLeftShiftRow(const vector<string>& row, int shift) {
    vector<string> shiftedRow(4);
    for (int i = 0; i < 4; i++) {
        int newPos = (i - shift + 4) % 4;
        shiftedRow[newPos] = row[i];
    }
    return shiftedRow;
}

Matrix roundKey(const string &key) {
    Matrix round(4, std::vector<std::string>(4, ""));
    int keyIndex = 0;
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            round[row][col] = key.substr(keyIndex, 2);
            keyIndex += 2;
        }
    }
    return round;
}

string MatrixToString(Matrix finale){
    string output = "";
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            output += finale[i][j];
        }
    }
    return output;
}

Matrix ShiftRows(Matrix input, bool left) {
    Matrix output(4, std::vector<std::string>(4, ""));
    for (int row = 0; row < 4; row++) {
        vector<string> temp;
        if(left){
             temp = circularLeftShiftRow(input[row], row);
        }else{
            temp = circularRightShiftRow(input[row], row);
        }
        for (int col = 0; col < 4; col++) {
            output[row][col] = temp[col];
        }
    }
    return output;
}

vector<string> circularRightShiftRow(const vector<string>& row, int shift) {
    vector<string> shiftedRow(4);
    for (int i = 0; i < 4; i++) {
        int newPos = (i + shift) % 4;
        shiftedRow[newPos] = row[i];
    }
    return shiftedRow;
}

string InverseSBox(int row, int col) {
    const string InverseSBox[16][16] = {
        {"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
        {"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
        {"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
        {"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
        {"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
        {"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
        {"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
        {"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
        {"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
        {"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
        {"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
        {"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
        {"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
        {"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
        {"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
        {"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}
    };
    return InverseSBox[row][col];
}

string MatrixToStringForDecryption(Matrix finale){
    string output = "";
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            output += finale[j][i];
        }
    }
    return output;
}