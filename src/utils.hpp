#ifndef _UTIL_
#define _UTIL_

#include <iostream>
#include <iomanip>
#include "dhaes.hpp"
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>
#include <crypto++/hex.h>

class utils
{
    public:
        static string SecByteToString(SecByteBlock block)
        {
            Integer a;
            a.Decode(block.BytePtr(), block.SizeInBytes());
            cout << " conv : " << a << endl;
            return IntegerTohexString(a);
        }

        static SecByteBlock stringToSecByte(string s)
        {
            Integer a = stringHexToInteger(s);
            SecByteBlock out;
            UnsignedIntegerToByteBlock(a, out);
            return out;

        }

        static string IntegerTohexString(Integer input)
        {
            stringstream ss;
            ss << hex << input;
            string s = ss.str();
            return s;
        }

        static Integer stringHexToInteger(string s)
        {
            Integer out(s.c_str());
            return out;
        }

        static string findMD5(SecByteBlock key)
        {
            byte digest[ CryptoPP::Weak::MD5::DIGESTSIZE ];
            CryptoPP::Weak::MD5 hash;
            hash.CalculateDigest( digest, key, sizeof(SecByteBlock));
            HexEncoder encoder;
            std::string output;
            encoder.Attach( new CryptoPP::StringSink( output ) );
            encoder.Put( digest, sizeof(digest) );
            encoder.MessageEnd();
            return output;
        }
        static void UnsignedIntegerToByteBlock(const Integer& x, SecByteBlock& bytes)
        {
            size_t encodedSize = x.MinEncodedSize(Integer::UNSIGNED);
            bytes.resize(encodedSize);
            x.Encode(bytes.BytePtr(), encodedSize, Integer::UNSIGNED);
        }   
        

};

#endif