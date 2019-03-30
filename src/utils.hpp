#ifndef _UTIL_
#define _UTIL_

#include <iostream>
#include <iomanip>
#include "dhaes.hpp"
#include <crypto++/md5.h>
#include <crypto++/hex.h>

class utils
{
    public:
        static string SecByteToString(SecByteBlock block)
        {
            string s((const char*)block.data(), block.size());
            return s;
        }

        static SecByteBlock stringToSecByte(string s)
        {
            SecByteBlock block((const byte*)s.data(), s.size());
            return block;

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
        

};

#endif