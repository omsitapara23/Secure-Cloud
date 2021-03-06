#ifndef _DHAES_
#define _DHAES_

#include <iostream>
#include <iomanip>

#include <crypto++/dh2.h>
#include <crypto++/dh.h>
#include <crypto++/modes.h>
#include <crypto++/aes.h>
#include <crypto++/filters.h>
#include <crypto++/osrng.h>

using namespace std;
using namespace CryptoPP;

class Deffie_Hellman
{
    private:
        Integer iPrime;
        Integer iGenerator;
        SecByteBlock priv;
        SecByteBlock pub;
        SecByteBlock aesGen;
        AutoSeededRandomPool rng;
        SecByteBlock aesShaKey;
        DH dh;
    
    public:
        Integer getPrime()
        {
            return iPrime;
        }

        // void setPrime(Integer Prime)
        // {
        //     iPrime = Prime;
        // }

        Integer getGenerator()
        {
            return iGenerator;
        }


        bool AgreeFunc(SecByteBlock ipub)
        {
            if(!dh.Agree(aesGen, priv, ipub))
            {
                return false;
            }
            SHA256().CalculateDigest(aesShaKey, aesGen, aesGen.size());
            return true;

        }

        SecByteBlock getaesKey()
        {
            return aesGen;
        }

        SecByteBlock getpubKey()
        {
            return pub;
        }

        SecByteBlock getaesShaKey()
        {
            return aesShaKey;
        }


        // void setPrime(Integer Generator)
        // {
        //     iGenerator = Generator;
        // }
        Deffie_Hellman()
        {
            dh.AccessGroupParameters().GenerateRandomWithKeySize(rng, 1024);
            iPrime = dh.GetGroupParameters().GetModulus();
            iGenerator = dh.GetGroupParameters().GetSubgroupGenerator();
            priv = SecByteBlock(dh.PrivateKeyLength());
            pub = SecByteBlock(dh.PublicKeyLength());
            aesGen = SecByteBlock(dh.AgreedValueLength());
            aesShaKey = SecByteBlock(SHA256::DIGESTSIZE);
            dh.GenerateKeyPair(rng, priv, pub);
        }

        Deffie_Hellman(Integer prime, Integer generator)
        {
            dh = DH(prime, generator);
            iPrime = dh.GetGroupParameters().GetModulus();
            iGenerator = dh.GetGroupParameters().GetSubgroupGenerator();
            priv = SecByteBlock(dh.PrivateKeyLength());
            pub = SecByteBlock(dh.PublicKeyLength());
            aesGen = SecByteBlock(dh.AgreedValueLength());
            aesShaKey = SecByteBlock(SHA256::DIGESTSIZE);
            dh.GenerateKeyPair(rng, priv, pub);
        }

};

#endif