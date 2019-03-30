#define CATCH_CONFIG_MAIN
#include "../include/catch.hpp"
#include "../src/utils.hpp"


TEST_CASE("UTILSsec thest", "[secstring]") {
    Deffie_Hellman alice;
    Deffie_Hellman bob(alice.getPrime(), alice.getGenerator());
    SecByteBlock puba = alice.getpubKey();
    REQUIRE(puba == utils::stringToSecByte(utils::SecByteToString(puba)));
}

TEST_CASE("UTILSITnt thest", "[integerhex]") {
    Deffie_Hellman alice;
    Deffie_Hellman bob(alice.getPrime(), alice.getGenerator());
    Integer puba = alice.getPrime();
    REQUIRE(puba == utils::stringHexToInteger(utils::IntegerTohexString(puba)));
}
