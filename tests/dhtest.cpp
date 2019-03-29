#define CATCH_CONFIG_MAIN
#include "../include/catch.hpp"
#include "../src/dhaes.hpp"


TEST_CASE("DH thest", "[aes]") {
    Deffie_Hellman alice;
    Deffie_Hellman bob(alice.getPrime(), alice.getGenerator());
    REQUIRE(alice.AgreeFunc(bob.getpubKey()) == true);
    REQUIRE(bob.AgreeFunc(alice.getpubKey()) == true);
    Integer a, b;
    a.Decode(alice.getaesKey().BytePtr(), alice.getaesKey().SizeInBytes());
    b.Decode(bob.getaesKey().BytePtr(), bob.getaesKey().SizeInBytes());
    REQUIRE(a==b);
}
