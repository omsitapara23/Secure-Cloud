#define CATCH_CONFIG_MAIN
#include "../include/catch.hpp"
#include "../src/myint.hpp"



TEST_CASE("Creating a Point", "[point]") {
    MyInt mi1 = MyInt(10);

    REQUIRE(mi1.isOdd() == 0);
}
