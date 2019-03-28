#define CATCH_CONFIG_MAIN
#include "../include/catch.hpp"
#include "../src/bank.hpp"



TEST_CASE("Creating a Point", "[point]") {
    Bank acc = Bank();
    acc.set(5);
    REQUIRE(acc.num_ == 5);
    acc.credit(4);
    REQUIRE(acc.num_ == 9);

}
