#ifndef _MY_INT_
#define _MY_INT_

class MyInt
{
public:
MyInt(int num)
:num_(num)
{}
  bool isOdd()
  {
    return (num_ % 2) != 0 ? true : false;
  }
private:
  int num_;
};



#endif
