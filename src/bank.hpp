#ifndef _BANK_
#define _BANK_

class Bank
{
public:
Bank()
{}
  void set(int i)
  {
      num_ = i;
  }
  void credit(int x)
  {
      num_ += x;
  }
  int num_ = -1;
};



#endif
