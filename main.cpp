#include <iostream>
#include "obfuscator.h"

using namespace std;
using namespace PointerCipher;

int main()
{
    auto p = new int;
    cout << "plain pointer : " << hex << p << endl;
    auto ep = Pointer<int*>(p);
    cout << "decrypted pointer : " << hex << ep.get() << endl;
    auto p2 = new int;
    cout << hex << "pointer2 to be changed : " << p2 << endl;
    ep.set(p2);
    cout << hex << "changed pointer : " << ep.get() << endl;
    *ep.get() = 1;
    cout << "value to 1 : " << *ep.get() << endl;
    
    auto n = Encrypted<int>(1);
    cout << "initialized : " << n.val() << endl;
    n.val(2);
    cout << "value to 2 : " << n.val() << endl;

    auto s = Encrypted<char *>("12");
    cout << "initialized : " << s.val() << endl;
    s.val("2");
    cout << "value to 2 : " << s.val() << endl;
    
    return 0;
}