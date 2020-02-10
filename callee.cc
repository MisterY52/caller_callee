#include <Windows.h>
#include <string>
#include <iostream>

using namespace std;

void f1(int a)
{
	cout<<"F1 called"<<endl<<a<<endl;
}

void f2(int a, int b)
{
	cout<<"F2 called"<<endl<<a<<endl<<b<<endl;
}

void f3(char* s)
{
    cout<<"F3 called"<<endl<<s<<endl;
}

int main()
{
    cout<<"Function 1 address: "<<(void*)f1<<endl;
    cout<<"Function 2 address: "<<(void*)f2<<endl;
    cout<<"Function 3 address: "<<(void*)f3<<endl;

    while(true)
    {
        Sleep(5);
    }
    return 0;
}