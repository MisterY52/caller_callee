#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

using namespace std;

HANDLE FindProcess(const char* szProcess)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, szProcess) == 0)
            {
                CloseHandle(snapshot);
                return OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
            }
        }
    }
    CloseHandle(snapshot);
    return NULL;  
}


int main()
{
	cout<<"Searching process callee.exe..."<<endl;

	HANDLE proc = NULL;
	int m = 0;

	while (!proc)
	{
		proc = FindProcess("callee.exe");
	}
	cout<<"Process found"<<endl;
	int arg = 10;
    int address = 0x401460; //function 1 address (one argument)
	HANDLE thr = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)address, (void*)arg, 0, NULL);

	if (!thr)
    {
        cout<<"Error"<<endl;
    }		
	else
	{
		cout<<"Function 1 called"<<endl;
		CloseHandle(thr);
	}

	do
    {
        cout<<"Call function with multiple parameters? (1 or 0): ";
        cin>>m;
    }
    while(m!=0 && m!=1);

	if (m == 1)
	{
		void* alloc_addr = VirtualAllocEx(proc, 0, 0x40, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //allocate space for payload

		struct _Args
		{
            int b;
			int a;      
		};

		_Args args = {2, 1};

		if (!WriteProcessMemory(proc, alloc_addr, &args, sizeof(args), nullptr)) //write arguments in the beginning of allocated space
			cout<<"Error while writing to memory"<<endl;

		byte payload[32] = {
			0xB8, 0x00, 0x00, 0x00, 0x00,	//mov eax, 0; the 4 bytes after B8 will contain the start address of the allocated space, which contains the parameters.
			0xFF, 0x30,						//push [eax]; dereference EAX, push the first parameter
			0xFF, 0x70, 0x04,				//push [eax+4]; dereference EAX+4, push the second parameter
			0xB8, 0x00, 0x00, 0x00, 0x00,	//mov eax, 0; the 4 bytes after B8 will contain the address of the function to be called
			0xFF, 0xD0,						//call eax 
			0x83, 0xC4, 0x08,				//add esp, 8; clean the stack
			0xC3							//ret
		};

		memcpy(&payload[1], &alloc_addr, sizeof(uintptr_t)); //write the start address of the allocated space after the first byte of the payload

		address = 0x4014b1; //function 2 address (multiple arguments)
		memcpy(&payload[0xB], &address, sizeof(uintptr_t)); //write the address of the function to be called after the 11th byte of the payload.

		uintptr_t payload_addr = (uintptr_t)alloc_addr + sizeof(args) ; //write payload to this address of the allocated space, after the arguments
		WriteProcessMemory(proc, (void*)payload_addr, payload, sizeof(payload), nullptr); //write the payload code into the process

		thr = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)payload_addr, nullptr, 0, NULL); //nullptr as argument because the arguments are already in the allocated memory
		if (!thr)
        {
            cout<<"Error"<<endl;
        }	
		else
		{
			cout<<"Function 2 called"<<endl;
			WaitForSingleObjectEx(thr, INFINITE, FALSE); //wait the thread
			VirtualFreeEx(proc, alloc_addr, 0, MEM_RELEASE); //release the allocated memory
			CloseHandle(thr);
		}
		m=0;
	}

	do
    {
        cout<<"Call function with string parameter? (1 or 0): ";
        cin>>m;
    }
    while(m!=0 && m!=1);

	if (m == 1)
	{
		void* alloc_addr = VirtualAllocEx(proc, 0, 0x40, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		char* s=new char[4];
        strncpy(s, "arg", 3);
        s[3]='\0';

		byte buf[4]={0x00,0x00,0x00,0x00}; //the buffer will contain the address of the string in the allocated space
		uintptr_t str_addr = (uintptr_t)alloc_addr + 4; 
		memcpy(&buf[0], &str_addr, sizeof(uintptr_t));

		if (!WriteProcessMemory(proc, alloc_addr, &buf[0], sizeof(uintptr_t), nullptr)) //write the address of the string at the beginning of the allocated space
			cout<<"Error while writing to memory"<<endl;
		if (!WriteProcessMemory(proc, (void*)((uintptr_t)alloc_addr+4), &s[0], strlen(s)+1, nullptr)) //write the string into the allocated space
			cout<<"Error while writing to memory"<<endl;

		byte payload[32] = {
			0xB8, 0x00, 0x00, 0x00, 0x00,	//mov eax, 0;
			0xFF, 0x30,						//push [eax]; the content of EAX is the address of the string in the allocated space, the cout function will dereference this address and will print the string
			0xB8, 0x00, 0x00, 0x00, 0x00,	//mov eax, 0;
			0xFF, 0xD0,						//call eax 
			0x83, 0xC4, 0x04,				//add esp, 4;
			0xC3							//ret
		};		

		memcpy(&payload[1], &alloc_addr, sizeof(uintptr_t));

		address = 0x401525; //function 3 address (string arg)
		memcpy(&payload[0x8], &address, sizeof(uintptr_t));

		uintptr_t payload_addr = (uintptr_t)alloc_addr + sizeof(uintptr_t) + strlen(s)+1;
		WriteProcessMemory(proc, (void*)payload_addr, payload, sizeof(payload), nullptr);

		thr = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)payload_addr, nullptr, 0, NULL);
		if (!thr)
        {
            cout<<"Error"<<endl;
        }
		else
		{
			cout<<"Function 3 called"<<endl;
			WaitForSingleObjectEx(thr, INFINITE, FALSE);
			VirtualFreeEx(proc, alloc_addr, 0, MEM_RELEASE);
			CloseHandle(thr);
		}
	}
	CloseHandle(proc);
    return 0;
}

