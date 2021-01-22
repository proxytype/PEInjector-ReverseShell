# PEInjector-ReverseShell
Inject new function to target memory and execute reverse shell

# Injector.cpp
Program to inject function from itself to another process and execute the function using CreateRemoteThread, the injected function load WS2_32.dll and create cmd.exe process, redirecting the std to the socket and connecting to remote server.

# ShellServerGui
Simple C# Tcplistener wating for the victim connection.
