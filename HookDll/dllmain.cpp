// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// Global variable to store the VirtualAllocPtr
WinWrap::VirtualAllocPtr g_HooksMemory;

// Global map to associate detour function addresses with their original functions
std::unordered_map<void*, void*> g_DetourMap;
std::mutex g_DetourMapMutex;

// Template data for trampoline hooks
unsigned char g_TrampolineTemplate[] = {
    0x48, 0xB8,                    // mov rax, immediate 64-bit value
    0x00, 0x00, 0x00, 0x00,        // Placeholder for hookWrapperAddress (low DWORD)
    0x00, 0x00, 0x00, 0x00,        // Placeholder for hookWrapperAddress (high DWORD)
    0xFF, 0xE0                     // jmp rax (jump to hookWrapperAddress)
};

// Simple logging function
void LogError(const std::string& message) {
    std::ofstream logFile("detour_errors.log", std::ios::app);
    logFile << message << std::endl;
}

extern "C" void GenericHookWrapper();

void* LookupRealFunctionAddress(void* trampolineAddress) {
    std::lock_guard<std::mutex> lock(g_DetourMapMutex);  // Lock the mutex to ensure thread safety

    auto it = g_DetourMap.find(trampolineAddress);
    if (it != g_DetourMap.end()) {
        return it->second;  // Return the real function address if found
    }
    else {
        std::cerr << "Error: Trampoline address not found in the detour map!" << std::endl;
        return nullptr;  // Return nullptr if the trampoline address is not found
    }
}

// The C++ detour function called by the assembly wrapper
extern "C" void MonitorHook(...)
{
    // Get the trampoline address
    void* trampolineAddress = _ReturnAddress();

    // Lookup the actual address
    auto realFunctionAddress = LookupRealFunctionAddress(trampolineAddress);

    // Call the real function
    typedef void (*RealFunctionType)(...);
    RealFunctionType realFunction = (RealFunctionType)realFunctionAddress;

    va_list args;
    va_start(args, trampolineAddress);  // Start processing variadic arguments
    realFunction(args);                 // Call the real function with the arguments
    va_end(args);                       // End variadic argument processing
}

// Generate a trampoline hook that pushes the unique ID
void* GenerateTrampoline(void* trampolineAddress, void* realFunctionAddress, void* hookWrapperAddress) 
{
    // Copy the template to the target location
    memcpy(trampolineAddress, g_TrampolineTemplate, sizeof(g_TrampolineTemplate));

    // Fill in the placeholders with the actual addresses
    uintptr_t hookWrapperAddr = reinterpret_cast<uintptr_t>(hookWrapperAddress);
    memcpy(&((unsigned char*)trampolineAddress)[2], &hookWrapperAddr, sizeof(uintptr_t));

    return trampolineAddress;
}

std::expected<WinWrap::VirtualAllocPtr, std::string> SetupHooks()
{
    // Resolve the EAT for kernel32
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    auto kernel32DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hKernel32);
    if (kernel32DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return std::unexpected("Could not parse target Kernel32");

    auto kernel32NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(hKernel32) + kernel32DosHeader->e_lfanew);
    if (kernel32NtHeaders->Signature != IMAGE_NT_SIGNATURE) return std::unexpected("Could not parse target Kernel32");

    auto kernel32ExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<uint8_t*>(hKernel32) +
        kernel32NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    auto kernel32Functions = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(hKernel32) + kernel32ExportDirectory->AddressOfFunctions);
    auto kernel32Names = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(hKernel32) + kernel32ExportDirectory->AddressOfNames);
    auto kernel32Ordinals = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(hKernel32) + kernel32ExportDirectory->AddressOfNameOrdinals);

    // Resolve the EAT for ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return std::unexpected("Could not find target NTDLL");

    auto ntdllDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(hNtdll);
    if (ntdllDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return std::unexpected("Could not parse target NTDLL");

    auto ntdllNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(hNtdll) + ntdllDosHeader->e_lfanew);
    if (ntdllNtHeaders->Signature != IMAGE_NT_SIGNATURE) return std::unexpected("Could not parse target NTDLL");

    auto ntdllExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<uint8_t*>(hNtdll) +
        ntdllNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

    auto ntdllFunctions = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(hNtdll) + ntdllExportDirectory->AddressOfFunctions);
    auto ntdllNames = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(hNtdll) + ntdllExportDirectory->AddressOfNames);
    auto ntdllOrdinals = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(hNtdll) + ntdllExportDirectory->AddressOfNameOrdinals);

    // Calculate the total hook section size
    size_t trampolineAllocSize = sizeof(g_TrampolineTemplate) * (kernel32ExportDirectory->NumberOfNames + ntdllExportDirectory->NumberOfNames);

    // Allocate memory for the hooks
    auto trampolineAllocResult = WinWrap::_VirtualAlloc(trampolineAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampolineAllocResult) {
        return std::unexpected("Failed to allocate memory for trampoline hooks: " + trampolineAllocResult.error());
    }

    auto trampolineBasePtr = reinterpret_cast<uint8_t*>(trampolineAllocResult.value().get());

    // Iterate over the kernel32 names and insert hooks
    for (uint32_t i = 0; i < kernel32ExportDirectory->NumberOfNames; ++i) {
        const char* functionName = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(hKernel32) + kernel32Names[i]);
        std::string functionNameStr = functionName;
        auto functionAddress = reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(hKernel32) + kernel32Functions[kernel32Ordinals[i]]);
        auto originalFunc = functionAddress;

        // Generate a trampoline for this function
        auto trampolineAddress = GenerateTrampoline(trampolineBasePtr, originalFunc, GenericHookWrapper);        
        trampolineBasePtr += sizeof(g_TrampolineTemplate);

        if (i == 0x1A9) {
            __debugbreak();  // Triggers a breakpoint
        }

        // Hook the function with GenericDetour
        if (DetourTransactionBegin() != NO_ERROR) {
            return std::unexpected("DetourTransactionBegin failed for function: " + functionNameStr);
        }
        if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
            return std::unexpected("DetourUpdateThread failed for function: " + functionNameStr);
        }
        if (DetourAttach(&originalFunc, trampolineAddress) != NO_ERROR) {
            return std::unexpected("DetourAttach failed for function: " + functionNameStr);
        }
        if (DetourTransactionCommit() != NO_ERROR) {
            return std::unexpected("DetourTransactionCommit failed for function: " + functionNameStr);
        }

        // Store the mapping of the detour address to the original function
        {
            std::lock_guard<std::mutex> lock(g_DetourMapMutex);
            g_DetourMap[originalFunc] = functionAddress; // Map the original function to the trampoline
        }
    }

    // Iterate over the ntdll names and insert hooks
    for (uint32_t i = 0; i < ntdllExportDirectory->NumberOfNames; ++i) {
        const char* functionName = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(hNtdll) + ntdllNames[i]);
        std::string functionNameStr = functionName;
        auto functionAddress = reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(hNtdll) + ntdllFunctions[ntdllOrdinals[i]]);
        auto originalFunc = functionAddress;

        // Generate a trampoline for this function
        auto trampolineAddress = GenerateTrampoline(trampolineBasePtr, originalFunc, GenericHookWrapper);
        trampolineBasePtr += sizeof(g_TrampolineTemplate);

        // Hook the function with GenericDetour
        if (DetourTransactionBegin() != NO_ERROR) {
            return std::unexpected("DetourTransactionBegin failed for function: " + functionNameStr);
        }
        if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) {
            return std::unexpected("DetourUpdateThread failed for function: " + functionNameStr);
        }
        if (DetourAttach(&originalFunc, trampolineAddress) != NO_ERROR) {
            return std::unexpected("DetourAttach failed for function: " + functionNameStr);
        }
        if (DetourTransactionCommit() != NO_ERROR) {
            return std::unexpected("DetourTransactionCommit failed for function: " + functionNameStr);
        }

        // Store the mapping of the detour address to the original function
        {
            std::lock_guard<std::mutex> lock(g_DetourMapMutex);
            g_DetourMap[originalFunc] = functionAddress; // Map the detour function to the original function
        }
    }

    return trampolineAllocResult;
}

//// Function to apply hooks to all exports in a module
//std::expected<WinWrap::VirtualAllocPtr, std::string> SetupHooks() {
//    // Hook kernel32.dll exports
//    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
//    if (hKernel32 == nullptr) {
//        return std::unexpected("Failed to get handle for kernel32.dll.");
//    }
//    auto kernel32Result = HookModuleExports(hKernel32, "kernel32.dll");
//    if (!kernel32Result) {
//        return std::unexpected("Failed to hook kernel32.dll exports: " + kernel32Result.error());
//    }
//
//    // Hook ntdll.dll exports
//    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
//    if (hNtdll == nullptr) {
//        return std::unexpected("Failed to get handle for ntdll.dll.");
//    }
//    auto ntdllResult = HookModuleExports(hNtdll, "ntdll.dll");
//    if (!ntdllResult) {
//        return std::unexpected("Failed to hook ntdll.dll exports: " + ntdllResult.error());
//    }
//
//    // Combine the allocated memory
//    size_t totalSize = kernel32Result.value().size() + ntdllResult.value().size();
//    auto combinedMemory = WinWrap::_VirtualAlloc(totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//    if (!combinedMemory) {
//        return std::unexpected("Failed to allocate combined memory: " + combinedMemory.error());
//    }
//
//    // Copy memory from kernel32 and ntdll allocations to the combined allocation
//    uint8_t* dest = static_cast<uint8_t*>(combinedMemory.value().get());
//    memcpy(dest, kernel32Result.value().get(), kernel32Result.value().size());
//    memcpy(dest + kernel32Result.value().size(), ntdllResult.value().get(), ntdllResult.value().size());
//
//    // Update the g_DetourMap with the new addresses
//    {
//        std::lock_guard<std::mutex> lock(g_DetourMapMutex);
//        for (const auto& [oldAddress, funcAddress] : g_DetourMap) {
//            if (oldAddress >= kernel32Result.value().get() &&
//                oldAddress < static_cast<uint8_t*>(kernel32Result.value().get()) + kernel32Result.value().size()) {
//                // This is a kernel32 trampoline
//                size_t offset = static_cast<uint8_t*>(oldAddress) - static_cast<uint8_t*>(kernel32Result.value().get());
//                g_DetourMap[dest + offset] = funcAddress;
//            }
//            else if (oldAddress >= ntdllResult.value().get() &&
//                oldAddress < static_cast<uint8_t*>(ntdllResult.value().get()) + ntdllResult.value().size()) {
//                // This is an ntdll trampoline
//                size_t offset = static_cast<uint8_t*>(oldAddress) - static_cast<uint8_t*>(ntdllResult.value().get());
//                g_DetourMap[dest + kernel32Result.value().size() + offset] = funcAddress;
//            }
//        }
//    }
//
//    // Clear the old entries from g_DetourMap
//    g_DetourMap.erase(
//        std::remove_if(g_DetourMap.begin(), g_DetourMap.end(),
//            [&](const auto& pair) {
//                return pair.first < dest || pair.first >= dest + totalSize;
//            }),
//        g_DetourMap.end());
//
//    return combinedMemory;
//}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) 
{
    case DLL_PROCESS_ATTACH: {
        auto result = SetupHooks();
        if (!result) {
            // Log or handle the error
            LogError("SetupHooks failed: " + result.error());
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
