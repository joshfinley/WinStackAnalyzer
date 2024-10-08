// WinWrap.hpp
// Header-only library to wrap a subset of the Windows API for the purpose of 
// increasing memory safety and modernizing Windows C++ codebases

#pragma once

#include <concepts>
#include <utility>
#include <stdexcept>
#include <format>
#include <memory>
#include <expected>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>


// Windows API Wrappers
namespace WinWrap
{
    //
    // Internal API implementation (unstable)
    //
    namespace detail {

        // Custom deleter for Windows LocalFree function with double-free protection
        class LocalFreeDeleter {
        private:
            // Atomic flag to track if the pointer has been freed
            mutable std::atomic<bool> freed{ false };

        public:
            // Function call operator, used by unique_ptr to delete the object
            inline void operator()(void* ptr) const noexcept {
                bool expected = false;
                // Only free if the pointer is not null and it hasn't been freed before
                if (ptr && freed.compare_exchange_strong(expected, true)) {
                    ::LocalFree(ptr);
                }
            }

            // Reset the freed state (useful for move operations)
            inline void reset() noexcept {
                freed.store(false);
            }
        };

        // Custom unique pointer for Windows LocalAlloc/LocalFree memory management
        class UniqueLocalPtr {
        private:
            void* ptr;                 // The raw pointer
            LocalFreeDeleter deleter;  // The deleter object

        public:
            // Default constructor
            inline UniqueLocalPtr() noexcept : ptr(nullptr) {}

            // Constructor taking ownership of a raw pointer
            inline explicit UniqueLocalPtr(void* p) noexcept : ptr(p) {}

            // Disable copy operations
            UniqueLocalPtr(const UniqueLocalPtr&) = delete;
            UniqueLocalPtr& operator=(const UniqueLocalPtr&) = delete;

            // Move constructor
            inline UniqueLocalPtr(UniqueLocalPtr&& other) noexcept
                : ptr(other.ptr) {
                other.ptr = nullptr;
                other.deleter.reset();  // Reset the moved-from deleter's state
            }

            // Move assignment operator
            inline UniqueLocalPtr& operator=(UniqueLocalPtr&& other) noexcept {
                if (this != &other) {
                    reset();  // Free current resource if any
                    ptr = other.ptr;
                    other.ptr = nullptr;
                    other.deleter.reset();  // Reset the moved-from deleter's state
                }
                return *this;
            }

            // Destructor
            inline ~UniqueLocalPtr() noexcept {
                reset();
            }

            // Reset the pointer, freeing current resource if any
            inline void reset(void* p = nullptr) noexcept {
                if (ptr != p) {
                    deleter(ptr);  // Free current resource
                    ptr = p;
                    deleter.reset();  // Reset deleter state for new pointer
                }
            }

            // Release ownership of the pointer without freeing
            inline void* release() noexcept {
                void* tmp = ptr;
                ptr = nullptr;
                deleter.reset();  // Reset deleter state as we're releasing ownership
                return tmp;
            }

            // Get the stored pointer without affecting ownership
            inline void* get() const noexcept {
                return ptr;
            }

            // Check if the pointer is non-null
            inline explicit operator bool() const noexcept {
                return ptr != nullptr;
            }
        };
    }

    //
    // Safe Handle
    //

    // Concept to ensure the template parameter is of type HANDLE
    template <typename T>
    concept HandleType = std::same_as<T, HANDLE>;

    // SafeHandle class template for managing Windows handles
    // 
    // The template parameter H ensures that the data type of the handle
    // is the same as HANDLE
    template <HandleType H>
    class WrappedHandle final
    {
    public:
        // SafeHandle default constructor
        inline WrappedHandle() noexcept = default;

        // SafeHandle explicit constructor from H handle
        // Validates the handle upon construction
        inline explicit WrappedHandle(H handle) noexcept : m_handle(handle)
        {
            ValidateHandle();
        }

        // SafeHandle destructor
        // Ensures the handle is properly closed
        inline ~WrappedHandle() noexcept
        {
            Close();
        }

        // Disable copy operations to prevent unintended handle duplication
        WrappedHandle(const WrappedHandle&) = delete;
        WrappedHandle& operator=(const WrappedHandle&) = delete;

        // SafeHandle move constructor
        // Transfers ownership of the handle and its validity state
        inline WrappedHandle(WrappedHandle&& other) noexcept
            : m_handle(std::exchange(other.m_handle, s_nullValue)),
            m_isValid(std::exchange(other.m_isValid, false))
        {
        }

        // SafeHandle move assignment operator
        // Closes current handle and transfers ownership from other
        inline WrappedHandle& operator=(WrappedHandle&& other) noexcept
        {
            if (this != &other)
            {
                Close();
                m_handle = std::exchange(other.m_handle, s_nullValue);
                m_isValid = std::exchange(other.m_isValid, false);
            }
            return *this;
        }

        // Check if the handle is valid
        // Revalidates the handle before returning the status
        [[nodiscard]] inline bool IsValid() const noexcept
        {
            ValidateHandle();
            return m_isValid;
        }

        // Get the raw handle
        [[nodiscard]] inline H Get() const noexcept
        {
            return m_handle;
        }

        // Reassign the SafeHandle's handle
        // Closes the current handle and validates the new one
        inline void Reset(H newHandle = s_nullValue) noexcept
        {
            if (m_handle != newHandle)
            {
                Close();
                m_handle = newHandle;
                ValidateHandle();
            }
        }

        // Get the handle and release the SafeHandle's ownership
        // The caller becomes responsible for closing the handle
        inline H Release() noexcept
        {
            m_isValid = false;
            return std::exchange(m_handle, s_nullValue);
        }

        // SafeHandle bool() operator
        // Returns true if the handle is valid
        inline explicit operator bool() const noexcept
        {
            return IsValid();
        }

        // SafeHandle conversion operator to H
        inline explicit operator H() const noexcept
        {
            return m_handle;
        }

    private:
        static constexpr H s_nullValue = nullptr;
        static constexpr H s_invalidValue = INVALID_HANDLE_VALUE;

        mutable H m_handle{ s_nullValue };
        mutable bool m_isValid{ false };

        // Check if the HANDLE value is invalid
        inline static bool IsInvalidValue(H handle) noexcept
        {
            return handle == s_nullValue || handle == s_invalidValue;
        }

        // Validate the handle using GetHandleInformation
        // Updates m_isValid based on the result
        // If handle is invalid, sets m_handle to s_nullValue
        inline void ValidateHandle() const noexcept
        {
            if (!IsInvalidValue(m_handle))
            {
                DWORD flags;
                m_isValid = ::GetHandleInformation(m_handle, &flags) != 0;
                if (!m_isValid)
                {
                    m_handle = s_nullValue; // Ensure we don't try to close an invalid handle later
                }
            }
            else
            {
                m_isValid = false;
                m_handle = s_nullValue;
            }
        }

        // Close the handle if it's valid
        // Revalidates the handle before attempting to close
        // Resets m_handle to s_nullValue and m_isValid to false
        inline void Close() noexcept
        {
            ValidateHandle(); // Revalidate before closing
            if (m_isValid && !IsInvalidValue(m_handle))
            {
                BOOL result = ::CloseHandle(m_handle);
                if (!result) {
                    // Log error or handle it as appropriate for your application
                    std::cerr << "Warning: Failed to close handle " << m_handle << ". Error code: " << GetLastError() << std::endl;
                }
            }
            m_handle = s_nullValue;
            m_isValid = false;
        }
    };

    //
    // Memory Management
    // 
    
    // Custom deleter for VirtualAlloc
    struct VirtualAllocDeleter {
        void operator()(void* ptr) const {
            if (ptr) {
                VirtualFree(ptr, 0, MEM_RELEASE);
            }
        }
    };

    // Alias for unique_ptr with VirtualAllocDeleter
    using VirtualAllocPtr = std::unique_ptr<void, VirtualAllocDeleter>;

    // Helper function to create a VirtualAllocPtr, returning std::expected
    inline std::expected<VirtualAllocPtr, std::string> _VirtualAlloc(
        SIZE_T size,
        DWORD allocationType = MEM_COMMIT | MEM_RESERVE,
        DWORD protect = PAGE_READWRITE)
    {
        void* ptr = VirtualAlloc(nullptr, size, allocationType, protect);
        if (!ptr) {
            return std::unexpected("VirtualAlloc failed with error code: " + std::to_string(GetLastError()));
        }
        return VirtualAllocPtr(ptr);
    }

    //
    // Error Management
    //

    // Convert Windows error code to string representation
    inline std::expected<std::string, uint32_t> GetWinErrorAsString(uint32_t errorCode) noexcept {
        detail::UniqueLocalPtr messageBuffer;
        LPSTR rawBuffer = nullptr;

        uint32_t size = ::FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPSTR>(&rawBuffer),
            0,
            nullptr
        );

        if (size == 0) {
            return std::unexpected(::GetLastError());
        }

        messageBuffer.reset(rawBuffer);

        // Remove trailing newline characters
        while (size > 0 && (rawBuffer[size - 1] == '\r' || rawBuffer[size - 1] == '\n')) {
            rawBuffer[--size] = '\0';
        }

        try {
            return std::string(rawBuffer, size);
        }
        catch (...) {
            // In case std::string constructor throws (e.g., out of memory)
            return std::unexpected(ERROR_OUTOFMEMORY);
        }
    }

    //
    // HANDLE operations
    //

    inline std::expected<bool, std::string> _GetHandleInformation(const WrappedHandle<HANDLE>& hObject) {
        DWORD flags;
        if (GetHandleInformation(hObject.Get(), &flags)) {
            return true;  // Handle is valid
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_INVALID_HANDLE) {
                return std::unexpected("Invalid handle");
            }
            else {
                return std::unexpected("Failed to get handle information. Error: " + std::to_string(error));
            }
        }
    }

    inline std::expected<void, std::string> _CloseHandle(WrappedHandle<HANDLE>& hObject) {
        auto handleCheck = _GetHandleInformation(hObject);
        if (!handleCheck) {
            return std::unexpected(handleCheck.error());
        }

        if (handleCheck.value()) {
            if (CloseHandle(hObject.Release())) {
                return {}; // Success, handle closed
            }
            else {
                return std::unexpected("Failed to close handle. Error: " + std::to_string(GetLastError()));
            }
        }
        else {
            return std::unexpected("Cannot close an invalid handle.");
        }
    }

    // Get the last error code automatically
    inline std::expected<std::string, uint32_t> GetLastErrorAsString() noexcept {
        return GetWinErrorAsString(::GetLastError());
    }

    //
    // Tool Help Function Wrappers
    //

    inline std::expected<WrappedHandle<HANDLE>, std::string> _CreateToolhelp32Snapshot(uint32_t flags, uint32_t th32ProcessID) noexcept
    {
        HANDLE hSnapshot = ::CreateToolhelp32Snapshot(flags, th32ProcessID);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            auto errorResult = GetLastErrorAsString();
            if (errorResult)
            {
                return std::unexpected(*errorResult);
            }
            else
            {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return WrappedHandle<HANDLE>(hSnapshot);
    }

    //
    // HMODULE related wrappers
    //

    // Wrapper for GetModuleHandle
    inline std::expected<HMODULE, std::string> _GetModuleHandle(const wchar_t* moduleName) noexcept {
        HMODULE hModule = ::GetModuleHandleW(moduleName);
        if (hModule == nullptr) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return hModule;
    }

    // Wrapper for EnumProcessModules
    inline std::expected<std::vector<HMODULE>, std::string> _EnumProcessModules() noexcept {
        std::vector<HMODULE> modules;
        DWORD cbNeeded;

        if (!::EnumProcessModules(GetCurrentProcess(), nullptr, 0, &cbNeeded)) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }

        modules.resize(cbNeeded / sizeof(HMODULE));

        if (!::EnumProcessModules(GetCurrentProcess(), modules.data(), cbNeeded, &cbNeeded)) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }

        return modules;
    }

    // Wrapper for GetModuleInformation
    inline std::expected<MODULEINFO, std::string> _GetModuleInformation(HANDLE hProcess, HMODULE hModule) noexcept {
        MODULEINFO modInfo;
        if (!::GetModuleInformation(hProcess, hModule, &modInfo, sizeof(MODULEINFO))) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return modInfo;
    }

    // Wrapper for GetModuleFileNameEx
    inline std::expected<std::wstring, std::string> _GetModuleFileNameEx(HANDLE hProcess, HMODULE hModule) noexcept {
        std::wstring fileName(MAX_PATH, L'\0');
        DWORD result = ::GetModuleFileNameExW(hProcess, hModule, fileName.data(), static_cast<DWORD>(fileName.size()));
        if (result == 0) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        fileName.resize(result);
        return fileName;
    }

    // Wrapper for EnumProcessModulesEx
    inline std::expected<std::vector<HMODULE>, std::string> _EnumProcessModulesEx(HANDLE hProcess, DWORD dwFilterFlag = LIST_MODULES_ALL) noexcept {
        std::vector<HMODULE> modules;
        DWORD cbNeeded;

        if (!::EnumProcessModulesEx(hProcess, nullptr, 0, &cbNeeded, dwFilterFlag)) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }

        modules.resize(cbNeeded / sizeof(HMODULE));

        if (!::EnumProcessModulesEx(hProcess, modules.data(), cbNeeded, &cbNeeded, dwFilterFlag)) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }

        return modules;
    }

    // Get the base address of a module in a remote process
    inline std::expected<PVOID, std::string> GetModuleBaseAddress(HANDLE hProcess, const std::wstring& moduleName) noexcept {
        auto modulesResult = _EnumProcessModulesEx(hProcess);
        if (!modulesResult) {
            return std::unexpected(modulesResult.error());
        }

        std::wstring lowerModuleName = moduleName;
        std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::towlower);

        for (const auto& hModule : modulesResult.value()) {
            auto fileNameResult = _GetModuleFileNameEx(hProcess, hModule);
            if (!fileNameResult) {
                continue; // Skip this module if we can't get its file name
            }

            std::wstring lowerFileName = fileNameResult.value();
            std::transform(lowerFileName.begin(), lowerFileName.end(), lowerFileName.begin(), ::towlower);

            if (lowerFileName.find(lowerModuleName) != std::wstring::npos) {
                auto modInfoResult = _GetModuleInformation(hProcess, hModule);
                if (!modInfoResult) {
                    return std::unexpected(modInfoResult.error());
                }
                return modInfoResult.value().lpBaseOfDll;
            }
        }

        return std::unexpected("Module not found in the specified process");
    }

    inline std::expected<HMODULE, std::string> _GetModuleHandleEx(
        DWORD dwFlags,
        LPCWSTR lpModuleName
    ) noexcept {
        HMODULE hModule;
        if (!::GetModuleHandleExW(dwFlags, lpModuleName, &hModule)) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return hModule;
    }

    //
    // Process and Thread APIs
    //

    inline std::expected<WrappedHandle<HANDLE>, std::string> _OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) noexcept {
        HANDLE hThread = ::OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
        if (hThread == nullptr) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return WrappedHandle<HANDLE>(hThread);
    }

    // Wrapper for CreateRemoteThread
    inline std::expected<WrappedHandle<HANDLE>, std::string> _CreateRemoteThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) noexcept {
        HANDLE hThread = ::CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpStartAddress), lpParameter, 0, nullptr);
        if (!hThread) {
            return std::unexpected("Failed to create remote thread. Error: " + std::to_string(::GetLastError()));
        }
        return WrappedHandle<HANDLE>(hThread);
    }

    inline std::expected<CONTEXT, std::string> _GetThreadContext(HANDLE hThread) noexcept {
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        if (!::GetThreadContext(hThread, &context)) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return context;
    }

    inline std::expected<WrappedHandle<HANDLE>, std::string> _OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) noexcept {
        HANDLE hProcess = ::OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
        if (hProcess == nullptr) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return WrappedHandle<HANDLE>(hProcess);
    }


    inline std::expected<DWORD, std::string> _GetProcessId(HANDLE hProcess) noexcept {
        DWORD processId = ::GetProcessId(hProcess);
        if (processId == 0) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return processId;
    }

    inline std::expected<BOOL, std::string> _Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte) noexcept {
        if (!::Thread32First(hSnapshot, lpte)) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return TRUE;
    }

    inline std::expected<BOOL, std::string> _Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte) noexcept {
        if (!::Thread32Next(hSnapshot, lpte)) {
            auto errorResult = GetLastErrorAsString();
            if (errorResult) {
                return std::unexpected(*errorResult);
            }
            else {
                return std::unexpected("Failed to get error message. Error code: " + std::to_string(errorResult.error()));
            }
        }
        return TRUE;
    }

    inline std::expected<std::wstring, std::string> _GetModuleFileName(HMODULE hModule) {
        wchar_t fullPath[MAX_PATH];
        if (GetModuleFileNameW(hModule, fullPath, MAX_PATH) == 0) {
            return std::unexpected("Failed to get full path for module. Error: " + std::to_string(GetLastError()));
        }
        return std::wstring(fullPath);
    }

    class ThreadContextWrapper {
    public:
        // Default constructor initializes a new CONTEXT structure
        ThreadContextWrapper(DWORD contextFlags = CONTEXT_FULL)
            : m_context(std::make_unique<CONTEXT>()) {
            m_context->ContextFlags = contextFlags;
        }

        // Constructor that captures the thread context from a SafeHandle
        ThreadContextWrapper(WrappedHandle<HANDLE>&& hThread, DWORD contextFlags = CONTEXT_FULL)
            : m_context(std::make_unique<CONTEXT>()) {
            m_context->ContextFlags = contextFlags;
            auto result = _GetThreadContextWrapped(std::move(hThread));
            if (!result) {
                throw std::runtime_error("Failed to get thread context: " + result.error());
            }
        }

        // Copy constructor (deep copy)
        ThreadContextWrapper(const ThreadContextWrapper& other)
            : m_context(std::make_unique<CONTEXT>(*other.m_context)) {}

        // Move constructor
        ThreadContextWrapper(ThreadContextWrapper&& other) noexcept = default;

        // Copy assignment operator (deep copy)
        ThreadContextWrapper& operator=(const ThreadContextWrapper& other) {
            if (this != &other) {
                m_context = std::make_unique<CONTEXT>(*other.m_context);
            }
            return *this;
        }

        // Move assignment operator
        ThreadContextWrapper& operator=(ThreadContextWrapper&& other) noexcept = default;

        // Accessor for the internal CONTEXT structure
        CONTEXT* GetContext() { return m_context.get(); }
        const CONTEXT* GetContext() const { return m_context.get(); }

    private:
        std::unique_ptr<CONTEXT> m_context;  // Managed memory for CONTEXT

        // Private method to retrieve thread context from a SafeHandle
        std::expected<void, std::string> _GetThreadContextWrapped(WrappedHandle<HANDLE>&& hThread) {
            if (!GetThreadContext(hThread.Get(), m_context.get())) {
                return std::unexpected("Failed to get thread context. Error: " + std::to_string(GetLastError()));
            }
            return {};
        }
    };

    //
    // Named Pipe Wrapper
    //

    class NamedPipe {
    public:
        static std::expected<NamedPipe, std::string> Create(
            const std::wstring& pipeName,
            DWORD openMode,
            DWORD pipeMode,
            DWORD maxInstances,
            DWORD outBufferSize,
            DWORD inBufferSize,
            DWORD defaultTimeOut,
            LPSECURITY_ATTRIBUTES securityAttributes = nullptr
        ) {
            HANDLE hPipe = CreateNamedPipeW(
                pipeName.c_str(),
                openMode,
                pipeMode,
                maxInstances,
                outBufferSize,
                inBufferSize,
                defaultTimeOut,
                securityAttributes
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                return std::unexpected("Failed to create named pipe: " + std::to_string(GetLastError()));
            }

            return NamedPipe(WrappedHandle(hPipe));
        }

        static std::expected<NamedPipe, std::string> Connect(const std::wstring& pipeName) {
            HANDLE hPipe = CreateFileW(
                pipeName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                return std::unexpected("Failed to connect to named pipe: " + std::to_string(GetLastError()));
            }

            return NamedPipe(WrappedHandle(hPipe));
        }

        std::expected<void, std::string> ConnectToNewClient() {
            if (!ConnectNamedPipe(m_hPipe.Get(), nullptr)) {
                return std::unexpected("Failed to connect to new client: " + std::to_string(GetLastError()));
            }
            return {};
        }

        std::expected<size_t, std::string> Read(void* buffer, size_t bufferSize) {
            DWORD bytesRead;
            if (!ReadFile(m_hPipe.Get(), buffer, static_cast<DWORD>(bufferSize), &bytesRead, nullptr)) {
                return std::unexpected("Failed to read from pipe: " + std::to_string(GetLastError()));
            }
            return bytesRead;
        }

        std::expected<size_t, std::string> Write(const void* buffer, size_t bufferSize) {
            DWORD bytesWritten;
            if (!WriteFile(m_hPipe.Get(), buffer, static_cast<DWORD>(bufferSize), &bytesWritten, nullptr)) {
                return std::unexpected("Failed to write to pipe: " + std::to_string(GetLastError()));
            }
            return bytesWritten;
        }

    private:
        explicit NamedPipe(WrappedHandle<HANDLE>&& hPipe) : m_hPipe(std::move(hPipe)) {}

        WrappedHandle<HANDLE> m_hPipe;
    };

    //
    // Memory Allocation
    //

     // Wrapper for VirtualAllocEx in remote process
    inline std::expected<LPVOID, std::string> _VirtualAllocEx(HANDLE hProcess, SIZE_T size, DWORD flAllocationType = MEM_COMMIT, DWORD flProtect = PAGE_READWRITE) noexcept {
        LPVOID allocatedMemory = ::VirtualAllocEx(hProcess, nullptr, size, flAllocationType, flProtect);
        if (!allocatedMemory) {
            return std::unexpected("Failed to allocate memory in target process. Error: " + std::to_string(::GetLastError()));
        }
        return allocatedMemory;
    }

    // Wrapper for VirtualFreeEx in remote process
    inline std::expected<void, std::string> _VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T size = 0, DWORD dwFreeType = MEM_RELEASE) noexcept {
        if (!::VirtualFreeEx(hProcess, lpAddress, size, dwFreeType)) {
            return std::unexpected("Failed to free memory in target process. Error: " + std::to_string(::GetLastError()));
        }
        return {};
    }

    //
    // Memory Writing
    //

    // Wrapper for WriteProcessMemory
    inline std::expected<void, std::string> _WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize) noexcept {
        SIZE_T bytesWritten;
        if (!::WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten) || bytesWritten != nSize) {
            return std::unexpected("Failed to write memory in target process. Error: " + std::to_string(::GetLastError()));
        }
        return {};
    }

    // 
    // Windows and NT API Extensions
    //
    namespace Extensions
    {
        // Wrapper to get the address of a function (e.g., LoadLibraryW) in a remote process
        inline std::expected<LPVOID, std::string> GetRemoteProcAddress(HANDLE hProcess, const std::wstring& moduleName, const std::string& procName) noexcept {
            auto moduleBaseResult = GetModuleBaseAddress(hProcess, moduleName);
            if (!moduleBaseResult) {
                return std::unexpected("Failed to find module base address: " + moduleBaseResult.error());
            }

            HMODULE localModuleHandle = ::GetModuleHandleW(moduleName.c_str());
            if (!localModuleHandle) {
                return std::unexpected("Failed to get local module handle. Error: " + std::to_string(::GetLastError()));
            }

            FARPROC localProcAddress = ::GetProcAddress(localModuleHandle, procName.c_str());
            if (!localProcAddress) {
                return std::unexpected("Failed to get local procedure address. Error: " + std::to_string(::GetLastError()));
            }

            uintptr_t offset = reinterpret_cast<uintptr_t>(localProcAddress) - reinterpret_cast<uintptr_t>(localModuleHandle);
            LPVOID remoteProcAddress = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(moduleBaseResult.value()) + offset);

            return remoteProcAddress;
        }
    }

} // namespace Wrappers