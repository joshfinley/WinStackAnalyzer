#pragma once

#include <concepts>
#include <utility>
#include <stdexcept>
#include <format>
#include <memory>
#include <expected>
#include <string>
#include <vector>

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

    template <typename T>
    concept HandleType = std::same_as<T, HANDLE>;

    // SafeHandle class template for managing Windows handles
    // 
    // The template parameter H ensures that the data type of the handle
    // is the same as HANDLE
    template <HandleType H>
    class SafeHandle final
    {
    public:
        // SafeHandle default constructor
        inline SafeHandle() noexcept = default;

        // SafeHandle explicity constructor from H handle
        inline explicit SafeHandle(H handle) noexcept : m_handle(handle) {}

        // SafeHandle deconstructor
        inline ~SafeHandle() noexcept
        {
            Close();
        }

        SafeHandle(const SafeHandle&) = delete;
        SafeHandle& operator=(const SafeHandle&) = delete;

        // SafeHandle move constructor
        inline SafeHandle(SafeHandle&& other) noexcept
            : m_handle(std::exchange(other.m_handle, s_nullValue))
        {
        }

        // SafeHandle move assignment operator
        inline SafeHandle& operator=(SafeHandle&& other) noexcept
        {
            if (this != &other)
            {
                Close();
                m_handle = std::exchange(other.m_handle, s_nullValue);
            }
            return *this;
        }

        // Check if the handle is valid
        [[nodiscard]] inline bool IsValid() const noexcept
        {
            return !IsInvalid(m_handle);
        }

        // Get the raw handle
        [[nodiscard]] inline H Get() const noexcept
        {
            return m_handle;
        }

        // Reassign the SafeHandle's handle
        inline void Reset(H newHandle = s_nullValue) noexcept
        {
            if (m_handle != newHandle)
            {
                Close();
                m_handle = newHandle;
            }
        }

        // Get the handle and release the SafeHandle's handle
        inline H Release() noexcept
        {
            return std::exchange(m_handle, s_nullValue);
        }

        // SafeHandle bool() operator
        inline explicit operator bool() const noexcept
        {
            return IsValid();
        }

        // SafeHandle conversion operator
        inline explicit operator H() const noexcept
        {
            return m_handle;
        }

    private:
        static constexpr H s_nullValue = nullptr;
        static constexpr H s_invalidValue = INVALID_HANDLE_VALUE;

        H m_handle{ s_nullValue };

        // Check if the HANDLE value is invalid
        inline  static bool IsInvalid(H handle) noexcept
        {
            return handle == s_nullValue || handle == s_invalidValue;
        }

        // Close the handle if not invalid
        inline void Close() noexcept
        {
            if (!IsInvalid(m_handle))
            {
                ::CloseHandle(m_handle);
                m_handle = s_nullValue;
            }
        }
    };

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

    // Get the last error code automatically
    inline std::expected<std::string, uint32_t> GetLastErrorAsString() noexcept {
        return GetWinErrorAsString(::GetLastError());
    }

    //
    // Tool Help Function Wrappers
    //

    inline std::expected<SafeHandle<HANDLE>, std::string> _CreateToolhelp32Snapshot(uint32_t flags, uint32_t th32ProcessID) noexcept
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
        return SafeHandle<HANDLE>(hSnapshot);
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

        for (const auto& hModule : modulesResult.value()) {
            auto fileNameResult = _GetModuleFileNameEx(hProcess, hModule);
            if (!fileNameResult) {
                continue; // Skip this module if we can't get its file name
            }

            if (fileNameResult.value().find(moduleName) != std::wstring::npos) {
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

    inline std::expected<SafeHandle<HANDLE>, std::string> _OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) noexcept {
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
        return SafeHandle<HANDLE>(hThread);
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

    inline std::expected<SafeHandle<HANDLE>, std::string> _OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) noexcept {
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
        return SafeHandle<HANDLE>(hProcess);
    }

} // namespace Wrappers