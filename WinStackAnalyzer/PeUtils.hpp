// PeUtils.hpp
// Header-only library for parsing PE files
#pragma once

#include <Windows.h>
#include <winnt.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <memory>
#include <expected>
#include <fstream>
#include <functional>
#include <system_error>

#include "WinWrap.hpp"  // Include WinWrap for necessary utilities

namespace PeUtils
{
    //
    // Class representing a Portable Executable (PE) file
    //
    class PeFile
    {
    public:
        // Constructor now returns a result type
        static std::expected<PeFile, std::string> Create(const std::wstring& filePath)
        {
            auto fileDataResult = ReadFileContents(filePath);
            if (!fileDataResult) {
                return std::unexpected(fileDataResult.error());
            }

            return PeFile(std::move(fileDataResult.value()));
        }

        // Check if the PE file is 64-bit
        std::expected<bool, std::string> Is64Bit() const noexcept
        {
            try {
                return m_ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
            }
            catch (...) {
                return std::unexpected("Failed to determine if PE is 64-bit");
            }
        }

        // Get the image base of the PE file
        std::expected<DWORD, std::string> GetImageBase() const noexcept
        {
            try {
                return m_ntHeaders->OptionalHeader.ImageBase;
            }
            catch (...) {
                return std::unexpected("Failed to get image base");
            }
        }

        // Get the size of the image
        std::expected<DWORD, std::string> GetSizeOfImage() const noexcept
        {
            try {
                return m_ntHeaders->OptionalHeader.SizeOfImage;
            }
            catch (...) {
                return std::unexpected("Failed to get size of image");
            }
        }

        // Get all sections of the PE file
        std::expected<std::vector<IMAGE_SECTION_HEADER>, std::string> GetSections() const noexcept
        {
            try {
                std::vector<IMAGE_SECTION_HEADER> sections;
                WORD numberOfSections = m_ntHeaders->FileHeader.NumberOfSections;
                IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(m_ntHeaders);

                for (WORD i = 0; i < numberOfSections; ++i) {
                    sections.push_back(sectionHeader[i]);
                }

                return sections;
            }
            catch (...) {
                return std::unexpected("Failed to get sections");
            }
        }

        // Get a specific section by its name
        std::expected<IMAGE_SECTION_HEADER, std::string> GetSectionByName(const std::string& name) const noexcept
        {
            try {
                auto sectionsResult = GetSections();
                if (!sectionsResult) {
                    return std::unexpected(sectionsResult.error());
                }

                for (const auto& section : sectionsResult.value()) {
                    if (std::string(reinterpret_cast<const char*>(section.Name)) == name) {
                        return section;
                    }
                }

                return std::unexpected("Section not found");
            }
            catch (...) {
                return std::unexpected("Failed to get section by name");
            }
        }

        // Get all imported DLLs
        std::expected<std::vector<std::string>, std::string> GetImportedDlls() const noexcept
        {
            try {
                std::vector<std::string> dlls;
                auto importDir = m_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDir.Size == 0) {
                    return dlls;  // No imports
                }

                auto offsetResult = RvaToFileOffset(importDir.VirtualAddress);
                if (!offsetResult) {
                    return std::unexpected(offsetResult.error());
                }

                auto importDescriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                    m_fileData.data() + offsetResult.value());

                while (importDescriptor->Name != 0) {
                    auto nameOffsetResult = RvaToFileOffset(importDescriptor->Name);
                    if (!nameOffsetResult) {
                        return std::unexpected(nameOffsetResult.error());
                    }

                    dlls.emplace_back(reinterpret_cast<const char*>(
                        m_fileData.data() + nameOffsetResult.value()));
                    importDescriptor++;
                }
                return dlls;
            }
            catch (...) {
                return std::unexpected("Failed to get imported DLLs");
            }
        }

        // Get all RUNTIME_FUNCTIONs (exception handling data)
        std::expected<std::vector<RUNTIME_FUNCTION>, std::string> GetRuntimeFunctions() const noexcept
        {
            try {
                std::vector<RUNTIME_FUNCTION> functions;
                auto exceptionDir = m_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (exceptionDir.Size == 0) {
                    return functions;  // No exception data
                }

                auto is64BitResult = Is64Bit();
                if (!is64BitResult) {
                    return std::unexpected(is64BitResult.error());
                }

                if (!is64BitResult.value()) {
                    return std::unexpected("RUNTIME_FUNCTIONs are only available for 64-bit PE files");
                }

                auto offsetResult = RvaToFileOffset(exceptionDir.VirtualAddress);
                if (!offsetResult) {
                    return std::unexpected(offsetResult.error());
                }

                auto runtimeFunctions = reinterpret_cast<const RUNTIME_FUNCTION*>(
                    m_fileData.data() + offsetResult.value());
                size_t functionCount = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

                for (size_t i = 0; i < functionCount; ++i) {
                    functions.push_back(runtimeFunctions[i]);
                }

                return functions;
            }
            catch (...) {
                return std::unexpected("Failed to get RUNTIME_FUNCTIONs");
            }
        }

        // Method to get all exported functions as a vector
        std::expected<std::vector<std::pair<std::string, DWORD>>, std::string> GetExportedFunctions() const noexcept
        {
            std::vector<std::pair<std::string, DWORD>> exports;
            auto result = ParseExportTable([&exports](const std::string& name, DWORD rva) {
                exports.emplace_back(name, rva);
                return std::expected<void, std::string>{};
                });

            if (!result) {
                return std::unexpected(result.error());
            }

            return exports;
        }

        // Method to iterate over the Export Address Table (EAT) with a callback
        std::expected<void, std::string> GetExportedFunctions(
            const std::function<std::expected<void, std::string>(const std::string&, DWORD)>& callback) const noexcept
        {
            return ParseExportTable(callback);
        }

        // Check if the file is a valid DLL
        std::expected<bool, std::string> IsValidDll() const noexcept
        {
            try {
                // Check if the file is a PE file
                if (m_ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
                    return true;
                }
                return false;
            }
            catch (...) {
                return std::unexpected("Failed to validate DLL");
            }
        }

    private:
        std::vector<uint8_t> m_fileData;
        const IMAGE_DOS_HEADER* m_dosHeader;
        const IMAGE_NT_HEADERS* m_ntHeaders;

        // Private constructor
        explicit PeFile(std::vector<uint8_t>&& fileData)
            : m_fileData(std::move(fileData))
            , m_dosHeader(nullptr)
            , m_ntHeaders(nullptr)
        {
            m_dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_fileData.data());
            if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                throw std::runtime_error("Invalid DOS signature");
            }

            m_ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(m_fileData.data() + m_dosHeader->e_lfanew);
            if (m_ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
                throw std::runtime_error("Invalid NT signature");
            }
        }

        // Read the entire contents of a file into a vector
        static std::expected<std::vector<uint8_t>, std::string> ReadFileContents(const std::wstring& filePath)
        {
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file) {
                return std::unexpected("Failed to open file");
            }

            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);

            std::vector<uint8_t> buffer(static_cast<size_t>(size));
            if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                return std::unexpected("Failed to read file");
            }

            return buffer;
        }

        // Convert a Relative Virtual Address (RVA) to a file offset
        std::expected<DWORD, std::string> RvaToFileOffset(DWORD rva) const
        {
            auto sectionsResult = GetSections();
            if (!sectionsResult) {
                return std::unexpected(sectionsResult.error());
            }

            for (const auto& section : sectionsResult.value()) {
                if (rva >= section.VirtualAddress &&
                    rva < section.VirtualAddress + section.Misc.VirtualSize) {
                    return rva - section.VirtualAddress + section.PointerToRawData;
                }
            }

            return std::unexpected("RVA not found in any section");
        }

        // Private method to parse the export table
        std::expected<void, std::string> ParseExportTable(
            const std::function<std::expected<void, std::string>(const std::string&, DWORD)>& callback) const noexcept
        {
            try {
                auto exportDir = m_ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                if (exportDir.Size == 0) {
                    return {}; // No exports, return successfully
                }

                auto offsetResult = RvaToFileOffset(exportDir.VirtualAddress);
                if (!offsetResult) {
                    return std::unexpected(offsetResult.error());
                }

                if (offsetResult.value() + sizeof(IMAGE_EXPORT_DIRECTORY) > m_fileData.size()) {
                    return std::unexpected("Export directory out of bounds");
                }

                auto exportTable = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                    m_fileData.data() + offsetResult.value());

                auto functionsOffsetResult = RvaToFileOffset(exportTable->AddressOfFunctions);
                auto namesOffsetResult = RvaToFileOffset(exportTable->AddressOfNames);
                auto ordinalsOffsetResult = RvaToFileOffset(exportTable->AddressOfNameOrdinals);

                if (!functionsOffsetResult || !namesOffsetResult || !ordinalsOffsetResult) {
                    return std::unexpected("Failed to get offsets for export table");
                }

                auto functionsOffset = functionsOffsetResult.value();
                auto namesOffset = namesOffsetResult.value();
                auto ordinalsOffset = ordinalsOffsetResult.value();

                if (functionsOffset + exportTable->NumberOfFunctions * sizeof(DWORD) > m_fileData.size() ||
                    namesOffset + exportTable->NumberOfNames * sizeof(DWORD) > m_fileData.size() ||
                    ordinalsOffset + exportTable->NumberOfNames * sizeof(WORD) > m_fileData.size()) {
                    return std::unexpected("Export table data out of bounds");
                }

                const DWORD* functions = reinterpret_cast<const DWORD*>(m_fileData.data() + functionsOffset);
                const DWORD* names = reinterpret_cast<const DWORD*>(m_fileData.data() + namesOffset);
                const WORD* ordinals = reinterpret_cast<const WORD*>(m_fileData.data() + ordinalsOffset);

                for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
                    if (i >= exportTable->NumberOfFunctions) {
                        return std::unexpected("Export table corrupted: more names than functions");
                    }

                    auto nameRvaResult = RvaToFileOffset(names[i]);
                    if (!nameRvaResult) {
                        return std::unexpected("Failed to get name RVA for export " + std::to_string(i));
                    }

                    auto nameOffset = nameRvaResult.value();
                    if (nameOffset >= m_fileData.size()) {
                        return std::unexpected("Name offset out of bounds for export " + std::to_string(i));
                    }

                    std::string functionName;
                    for (size_t j = nameOffset; j < m_fileData.size(); ++j) {
                        if (m_fileData[j] == 0) {
                            functionName = std::string(reinterpret_cast<const char*>(&m_fileData[nameOffset]), j - nameOffset);
                            break;
                        }
                    }

                    if (functionName.empty()) {
                        return std::unexpected("Failed to read function name for export " + std::to_string(i));
                    }

                    if (ordinals[i] >= exportTable->NumberOfFunctions) {
                        return std::unexpected("Ordinal out of bounds for export " + std::to_string(i));
                    }

                    DWORD functionRva = functions[ordinals[i]];

                    auto callbackResult = callback(functionName, functionRva);
                    if (!callbackResult) {
                        return std::unexpected("Callback failed for function " + functionName + ": " + callbackResult.error());
                    }
                }

                return {};
            }
            catch (const std::exception& e) {
                return std::unexpected("Exception in ParseExportTable: " + std::string(e.what()));
            }
            catch (...) {
                return std::unexpected("Unknown exception in ParseExportTable");
            }
        }
    };

    // Check if a file is a valid PE file
    inline std::expected<bool, std::string> IsPeFile(const std::wstring& filePath) noexcept
    {
        auto peFileResult = PeFile::Create(filePath);
        return peFileResult.has_value();
    }
}