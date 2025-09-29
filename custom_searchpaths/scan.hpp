#include <sstream>
#include <vector>

inline std::vector<int> ParseSignature(const char* sig)
{
    std::vector<int> pattern;
    std::istringstream iss(sig);
    std::string tok;
    while (iss >> tok) {
        if (tok == "?" || tok == "??") {
            pattern.push_back(-1);
            continue;
        }
        size_t start = 0;
        if (tok.size() > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X'))
            start = 2;
        if (tok.size() - start != 2) {
            pattern.push_back(-1);
            continue;
        }
        char hi = tok[start];
        char lo = tok[start + 1];
        auto hexval = [](char c)->int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
            };
        int hv = hexval(hi);
        int lv = hexval(lo);
        if (hv < 0 || lv < 0) {
            pattern.push_back(-1);
            continue;
        }
        pattern.push_back((hv << 4) | lv);
    }
    return pattern;
}

inline void* ScanModule(HMODULE Module, const char* signature)
{
    if (!Module || !signature) return nullptr;
    std::vector<int> pattern = ParseSignature(signature);
    if (pattern.empty()) return nullptr;
    SIZE_T patLen = pattern.size();
    BYTE* base = reinterpret_cast<BYTE*>(Module);
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    if (imageSize <= patLen) return nullptr;
    const SIZE_T maxScan = imageSize - patLen;
    for (SIZE_T i = 0; i <= maxScan; ++i) {
        bool matched = true;
        for (SIZE_T j = 0; j < patLen; ++j) {
            int pb = pattern[j];
            if (pb != -1 && base[i + j] != static_cast<BYTE>(pb)) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return static_cast<void*>(base + i);
        }
    }
    return nullptr;
}