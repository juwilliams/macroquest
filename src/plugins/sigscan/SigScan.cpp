/*
 * MacroQuest: The extension platform for EverQuest
 * Copyright (C) 2002-present MacroQuest Authors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "SigScan.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <cmath>

namespace sigscan {

SigScanner::SigScanner()
{
}

void SigScanner::SetTextSection(uintptr_t baseAddress, size_t size)
{
	m_textBase = baseAddress;
	m_textSize = size;
}

void SigScanner::SetBaseAddresses(uintptr_t preferredBase, uintptr_t actualBase)
{
	m_preferredBase = preferredBase;
	m_actualBase = actualBase;
}

std::vector<uintptr_t> SigScanner::FindAllMatches(const PatternData& pattern) const
{
	std::vector<uintptr_t> matches;

	if (m_textBase == 0 || m_textSize == 0 || pattern.bytes.empty())
		return matches;

	const uint8_t* base = reinterpret_cast<const uint8_t*>(m_textBase);
	size_t patLen = pattern.bytes.size();

	if (patLen > m_textSize)
		return matches;

	for (size_t i = 0; i <= m_textSize - patLen; ++i)
	{
		bool match = true;
		for (size_t j = 0; j < patLen; ++j)
		{
			if (pattern.mask[j] == 'x' && base[i + j] != pattern.bytes[j])
			{
				match = false;
				break;
			}
		}
		if (match)
		{
			matches.push_back(m_textBase + i);
		}
	}

	return matches;
}

uintptr_t SigScanner::ResolveGlobalRef(uintptr_t matchAddr, int offsetAdjust, int derefInsnLen) const
{
	// Read the RIP-relative displacement
	uintptr_t dispAddr = matchAddr + offsetAdjust;
	int32_t disp;
	std::memcpy(&disp, reinterpret_cast<const void*>(dispAddr), 4);

	// RIP-relative: target = instruction_end + displacement
	// instruction_end = matchAddr + derefInsnLen (from start of the referencing instruction)
	// But offsetAdjust points to the disp within the pattern, and the instruction starts
	// at matchAddr + (offsetAdjust - dispOffsetWithinInsn). Since we stored offsetAdjust
	// as the offset from pattern start to the displacement, and derefInsnLen as the
	// instruction length, the instruction starts at (dispAddr - dispOffsetWithinInsn).
	// Actually: the instruction that contains the displacement starts at some offset,
	// and ends at instrStart + derefInsnLen. The displacement is at instrStart + dispOffsetInInsn.
	// We have: dispAddr = matchAddr + offsetAdjust = instrStart + dispOffsetInInsn
	// We need: instrEnd = instrStart + derefInsnLen
	// But we don't separately store dispOffsetInInsn vs instrStart offset.
	//
	// Simplification: For most RIP-relative instructions, the displacement is the last
	// 4 bytes of the instruction. So instrEnd = dispAddr + 4.
	// This is true for MOV, LEA, CMP, etc. with no immediate following the displacement.

	uintptr_t instrEnd = dispAddr + 4;
	uintptr_t target = instrEnd + static_cast<int64_t>(disp);

	return target;
}

ScanResult SigScanner::Scan(const SignatureEntry& entry) const
{
	ScanResult result;
	result.name = entry.name;

	// Parse old address
	if (!entry.previousAddress.empty())
	{
		result.oldAddress = std::stoull(entry.previousAddress, nullptr, 16);
	}

	PatternData pattern = PatternFromString(entry.pattern);
	auto matches = FindAllMatches(pattern);

	result.matchCount = static_cast<int>(matches.size());

	if (matches.empty())
	{
		result.confidence = ScanConfidence::NotFound;
		result.errorMessage = "No matches found";
		return result;
	}

	uintptr_t matchAddr;

	if (matches.size() == 1)
	{
		matchAddr = matches[0];
		result.confidence = ScanConfidence::High;
	}
	else
	{
		// Multiple matches - pick the one nearest to the old address (adjusted for base)
		uintptr_t oldActual = result.oldAddress - m_preferredBase + m_actualBase;
		matchAddr = matches[0];
		int64_t bestDist = std::abs(static_cast<int64_t>(matches[0]) - static_cast<int64_t>(oldActual));

		for (size_t i = 1; i < matches.size(); ++i)
		{
			int64_t dist = std::abs(static_cast<int64_t>(matches[i]) - static_cast<int64_t>(oldActual));
			if (dist < bestDist)
			{
				bestDist = dist;
				matchAddr = matches[i];
			}
		}

		result.confidence = ScanConfidence::Low;
		std::ostringstream oss;
		oss << matches.size() << " matches found, picked nearest to old address";
		result.errorMessage = oss.str();
	}

	// Resolve the actual address
	if (entry.type == OffsetType::Function)
	{
		// Pattern match IS the function address
		uintptr_t preferredAddr = matchAddr - m_actualBase + m_preferredBase;
		result.newAddress = preferredAddr;
	}
	else if (entry.type == OffsetType::GlobalRef)
	{
		// Need to dereference RIP-relative to get the actual global address
		uintptr_t actualAddr = ResolveGlobalRef(matchAddr, entry.offsetAdjust, entry.derefInsnLen);
		uintptr_t preferredAddr = actualAddr - m_actualBase + m_preferredBase;
		result.newAddress = preferredAddr;
	}

	result.delta = static_cast<int64_t>(result.newAddress) - static_cast<int64_t>(result.oldAddress);

	return result;
}

std::vector<ScanResult> SigScanner::ScanAll(const std::vector<SignatureEntry>& entries) const
{
	std::vector<ScanResult> results;
	results.reserve(entries.size());

	for (const auto& entry : entries)
	{
		results.push_back(Scan(entry));
	}

	return results;
}

// --- JSON Serialization ---
// Using simple manual JSON generation to avoid adding a JSON library dependency.

static std::string EscapeJson(const std::string& s)
{
	std::string result;
	result.reserve(s.size());
	for (char c : s)
	{
		switch (c)
		{
		case '"':  result += "\\\""; break;
		case '\\': result += "\\\\"; break;
		case '\n': result += "\\n"; break;
		case '\r': result += "\\r"; break;
		case '\t': result += "\\t"; break;
		default:   result += c; break;
		}
	}
	return result;
}

std::string SignaturesToJson(const std::vector<SignatureEntry>& entries, const std::string& clientDate)
{
	std::ostringstream json;
	json << "{\n";
	json << "  \"version\": 1,\n";
	json << "  \"generated_from\": \"" << EscapeJson(clientDate) << "\",\n";
	json << "  \"signatures\": {\n";

	for (size_t i = 0; i < entries.size(); ++i)
	{
		const auto& e = entries[i];
		json << "    \"" << EscapeJson(e.name) << "\": {\n";
		json << "      \"pattern\": \"" << EscapeJson(e.pattern) << "\",\n";
		json << "      \"type\": \"" << (e.type == OffsetType::Function ? "function" : "global_ref") << "\",\n";
		json << "      \"offset_adjust\": " << e.offsetAdjust << ",\n";
		json << "      \"deref_insn_len\": " << e.derefInsnLen << ",\n";
		json << "      \"previous_address\": \"" << EscapeJson(e.previousAddress) << "\"\n";
		json << "    }";
		if (i + 1 < entries.size())
			json << ",";
		json << "\n";
	}

	json << "  }\n";
	json << "}\n";

	return json.str();
}

// Simple JSON parser for our specific format
static std::string ExtractJsonString(const std::string& json, const std::string& key)
{
	std::string searchKey = "\"" + key + "\"";
	size_t pos = json.find(searchKey);
	if (pos == std::string::npos) return "";

	pos = json.find(':', pos + searchKey.size());
	if (pos == std::string::npos) return "";

	pos = json.find('"', pos + 1);
	if (pos == std::string::npos) return "";

	size_t end = pos + 1;
	while (end < json.size() && json[end] != '"')
	{
		if (json[end] == '\\') end++; // skip escaped char
		end++;
	}

	return json.substr(pos + 1, end - pos - 1);
}

static int ExtractJsonInt(const std::string& json, const std::string& key)
{
	std::string searchKey = "\"" + key + "\"";
	size_t pos = json.find(searchKey);
	if (pos == std::string::npos) return 0;

	pos = json.find(':', pos + searchKey.size());
	if (pos == std::string::npos) return 0;

	pos++;
	while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

	return std::atoi(json.c_str() + pos);
}

std::vector<SignatureEntry> SignaturesFromJson(const std::string& json, std::string* outClientDate)
{
	std::vector<SignatureEntry> entries;

	if (outClientDate)
		*outClientDate = ExtractJsonString(json, "generated_from");

	// Find "signatures" block
	size_t sigPos = json.find("\"signatures\"");
	if (sigPos == std::string::npos)
		return entries;

	// Find each entry by looking for pattern of "name": {
	size_t pos = json.find('{', sigPos + 12); // skip past "signatures":
	if (pos == std::string::npos)
		return entries;

	pos++; // skip opening brace of signatures object

	while (pos < json.size())
	{
		// Find next entry name
		size_t nameStart = json.find('"', pos);
		if (nameStart == std::string::npos)
			break;

		// Check if we've hit the closing brace
		size_t bracePos = json.find('}', pos);
		if (bracePos != std::string::npos && bracePos < nameStart)
			break;

		size_t nameEnd = json.find('"', nameStart + 1);
		if (nameEnd == std::string::npos)
			break;

		std::string name = json.substr(nameStart + 1, nameEnd - nameStart - 1);

		// Find the entry's object
		size_t objStart = json.find('{', nameEnd);
		if (objStart == std::string::npos)
			break;

		// Find matching closing brace (simple - no nested objects in entries)
		size_t objEnd = json.find('}', objStart);
		if (objEnd == std::string::npos)
			break;

		std::string entryJson = json.substr(objStart, objEnd - objStart + 1);

		SignatureEntry entry;
		entry.name = name;
		entry.pattern = ExtractJsonString(entryJson, "pattern");

		std::string typeStr = ExtractJsonString(entryJson, "type");
		entry.type = (typeStr == "global_ref") ? OffsetType::GlobalRef : OffsetType::Function;

		entry.offsetAdjust = ExtractJsonInt(entryJson, "offset_adjust");
		entry.derefInsnLen = ExtractJsonInt(entryJson, "deref_insn_len");
		entry.previousAddress = ExtractJsonString(entryJson, "previous_address");

		entries.push_back(entry);

		pos = objEnd + 1;
	}

	return entries;
}

std::string ScanResultsToJson(const std::vector<ScanResult>& results)
{
	std::ostringstream json;
	json << "{\n";
	json << "  \"results\": [\n";

	for (size_t i = 0; i < results.size(); ++i)
	{
		const auto& r = results[i];
		json << "    {\n";
		json << "      \"name\": \"" << EscapeJson(r.name) << "\",\n";

		const char* confStr = "not_found";
		if (r.confidence == ScanConfidence::High) confStr = "high";
		else if (r.confidence == ScanConfidence::Low) confStr = "low";

		json << "      \"confidence\": \"" << confStr << "\",\n";
		json << "      \"new_address\": \"0x" << std::uppercase << std::hex << r.newAddress << "\",\n";
		json << "      \"old_address\": \"0x" << std::uppercase << std::hex << r.oldAddress << "\",\n";
		json << std::dec;
		json << "      \"delta\": " << r.delta << ",\n";
		json << "      \"match_count\": " << r.matchCount;
		if (!r.errorMessage.empty())
			json << ",\n      \"error\": \"" << EscapeJson(r.errorMessage) << "\"";
		json << "\n    }";
		if (i + 1 < results.size())
			json << ",";
		json << "\n";
	}

	json << "  ]\n";
	json << "}\n";

	return json.str();
}

} // namespace sigscan
