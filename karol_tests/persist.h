#pragma once

#include <string>
#include <unordered_map>

#include "tools.h"

struct Persist
{
  // min 438, max 9504
  OlmBuffer account;
  // min = 224, max = 4384
  std::unordered_map<std::string, OlmBuffer> sessions;
};