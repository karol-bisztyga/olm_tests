#pragma once

#include <string>
#include <unordered_map>

#include "tools.h"

using namespace std;

struct Persist
{
  // min 438, max 9504
  OlmBuffer account;
  // min = 224, max = 4384
  unordered_map<string, OlmBuffer> sessions;
};